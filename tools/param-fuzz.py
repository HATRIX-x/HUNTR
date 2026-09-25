#!/usr/bin/env python3
"""
param-fuzz — hidden parameter discovery via differential response analysis.

Strategy (Arjun-style):
  1. Send baseline request, note response size + status.
  2. Inject parameter batches (default 30 at a time) with random sentinel values.
  3. Any response that deviates (size diff >30 bytes OR status change OR
     sentinel reflected) → binary-search the batch to isolate the parameter.
  4. For IDOR: if --idor-field is set, also test sequential IDs and UUID variants.

Usage:
  param-fuzz.py --url https://api.acme.com/v1/profile
                [--method GET|POST] [--token Bearer_xxx]
                [--header X-Foo:bar] [--data '{"a":1}']
                [--wordlist params.txt]
                [--idor-field id] [--idor-base 1234]
                [--batch 30] [--threads 10] [--delay 0]
                [--json] [--out results.json]
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, ssl, random, string
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
def args_multi(n):
    vals = []
    for i, a in enumerate(sys.argv):
        if a == n and i+1 < len(sys.argv): vals.append(sys.argv[i+1])
    return vals
def flag(n): return n in sys.argv

# built-in parameter wordlist (~400 common hidden params)
BUILTIN_PARAMS = """debug test verbose trace admin superuser internal hidden
id user_id userId uid account_id accountId profile_id org_id orgId
role roles access level tier priv privilege permissions scope
token api_key apiKey api_token secret key auth authorization
format output type version v lang locale country region
callback redirect url next return redirect_uri returnUrl returnTo
ref referrer source src origin page limit offset skip cursor
order sort filter search q query fields include exclude expand
view mode action cmd command op operation method format
preview draft publish unpublish archive restore delete
enable disable toggle override bypass force dev preview_token
_debug _test _internal _format _method override X-Original-URL
admin_token access_token refresh_token session_id sessionId
affiliate_id partner_id promo_code discount coupon
webhook_url notify_url callback_url ipn_url
file path dir folder filename attachment
email phone address name username display_name
password old_password new_password confirm_password
code otp mfa pin verify verification_code
client_id client_secret app_id app_key
transaction_id order_id payment_id invoice_id
start_date end_date from to date timestamp
lat lng latitude longitude location address
color theme style template layout
width height size resolution quality
custom1 custom2 extra info metadata tags labels
_wpnonce nonce csrf_token authenticity_token _token
jsonp callback _callback json xml csv pdf
expand fields embed related associations includes
sudo impersonate as_user run_as on_behalf""".split()

def random_sentinel(length=8):
    return "huntr" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def send_request(url, method, headers, params=None, body=None, timeout=12):
    """Returns (status, body_text, response_size)."""
    import urllib.request, urllib.parse
    ctx = build_ctx()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    target = url
    if params and method.upper() == "GET":
        qs = urllib.parse.urlencode(params)
        target = url + ("&" if "?" in url else "?") + qs
    data = None
    if method.upper() in ("POST","PUT","PATCH"):
        if params and not body:
            # inject as JSON if content-type json, else form
            ct = headers.get("Content-Type","")
            if "json" in ct:
                try:
                    existing = json.loads(body or "{}")
                    existing.update(params)
                    data = json.dumps(existing).encode()
                except Exception:
                    data = json.dumps(params).encode()
            else:
                data = urllib.parse.urlencode(params).encode()
        elif body:
            data = body.encode() if isinstance(body, str) else body
    req = Request(target, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            resp = r.read(8192).decode("utf-8","ignore")
            return r.status, resp, len(resp)
    except HTTPError as e:
        resp = ""
        try: resp = e.read(2048).decode("utf-8","ignore")
        except: pass
        return e.code, resp, len(resp)
    except Exception as e:
        return 0, str(e)[:200], 0

def deviation(base_status, base_size, new_status, new_size, new_body, sentinel):
    if new_status != base_status: return True, f"status changed {base_status}→{new_status}"
    size_diff = abs(new_size - base_size)
    if size_diff > 30: return True, f"size changed by {size_diff}"
    if sentinel and sentinel in new_body: return True, f"sentinel reflected in response"
    return False, ""

def build_headers(token=None, extra_headers=None, method="GET"):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, text/html, */*"}
    if token:
        h["Authorization"] = token if " " in token else f"Bearer {token}"
    if method.upper() in ("POST","PUT","PATCH"):
        h["Content-Type"] = "application/json"
    if extra_headers:
        for eh in extra_headers:
            if ":" in eh:
                k,v = eh.split(":",1); h[k.strip()] = v.strip()
    return h

def binary_search_params(url, method, headers, batch, base_status, base_size, body, sentinel, timeout=12):
    """Find which param(s) in the batch cause deviation."""
    if len(batch) == 0: return []
    if len(batch) == 1:
        # confirm it individually
        params = {batch[0]: sentinel}
        status, resp, size = send_request(url, method, headers, params=params, body=body, timeout=timeout)
        dev, reason = deviation(base_status, base_size, status, size, resp, sentinel)
        if dev:
            return [{"param": batch[0], "status": status, "deviation": reason, "sentinel": sentinel}]
        return []

    mid = len(batch)//2
    for half in (batch[:mid], batch[mid:]):
        params = {p: sentinel for p in half}
        status, resp, size = send_request(url, method, headers, params=params, body=body, timeout=timeout)
        dev, _ = deviation(base_status, base_size, status, size, resp, sentinel)
        if dev:
            return binary_search_params(url, method, headers, half, base_status, base_size, body, sentinel, timeout)
    return []

def test_idor(url, method, headers, idor_field, idor_base, timeout=12):
    """Test sequential IDs and cross-user access patterns."""
    findings = []
    try:
        base_id = int(idor_base)
    except:
        return []
    test_ids = [
        base_id - 1, base_id + 1, base_id - 100, base_id + 100,
        1, 2, 3, 100, 9999, 99999,
    ]
    # get baseline with correct ID
    base_status, base_body, base_size = send_request(url, method, headers, params={idor_field: base_id}, timeout=timeout)
    for test_id in test_ids:
        if test_id <= 0 or test_id == base_id: continue
        status, body, size = send_request(url, method, headers, params={idor_field: test_id}, timeout=timeout)
        if is_success(status):
            # check if body is meaningfully different (different resource)
            if size > 50 and abs(size - base_size) > 20:
                findings.append({
                    "type": "idor_candidate",
                    "field": idor_field,
                    "test_id": test_id,
                    "base_id": base_id,
                    "status": status,
                    "severity": "high",
                    "note": f"Different resource returned for {idor_field}={test_id} (size diff {abs(size-base_size)}b) — verify manually",
                })
    return findings

def is_success(status): return 200 <= status < 300

def main():
    url         = arg("--url")
    method      = arg("--method","GET").upper()
    token       = arg("--token")
    extra_h     = args_multi("--header")
    body        = arg("--data")
    wordlist    = arg("--wordlist")
    idor_field  = arg("--idor-field")
    idor_base   = arg("--idor-base")
    batch_size  = int(arg("--batch","30"))
    threads     = int(arg("--threads","10"))
    delay_s     = float(arg("--delay","0"))
    out_file    = arg("--out")

    if not url: print(__doc__); sys.exit(0)

    # load parameter list
    params = list(BUILTIN_PARAMS)
    if wordlist and Path(wordlist).exists():
        extras = [w.strip() for w in Path(wordlist).read_text().splitlines() if w.strip() and not w.startswith("#")]
        params = list(dict.fromkeys(extras + params))  # deduplicate, extras first

    headers = build_headers(token, extra_h, method)

    # baseline
    print(f"[param-fuzz] baseline {method} {url} …", file=sys.stderr)
    base_status, base_body, base_size = send_request(url, method, headers, body=body)
    print(f"[param-fuzz] baseline: HTTP {base_status} size={base_size}", file=sys.stderr)

    # batch sweep
    batches = [params[i:i+batch_size] for i in range(0, len(params), batch_size)]
    print(f"[param-fuzz] testing {len(params)} params in {len(batches)} batches …", file=sys.stderr)

    discovered = []
    sentinel = random_sentinel()

    def probe_batch(batch):
        p = {param: sentinel for param in batch}
        status, resp, size = send_request(url, method, headers, params=p, body=body)
        dev, reason = deviation(base_status, base_size, status, size, resp, sentinel)
        if dev:
            found = binary_search_params(url, method, headers, batch, base_status, base_size, body, sentinel)
            return found
        if delay_s: time.sleep(delay_s)
        return []

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe_batch, b): b for b in batches}
        for fut in as_completed(futs):
            results = fut.result()
            if results:
                for r in results:
                    print(f"  [FOUND] param={r['param']} deviation={r['deviation']}", file=sys.stderr)
                discovered += results

    # IDOR test
    idor_findings = []
    if idor_field and idor_base:
        print(f"[param-fuzz] IDOR test on {idor_field}={idor_base} …", file=sys.stderr)
        idor_findings = test_idor(url, method, headers, idor_field, idor_base)

    all_findings = []
    for d in discovered:
        all_findings.append({
            "type": "hidden_param",
            "param": d["param"],
            "deviation": d["deviation"],
            "status": d["status"],
            "severity": "medium",
            "note": f"Hidden parameter '{d['param']}' causes response deviation — test for injection/behavior change",
            "url": url,
        })
    all_findings += idor_findings

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url, "method": method,
        "params_tested": len(params),
        "total": len(all_findings),
        "findings": all_findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if all_findings else 0)

    print(f"\n══ Param fuzz · {url} ══════════════════════════")
    print(f"  Params tested: {len(params)}  Findings: {len(all_findings)}")
    if all_findings:
        print()
        for f in all_findings:
            sev = f.get("severity","?").upper()
            print(f"  [{sev}] {f.get('param',f.get('field','?'))} — {f['note'][:90]}")
    else:
        print("  No hidden parameters found.")

    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
