#!/usr/bin/env python3
"""
cors-test — systematic CORS misconfiguration tester.

Tests:
  1. Arbitrary origin reflection (attacker.com)
  2. Null origin
  3. Pre-domain prefix bypass (evil.TARGET.com)
  4. Post-domain suffix bypass (TARGET.com.evil.com)
  5. Trusted subdomain injection (sub.TARGET.com)
  6. HTTP downgrade (http:// origin on HTTPS endpoint)
  7. Special chars (TARGET.com_, TARGET.com!, TARGET.com%60)
  8. Wild subdomain (*. reflection)
  9. Credentials:true check on any misconfigured response

Usage:
  cors-test.py --url https://api.acme.com/v1/me [--token Bearer_xxx]
               [--header X-Custom:value] [--json] [--out results.json]
  cors-test.py --url-file urls.txt [--token ...]
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, ssl, socket
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def args_multi(n):
    vals = []
    for i, a in enumerate(sys.argv):
        if a == n and i+1 < len(sys.argv):
            vals.append(sys.argv[i+1])
    return vals

def flag(n): return n in sys.argv

def extract_domain(url):
    m = re.search(r"https?://([^/?\#:]+)", url)
    return m.group(1) if m else ""

def build_origins(domain):
    """Return list of (label, origin) test cases for a target domain."""
    return [
        ("arbitrary",       "https://attacker.com"),
        ("null",            "null"),
        ("prefix_bypass",   f"https://evil.{domain}"),
        ("suffix_bypass",   f"https://{domain}.evil.com"),
        ("subdomain",       f"https://trusted.{domain}"),
        ("http_downgrade",  f"http://{domain}"),
        ("underscore",      f"https://{domain}_evil.com"),
        ("special_char",    f"https://{domain}!.evil.com"),
        ("backtick",        f"https://{domain}%60.evil.com"),
    ]

def send_cors(url, origin, token=None, extra_headers=None, timeout=10):
    """Send a CORS preflight + actual request. Return (acao, acac, status)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    if token:
        headers["Authorization"] = token if " " in token else f"Bearer {token}"
    if extra_headers:
        for h in extra_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    import urllib.request
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    # preflight OPTIONS
    req_opts = Request(url, headers=dict(headers,
        **{"Access-Control-Request-Method": "GET",
           "Access-Control-Request-Headers": "authorization,content-type"}),
        method="OPTIONS"
    )
    # actual GET
    req_get = Request(url, headers=headers, method="GET")

    acao = acac = ""
    status = 0
    for req in (req_opts, req_get):
        try:
            with opener.open(req, timeout=timeout) as r:
                status = r.status
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao: break
        except HTTPError as e:
            status = e.code
            acao = e.headers.get("Access-Control-Allow-Origin", "")
            acac = e.headers.get("Access-Control-Allow-Credentials", "")
            if acao: break
        except Exception:
            pass

    return acao, acac, status

def classify_finding(label, origin, acao, acac):
    """Return severity string or None if not exploitable."""
    creds = acac.lower() == "true"
    if not acao: return None
    reflects_origin = acao == origin or acao == "*"
    if acao == "*":
        # wildcard is only a problem with creds (browsers block it, but worth noting)
        return "low" if creds else None
    if not reflects_origin: return None
    # any reflection without creds = medium; with creds = critical
    return "critical" if creds else "medium"

def test_url(url, token=None, extra_headers=None):
    domain = extract_domain(url)
    if not domain: return []
    findings = []
    for label, origin in build_origins(domain):
        acao, acac, status = send_cors(url, origin, token, extra_headers)
        sev = classify_finding(label, origin, acao, acac)
        if sev:
            findings.append({
                "url": url,
                "label": label,
                "origin_sent": origin,
                "acao": acao,
                "acac": acac,
                "status": status,
                "severity": sev,
                "exploitable": acac.lower() == "true",
                "chain_needed": acac.lower() != "true",
                "note": (
                    "CORS + credentials:true → Cross-Origin authenticated request possible"
                    if acac.lower() == "true"
                    else "CORS reflection without credentials (chain with XSS/subdomain takeover for impact)"
                ),
            })
    return findings

def format_report(f):
    lines = [
        f"## CORS Misconfiguration — {f['label']}",
        f"**URL**: {f['url']}",
        f"**Severity**: {f['severity'].upper()}",
        f"**Origin sent**: `{f['origin_sent']}`",
        f"**Access-Control-Allow-Origin**: `{f['acao']}`",
        f"**Access-Control-Allow-Credentials**: `{f['acac']}`",
        "",
        "**PoC** (browser console or fetch from attacker page):",
        "```javascript",
        f'fetch("{f["url"]}", {{',
        f'  credentials: "include",',
        f'  headers: {{ "Origin": "{f["origin_sent"]}" }}',
        "}).then(r => r.text()).then(console.log)",
        "```",
        "",
        f"**Impact**: {f['note']}",
    ]
    return "\n".join(lines)

def main():
    url       = arg("--url")
    url_file  = arg("--url-file")
    token     = arg("--token")
    extra_h   = args_multi("--header")
    out_file  = arg("--out")

    urls = []
    if url: urls.append(url)
    if url_file:
        p = Path(url_file)
        if p.exists():
            urls += [l.strip() for l in p.read_text().splitlines() if l.strip()]

    if not urls: print(__doc__); sys.exit(0)

    all_findings = []
    for u in urls:
        print(f"[cors-test] testing {u} …", file=sys.stderr)
        findings = test_url(u, token, extra_h)
        all_findings += findings
        for f in findings:
            print(f"  [{f['severity'].upper()}] {f['label']} → ACAO={f['acao']} ACAC={f['acac']}", file=sys.stderr)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "urls_tested": len(urls),
        "total": len(all_findings),
        "critical": sum(1 for f in all_findings if f["severity"]=="critical"),
        "medium":   sum(1 for f in all_findings if f["severity"]=="medium"),
        "findings": all_findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if all_findings else 0)

    print(f"\n══ CORS test ══════════════════════════")
    print(f"  URLs tested: {len(urls)}  Findings: {len(all_findings)}")
    print(f"  Critical: {result['critical']}  Medium: {result['medium']}")
    if all_findings:
        print()
        for f in all_findings:
            print(f"  [{f['severity'].upper():<8}] {f['url']}")
            print(f"             origin={f['origin_sent']}")
            print(f"             ACAO={f['acao']}  ACAC={f['acac']}")
        print()
        for f in [x for x in all_findings if x["severity"]=="critical"][:3]:
            print(format_report(f))
            print("─"*60)

    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
