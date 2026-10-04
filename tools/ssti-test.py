#!/usr/bin/env python3
"""
ssti-test.py — server-side template injection probe (reflected), JSON out for the HUNTR engine.

Injects polyglot math payloads for the common engines (Jinja2/Twig {{·}}, FreeMarker/JSP-EL
${·}, Ruby/Thymeleaf #{·}, ERB <%= · %>) into each GET parameter and confirms SSTI only when
the UNIQUE product is reflected while the literal payload is NOT — i.e., the template evaluated.
Non-destructive (GET, arithmetic only). Bounded.

Usage:  ssti-test.py --url "https://t/p?q=1" [--token "Bearer x"] [--json]
Emits:  {"findings":[{"severity","param","payload","engine","detail","url"}], "tested":true}
"""
import sys, json, urllib.request, urllib.parse, re

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

URL = arg("--url"); TOKEN = arg("--token"); TIMEOUT = int(arg("--timeout", "8") or 8)
A, B = 1337, 7
PROD = str(A * B)  # 9359 — unlikely to appear by chance
PAYLOADS = [("{{%d*%d}}" % (A, B), "Jinja2/Twig"), ("${%d*%d}" % (A, B), "FreeMarker/JSP-EL"),
            ("#{%d*%d}" % (A, B), "Ruby/Thymeleaf"), ("<%%= %d*%d %%>" % (A, B), "ERB"),
            ("${{%d*%d}}" % (A, B), "Smarty/Twig")]

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not URL or "?" not in URL or "=" not in URL.split("?", 1)[1]:
    out({"findings": [], "tested": False, "error": "no query parameters to test"})

def fetch(u):
    req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 HUNTR"})
    if TOKEN:
        req.add_header("Authorization", TOKEN if TOKEN.lower().startswith("bearer") else "Bearer " + TOKEN)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read(200000).decode("utf-8", "ignore")
    except Exception:
        return ""

try:
    parts = urllib.parse.urlparse(URL)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    findings = []
    for i, (k, _v) in enumerate(qs):
        for payload, engine in PAYLOADS:
            nq = qs[:]; nq[i] = (k, payload)
            u2 = urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(nq)))
            body = fetch(u2)
            if not body:
                continue
            # evaluated iff the product appears AND the raw payload does not (it was consumed)
            if PROD in body and payload not in body:
                findings.append({"severity": "c", "param": k, "payload": payload, "engine": engine,
                                 "detail": "Parameter '%s' evaluated template expression %s → %s (reflected). Engine: %s. SSTI commonly escalates to RCE." % (k, payload, PROD, engine),
                                 "url": URL})
                break  # one confirmed payload per param is enough
    out({"findings": findings, "tested": True})
except Exception as e:
    out({"findings": [], "tested": False, "error": str(e)[:120]})
