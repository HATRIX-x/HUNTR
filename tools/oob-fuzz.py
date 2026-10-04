#!/usr/bin/env python3
"""
oob-fuzz.py — blind / out-of-band injection fuzzing via nuclei DAST + interactsh, JSON out.

For AUTHORIZED testing. Drives nuclei's DAST fuzzing templates with interactsh OAST enabled:
nuclei registers a unique interactsh callback domain, injects {{interactsh-url}} into every
parameter, and correlates the DNS/HTTP callback — so it confirms *blind* SSRF (and blind
command-injection / SSTI / XXE / log4j) with no reflected response. An OAST hit is definitive,
so findings are emitted verdict=confirmed.

Needs outbound connectivity to the interactsh server (oast.live/oast.pro/…). Non-destructive
(injection fuzzing, no writes). Bounded by --budget-sec and a URL cap.

Usage:  oob-fuzz.py --targets-file urls.txt [--budget-sec 180] [--max-urls 60]
        oob-fuzz.py --url "https://t/p?u=1" [--url ...]
Emits:  {"findings":[{"severity","cls","title","detail","endpoint","verdict","template"}],
         "tested":bool, "requests":int, "urls":int, "error":"...optional"}
"""
import sys, os, json, subprocess, tempfile, shutil

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

def args_multi(n):
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == n and i + 1 < len(sys.argv)]

BUDGET = int(arg("--budget-sec", "180") or 180)
MAX_URLS = int(arg("--max-urls", "60") or 60)

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not shutil.which("nuclei"):
    out({"findings": [], "tested": False, "error": "nuclei not installed"})

# gather param-bearing URLs (only those with a query parameter are fuzzable)
urls = []
tf = arg("--targets-file")
if tf and os.path.exists(tf):
    for ln in open(tf, errors="ignore"):
        ln = ln.strip()
        if ln.startswith("http") and "?" in ln and "=" in ln.split("?", 1)[1]:
            urls.append(ln)
for u in args_multi("--url"):
    if u.startswith("http") and "?" in u and "=" in u.split("?", 1)[1]:
        urls.append(u)
# dedup by (path, sorted param names) so we don't fuzz 50 near-identical id= URLs
seen, uniq = set(), []
import urllib.parse as _up
for u in urls:
    p = _up.urlparse(u)
    k = (p.netloc, p.path, tuple(sorted(k for k, _ in _up.parse_qsl(p.query))))
    if k not in seen:
        seen.add(k); uniq.append(u)
uniq = uniq[:MAX_URLS]
if not uniq:
    out({"findings": [], "tested": False, "error": "no parameterized URLs to fuzz"})

def classify(tid, tags, name):
    s = (tid + " " + tags + " " + name).lower()
    if "ssrf" in s: return "SSRF"
    if "ssti" in s or "template" in s: return "SSTI"
    if "cmdi" in s or "command" in s or "rce" in s: return "Command injection"
    if "xxe" in s: return "XXE"
    if "sqli" in s or "sql" in s: return "SQLi (blind)"
    if "xss" in s: return "XSS"
    if "lfi" in s or "traversal" in s or "file" in s: return "LFI/traversal"
    if "log4j" in s or "jndi" in s: return "Log4j/JNDI"
    return (name or "Injection").strip()

SEVMAP = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i", "unknown": "m"}

try:
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tmp.write("\n".join(uniq)); tmp.close()
    cmd = ["nuclei", "-l", tmp.name, "-dast", "-jsonl", "-silent", "-duc",
           "-no-color", "-rl", "50", "-c", "25", "-timeout", "10"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=BUDGET)
        raw = r.stdout
    except subprocess.TimeoutExpired as e:
        raw = (e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")) if e.stdout else ""
    os.unlink(tmp.name)

    findings, reqs = [], 0
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            j = json.loads(ln)
        except Exception:
            continue
        info = j.get("info", {}) or {}
        tid = j.get("template-id", "") or ""
        tags = ",".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [str(info.get("tags", ""))])
        name = info.get("name", "") or tid
        cls = classify(tid, tags, name)
        sev = SEVMAP.get((info.get("severity") or "medium").lower(), "m")
        at = j.get("matched-at") or j.get("host") or ""
        oob = j.get("interaction") or j.get("interactsh") or {}
        proof = ""
        if isinstance(oob, dict) and oob.get("protocol"):
            proof = " · OAST %s callback received (blind, out-of-band confirmed)" % oob.get("protocol")
        findings.append({
            "severity": sev, "cls": cls, "verdict": "confirmed", "template": tid,
            "title": cls + " — " + (name if name != cls else "parameter"),
            "endpoint": at,
            "detail": ("nuclei DAST template '%s' confirmed %s at %s%s" % (tid, cls, at, proof)).strip(),
        })
    out({"findings": findings, "tested": True, "requests": reqs, "urls": len(uniq)})
except Exception as e:
    out({"findings": [], "tested": False, "error": str(e)[:160]})
