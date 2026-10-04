#!/usr/bin/env python3
"""
sqli-test.py — SQL injection probe (sqlmap wrapper), JSON out for the HUNTR engine.

Usage:
  sqli-test.py --url "https://t/item?id=1" [--token "Bearer x"] [--json]

Emits: {"findings":[{"severity","type","param","detail","url"}], "tested":true}
Bounded + non-destructive: --batch, level 1 / risk 1, techniques B,E,U only
(boolean/error/union — NO time-based or stacked, so no slow or state-changing probes),
hard wall-clock cap. Only meaningful on URLs that carry parameters.
"""
import sys, json, subprocess, shutil, re, tempfile, os

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

URL = arg("--url")
TOKEN = arg("--token")
TIMEOUT = int(arg("--timeout", "120") or 120)

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not URL:
    out({"findings": [], "tested": False, "error": "no --url"})
if "?" not in URL or "=" not in URL.split("?", 1)[1]:
    out({"findings": [], "tested": False, "error": "no query parameters to test"})
if not shutil.which("sqlmap"):
    out({"findings": [], "tested": False, "error": "sqlmap not installed"})

outdir = tempfile.mkdtemp(prefix="sqli_")
cmd = ["sqlmap", "-u", URL, "--batch", "--smart", "--level", "1", "--risk", "1",
       "--technique", "BEU", "--timeout", "8", "--retries", "0", "--threads", "4",
       "--disable-coloring", "--flush-session", "--output-dir", outdir]
if TOKEN:
    cmd += ["--headers", "Authorization: " + (TOKEN if TOKEN.lower().startswith("bearer") else "Bearer " + TOKEN)]

raw = ""
try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    raw = (p.stdout or "") + "\n" + (p.stderr or "")
except subprocess.TimeoutExpired as e:
    raw = (e.stdout.decode() if e.stdout else "") if hasattr(e, "stdout") and e.stdout else ""
except Exception as e:
    out({"findings": [], "tested": False, "error": str(e)[:120]})
finally:
    try:
        import shutil as _sh; _sh.rmtree(outdir, ignore_errors=True)
    except Exception:
        pass

findings = []
injectable = ("the following injection point" in raw.lower()
              or re.search(r"parameter\s+'?[\w\[\]]+'?\s+is vulnerable", raw, re.I)
              or "is vulnerable. do you want to keep testing" in raw.lower())

if injectable:
    # extract parameter names and the detected DBMS if present
    params = re.findall(r"Parameter:\s*([^\s(]+)", raw)
    dbms = ""
    m = re.search(r"back-end DBMS:\s*(.+)", raw)
    if m:
        dbms = m.group(1).strip()
    types = re.findall(r"Type:\s*(.+)", raw)
    detail = ("sqlmap confirmed an injectable parameter"
              + ((" (" + ", ".join(sorted(set(params))) + ")") if params else "")
              + ((" · types: " + "; ".join(sorted(set(t.strip() for t in types)))) if types else "")
              + ((" · DBMS: " + dbms) if dbms else "") + ".")
    findings.append({
        "severity": "c",
        "type": "SQL injection",
        "param": (params[0] if params else ""),
        "detail": detail[:400],
        "url": URL,
    })

out({"findings": findings, "tested": True})
