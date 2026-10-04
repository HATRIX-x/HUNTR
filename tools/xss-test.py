#!/usr/bin/env python3
"""
xss-test.py — reflected/DOM XSS probe (dalfox wrapper), JSON out for the HUNTR engine.

Usage:
  xss-test.py --url "https://t/search?q=1" [--token "Bearer x"] [--json]

Emits: {"findings":[{"severity","type","param","payload","detail","url"}], "tested":true}
Only meaningful on URLs that carry parameters. Bounded + non-destructive (GET reflection).
"""
import sys, json, subprocess, shutil, re

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

URL = arg("--url")
TOKEN = arg("--token")
TIMEOUT = int(arg("--timeout", "45") or 45)

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not URL:
    out({"findings": [], "tested": False, "error": "no --url"})
if not shutil.which("dalfox"):
    out({"findings": [], "tested": False, "error": "dalfox not installed"})

cmd = ["dalfox", "url", URL, "--format", "json", "--no-color", "--no-spinner",
       "--skip-bav", "--skip-mining-dom", "--worker", "20", "--timeout", "10"]
if TOKEN:
    cmd += ["-H", "Authorization: " + (TOKEN if TOKEN.lower().startswith("bearer") else "Bearer " + TOKEN)]

try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    raw = (p.stdout or "").strip()
except subprocess.TimeoutExpired:
    out({"findings": [], "tested": True, "note": "dalfox timed out"})
except Exception as e:
    out({"findings": [], "tested": False, "error": str(e)[:120]})

findings = []
# dalfox --format json emits a JSON array of PoC objects (may be empty / noisy lines)
pocs = []
try:
    m = re.search(r"\[.*\]", raw, re.S)
    if m:
        pocs = json.loads(m.group(0))
except Exception:
    pocs = []

seen = set()
for poc in pocs if isinstance(pocs, list) else []:
    if not isinstance(poc, dict):
        continue
    itype = (poc.get("type") or "").upper()          # e.g. "V" verified, "R" reflected, "G" grep
    param = poc.get("param") or poc.get("inject_type") or ""
    data = poc.get("data") or poc.get("poc") or poc.get("evidence") or ""
    # only report real injection PoCs (verified/reflected), not informational grep hits
    if itype in ("V", "R") or poc.get("severity", "").lower() in ("high", "medium", "critical"):
        key = (param, itype)
        if key in seen:
            continue
        seen.add(key)
        sev = "h" if itype == "V" else "m"
        findings.append({
            "severity": sev,
            "type": "Reflected XSS" if itype != "V" else "Verified XSS",
            "param": param,
            "payload": (data or "")[:300],
            "detail": ("Parameter '" + str(param) + "' reflects an injected script context. " +
                       ("Verified executable by dalfox." if itype == "V" else "Reflected without adequate encoding.")),
            "url": URL,
        })

out({"findings": findings, "tested": True})
