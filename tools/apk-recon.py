#!/usr/bin/env python3
"""
apk-recon — pull a mobile app's backend attack surface out of its APK.

A mobile app's API is usually DIFFERENT hosts + endpoints + hardcoded secrets that never appear on web,
and HUNTR had zero mobile support despite mobile being in most exchange/fintech scopes. This extracts,
from the APK itself:
  • backend HOSTS + full URLs + API paths (/v1/.., /api/..) hardcoded in the code/resources
  • likely SECRETS (api keys, tokens, Firebase/AWS/GCP keys, signing secrets) — flagged, never trusted
  • package id + exported components (from AndroidManifest, when apktool is present)

Baseline uses only `unzip` + `strings` (always on Kali) over classes*.dex + resources + assets, so it works
with no extra tooling; if `apktool`/`jadx` are installed it also decodes AndroidManifest + smali for more.

Usage:  apk-recon.py --apk /path/app.apk [--host-filter cointr.com] [--json]
Output (--json): {"package":.., "hosts":[..], "urls":[..], "api_paths":[..], "secrets":[..], "components":[..]}

Treat the APK as untrusted: it is only read (unzip/strings), never executed.
"""
import json, sys, os, re, subprocess, tempfile, shutil
from pathlib import Path

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv
def has(tool):
    return shutil.which(tool) is not None

URL_RE   = re.compile(rb"https?://[a-zA-Z0-9_.\-]+(?::\d+)?(?:/[a-zA-Z0-9_./\-{}%?=&:]*)?")
WS_RE    = re.compile(rb"wss?://[a-zA-Z0-9_.\-]+(?::\d+)?(?:/[a-zA-Z0-9_./\-{}]*)?")
APIPATH  = re.compile(rb"\"(/(?:v\d+|api|rest|gateway|service)/[a-zA-Z0-9_/\-{}:.]{2,120})\"")
# secret heuristics — high-signal, low-FP. Public-by-design keys are tagged separately (not a finding).
SECRETS = [
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("firebase_db",    re.compile(rb"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("slack_token",    re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("stripe_secret",  re.compile(rb"sk_live_[0-9A-Za-z]{16,}")),
    ("private_key",    re.compile(rb"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----")),
    ("jwt",            re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer_hardcoded", re.compile(rb"[Bb]earer\s+[A-Za-z0-9_\-\.=]{20,}")),
    ("generic_secret", re.compile(rb"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token)\"?\s*[:=]\s*\"?[A-Za-z0-9_\-]{12,}")),
]
# public-by-design (info only, matches the web FP bar) — reported but tagged non-sensitive
PUBLIC_TAG = re.compile(rb"(?i)(AIza|recaptcha|sentry.*public|pk_live_|pk_test_|GTM-|UA-|G-[A-Z0-9]{8})")

def run(cmd, timeout=120):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout).stdout
    except Exception:
        return b""

def scan_bytes(blob, hostf):
    hosts, urls, apis, ws, secrets = set(), set(), set(), set(), []
    for m in URL_RE.findall(blob):
        try: u = m.decode("utf-8", "ignore")
        except Exception: continue
        host = re.sub(r"^https?://", "", u).split("/")[0].split(":")[0]
        if hostf and hostf not in host and not host.endswith(hostf):
            # keep the full URL list broad but host set filtered to the target when a filter is given
            urls.add(u); continue
        hosts.add(host); urls.add(u)
    for m in WS_RE.findall(blob):
        ws.add(m.decode("utf-8", "ignore"))
    for m in APIPATH.findall(blob):
        apis.add(m.decode("utf-8", "ignore"))
    for name, rx in SECRETS:
        for m in rx.findall(blob)[:20]:
            val = m.decode("utf-8", "ignore")
            secrets.append({"type": name, "value": val[:60] + ("…" if len(val) > 60 else ""),
                            "public_by_design": bool(PUBLIC_TAG.search(m))})
    return hosts, urls, apis, ws, secrets

def main():
    apk = arg("--apk")
    hostf = arg("--host-filter", "")
    res = {"apk": apk, "package": None, "hosts": [], "urls": [], "api_paths": [], "ws": [],
           "secrets": [], "components": [], "tools": {"apktool": has("apktool"), "jadx": has("jadx"),
           "strings": has("strings"), "unzip": has("unzip")}}
    if not apk or not Path(apk).exists():
        print(json.dumps({**res, "error": "need --apk <path to .apk> (file not found)"})); sys.exit(1)

    tmp = tempfile.mkdtemp(prefix="apkrecon_")
    hosts, urls, apis, ws, secrets = set(), set(), set(), set(), []
    try:
        # 1) unzip + scan every dex/resource/asset (baseline — no extra tooling needed)
        if has("unzip"):
            run(["unzip", "-o", "-qq", apk, "-d", tmp], timeout=120)
            for root, _, files in os.walk(tmp):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        if os.path.getsize(fp) > 60 * 1024 * 1024:
                            continue
                        blob = Path(fp).read_bytes()
                    except Exception:
                        continue
                    h, u, a, w, s = scan_bytes(blob, hostf)
                    hosts |= h; urls |= u; apis |= a; ws |= w; secrets += s
        else:
            # no unzip → strings over the raw apk
            blob = run(["strings", "-n", "6", apk], timeout=120) if has("strings") else Path(apk).read_bytes()
            hosts, urls, apis, ws, secrets = scan_bytes(blob, hostf)

        # 2) apktool enrichment: package id, exported components, network_security_config hosts
        if has("apktool"):
            dec = os.path.join(tmp, "_decoded")
            run(["apktool", "d", "-f", "-s", "-o", dec, apk], timeout=240)
            manifest = Path(dec) / "AndroidManifest.xml"
            if manifest.exists():
                mx = manifest.read_text("utf-8", "ignore")
                pkg = re.search(r'package="([^"]+)"', mx)
                res["package"] = pkg.group(1) if pkg else None
                for cm in re.finditer(r'<(activity|service|receiver|provider)[^>]*android:name="([^"]+)"[^>]*android:exported="true"', mx):
                    res["components"].append(cm.group(1) + ":" + cm.group(2))
                for hm in re.finditer(r'<domain[^>]*>([^<]+)</domain>', mx):
                    hosts.add(hm.group(1).strip())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # dedup secrets by (type,value)
    seen = set(); uniq_sec = []
    for s in secrets:
        k = (s["type"], s["value"])
        if k not in seen:
            seen.add(k); uniq_sec.append(s)
    res["hosts"] = sorted(hosts)
    res["urls"] = sorted(urls)[:800]
    res["api_paths"] = sorted(apis)
    res["ws"] = sorted(ws)
    res["secrets"] = uniq_sec[:120]

    if flag("--json"):
        print(json.dumps(res))
    else:
        print(f"APK {apk}  package={res['package']}")
        print(f"  hosts: {len(res['hosts'])}  urls: {len(res['urls'])}  api_paths: {len(res['api_paths'])}  ws: {len(res['ws'])}")
        for h in res["hosts"][:30]: print("   host", h)
        for a in res["api_paths"][:30]: print("   api ", a)
        real = [s for s in res["secrets"] if not s["public_by_design"]]
        print(f"  secrets (non-public): {len(real)}")
        for s in real[:20]: print("   !!", s["type"], s["value"])

if __name__ == "__main__":
    main()
