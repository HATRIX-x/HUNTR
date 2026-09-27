#!/usr/bin/env python3
"""
evidence-bundle — assemble a submit-ready proof bundle for one finding.

Pulls together everything that makes a report land on first read:
  · request.txt / response.txt   (written by exec-http / exec-cdp under .hunt/evidence/<id>/)
  · a curl repro (repro.sh) reconstructed from request.txt
  · a HAR-style capture.json (parsed request + response)
  · a screenshot (optional): headless-Chrome shot of --capture URL, or an existing --screenshot file
  · meta.json (the finding record) + index.md (human summary)
  · zips it all to .hunt/evidence/<id>/bundle-<id>.zip

Usage:
  evidence-bundle.py --id F1 [--finding-file f.json] [--capture https://target/poc] \
                     [--screenshot shot.png] [--chrome /path/to/chrome] [--json]
Exit: 0 ok · 2 nothing to bundle.
"""
import sys, os, re, json, time, shutil, zipfile, subprocess
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
EV = HUNT / "evidence"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def find_chrome(explicit):
    if explicit and Path(explicit).exists():
        return explicit
    for c in ("google-chrome", "chromium", "chromium-browser", "chrome", "brave-browser"):
        p = shutil.which(c)
        if p:
            return p
    for p in ("/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
              "/opt/pw-browsers/chromium/chrome-linux/chrome"):
        if Path(p).exists():
            return p
    return None


def screenshot(url, out, chrome):
    if not chrome:
        return False, "no chrome binary found"
    try:
        subprocess.run([chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                        "--hide-scrollbars", "--window-size=1366,900",
                        f"--screenshot={out}", url],
                       capture_output=True, timeout=45)
        return (Path(out).exists() and Path(out).stat().st_size > 0), ""
    except Exception as ex:
        return False, str(ex)[:120]


def parse_request(txt):
    """request.txt → {method, url, headers, body} (best-effort)."""
    lines = txt.splitlines()
    if not lines:
        return {}
    m = re.match(r"([A-Z]+)\s+(\S+)", lines[0])
    method, target = (m.group(1), m.group(2)) if m else ("GET", "")
    headers, i = {}, 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i + 1:]).strip() if i + 1 < len(lines) else ""
    url = target
    if target.startswith("/") and headers.get("Host"):
        url = f"https://{headers['Host']}{target}"
    return {"method": method, "url": url, "headers": headers, "body": body}


def build_curl(req):
    if not req.get("url"):
        return "# no request.txt to reconstruct from\n"
    parts = [f"curl -sk -X {req.get('method','GET')} {json.dumps(req['url'])}"]
    for k, v in (req.get("headers") or {}).items():
        if k.lower() == "host":
            continue
        parts.append(f"  -H {json.dumps(f'{k}: {v}')}")
    if req.get("body"):
        parts.append(f"  --data {json.dumps(req['body'])}")
    return "#!/bin/sh\n" + " \\\n".join(parts) + "\n"


def parse_response(txt):
    lines = txt.splitlines()
    status = 0
    if lines:
        m = re.search(r"\b(\d{3})\b", lines[0])
        if m:
            status = int(m.group(1))
    headers, i = {}, 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i + 1:]) if i + 1 < len(lines) else ""
    return {"status": status, "headers": headers, "body_snippet": body[:2000]}


def main():
    fid = arg("--id")
    finding_file = arg("--finding-file")
    capture = arg("--capture")
    screenshot_in = arg("--screenshot")
    chrome = arg("--chrome")

    if not fid:
        print(__doc__)
        sys.exit(0)

    d = EV / fid
    d.mkdir(parents=True, exist_ok=True)
    included, warnings = [], []

    finding = {}
    if finding_file and Path(finding_file).exists():
        try:
            finding = json.loads(Path(finding_file).read_text())
        except Exception:
            warnings.append("finding-file not valid JSON")
    (d / "meta.json").write_text(json.dumps(finding or {"id": fid}, indent=2))
    included.append("meta.json")

    req = {}
    rp = d / "request.txt"
    if rp.exists():
        req = parse_request(rp.read_text())
        (d / "repro.sh").write_text(build_curl(req))
        os.chmod(d / "repro.sh", 0o755)
        included += ["request.txt", "repro.sh"]
    else:
        warnings.append("no request.txt (run exec-http/exec-cdp first to capture it)")

    resp = {}
    rsp = d / "response.txt"
    if rsp.exists():
        resp = parse_response(rsp.read_text())
        included.append("response.txt")

    if req or resp:
        (d / "capture.json").write_text(json.dumps({"request": req, "response": resp}, indent=2))
        included.append("capture.json")

    shot = None
    if screenshot_in and Path(screenshot_in).exists():
        shutil.copy(screenshot_in, d / "screenshot.png")
        shot = "screenshot.png"
    elif capture:
        ok, err = screenshot(capture, str(d / "screenshot.png"), find_chrome(chrome))
        if ok:
            shot = "screenshot.png"
        else:
            warnings.append(f"screenshot failed: {err}")
    if shot:
        included.append(shot)

    sev = finding.get("severity") or finding.get("estimated_severity") or "?"
    title = finding.get("title") or finding.get("attack") or finding.get("test") or fid
    index = [
        f"# Evidence · {title}",
        f"- id: `{fid}`",
        f"- severity: {sev}",
        f"- captured: {time.strftime('%Y-%m-%d %H:%M')}",
        "",
        f"- request: {'request.txt' if 'request.txt' in included else '—'}",
        f"- response: {'response.txt (HTTP %d)' % resp['status'] if resp else '—'}",
        f"- repro: {'repro.sh' if 'repro.sh' in included else '—'}",
        f"- screenshot: {shot or '—'}",
    ]
    (d / "index.md").write_text("\n".join(index) + "\n")
    included.append("index.md")

    zpath = d / f"bundle-{fid}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for name in included:
            fp = d / name
            if fp.exists():
                z.write(fp, arcname=f"{fid}/{name}")

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "id": fid, "dir": str(d), "bundle": str(zpath),
        "included": included, "warnings": warnings,
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"\n== evidence-bundle · {fid} ==")
    print(f"  bundle: {zpath}")
    print(f"  files:  {', '.join(included)}")
    for w in warnings:
        print(f"  ! {w}")
    sys.exit(0)


if __name__ == "__main__":
    main()
