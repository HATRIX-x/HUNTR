#!/usr/bin/env python3
"""
retest — re-fire a stored finding and compare to the original to prove it's still
vulnerable (or fixed). Use it to confirm a bug before submit, to claim retest
bonuses after a program marks it resolved, and as a regression check.

Reads the original request/response from one of:
  · <HUNT_DIR>/evidence/<id>/request.txt (+ response.txt)   [written by exec-http/cdp]
  · a --finding-file with {url, method, data, match, status}
The "still vulnerable" signal is the proof string (--match or finding.match /
response_snippet): present again → still vulnerable; gone → likely fixed.

Usage:
  retest.py --id F1 [--match "owner":"someone"] [--token JWT] [--json]
  retest.py --finding-file f.json [--json]
Exit: 0 fixed / inconclusive · 1 still vulnerable.
"""
import sys, os, re, json, time, ssl
from pathlib import Path
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
EV = HUNT / "evidence"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def parse_request(txt):
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


def fire(method, url, headers, body, timeout=10):
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    data = body.encode() if isinstance(body, str) and body else None
    req = Request(url, data=data, headers=headers, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(65536)
            return r.status, len(raw), raw.decode("utf-8", "ignore")
    except HTTPError as e:
        try:
            raw = e.read(16384)
        except Exception:
            raw = b""
        return e.code, len(raw), raw.decode("utf-8", "ignore")
    except Exception as ex:
        return 0, 0, str(ex)[:200]


def main():
    fid = arg("--id")
    finding_file = arg("--finding-file")
    token = arg("--token")
    match = arg("--match")

    orig_status = None
    orig_snippet = ""
    req = {}

    if finding_file and Path(finding_file).exists():
        f = json.loads(Path(finding_file).read_text())
        req = {"method": (f.get("method") or "GET"),
               "url": f.get("url") or f.get("base_url") or "",
               "headers": {}, "body": f.get("data") or ""}
        match = match or f.get("match") or f.get("response_snippet") or f.get("snippet")
        orig_status = f.get("status") or f.get("status_b")
    elif fid:
        d = EV / fid
        rp = d / "request.txt"
        if not rp.exists():
            out = {"ok": False, "error": f"no evidence/{fid}/request.txt — capture it with exec-http first"}
            print(json.dumps(out) if flag("--json") else out["error"])
            sys.exit(0)
        req = parse_request(rp.read_text())
        rsp = d / "response.txt"
        if rsp.exists():
            rt = rsp.read_text()
            m = re.search(r"\b(\d{3})\b", rt.splitlines()[0] if rt.splitlines() else "")
            orig_status = int(m.group(1)) if m else None
            parts = re.split(r"\r?\n\r?\n", rt, 1)
            orig_snippet = parts[1] if len(parts) > 1 else ""
    else:
        print(__doc__)
        sys.exit(0)

    if not req.get("url"):
        out = {"ok": False, "error": "no URL to retest"}
        print(json.dumps(out) if flag("--json") else out["error"])
        sys.exit(0)

    headers = dict(req.get("headers") or {})
    headers.pop("Content-Length", None)
    headers.setdefault("User-Agent", "Mozilla/5.0")
    if token:
        headers["Authorization"] = token if " " in token else f"Bearer {token}"

    proof = (match or orig_snippet or "").strip()[:200]
    status, size, body = fire(req["method"], req["url"], headers, req.get("body", ""))

    proof_present = bool(proof) and proof in body
    if proof:
        still_vuln = proof_present
        basis = "proof string present" if proof_present else "proof string gone"
    else:
        still_vuln = orig_status is not None and status == orig_status
        basis = f"status matches original ({status})" if still_vuln else "status changed / no proof set"

    verdict = "STILL_VULNERABLE" if still_vuln else ("FIXED" if proof else "INCONCLUSIVE")

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "id": fid, "url": req["url"], "method": req["method"],
        "original_status": orig_status, "current_status": status, "current_size": size,
        "proof": proof, "proof_present": proof_present,
        "verdict": verdict, "basis": basis,
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if still_vuln else 0)

    print(f"\n== retest · {fid or req['url']} ==")
    print(f"  {req['method']} {req['url']}")
    print(f"  original HTTP {orig_status} → current HTTP {status} ({size}b)")
    if proof:
        print(f"  proof {'STILL present' if proof_present else 'GONE'}: {proof[:70]!r}")
    print(f"  verdict: {verdict}  ({basis})")
    sys.exit(1 if still_vuln else 0)


if __name__ == "__main__":
    main()
