#!/usr/bin/env python3
"""
exec-http — the engine's hands. Disciplined, evidence-bound HTTP execution through scope-guard.

Every request goes through scope-guard.py (scope + write-approval + circuit breaker), and every
response is auto-saved to ./.hunt/evidence/<id>/ as request.txt + response.txt — so proof is captured
by construction, not as an afterthought. It loads named identities, replays saved requests, retries a
blocked request through a WAF-bypass variant matrix, and — the killer combo — runs the SAME request as
two identities and auto-diffs them (diff-oracle) to DISCOVER access bugs in one command.

Identities: ./.hunt/identities.json = {"admin":{"authorization":"Bearer ..","cookie":"..","headers":{"X-CSRF":".."}}, ...}

Usage:
  exec-http.py --url https://api.acme.com/api/v1/orders/1337 [--method GET] [--identity low-priv] [--data '{"x":1}']
  exec-http.py --url .../orders/1337 --diff admin,low-priv --expect deny      # run as both → auto access-bug check
  exec-http.py --replay e7                                                     # re-run a saved request
  exec-http.py --url '...?q=1' --waf 'UNION SELECT'                            # retry blocked req with bypass variants
Exit: 0 ok · 1 diff violation · 2 scope/blocked.
"""
import sys, os, re, json, subprocess, urllib.parse
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
EV = HUNT / "evidence"
IDS = HUNT / "identities.json"
TOOLS = Path(__file__).parent
SG = str(TOOLS / "scope-guard.py")


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def args_all(n):
    out, a = [], sys.argv
    for i, x in enumerate(a):
        if x == n and i + 1 < len(a):
            out.append(a[i + 1])
    return out


def load_identity(name):
    if not name or not IDS.exists():
        return {}
    try:
        j = json.loads(IDS.read_text())
    except Exception:
        return {}
    return j.get(name, {})


def headers_for(name):
    idn = load_identity(name)
    hs = []
    if idn.get("authorization"):
        hs.append(f"Authorization: {idn['authorization']}")
    if idn.get("cookie") or idn.get("cookieHeader"):
        hs.append(f"Cookie: {idn.get('cookie') or idn.get('cookieHeader')}")
    for k, v in (idn.get("headers") or {}).items():
        hs.append(f"{k}: {v}")
    return hs


def next_id():
    EV.mkdir(parents=True, exist_ok=True)
    n = 1
    while (EV / f"e{n}").exists():
        n += 1
    return f"e{n}"


def run(method, url, headers, data, approve):
    curl_args = []
    for h in headers:
        curl_args += ["-H", h]
    if data:
        curl_args += ["-H", "Content-Type: application/json", "-d", data]
    cmd = ["python3", SG, method, url]
    if curl_args:
        cmd += ["--"] + curl_args
    if approve:
        cmd += ["--approve"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def status_of(resp):
    first = resp.split("\n", 1)[0] if resp else ""
    for tok in first.split():
        if tok.isdigit() and len(tok) == 3:
            return int(tok)
    return 0


def save(evid, method, url, headers, data, resp):
    d = EV / evid
    d.mkdir(parents=True, exist_ok=True)
    req = f"{method} {url}\n" + "\n".join(headers) + (f"\n\n{data}" if data else "") + "\n"
    (d / "request.txt").write_text(req)
    (d / "response.txt").write_text(resp)
    return d


def waf_variants(payload):
    p = payload
    return {
        "url-encode": urllib.parse.quote(p),
        "double-url-encode": urllib.parse.quote(urllib.parse.quote(p)),
        "case-flip": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
        "inline-comment": re.sub(r"\s+", "/**/", p),
        "plus-space": p.replace(" ", "+"),
        "unicode-dot": p.replace(".", "․"),
        "trailing-null": p + "%00",
    }


def cmd_replay():
    evid = arg("--replay")
    d = EV / evid
    if not (d / "request.txt").exists():
        sys.exit(f"no saved request at {d}")
    lines = (d / "request.txt").read_text().splitlines()
    method, url = lines[0].split(" ", 1)
    headers = [l for l in lines[1:] if ": " in l and not l.startswith("{")]
    data = None
    if "" in lines:
        idx = lines.index("")
        data = "\n".join(lines[idx + 1:]).strip() or None
    code, out, err = run(method, url, headers, data, "--approve" in sys.argv)
    st = status_of(out)
    nid = next_id()
    save(nid, method, url, headers, data, out)
    print(f"[exec] replay {evid} → {method} {url}  status {st}  (saved {EV/nid})")
    sys.exit(0)


def one(method, url, ident, extra_headers, data, approve, label=""):
    headers = headers_for(ident) + extra_headers
    code, out, err = run(method, url, headers, data, approve)
    st = status_of(out)
    evid = next_id()
    d = save(evid, method, url, headers, data, out or err)
    tag = f" [{label}]" if label else ""
    if code == 2 or "OUT OF SCOPE" in (err or ""):
        print(f"[exec]{tag} ⛔ {err.strip().splitlines()[0] if err else 'blocked'}")
        return None, st, d
    if code == 3:
        print(f"[exec]{tag} ⛔ write blocked — re-run with --approve")
        return None, st, d
    print(f"[exec]{tag} {method} {url}  → status {st}  ({d})")
    return out, st, d


def main():
    if "--replay" in sys.argv:
        return cmd_replay()
    url = arg("--url")
    if not url:
        sys.exit("usage: exec-http.py --url <URL> [--method] [--identity] [--data] [--diff a,b [--expect deny]] [--waf PAYLOAD] [--replay ID]")
    method = (arg("--method", "GET") or "GET").upper()
    data = arg("--data")
    approve = "--approve" in sys.argv
    extra_headers = args_all("--header")

    # --diff: run as two identities, then auto-run diff-oracle
    diff = arg("--diff")
    if diff:
        names = [x.strip() for x in diff.split(",")][:2]
        if len(names) < 2:
            sys.exit("--diff needs two identity names, e.g. --diff admin,low-priv")
        outA, sA, dA = one(method, url, names[0], extra_headers, data, approve, names[0])
        outB, sB, dB = one(method, url, names[1], extra_headers, data, approve, names[1])
        if outA is None or outB is None:
            sys.exit(2)
        cmd = ["python3", str(TOOLS / "diff-oracle.py"), "--a", str(dA / "response.txt"),
               "--b", str(dB / "response.txt"), "--a-owner", names[0], "--b-owner", names[1]]
        if arg("--expect"):
            cmd += ["--expect", arg("--expect")]
        print()
        r = subprocess.run(cmd)
        sys.exit(r.returncode)

    # --waf: retry a blocked payload through the bypass matrix
    waf = arg("--waf")
    if waf:
        base_out, base_st, _ = one(method, url, arg("--identity"), extra_headers, data, approve, "baseline")
        if base_st not in (403, 406, 429, 501):
            print(f"[exec] baseline not blocked (status {base_st}) — no WAF bypass needed.")
            sys.exit(0)
        print(f"\n[exec] baseline BLOCKED ({base_st}); trying {len(waf_variants(waf))} bypass variants:\n")
        wins = []
        for name, variant in waf_variants(waf).items():
            vurl = url.replace(urllib.parse.quote(waf), urllib.parse.quote(variant)) if urllib.parse.quote(waf) in url else \
                   (url.replace(waf, variant) if waf in url else url + ("&" if "?" in url else "?") + "p=" + urllib.parse.quote(variant))
            _, st, d = one(method, vurl, arg("--identity"), extra_headers, data, approve, name)
            if st and st not in (403, 406, 429, 501):
                wins.append((name, st, d))
        print()
        if wins:
            for name, st, d in wins:
                print(f"  ✓ BYPASS via {name} → status {st}  ({d})")
        else:
            print("  ✗ no variant bypassed the WAF on this endpoint.")
        sys.exit(0)

    # plain single request
    out, st, d = one(method, url, arg("--identity"), extra_headers, data, approve)
    sys.exit(0 if out is not None else 2)


if __name__ == "__main__":
    main()
