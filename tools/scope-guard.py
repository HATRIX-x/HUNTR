#!/usr/bin/env python3
"""
scope-guard — deterministic request gate for autonomous hunting.

EVERY outbound test request must go through this wrapper. It refuses, before any
packet is sent, to touch a host that isn't explicitly in scope, and refuses
state-changing HTTP methods unless the operator has approved writes. This makes
"blast radius" a mechanical guarantee, not a thing the model has to remember.

Usage:
  scope-guard.py <METHOD> <URL> [-- <extra curl args>]
  scope-guard.py --check <URL>                 # dry-run: print ALLOW/DENY, send nothing
  scope-guard.py --init                         # scaffold ./.hunt/scope.allow + scope.deny

Scope files (globs, one per line, '#' comments):
  ./.hunt/scope.allow    e.g.  *.acme.com   api.acme.com   acme.com
  ./.hunt/scope.deny     e.g.  blog.acme.com   *.thirdparty.com
Deny always wins. A URL with no allow match is DENIED.

Writes (POST/PUT/PATCH/DELETE) need one of:
  --approve      on the command line, or
  HUNT_ALLOW_WRITE=1  in the environment.

Every decision is appended to ./.hunt/audit.jsonl. A per-host circuit breaker
opens after 5 consecutive 403/429/timeout and blocks further requests to that host.
Exit codes: 0 ran · 2 out-of-scope · 3 method-blocked · 4 circuit-open · 5 usage/other.
"""
import sys, os, json, time, fnmatch, subprocess, urllib.parse
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
ALLOW = HUNT / "scope.allow"
DENY = HUNT / "scope.deny"
AUDIT = HUNT / "audit.jsonl"
CB = HUNT / "cb"
RULES = HUNT / "rules.json"
RL = HUNT / "rl"
SAFE = {"GET", "HEAD", "OPTIONS"}
WRITE = {"POST", "PUT", "PATCH", "DELETE"}
CB_THRESHOLD = 5


def load_rules():
    """Program guardrails: rate limit, required UA, blocked paths. Auto-honored on every request."""
    if RULES.exists():
        try:
            return json.loads(RULES.read_text())
        except Exception:
            pass
    return {}


def rate_limit(host, rps):
    """Throttle (sleep) to respect the program's max req/s per host — never exceed it."""
    if not rps or rps <= 0:
        return
    RL.mkdir(parents=True, exist_ok=True)
    p = RL / host.replace("/", "_")
    interval = 1.0 / rps
    now = time.time()
    last = float(p.read_text()) if p.exists() else 0
    wait = interval - (now - last)
    if wait > 0:
        time.sleep(wait)
    p.write_text(str(time.time()))


def die(code, msg):
    sys.stderr.write(f"[scope-guard] {msg}\n")
    sys.exit(code)


def load_patterns(p):
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


def host_of(url):
    if "://" not in url:
        url = "http://" + url
    return (urllib.parse.urlparse(url).hostname or "").lower()


def in_scope(host):
    if not host:
        return False, "no host parsed from URL"
    allow = load_patterns(ALLOW)
    deny = load_patterns(DENY)
    if not allow:
        return False, f"no allowlist — create {ALLOW} first (run --init)"
    for d in deny:
        if host == d or fnmatch.fnmatch(host, d):
            return False, f"host matches DENY pattern '{d}'"
    for a in allow:
        if host == a or fnmatch.fnmatch(host, a):
            return True, f"matches allow '{a}'"
    return False, "host not in allowlist"


def audit(rec):
    HUNT.mkdir(parents=True, exist_ok=True)
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with AUDIT.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def cb_path(host):
    CB.mkdir(parents=True, exist_ok=True)
    return CB / host.replace("/", "_")


def cb_count(host):
    p = cb_path(host)
    try:
        return int(p.read_text().strip())
    except Exception:
        return 0


def cb_set(host, n):
    cb_path(host).write_text(str(n))


def init():
    HUNT.mkdir(parents=True, exist_ok=True)
    if not ALLOW.exists():
        ALLOW.write_text("# in-scope hosts (globs). one per line.\n# *.example.com\n# api.example.com\n")
    if not DENY.exists():
        DENY.write_text("# explicitly OUT-of-scope (globs). deny wins over allow.\n# blog.example.com\n")
    print(f"[scope-guard] scaffolded {ALLOW} and {DENY} — fill scope.allow before hunting.")


def main():
    a = sys.argv[1:]
    if not a:
        die(5, "usage: scope-guard.py <METHOD> <URL> [-- curl args] | --check <URL> | --init")
    if a[0] == "--init":
        return init()
    if a[0] == "--check":
        if len(a) < 2:
            die(5, "usage: --check <URL>")
        host = host_of(a[1])
        ok, why = in_scope(host)
        print(f"{'ALLOW' if ok else 'DENY '}  {host or '?'}  ::  {why}")
        sys.exit(0 if ok else 2)

    method = a[0].upper()
    if len(a) < 2:
        die(5, "usage: scope-guard.py <METHOD> <URL> [-- curl args]")
    url = a[1]
    rest = a[2:]
    approve = "--approve" in rest
    rest = [x for x in rest if x != "--approve"]
    # strip a single leading "--" separator wherever it now sits at the front,
    # so it is NOT passed to curl (curl treats "--" as end-of-options and would
    # then ignore every -H/-u/-b after it — dropping auth headers).
    if rest and rest[0] == "--":
        rest = rest[1:]
    extra = rest
    host = host_of(url)

    ok, why = in_scope(host)
    if not ok:
        audit({"method": method, "url": url, "host": host, "decision": "DENY-SCOPE", "reason": why})
        die(2, f"OUT OF SCOPE: {host} — {why}. Not sent. Add it to {ALLOW} only if it is truly in scope.")

    if method in WRITE and not (approve or os.environ.get("HUNT_ALLOW_WRITE") == "1"):
        audit({"method": method, "url": url, "host": host, "decision": "DENY-METHOD", "reason": "write without approval"})
        die(3, f"BLOCKED: {method} is state-changing. Re-run with --approve or HUNT_ALLOW_WRITE=1 "
                "only after the operator confirms this write is intended and reversible.")
    if method not in SAFE and method not in WRITE:
        die(5, f"unknown method {method}")

    if cb_count(host) >= CB_THRESHOLD:
        audit({"method": method, "url": url, "host": host, "decision": "DENY-CIRCUIT", "reason": "breaker open"})
        die(4, f"CIRCUIT OPEN for {host}: {CB_THRESHOLD} consecutive 403/429/timeout. "
                f"Stop hammering; back off. Reset with: rm {cb_path(host)}")

    # ── program guardrails (rules.json): blocked paths, required UA, rate limit ──
    rules = load_rules()
    path = urllib.parse.urlparse(url).path or "/"
    for bp in rules.get("blocked_paths", []):
        if bp and bp.lower() in path.lower():
            audit({"method": method, "url": url, "host": host, "decision": "DENY-RULE", "reason": f"blocked path {bp}"})
            die(2, f"BLOCKED by program rule: path matches '{bp}' (out of scope / disallowed). Not sent.")
    ua = rules.get("ua") or os.environ.get("HUNT_UA")
    if ua and not any(str(x).lower() == "-a" or str(x).lower() == "--user-agent" for x in extra):
        extra = ["-A", ua] + extra
    rps = rules.get("rate_rps")
    if rps:
        rate_limit(host, float(rps))

    cmd = ["curl", "-sS", "-i", "--max-time", "25", "-X", method, url] + extra
    audit({"method": method, "url": url, "host": host, "decision": "ALLOW", "reason": why,
           "ua": bool(ua), "rps": rps})
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        die(5, "curl not found")
    out = r.stdout
    status = 0
    first = out.split("\n", 1)[0] if out else ""
    for tok in first.split():
        if tok.isdigit() and len(tok) == 3:
            status = int(tok)
            break
    if status in (403, 429) or r.returncode == 28:  # 28 = curl timeout
        cb_set(host, cb_count(host) + 1)
    else:
        cb_set(host, 0)
    sys.stdout.write(out)
    if r.stderr:
        sys.stderr.write(r.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
