#!/usr/bin/env python3
"""surface.py — clean, resumable crawl/surface-mapping primitive.

Does ONE thing: given a list of live hosts (from recon.py), crawl each one
(robots/sitemap, katana, historical URLs) into a deduped endpoint list.
Same contract as recon.py:
  - every failure CLASSIFIED (binary-missing / timeout / network-error /
    parse-error / scope-denied), never a silent `except Exception: pass`
  - checkpointed to --state after EVERY host, so a kill/crash resumes
  - stdout = one JSON result line; stderr = human progress
  - exit 0 = produced usable endpoints, 2 = produced nothing

No judgment calls here either — "is this endpoint list good enough, should
we crawl deeper, is the cap too low" belongs to the caller (the orchestrator:
a human, /autopilot, or hunt-run.py's phase_surface wrapper).
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from recon import sh, has  # reuse the same classified subprocess helper


def fetch_robots_sitemap(url, host, eps, errors, timeout=8):
    """robots.txt / sitemap.xml often reveal surface a crawler never reaches."""
    for rf in ("/robots.txt", "/sitemap.xml"):
        try:
            req = urllib.request.Request(url + rf, headers={"User-Agent": "Mozilla/5.0 HUNTR-surface"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                txt = r.read(200000).decode("utf-8", "ignore")
            for m in re.findall(r"(?:Allow|Disallow|Sitemap):\s*(\S+)", txt) + re.findall(r"<loc>\s*([^<\s]+)", txt):
                p = m.strip()
                full = p if p.startswith("http") else (url + ("" if p.startswith("/") else "/") + p)
                if full.startswith("http") and "*" not in full:
                    eps[full] = host
        except urllib.error.HTTPError:
            pass  # a 404 on robots.txt is normal, not a failure worth reporting
        except Exception as e:
            errors.append({"host": host, "step": rf, "kind": "network-error", "detail": str(e)[:150]})


def crawl_katana(url, host, eps, errors, stealth, timeout=110):
    if not has("katana"):
        return "binary-missing"
    cmd = ["katana", "-u", url, "-silent", "-d", "2", "-c", "5" if stealth else "15",
           "-jc", "-timeout", "10"] + (["-rl", "15"] if stealth else [])
    out, err, rc, kind = sh(cmd, timeout=timeout)
    if kind:
        errors.append({"host": host, "step": "katana", "kind": kind, "detail": err[:150]})
        return kind
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("http"):
            eps[ln] = host
    return None


def crawl_historical(host, eps, errors, timeout=45):
    """gau / waybackurls — public-archive history. Only meaningful for public hosts."""
    ran_any = False
    for tool, cmd in (("gau", ["gau", "--threads", "5", "--subs", host]),
                      ("waybackurls", ["waybackurls", host])):
        if not has(tool):
            continue
        ran_any = True
        out, err, rc, kind = sh(cmd, timeout=timeout)
        if kind:
            errors.append({"host": host, "step": tool, "kind": kind, "detail": err[:150]})
            continue
        for ln in out.splitlines()[:400]:
            ln = ln.strip()
            if ln.startswith("http"):
                eps[ln] = host
    if not ran_any:
        return "binary-missing"
    return None


def dedup(eps, cap):
    """Prefer parameterized URLs (the testable surface), then collapse near-duplicates
    by (host, path, sorted param NAMES) — ?id=1 and ?id=2 are the same test cell."""
    items = list(eps.items())
    items.sort(key=lambda kv: (0 if re.search(r"[?&][\w\[\]]+=", kv[0]) else 1, len(kv[0])))
    seen_sig, deduped = set(), []
    for u, h in items:
        try:
            pu = urllib.parse.urlparse(u)
            sig = (pu.netloc, pu.path, tuple(sorted(k for k, _ in urllib.parse.parse_qsl(pu.query))))
        except Exception:
            sig = (u,)
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        deduped.append((u, h))
    return [{"url": u, "host": h} for u, h in deduped[:cap]]


def load_state(path):
    if not path or not Path(path).exists():
        return {"hosts_done": {}, "endpoints": {}, "errors": [], "warnings": []}
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        sys.stderr.write("[surface] WARNING: state file unreadable, starting fresh: " + path + "\n")
        return {"hosts_done": {}, "endpoints": {}, "errors": [], "warnings": [], "_recovered_from_corrupt": True}


def save_state(path, state):
    if not path:
        return
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hosts", required=True,
                     help="JSON array of {host, scheme?} — inline, or @file.json (recon.py's \"hosts\" output works directly)")
    ap.add_argument("--state", default=None)
    ap.add_argument("--stealth", action="store_true")
    ap.add_argument("--single-host", action="store_true", help="skip gau/waybackurls (no public archive for IP/localhost/explicit-port targets)")
    ap.add_argument("--max-hosts", type=int, default=8)
    ap.add_argument("--max-endpoints", type=int, default=400)
    ap.add_argument("--endpoint-soft-cap", type=int, default=1200, help="stop crawling MORE hosts once raw endpoints collected passes this")
    args = ap.parse_args()

    raw = Path(args.hosts[1:]).read_text() if args.hosts.startswith("@") else args.hosts
    targets = json.loads(raw)

    state = load_state(args.state)
    state.setdefault("hosts_done", {})
    state.setdefault("endpoints", {})
    state.setdefault("errors", [])
    state.setdefault("warnings", [])

    t0 = time.time()
    crawled, skipped_cap = 0, []
    for h in targets[:args.max_hosts]:
        host = h.get("host") if isinstance(h, dict) else h
        if not host:
            continue
        if state["hosts_done"].get(host):
            sys.stderr.write("[surface] " + host + " already crawled (resumed) — skipping\n")
            continue
        if len(state["endpoints"]) > args.endpoint_soft_cap:
            skipped_cap.append(host)
            continue
        scheme = h.get("scheme") if isinstance(h, dict) else None
        url = (scheme or "https") + "://" + host
        sys.stderr.write("[surface] crawling " + url + "\n")

        fetch_robots_sitemap(url, host, state["endpoints"], state["errors"])
        k = crawl_katana(url, host, state["endpoints"], state["errors"], args.stealth)
        if k == "binary-missing":
            state["warnings"].append({"host": host, "kind": "katana-not-installed"})
        if not args.single_host:
            k2 = crawl_historical(host, state["endpoints"], state["errors"])
            if k2 == "binary-missing":
                state["warnings"].append({"host": host, "kind": "no-historical-url-tool", "detail": "neither gau nor waybackurls found"})

        state["hosts_done"][host] = True
        crawled += 1
        save_state(args.state, state)  # checkpoint after EVERY host

    endpoints = dedup(state["endpoints"], args.max_endpoints)
    remaining = [h.get("host") if isinstance(h, dict) else h for h in targets[args.max_hosts:]] + skipped_cap

    result = {
        "ok": len(endpoints) > 0,
        "endpoints": endpoints,
        "count": len(endpoints),
        "hosts_crawled": crawled,
        "hosts_remaining": [h for h in remaining if h],
        "errors": state["errors"],
        "warnings": state["warnings"],
        "elapsed_s": round(time.time() - t0, 1),
    }
    print(json.dumps(result))

    if result["hosts_remaining"]:
        sys.stderr.write("[surface] " + str(len(result["hosts_remaining"])) + " host(s) not yet crawled — re-run with the same --state and a higher --max-hosts to continue\n")
    if not endpoints:
        sys.stderr.write("[surface] no endpoints found — host may block crawlers or have no links\n")

    sys.exit(0 if result["ok"] else 2)


if __name__ == "__main__":
    main()
