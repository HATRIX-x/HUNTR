#!/usr/bin/env python3
"""
js-diff — watch JS bundles for new endpoints, params, tokens, and secrets.

New JS = new attack surface before anyone else finds it. This snapshots every
JS URL on a target, diffs on every check, and alerts on new endpoints/params/
removed paths/new secrets. New scope bumps the ROI freshness so the program
floats to the top of "hunt now".

Snapshots: ~/.claude/hunt-js/<target>/

Usage:
  js-diff.py --target acme --add-url https://app.acme.com/static/js/main.abc123.js
  js-diff.py --target acme --crawl https://app.acme.com          # auto-discover JS URLs
  js-diff.py --target acme --check [--json]                      # diff all URLs
  js-diff.py --target acme --report [--json]                     # show all changes
  js-diff.py --report --all [--json]                             # all targets
Exit: 0 no change · 1 changes found.
"""
import sys, os, re, json, time, hashlib
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urljoin, urlparse

ROOT = Path(os.environ.get("HUNT_JS", str(Path.home() / ".claude" / "hunt-js")))
FEED = ROOT / "changes.jsonl"

EP_PAT = re.compile(
    r"""(?:["'`\s(,=])(/(?:api|v\d|graphql|rest|ws|internal|admin|auth|oauth|user|account|payment|order|upload)[^\s"'`<>{}|\\^`\[\]]{1,120})""", re.I
)
ROUTE_PAT = re.compile(
    r"""(?:path|route|url|endpoint|href)\s*[:=]\s*["'`]([/][^"'`\s]{3,80})["'`]""", re.I
)
PARAM_PAT = re.compile(
    r"""["'`]([a-z_][a-z0-9_]{2,30})["'`]\s*:\s*(?:params|query|body|data|payload|form)""", re.I
)
SECRET_PAT = re.compile(
    r"""(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*|(?i)(?:api.?key|token|secret)\s*[:=]\s*["'`]([A-Za-z0-9\-_.~]{16,}))"""
)
JS_PAT = re.compile(r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def flag(n): return n in sys.argv

def tgt_dir(t):
    d = ROOT / re.sub(r"[^a-z0-9._-]+","_",t.lower())
    d.mkdir(parents=True, exist_ok=True)
    return d

def url_key(url):
    return hashlib.md5(url.encode()).hexdigest()[:16]

def fetch(url, timeout=15):
    try:
        req = Request(url, headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        with urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8","ignore")
    except Exception as e:
        return None

def extract_surface(js):
    eps = set()
    for m in EP_PAT.finditer(js): eps.add(m.group(1))
    for m in ROUTE_PAT.finditer(js): eps.add(m.group(1))
    params = set(m.group(1) for m in PARAM_PAT.finditer(js))
    secrets = [m.group(0)[:80] for m in SECRET_PAT.finditer(js)]
    return {"endpoints": sorted(eps), "params": sorted(params), "secrets": secrets[:20]}

def load_urls(t):
    p = tgt_dir(t) / "urls.json"
    return json.loads(p.read_text()) if p.exists() else []

def save_urls(t, urls):
    (tgt_dir(t) / "urls.json").write_text(json.dumps(urls))

def load_snap(t, key):
    p = tgt_dir(t) / f"{key}.json"
    return json.loads(p.read_text()) if p.exists() else None

def save_snap(t, key, data):
    (tgt_dir(t) / f"{key}.json").write_text(json.dumps(data, indent=2))

def cmd_add_url(t, url):
    urls = load_urls(t)
    if url not in urls:
        urls.append(url); save_urls(t, urls)
        print(f"[js-diff] added {url} to {t} ({len(urls)} URLs total)")
    else:
        print(f"[js-diff] {url} already tracked")

def cmd_crawl(t, base):
    print(f"[js-diff] crawling {base} for JS URLs…", file=sys.stderr)
    html = fetch(base)
    if not html:
        sys.exit(f"[js-diff] failed to fetch {base}")
    found = []
    for m in JS_PAT.finditer(html):
        raw = m.group(1)
        full = raw if raw.startswith("http") else urljoin(base, raw)
        if urlparse(full).netloc == urlparse(base).netloc:
            found.append(full)
    urls = list(set(load_urls(t) + found))
    save_urls(t, urls)
    print(f"[js-diff] discovered {len(found)} JS URL(s), {len(urls)} total tracked for {t}")
    for u in found: print(f"  + {u}")

def cmd_check(t):
    urls = load_urls(t)
    if not urls:
        print(f"[js-diff] no URLs tracked for {t}. Use --add-url or --crawl first."); return []
    changes = []
    for url in urls:
        key = url_key(url)
        js = fetch(url)
        if js is None:
            print(f"[js-diff] ⚠ could not fetch {url}", file=sys.stderr); continue
        cur = extract_surface(js)
        cur["hash"] = hashlib.sha256(js.encode()).hexdigest()[:16]
        cur["url"] = url; cur["ts"] = time.strftime("%Y-%m-%d %H:%M")
        old = load_snap(t, key)
        save_snap(t, key, cur)
        if old is None:
            print(f"[js-diff] baseline set for {url}"); continue
        if cur["hash"] == old.get("hash"): continue
        # compute diff
        added_eps  = sorted(set(cur["endpoints"]) - set(old.get("endpoints",[])))
        removed_ep = sorted(set(old.get("endpoints",[])) - set(cur["endpoints"]))
        added_par  = sorted(set(cur["params"]) - set(old.get("params",[])))
        new_secs   = [s for s in cur["secrets"] if s not in old.get("secrets",[])]
        rec = {
            "ts": time.strftime("%Y-%m-%d %H:%M"), "target": t, "url": url,
            "added_endpoints": added_eps, "removed_endpoints": removed_ep,
            "added_params": added_par, "new_secrets": new_secs,
        }
        if added_eps or removed_ep or added_par or new_secs:
            changes.append(rec)
            ROOT.mkdir(parents=True, exist_ok=True)
            with FEED.open("a") as f: f.write(json.dumps(rec)+"\n")
            print(f"[js-diff] ⚠ {url} CHANGED:")
            if added_eps: print(f"  +{len(added_eps)} new endpoints: {', '.join(added_eps[:5])}")
            if removed_ep: print(f"  -{len(removed_ep)} removed: {', '.join(removed_ep[:3])}")
            if added_par: print(f"  +{len(added_par)} new params: {', '.join(added_par[:5])}")
            if new_secs: print(f"  ⚠ {len(new_secs)} new secret(s) found!")
    return changes

def cmd_report(t=None, all_targets=False):
    rows = []
    if FEED.exists():
        for ln in FEED.read_text().splitlines():
            if ln.strip():
                try: rows.append(json.loads(ln))
                except Exception: pass
    if t: rows = [r for r in rows if r.get("target")==t]
    if flag("--json"):
        print(json.dumps({"changes": rows[-60:]})); return
    if not rows:
        print("[js-diff] no JS changes logged yet."); return
    print(f"[js-diff] JS surface changes ({len(rows)} events):\n")
    for r in rows[-30:]:
        ae = len(r.get("added_endpoints",[]))
        re_ = len(r.get("removed_endpoints",[]))
        ap = len(r.get("added_params",[]))
        ns = len(r.get("new_secrets",[]))
        flags = " ".join(filter(None,[f"+{ae}ep" if ae else "", f"-{re_}ep" if re_ else "",
                                      f"+{ap}par" if ap else "", f"⚠SECRET" if ns else ""]))
        print(f"  {r['ts']}  {r.get('target','?'):<16} {flags}")
        print(f"          {r['url'][:80]}")
        for ep in r.get("added_endpoints",[])[:4]: print(f"          ★ NEW: {ep}")
        if ns: print(f"          ⚠ NEW SECRET(S) — check immediately")

def main():
    t = arg("--target","default")
    if flag("--add-url"):   return cmd_add_url(t, arg("--add-url"))
    if flag("--crawl"):     return cmd_crawl(t, arg("--crawl"))
    if flag("--check"):
        changes = cmd_check(t)
        sys.exit(1 if changes else 0)
    if flag("--report"):    return cmd_report(t, all_targets=flag("--all"))
    print(__doc__)

if __name__ == "__main__":
    main()
