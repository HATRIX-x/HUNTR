#!/usr/bin/env python3
"""
scope-radar — monitor bug bounty program scope and reward changes.

Platforms supported:
  • HackerOne  (program slug)
  • Bugcrowd   (program slug)
  • YesWeHack  (program slug)
  • Intigriti  (company/program slug)

Snapshots program scope + rewards to ~/.cache/scope-radar/<slug>.json.
On next run: diffs new vs stored state and reports additions / removals /
reward changes. Great for catching new assets or bounty increases.

Usage:
  scope-radar.py --h1 shopify --bc acme --ywh target --ing company/slug
                 [--snapshot-only] [--diff-only] [--json] [--out results.json]
  scope-radar.py --h1 shopify   # single program
Exit: 0 no changes · 1 changes found.
"""
import sys, re, json, time, os, hashlib
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home()/".cache")) / "scope-radar"
CACHE.mkdir(parents=True, exist_ok=True)

H1_GRAPHQL = "https://hackerone.com/graphql"

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
def flag(n): return n in sys.argv

def fetch_json(url, headers=None, timeout=15):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json"}
    if headers: h.update(headers)
    try:
        req = Request(url, headers=h)
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8","ignore")), r.status
    except Exception as e:
        return {"error": str(e)}, 0

def post_json(url, body, headers=None, timeout=15):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json","Content-Type":"application/json"}
    if headers: h.update(headers)
    try:
        data = json.dumps(body).encode()
        req = Request(url, data=data, headers=h, method="POST")
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8","ignore")), r.status
    except Exception as e:
        return {"error": str(e)}, 0

# ── HackerOne ────────────────────────────────────────────────────────────
def fetch_h1(slug):
    query = {
        "query": """
        query Program($handle: String!) {
          team(handle: $handle) {
            name currency
            structured_scope_versions(archived: false) {
              edges { node { scope_versions_edges { edges { node {
                asset_type asset_identifier
                max_severity eligible_for_bounty
                instruction
              } } } } }
            }
            bounty_table { structured_scopes_bounties { label bounty_from bounty_to } }
          }
        }""",
        "variables": {"handle": slug},
    }
    data, code = post_json(H1_GRAPHQL, query)
    team = (data.get("data") or {}).get("team") or {}
    scopes = []
    try:
        sv = team.get("structured_scope_versions",{}).get("edges",[])
        for se in sv:
            for sn in se.get("node",{}).get("scope_versions_edges",{}).get("edges",[]):
                n = sn.get("node",{})
                scopes.append({
                    "identifier": n.get("asset_identifier",""),
                    "type": n.get("asset_type",""),
                    "severity": n.get("max_severity",""),
                    "eligible_bounty": n.get("eligible_for_bounty",False),
                })
    except Exception: pass
    bounties = {}
    try:
        for b in (team.get("bounty_table") or {}).get("structured_scopes_bounties",[]):
            bounties[b.get("label","")] = {"min": b.get("bounty_from"), "max": b.get("bounty_to")}
    except Exception: pass
    return {"platform":"h1","slug":slug,"name":team.get("name",slug),"scopes":scopes,"bounties":bounties}

# ── Bugcrowd ─────────────────────────────────────────────────────────────
def fetch_bc(slug):
    data, code = fetch_json(f"https://bugcrowd.com/{slug}.json")
    if code not in (200,): return {"platform":"bc","slug":slug,"error":f"HTTP {code}","scopes":[],"bounties":{}}
    scopes = []
    targets = data.get("targets",{})
    for group in targets.get("in_scope",[]):
        for t in group.get("targets",[]):
            scopes.append({
                "identifier": t.get("name",""),
                "type": t.get("category",""),
                "severity": "",
                "eligible_bounty": t.get("bounty_type","") != "kudos",
            })
    bounties = {}
    for rw in (data.get("rewards") or []):
        label = rw.get("identifier","")
        bounties[label] = {"min": rw.get("payment_from"), "max": rw.get("payment_to")}
    return {"platform":"bc","slug":slug,"name":data.get("name",slug),"scopes":scopes,"bounties":bounties}

# ── YesWeHack ────────────────────────────────────────────────────────────
def fetch_ywh(slug):
    data, code = fetch_json(f"https://api.yeswehack.com/programs/{slug}")
    if code not in (200,201): return {"platform":"ywh","slug":slug,"error":f"HTTP {code}","scopes":[],"bounties":{}}
    scopes = []
    for s in (data.get("scopes") or []):
        scopes.append({
            "identifier": s.get("scope",""),
            "type": s.get("scope_type",""),
            "severity": "",
            "eligible_bounty": True,
        })
    bounties = {}
    for rw in (data.get("rewards") or []):
        label = rw.get("label","?")
        bounties[label] = {"min": rw.get("min_reward"), "max": rw.get("max_reward")}
    return {"platform":"ywh","slug":slug,"name":data.get("title",slug),"scopes":scopes,"bounties":bounties}

# ── Intigriti ────────────────────────────────────────────────────────────
def fetch_ing(slug):
    # slug may be "company/program"
    parts = slug.split("/",1)
    company = parts[0]; prog = parts[1] if len(parts)>1 else parts[0]
    data, code = fetch_json(f"https://api.intigriti.com/core/researcher/program/{company}/{prog}")
    if code not in (200,201): return {"platform":"ing","slug":slug,"error":f"HTTP {code}","scopes":[],"bounties":{}}
    scopes = []
    for domain in (data.get("domains") or {}).get("inScope",[]):
        scopes.append({
            "identifier": domain.get("endpoint",""),
            "type": domain.get("type",""),
            "severity": "",
            "eligible_bounty": domain.get("bountyTable","") != "",
        })
    bounties = {}
    bt = data.get("bountyTable") or {}
    for row in (bt.get("rows") or []):
        label = row.get("rowName","")
        vals = row.get("cells",[])
        if vals:
            bounties[label] = {"min": vals[0].get("value"), "max": vals[-1].get("value")}
    return {"platform":"ing","slug":slug,"name":data.get("name",slug),"scopes":scopes,"bounties":bounties}

# ── diff ──────────────────────────────────────────────────────────────────
def cache_path(platform, slug):
    key = f"{platform}_{slug.replace('/','_')}"
    return CACHE / f"{key}.json"

def load_snapshot(platform, slug):
    p = cache_path(platform, slug)
    if p.exists():
        try: return json.loads(p.read_text())
        except: pass
    return None

def save_snapshot(data):
    data["snapshot_ts"] = time.strftime("%Y-%m-%d %H:%M")
    p = cache_path(data["platform"], data["slug"])
    p.write_text(json.dumps(data, indent=2))

def diff_scopes(old_scopes, new_scopes):
    old_ids = {s["identifier"] for s in old_scopes}
    new_ids = {s["identifier"] for s in new_scopes}
    added   = [s for s in new_scopes if s["identifier"] not in old_ids and s["identifier"]]
    removed = [s for s in old_scopes if s["identifier"] not in new_ids and s["identifier"]]
    return added, removed

def diff_bounties(old_bounties, new_bounties):
    changes = []
    for label in set(list(old_bounties.keys()) + list(new_bounties.keys())):
        old = old_bounties.get(label, {})
        new = new_bounties.get(label, {})
        if old != new:
            changes.append({
                "label": label,
                "old_min": old.get("min"), "old_max": old.get("max"),
                "new_min": new.get("min"), "new_max": new.get("max"),
                "direction": "increase" if (new.get("max") or 0) > (old.get("max") or 0) else "decrease"
            })
    return changes

def process(platform, slug, fetcher, results, snapshot_only, diff_only):
    print(f"[scope-radar] fetching {platform}:{slug} …", file=sys.stderr)
    current = fetcher(slug)
    if current.get("error"):
        print(f"  ! {current['error']}", file=sys.stderr)
        return
    old = load_snapshot(platform, slug)
    if not diff_only:
        save_snapshot(current)
    if not old:
        print(f"  First snapshot stored for {slug} ({len(current.get('scopes',[]))} scope items)", file=sys.stderr)
        results.append({"slug":slug,"platform":platform,"first_run":True,
                        "scope_count":len(current.get("scopes",[]))})
        return
    if snapshot_only: return
    added, removed = diff_scopes(old.get("scopes",[]), current.get("scopes",[]))
    b_changes = diff_bounties(old.get("bounties",{}), current.get("bounties",{}))
    if added or removed or b_changes:
        r = {"slug":slug,"platform":platform,"added":added,"removed":removed,"bounty_changes":b_changes}
        results.append(r)
        print(f"  Changes: +{len(added)} scope -{len(removed)} scope {len(b_changes)} bounty", file=sys.stderr)
    else:
        print(f"  No changes.", file=sys.stderr)

def main():
    h1_slug  = arg("--h1")
    bc_slug  = arg("--bc")
    ywh_slug = arg("--ywh")
    ing_slug = arg("--ing")
    out_file = arg("--out")
    snap_only = flag("--snapshot-only")
    diff_only = flag("--diff-only")

    if not any([h1_slug, bc_slug, ywh_slug, ing_slug]):
        print(__doc__); sys.exit(0)

    results = []
    if h1_slug:  process("h1",  h1_slug,  fetch_h1,  results, snap_only, diff_only)
    if bc_slug:  process("bc",  bc_slug,  fetch_bc,  results, snap_only, diff_only)
    if ywh_slug: process("ywh", ywh_slug, fetch_ywh, results, snap_only, diff_only)
    if ing_slug: process("ing", ing_slug, fetch_ing, results, snap_only, diff_only)

    has_changes = any(r for r in results if not r.get("first_run") and
                      (r.get("added") or r.get("removed") or r.get("bounty_changes")))

    out = {"ts": time.strftime("%Y-%m-%d %H:%M"), "results": results, "changes_found": has_changes}
    if out_file: Path(out_file).write_text(json.dumps(out, indent=2))

    if flag("--json"):
        print(json.dumps(out)); sys.exit(1 if has_changes else 0)

    print(f"\n══ Scope Radar ══════════════════════════")
    for r in results:
        if r.get("first_run"):
            print(f"  {r['platform']}:{r['slug']} — first snapshot ({r.get('scope_count',0)} items)")
        else:
            added   = r.get("added",[])
            removed = r.get("removed",[])
            b_chg   = r.get("bounty_changes",[])
            print(f"  {r['platform']}:{r['slug']}")
            if not added and not removed and not b_chg:
                print(f"    No changes.")
            if added:
                print(f"    +{len(added)} NEW scope items:")
                for s in added[:10]: print(f"      → {s['identifier']} ({s['type']})")
            if removed:
                print(f"    -{len(removed)} REMOVED scope items:")
                for s in removed[:5]: print(f"      ← {s['identifier']}")
            if b_chg:
                print(f"    Bounty changes:")
                for b in b_chg:
                    dir_sym = "↑" if b["direction"]=="increase" else "↓"
                    print(f"      {dir_sym} {b['label']}: {b['old_max']} → {b['new_max']}")

    sys.exit(1 if has_changes else 0)

if __name__ == "__main__":
    main()
