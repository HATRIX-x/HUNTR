#!/usr/bin/env python3
"""
capability-graph — deterministic chain discovery by reachability.

An LLM can't hold a 5-step chain in its head reliably. So don't make it. Model the hunt as a
graph: NODES are capabilities/assets you can hold (anon, userA-token, admin-hash, id-range,
ssrf-reach, admin-session, all-tenant-data). EDGES are a proven primitive that upgrades one
capability into another (SQLi -> db_read, crack -> admin_creds). Then chains are just PATHS,
found by graph search — including the one nobody typed out.

You (or the model) only supply edges as you prove them; the graph finds:
  • REACHABLE IMPACT   — impact nodes reachable using only PROVEN edges (a finished chain)
  • NEAR MISS          — impact reachable if ONE more edge were proven (your highest-ROI next probe)
  • the single best NEXT EDGE to attempt

Edges file  ./.hunt/capabilities.tsv  (tab-separated, '#' comments):
  from        primitive                       to              status    impact  evidence
  anon        SQLi:/api/v1/users/search       db_read         proven    -       evidence/..#T3
  db_read     dump users table                admin_hash      proven    -
  admin_hash  crack bcrypt (weak cost)        admin_creds     proven    -
  admin_creds login admin.acme.com            admin_session   proven    -
  admin_session admin API list all tenants    all_tenants     partial   c       evidence/..
status: proven | partial | unproven      impact: - or a severity letter (c/h/m/l) marking a goal node

Usage:  capability-graph.py [--file ./.hunt/capabilities.tsv] [--have userA,token] [--dot]
"""
import sys, os
from pathlib import Path
from collections import deque, defaultdict

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
FILE = Path(sys.argv[sys.argv.index("--file") + 1]) if "--file" in sys.argv else HUNT / "capabilities.tsv"
HAVE = set(sys.argv[sys.argv.index("--have") + 1].split(",")) if "--have" in sys.argv else set()
SEVNAME = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW"}


def load():
    if not FILE.exists():
        sys.exit(f"[capability-graph] no edges at {FILE}. Add proven primitives as edges first "
                 f"(from<TAB>primitive<TAB>to<TAB>status<TAB>impact<TAB>evidence).")
    edges = []
    for ln in FILE.read_text().splitlines():
        s = ln.rstrip()
        if not s.strip() or s.strip().startswith("#"):
            continue
        c = s.split("\t")
        if len(c) < 3:
            continue
        edges.append({"frm": c[0].strip(), "prim": c[1].strip(), "to": c[2].strip(),
                      "status": (c[3].strip().lower() if len(c) > 3 else "proven"),
                      "impact": (c[4].strip() if len(c) > 4 else "-"),
                      "ev": (c[5].strip() if len(c) > 5 else "")})
    return edges


def bfs(edges, starts, allow_status):
    adj = defaultdict(list)
    for e in edges:
        if e["status"] in allow_status:
            adj[e["frm"]].append(e)
    seen = set(starts)
    par = {}
    q = deque(starts)
    while q:
        n = q.popleft()
        for e in adj[n]:
            if e["to"] not in seen:
                seen.add(e["to"])
                par[e["to"]] = e
                q.append(e["to"])
    return seen, par


def path_to(node, par):
    chain = []
    while node in par:
        e = par[node]
        chain.append(e)
        node = e["frm"]
    return list(reversed(chain))


def render_path(chain, starts):
    if not chain:
        return "  (already held)"
    line = "  " + list(starts)[0] if starts else ""
    line = "  " + chain[0]["frm"]
    for e in chain:
        arrow = "──▶" if e["status"] == "proven" else "╌╌▶"
        line += f"  {arrow}[{e['prim']}]  {e['to']}"
    return line


def main():
    edges = load()
    starts = {"anon"} | HAVE
    impacts = {e["to"]: e["impact"] for e in edges if e["impact"] and e["impact"] != "-"}
    if "--dot" in sys.argv:
        print("digraph caps {")
        for e in edges:
            st = "solid" if e["status"] == "proven" else "dashed"
            print(f'  "{e["frm"]}" -> "{e["to"]}" [label="{e["prim"]}",style={st}];')
        print("}")
        return

    proven_reach, proven_par = bfs(edges, starts, {"proven"})
    all_reach, all_par = bfs(edges, starts, {"proven", "partial", "unproven"})

    print("\n── CAPABILITY GRAPH ──────────────────────────────────────")
    print(f"  start: {', '.join(sorted(starts))}   nodes: {len({e['frm'] for e in edges}|{e['to'] for e in edges})}   edges: {len(edges)}")

    done, near, unreach = [], [], []
    for node, sev in sorted(impacts.items(), key=lambda kv: "chml".find(kv[1] or 'l')):
        if node in proven_reach:
            done.append((node, sev))
        elif node in all_reach:
            near.append((node, sev))
        else:
            unreach.append((node, sev))

    if done:
        print("\n  ✓ PROVEN CHAINS TO IMPACT (report these):")
        for node, sev in done:
            print(f"    [{SEVNAME.get(sev, sev)}] → {node}")
            print(render_path(path_to(node, proven_par), starts))
    if near:
        print("\n  ◐ NEAR MISS — one or more edges left to prove (highest-ROI next work):")
        best = None
        for node, sev in near:
            ch = path_to(node, all_par)
            missing = [e for e in ch if e["status"] != "proven"]
            print(f"    [{SEVNAME.get(sev, sev)}] → {node}   ({len(missing)} edge(s) to prove)")
            print(render_path(ch, starts))
            for e in missing:
                print(f"        ⇒ prove: [{e['prim']}]  {e['frm']} → {e['to']}  ({e['status']})")
            rank = "chml".find(sev or 'l')
            if best is None or (len(missing), rank) < best[0]:
                best = ((len(missing), rank), node, sev, missing[0] if missing else None)
        if best and best[3]:
            e = best[3]
            print(f"\n  ➜ HIGHEST-LEVERAGE NEXT EDGE: prove [{e['prim']}] ({e['frm']} → {e['to']}) "
                  f"→ unlocks {SEVNAME.get(best[2], best[2])} {best[1]}")
    if unreach:
        print("\n  ✗ UNREACHABLE impact (no known edge path yet): " + ", ".join(n for n, _ in unreach))
    if not impacts:
        print("\n  (no impact nodes marked — set the impact column to c/h/m/l on goal nodes)")
    print()


if __name__ == "__main__":
    main()
