#!/usr/bin/env python3
"""
hunt-graph.py — build + cache a queryable KNOWLEDGE GRAPH of a hunt (graphify-style, zero tokens).

Constructs a graph from run.json (target → hosts → endpoints → params / findings / chains),
runs graphify's community detection + centrality + surprising-connection analysis (all deterministic,
no LLM), and caches the result to <hunt>/kgraph.json. Rebuilds only when run.json changed.

Insights it surfaces, free:
  • communities  — logical areas of the attack surface (clusters of related endpoints)
  • god-nodes    — the most pivotal endpoints/params (highest-value test targets)
  • surprises    — params/patterns shared across hosts (IDOR / pivot candidates)

Usage: hunt-graph.py --run <run.json> [--force] [--json]
Emits: {"ok":true, "cached":bool, "nodes":[...], "edges":[...], "communities":{...},
        "labels":{...}, "gods":[...], "surprises":[...], "stats":{...}}
"""
import sys, json, os, re, time
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

HERE = Path(__file__).resolve().parent

# self-bootstrap: this tool needs graphify + networkx (pipx venv). If the invoking python
# can't import graphify, re-exec under the graphify interpreter so the server can call it
# with its own python and still succeed.
try:
    import graphify  # noqa: F401
except Exception:
    import shutil
    _cands = [str(Path.home() / ".local/share/pipx/venvs/graphifyy/bin/python")]
    _rootfile = HERE.parent / "graphify-out" / ".graphify_python"
    for _p in (Path.cwd() / "graphify-out" / ".graphify_python", _rootfile):
        try:
            if _p.exists():
                _cands.insert(0, _p.read_text().strip())
        except Exception:
            pass
    _gb = shutil.which("graphify")
    if _gb:
        try:
            _cands.append(open(_gb).readline().strip().lstrip("#!").strip())
        except Exception:
            pass
    for _c in _cands:
        try:
            if _c and Path(_c).exists() and os.path.realpath(_c) != os.path.realpath(sys.executable):
                os.execv(_c, [_c, os.path.abspath(__file__)] + sys.argv[1:])
        except Exception:
            continue
    # if we get here, graphify truly isn't available — the clean error is emitted below


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def out(d):
    print(json.dumps(d)); sys.exit(0)


RUN = arg("--run")
if not RUN:
    out({"ok": False, "error": "need --run"})
rf = Path(RUN)
if not rf.exists():
    out({"ok": False, "error": "no run.json"})
kf = rf.with_name("kgraph.json")
run_ts = rf.stat().st_mtime

# cache: reuse unless run.json changed or --force
if kf.exists() and "--force" not in sys.argv:
    try:
        cached = json.loads(kf.read_text())
        if abs(cached.get("run_ts", 0) - run_ts) < 0.5:
            cached["cached"] = True
            out(cached)
    except Exception:
        pass

try:
    d = json.loads(rf.read_text())
except Exception as e:
    out({"ok": False, "error": "bad run.json: " + str(e)[:120]})

target = d.get("target", "target")
endpoints = [e if isinstance(e, str) else (e.get("url") or e.get("endpoint") or "") for e in (d.get("endpoints") or [])]
endpoints = [e for e in endpoints if e]
findings = d.get("findings") or []
chains = d.get("chains") or []

# ── build the extraction graph ──
nodes, edges, seen = [], [], set()
def add_node(nid, label, ntype, **ex):
    if nid in seen:
        return
    seen.add(nid)
    nodes.append(dict(id=nid, label=label[:60], ntype=ntype, source_file=ntype, **ex))
def add_edge(s, t, rel):
    edges.append({"source": s, "target": t, "relation": rel, "source_file": "hunt", "confidence": "EXTRACTED"})

add_node("target:" + target, target, "target")
for u in endpoints[:400]:
    try:
        p = urlparse(u); host = p.netloc; path = p.path or "/"
    except Exception:
        continue
    hid = "host:" + host
    add_node(hid, host, "host")
    add_edge("target:" + target, hid, "contains")
    eid = "ep:" + u
    add_node(eid, path, "endpoint", url=u)
    add_edge(hid, eid, "serves")
    # params become shared hubs → god-nodes / cross-host surprises
    try:
        for k, _v in parse_qsl(p.query, keep_blank_values=True):
            if not k:
                continue
            pid = "param:" + k.lower()
            add_node(pid, k, "param")
            add_edge(eid, pid, "accepts")
    except Exception:
        pass

for i, f in enumerate(findings):
    if f.get("verdict") == "false_positive":
        continue
    fid = "find:" + str(i)
    add_node(fid, (f.get("title") or ("#" + str(i)))[:50], "finding",
             sev=(f.get("sev") or "i"), verdict=f.get("verdict", ""), fi=i)
    ep = f.get("endpoint") or ""
    tgt = "ep:" + ep if ("ep:" + ep) in seen else None
    if not tgt and ep:
        try:
            h = "host:" + urlparse(ep).netloc
            tgt = h if h in seen else None
        except Exception:
            tgt = None
    add_edge(tgt or ("target:" + target), fid, "affects")

for i, c in enumerate(chains):
    cid = "chain:" + str(i)
    add_node(cid, (c.get("title") or ("chain " + str(i)))[:40], "chain")
    for fi in (c.get("findings") or []):
        if ("find:" + str(fi)) in seen:
            add_edge("find:" + str(fi), cid, "chains")

if len(nodes) < 2:
    out({"ok": False, "error": "not enough surface to graph yet"})

# ── graphify analysis (deterministic) ──
try:
    from graphify.build import build_from_json
    from graphify.cluster import cluster
    from graphify.analyze import surprising_connections
    import networkx as nx
except Exception as e:
    out({"ok": False, "error": "graphify not available: " + str(e)[:120]})

G = build_from_json({"nodes": nodes, "edges": edges})
communities = cluster(G)
try:
    surprises = surprising_connections(G, communities)
except Exception:
    surprises = []

# node_id → community
n2c = {}
for cid, members in communities.items():
    for m in members:
        n2c[m] = cid

# centrality for sizing + god-nodes (the most pivotal test targets).
# Betweenness finds true bridges; fall back to degree on large graphs for speed.
cent = nx.degree_centrality(G)
try:
    btw = nx.betweenness_centrality(G, k=min(120, G.number_of_nodes())) if G.number_of_nodes() <= 1500 else cent
except Exception:
    btw = cent
_nmeta_tmp = {n["id"]: n for n in nodes}
# god-nodes = most central endpoints/params (skip the target root + bare hosts)
_rank = sorted(((nid, btw.get(nid, 0) + cent.get(nid, 0) * 0.3) for nid in G.nodes()
                if _nmeta_tmp.get(nid, {}).get("ntype") in ("endpoint", "param", "finding")),
               key=lambda kv: -kv[1])
gods = [{"id": nid} for nid, _s in _rank[:12]]

nmeta = {n["id"]: n for n in nodes}
# deterministic community labels: dominant host / path prefix in the community
def label_comm(members):
    hosts, paths = {}, {}
    for m in members:
        nm = nmeta.get(m, {})
        if nm.get("ntype") == "host":
            hosts[nm["label"]] = hosts.get(nm["label"], 0) + 1
        if nm.get("ntype") == "endpoint":
            seg = (nm.get("label") or "/").strip("/").split("/")[0] or "/"
            paths[seg] = paths.get(seg, 0) + 1
    if hosts:
        return max(hosts, key=hosts.get)
    if paths:
        return "/" + max(paths, key=paths.get)
    return "cluster"

labels = {str(cid): label_comm(members) for cid, members in communities.items()}

out_nodes = []
for n in nodes:
    out_nodes.append({"id": n["id"], "label": n["label"], "type": n["ntype"],
                      "community": n2c.get(n["id"], -1),
                      "community_name": labels.get(str(n2c.get(n["id"], -1)), ""),
                      "centrality": round(cent.get(n["id"], 0), 4),
                      **({"sev": n["sev"], "fi": n["fi"]} if n["ntype"] == "finding" else {}),
                      **({"url": n["url"]} if n.get("url") else {})})

result = {
    "ok": True, "cached": False, "run_ts": run_ts, "built": int(time.time()),
    "nodes": out_nodes, "edges": edges,
    "communities": {str(k): v for k, v in communities.items()},
    "labels": labels,
    "gods": [{"id": g["id"], "label": nmeta.get(g["id"], {}).get("label", g["id"]),
              "type": nmeta.get(g["id"], {}).get("ntype", ""),
              "score": round(btw.get(g["id"], 0), 4)} for g in gods],
    "surprises": surprises[:12] if isinstance(surprises, list) else [],
    "stats": {"nodes": len(out_nodes), "edges": len(edges), "communities": len(communities)},
}
try:
    tmp = kf.with_suffix(".json.tmp"); tmp.write_text(json.dumps(result)); tmp.replace(kf)
except Exception:
    pass
out(result)
