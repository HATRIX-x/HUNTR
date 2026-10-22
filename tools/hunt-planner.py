#!/usr/bin/env python3
"""
hunt-planner.py — GRAPH-DRIVEN attack planner (HUNTR's reasoning edge over XBOW).

XBOW tests endpoint-by-endpoint. HUNTR reasons over the whole surface as a graph. This planner
takes the cached knowledge graph (hosts → endpoints → shared params → findings → chains, plus
betweenness god-nodes and cross-cluster bridges) and an LLM reasons over its STRUCTURE to produce
a ranked, actionable attack plan: which node to hit, what class to try, WHY the graph says so, and
what it unlocks. Deterministic graph signals (centrality, bridges, finding density) are blended in
so the plan is grounded, not vibes.

AI-led (the model reasons over the topology) + graph-grounded (priority seeded from real centrality).

stdin : {"target": "<t>"}  (reads/builds the kgraph)
stdout: {"ok":true,"plan":[{rank,action,node,cls,rationale,unlocks,score}...],"summary":"..."}
"""
import sys, os, json, subprocess, re
from pathlib import Path
import agent_core as A

HERE = Path(__file__).resolve().parent
d_in = A.read_stdin_json()
target = d_in.get("target") or ""
RUN = A.RUN  # HUNT_DIR/run.json

# ── get the knowledge graph (cached; builds if stale) ──
kg = {}
try:
    r = subprocess.run([sys.executable, str(HERE / "hunt-graph.py"), "--run", str(RUN), "--json"],
                       capture_output=True, text=True, timeout=120, env=os.environ)
    kg = json.loads((r.stdout or "").strip().splitlines()[-1])
except Exception as e:
    A.emit({"ok": False, "error": "could not build knowledge graph: " + str(e)[:140]})
if not kg.get("ok"):
    A.emit({"ok": False, "error": kg.get("error", "no graph")})

nodes = {n["id"]: n for n in kg.get("nodes", [])}
gods = kg.get("gods", [])
surprises = kg.get("surprises", [])
labels = kg.get("labels", {})
run = A.read_run()
findings = [f for f in run.get("findings", []) if f.get("verdict") != "false_positive"]

# ── deterministic graph digest for the model ──
# god-nodes (pivotal), bridges (cross-cluster = pivot/IDOR candidates), finding map, param hubs
param_hubs = sorted([n for n in kg.get("nodes", []) if n.get("type") == "param"],
                    key=lambda n: -n.get("centrality", 0))[:12]
digest = {
    "target": target,
    "clusters": labels,
    "god_nodes": [{"label": g["label"], "type": g["type"], "centrality": g["score"]} for g in gods[:12]],
    "cross_cluster_bridges": [{"from": s.get("source"), "to": s.get("target"), "note": s.get("note")}
                              for s in surprises[:10]],
    "param_hubs": [{"param": p["label"], "centrality": p["centrality"]} for p in param_hubs],
    "findings": [{"cls": f.get("cls"), "sev": f.get("sev"), "verdict": f.get("verdict"),
                  "endpoint": f.get("endpoint"), "title": f.get("title")} for f in findings[:30]],
    "stats": kg.get("stats", {}),
}

system = (
    "You are HUNTR's lead attack strategist. You are given a target's attack surface as a KNOWLEDGE "
    "GRAPH digest: pivotal 'god-nodes' (high betweenness = reused/central endpoints & params), "
    "cross-cluster 'bridges' (a param/path spanning two areas — classic IDOR / pivot / auth-boundary "
    "candidates), parameter hubs (params reused across many endpoints), cluster labels, and current "
    "findings. Reason over the TOPOLOGY like a senior hacker planning an engagement, not endpoint-by-"
    "endpoint. Produce a RANKED attack plan that maximises impact per action.\n"
    "For each item decide: the concrete action (test a class on a node, enumerate an object, attempt a "
    "chain across findings, or expand recon on a bridge), WHY the graph structure implies it (cite the "
    "god-node/bridge/hub), and what confirming it UNLOCKS (impact or the next step). Favour: reused "
    "object-id params (IDOR/BOLA), bridges between an auth cluster and a data cluster, god-node "
    "endpoints (one bug = broad blast radius), and chains that turn two mediums into a critical.\n"
    "Reply STRICT JSON only: {\"plan\":[{\"action\":\"test|enumerate|chain|recon\",\"node\":\"<endpoint/param/"
    "finding>\",\"cls\":\"<vuln class>\",\"rationale\":\"<graph-grounded why>\",\"unlocks\":\"<impact/next>\","
    "\"score\":<1-100>}],\"summary\":\"<2-3 line attack thesis for this target>\"}. 6-12 items, highest "
    "score first. Ground every rationale in a node/bridge/hub from the digest — no generic advice.")
user = "Knowledge-graph digest:\n" + json.dumps(digest)[:7000]

reply = None
for mdl in ("claude-haiku-5-5", "claude-sonnet-5-5"):
    try:
        reply, err = A.lc().call_llm(system, user, model=mdl, provider="anthropic", max_tokens=2200, timeout=90)
    except Exception as e:
        reply, err = None, str(e)
    if reply:
        break
if not reply:
    A.emit({"ok": False, "error": "planner LLM unavailable: " + str(err or "")[:150]})

# parse — robust to ```json fences and truncated output
plan, summary = [], ""
txt = reply.strip()
txt = re.sub(r"^```(?:json)?\s*", "", txt); txt = re.sub(r"\s*```$", "", txt)
try:
    pj = json.loads(txt)
    plan = pj.get("plan", []) if isinstance(pj.get("plan"), list) else []
    summary = pj.get("summary", "")
except Exception:
    # salvage: pull each {...} object out of the plan array individually (handles truncation)
    sm = re.search(r'"summary"\s*:\s*"([^"]{0,400})"', txt)
    summary = sm.group(1) if sm else ""
    for obj in re.findall(r"\{[^{}]*\}", txt):
        try:
            it = json.loads(obj)
            if it.get("action") or it.get("cls"):
                plan.append(it)
        except Exception:
            continue

# ── blend deterministic graph priority: boost items whose node is a god-node or bridge ──
god_labels = {g["label"].lower() for g in gods}
bridge_nodes = {str(s.get("target", "")).lower() for s in surprises} | {str(s.get("source", "")).lower() for s in surprises}
for it in plan:
    try:
        n = str(it.get("node", "")).lower()
        boost = 0
        if any(gl and gl in n for gl in god_labels):
            boost += 15
        if any(bn and bn in n for bn in bridge_nodes):
            boost += 10
        if it.get("action") == "chain":
            boost += 8
        it["score"] = min(100, int(it.get("score", 50)) + boost)
        it["graph_boost"] = boost
    except Exception:
        pass
plan = sorted(plan, key=lambda x: -int(x.get("score", 0)))
for i, it in enumerate(plan):
    it["rank"] = i + 1

# persist next to the hunt so the UI / engine can consume it
try:
    (RUN.with_name("plan.json")).write_text(json.dumps({"plan": plan, "summary": summary,
                                                        "built": int(__import__("time").time())}))
except Exception:
    pass

A.emit({"ok": True, "plan": plan, "summary": summary,
        "graph": {"god_nodes": len(gods), "bridges": len(surprises), "clusters": len(labels)}})
