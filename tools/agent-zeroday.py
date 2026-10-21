#!/usr/bin/env python3
"""
agent-zeroday.py — invent NOVEL, target-specific vulnerabilities after knowing everything (the
researcher capability that separates HUNTR from a signature scanner).

Scanners match known patterns. Elite hunters win on ASSUMPTIONS and CHAINS no playbook lists. Once
the surface is fully mapped, this agent ingests the complete intel (stack, versions, endpoints,
params, roles, JS, errors, findings, the knowledge-graph's god-nodes & bridges) and reasons like an
attacker modelling the developer's mind:
  "given THIS id scheme + THIS auth flow + THIS cache + THIS tenant model, what invariant did the
   dev silently assume, and what single request breaks it?"
It produces ranked, FALSIFIABLE zero-day hypotheses — each a concrete test and what proves it — then
(optionally) tests the top ones with live tools.

stdin : {"target":"...", "test_top": <n, default 0>, "session_cookie"?/"session_token"?}
stdout: {"ok":true,"hypotheses":[{bug,rationale,test,novelty,class}...],"tested":[...],"summary":"..."}
"""
import sys, os, json, subprocess, re
from pathlib import Path
import agent_core as A

HERE = Path(__file__).resolve().parent
d = A.read_stdin_json()
target = d.get("target", "")
TEST_TOP = int(d.get("test_top", 0) or 0)
if d.get("session_cookie"):
    A.set_identity("session", cookie=d["session_cookie"])
elif d.get("session_token"):
    A.set_identity("session", authorization=d["session_token"])
has_sess = A.has_identity("session")

run = A.read_run()
# pull the knowledge graph (god-nodes + bridges = structural intel)
kg = {}
try:
    r = subprocess.run([sys.executable, str(HERE / "hunt-graph.py"), "--run", str(A.RUN), "--json"],
                       capture_output=True, text=True, timeout=120, env=os.environ)
    kg = json.loads((r.stdout or "").strip().splitlines()[-1])
except Exception:
    kg = {}

intel = {
    "target": target,
    "hosts": [h.get("host") if isinstance(h, dict) else h for h in (run.get("hosts") or [])][:20],
    "endpoints": [e if isinstance(e, str) else e.get("url", "") for e in (run.get("endpoints") or [])][:60],
    "tech": run.get("tech") or run.get("fingerprint") or {},
    "params": sorted({k for e in (run.get("endpoints") or []) for k in
                      re.findall(r"[?&]([a-zA-Z0-9_]+)=", e if isinstance(e, str) else e.get("url", ""))})[:40],
    "findings": [{"cls": x.get("cls"), "sev": x.get("sev"), "verdict": x.get("verdict"), "endpoint": x.get("endpoint"),
                  "title": x.get("title")} for x in (run.get("findings") or []) if x.get("verdict") != "false_positive"][:25],
    "god_nodes": [{"label": g.get("label"), "type": g.get("type")} for g in (kg.get("gods") or [])[:10]],
    "bridges": [s.get("note") for s in (kg.get("surprises") or [])[:8]],
}

TOOLS = [A.http_tool_def(has_sess)] if TEST_TOP else []
handlers = {"http_request": A.http_handler} if TEST_TOP else {}

system = (
    "You are HUNTR's zero-day researcher — the mind that finds the bug nobody scripted. You are given the "
    "COMPLETE intel on one target. Do NOT list generic OWASP checks. Reason like an attacker modelling the "
    "developer's hidden assumptions and the SYSTEM's emergent behaviour:\n"
    "  • For each feature/endpoint, what invariant did the dev silently assume (ownership, server-set price, "
    "step order, trust of a header/claim/id), and what single request violates it?\n"
    "  • Use the knowledge-graph god-nodes (reused central logic — one flaw = broad blast radius) and bridges "
    "(a param/path spanning two trust zones — the seam where authz breaks).\n"
    "  • Chain primitives into something new (id scheme + cache key → cache poisoning cross-user; JWT kid + a "
    "known bucket → key confusion; redirect + OAuth → token theft; mass-assign + role field → privesc).\n"
    "  • Treat 403/404/500 as doors: a protected/hidden/erroring route is a LEAD, not a stop.\n"
    "Produce RANKED, FALSIFIABLE hypotheses — each with the exact test and what would prove it. Favour novelty "
    "and impact over coverage.\n"
    "Reply STRICT JSON only: {\"hypotheses\":[{\"bug\":\"<the novel vuln>\",\"class\":\"<class>\",\"rationale\":"
    "\"<the assumption/chain it breaks, grounded in the intel>\",\"test\":\"<exact request/steps>\",\"proves\":"
    "\"<the signal that confirms it>\",\"novelty\":<1-100>}],\"summary\":\"<2-line attack thesis>\"}. 6-10 items, "
    "most novel+impactful first.")
user = "COMPLETE target intel:\n" + json.dumps(intel)[:7000]

hypotheses, summary, tested = [], "", []
if TEST_TOP:
    reply, tlog, err = A.run_agent(system, user, TOOLS, handlers, max_rounds=10, max_tokens=2200, timeout=90)
else:
    reply = None
    for mdl in ("claude-haiku-4-5-20251001", "claude-sonnet-4-6"):
        try:
            reply, err = A.lc().call_llm(system, user, model=mdl, provider="anthropic", max_tokens=2200, timeout=90)
        except Exception as e:
            reply, err = None, str(e)
        if reply:
            break
    tlog = []
if not reply:
    A.emit({"ok": False, "error": "zero-day agent unavailable: " + str(err or "")[:150]})

txt = reply.strip()
txt = re.sub(r"^```(?:json)?\s*", "", txt); txt = re.sub(r"\s*```$", "", txt)
try:
    pj = json.loads(txt)
    hypotheses = pj.get("hypotheses", []) if isinstance(pj.get("hypotheses"), list) else []
    summary = pj.get("summary", "")
except Exception:
    sm = re.search(r'"summary"\s*:\s*"([^"]{0,300})"', txt)
    summary = sm.group(1) if sm else ""
    for obj in re.findall(r"\{[^{}]*\}", txt):
        try:
            it = json.loads(obj)
            if it.get("bug"):
                hypotheses.append(it)
        except Exception:
            continue
hypotheses = sorted(hypotheses, key=lambda x: -int(x.get("novelty", 0)))

# persist for the UI
try:
    (A.RUN.with_name("zeroday.json")).write_text(json.dumps({"hypotheses": hypotheses, "summary": summary,
                                                             "built": int(__import__("time").time())}))
except Exception:
    pass

A.emit({"ok": True, "hypotheses": hypotheses, "summary": summary, "tested": tested, "tool_calls": tlog})
