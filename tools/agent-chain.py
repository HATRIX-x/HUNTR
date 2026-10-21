#!/usr/bin/env python3
"""
agent-chain.py — chains findings into higher-impact exploits.

Reads ALL findings, reasons about how they combine (e.g. open-redirect + OAuth code → ATO;
exposed key + API → data access), and TESTS promising chains with real requests. Writes
proven/plausible chains into run.json["chains"] and returns them.

stdin : {"session_cookie":"...optional..."}
stdout: {"ok":true,"chains":[...],"summary":"...","tool_calls":[...]}
"""
import agent_core as A

d = A.read_stdin_json()
if d.get("session_cookie"):
    A.set_identity("session", cookie=d["session_cookie"])
has_sess = A.has_identity("session")

run = A.read_run()
fs = run.get("findings", [])
if len(fs) < 2:
    A.emit({"ok": False, "error": "need at least 2 findings to chain"})


def _cluster_key(f):
    return (str(f.get("cls", "")).lower(), (f.get("detail") or "").strip())


# Group findings that share IDENTICAL (cls, detail) — i.e. the same root cause hit at
# many different paths (a load-balancer / gateway-level control is the classic case).
# Without this, 25 instances of one bug look to the model like 25 independent app-level
# findings, and it invents a separate, untested business-logic narrative for each one
# (this is exactly what produced the /forgot, /oauth/token, /verify "chains" — none of
# those paths were ever actually requested before the narrative was written).
_clusters = {}
for _i, _f in enumerate(fs):
    _clusters.setdefault(_cluster_key(_f), []).append(_i)
idx_to_cluster = {i: tuple(idxs) for idxs in _clusters.values() for i in idxs}

digest = []
for key, idxs in _clusters.items():
    rep = idxs[0]
    f = fs[rep]
    row = {"i": rep, "title": f.get("title"), "cls": f.get("cls"), "sev": f.get("sev"),
           "verdict": f.get("verdict"), "endpoint": f.get("endpoint"),
           "detail": (f.get("detail") or "")[:250]}
    if len(idxs) > 1:
        row["cluster_size"] = len(idxs)
        row["other_endpoints_same_cause"] = [fs[j].get("endpoint") for j in idxs[1:8]]
    digest.append(row)

tested_urls = []
def _http_handler_logged(inp):
    tested_urls.append(inp.get("url", ""))
    return A.http_handler(inp)

chains = []
def record_chain(inp):
    finding_idxs = inp.get("findings", []) or []
    # Collapse multiple indices from the SAME cluster to one — citing 3 members of a
    # 25-way duplicate as if they were 3 separate chain steps is the same inflation bug
    # at the recording layer, not just the reasoning layer.
    seen_clusters, deduped = set(), []
    for fi in finding_idxs:
        ck = idx_to_cluster.get(fi, (fi,))
        if ck not in seen_clusters:
            seen_clusters.add(ck)
            deduped.append(fi)

    cited_endpoints = [str(fs[fi].get("endpoint") or "").lower() for fi in deduped if 0 <= fi < len(fs)]
    directly_tested = any(
        ep and any(ep in u.lower() for u in tested_urls) for ep in cited_endpoints
    )
    status = inp.get("status", "plausible")
    steps = inp.get("steps", "")
    if status == "proven" and not directly_tested:
        # The model claimed "proven" without ever issuing an http_request at the cited
        # endpoint(s) — downgrade rather than trust the label at face value.
        status = "plausible"
    if not directly_tested:
        steps = "[UNTESTED — no http_request was made to the cited endpoint(s) this session; " \
                "this narrative assumes unverified application behavior] " + str(steps)

    c = {"title": inp.get("title", "chain"), "impact": inp.get("impact", ""),
         "steps": steps, "findings": deduped, "status": status,
         "endpoint_tested": directly_tested}
    chains.append(c)
    return "recorded chain" + ("" if directly_tested else " (marked UNTESTED — no matching http_request seen)")

tools = [
    A.http_tool_def(has_sess),
    {"name": "record_chain", "description": "Record a multi-step chain across findings that raises impact. "
     "status=proven is only honored if you actually called http_request against the cited finding's "
     "endpoint(s) in this session — otherwise it is downgraded to plausible and marked untested.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"}, "impact": {"type": "string"},
         "steps": {"type": "string", "description": "numbered chain steps"},
         "findings": {"type": "array", "items": {"type": "integer"}, "description": "finding indices involved"},
         "status": {"type": "string", "enum": ["proven", "plausible"]}},
         "required": ["title", "impact", "steps"]}},
]
handlers = {"http_request": _http_handler_logged, "record_chain": record_chain}

system = (
    "You are an exploit-chaining agent. Given a set of findings on one target, find combinations that "
    "produce impact greater than any single finding (open-redirect + OAuth authorize → token theft/ATO; "
    "exposed key + its API → data access; CSRF + state-change → account takeover; info-leak feeding an "
    "IDOR, etc.).\n\n"
    "Some entries carry 'cluster_size' > 1 with 'other_endpoints_same_cause': that means many findings "
    "share byte-identical evidence/detail text across different paths — one root cause (commonly a "
    "load-balancer or gateway-level control, e.g. an auth proxy that intercepts EVERY path before app "
    "routing) reachable from many endpoints, not independent per-endpoint application bugs. Treat a "
    "clustered entry as ONE finding, never as separate chainable primitives per endpoint.\n\n"
    "CRITICAL — never assume application-specific business logic (a password-reset email is sent, an "
    "OAuth token is issued, an account is verified, ...) is reached by a given endpoint unless you "
    "actually call http_request against THAT exact endpoint and the response itself shows app-level "
    "content. A generic redirect to a login/auth wall (especially one identical to other endpoints' "
    "responses) is evidence the request did NOT reach application code — it proves nothing about what "
    "runs behind that wall, so do not build a narrative assuming it does. If you have not tested a "
    "specific endpoint named in your chain, say so plainly instead of writing as if you observed it. "
    "Call record_chain for each credible chain. status=proven is only honored if you probed the exact "
    "cited endpoint — otherwise it will be downgraded and marked untested automatically. Be honest — "
    "if no real chain exists, say so and record nothing. End with a 2-4 line summary."
    + A.skill_for(by_name="chain-builder", budget=2600))
user = "Findings on target " + str(run.get("target", "")) + ":\n" + A.json.dumps(digest)[:5000]

reply, tlog, err = A.run_agent(system, user, tools, handlers, max_rounds=12, max_tokens=1800, timeout=70)
if not reply:
    A.emit({"ok": False, "error": "chain agent unavailable: " + str(err or "")[:150], "chains": chains, "tool_calls": tlog})

if chains:
    rd = A.read_run(); rd["chains"] = (rd.get("chains") or []) + chains; A.write_run(rd)
A.emit({"ok": True, "chains": chains, "summary": reply.strip(), "tool_calls": tlog})
