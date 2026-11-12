#!/usr/bin/env python3
"""
agent-authtest.py — authenticated access-control agent (IDOR / BOLA / broken authz).

Loads one or two operator identities and hunts the highest-bounty class: it requests the
SAME object/endpoint as different identities (and as anon) with http_request, diffs the real
responses, and flags a bug only when a low-priv/other/anon identity gets data it shouldn't.
Confirmed access bugs are written into run.json via add_finding.

stdin : {"session_cookie":"<idA>", "session2_cookie":"<idB,optional>", "endpoints":[...optional...]}
stdout: {"ok":true,"summary":"...","added":[idx...],"tool_calls":[...]}
"""
import agent_core as A

d = A.read_stdin_json()
if d.get("session_cookie"):
    A.set_identity("idA", cookie=d["session_cookie"])
elif d.get("session_token"):
    A.set_identity("idA", authorization=d["session_token"])
if d.get("session2_cookie"):
    A.set_identity("idB", cookie=d["session2_cookie"])
elif d.get("session2_token"):
    A.set_identity("idB", authorization=d["session2_token"])
has_a = A.has_identity("idA")
has_b = A.has_identity("idB")
if not has_a:
    A.emit({"ok": False, "error": "no session loaded — set one with /session first (authenticated testing needs a logged-in cookie)"})

run = A.read_run()
endpoints = d.get("endpoints") or []
# default candidate surface: object-ish authed endpoints from recon/findings
if not endpoints:
    seen = set()
    for f in run.get("findings", []):
        ep = f.get("endpoint")
        if ep and ep not in seen:
            seen.add(ep); endpoints.append(ep)
    for e in (run.get("endpoints") or [])[:40]:
        u = e.get("url") if isinstance(e, dict) else e
        if u and u not in seen and A.re.search(r"/(api|v\d|users?|orders?|accounts?|me|profile|\d{3,}|[0-9a-f-]{16,})", str(u)):
            seen.add(u); endpoints.append(u)
endpoints = endpoints[:25]

added = []
def add_finding(inp):
    sev = (inp.get("sev") or "h").lower()[:1]
    f = {"title": inp.get("title", "Broken access control"), "sev": sev if sev in "chmli" else "h",
         "endpoint": inp.get("endpoint", ""), "cls": "Authz/IDOR", "verdict": "likely",
         "detail": inp.get("evidence", "")[:1200], "impact_text": inp.get("impact", ""),
         "steps": inp.get("steps", ""), "_det": True, "source": "authtest-agent"}
    i = A.append_finding(f)
    added.append(i)
    return "recorded as finding #" + str(i)

tools = [
    A.http_tool_def(True),
    {"name": "add_finding", "description": "Record a CONFIRMED access-control bug (only when a request as a "
     "lower-priv/other/anon identity returned data or performed an action it must not). Needs concrete diff evidence.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"}, "endpoint": {"type": "string"},
         "sev": {"type": "string", "enum": ["c", "h", "m", "l"]},
         "evidence": {"type": "string", "description": "the diff: what idB/anon got vs idA, quoted"},
         "impact": {"type": "string"}, "steps": {"type": "string"}},
         "required": ["title", "endpoint", "evidence"]}},
]
handlers = {"http_request": A.http_handler, "add_finding": add_finding}

idlist = "idA" + (", idB" if has_b else "") + ", and no identity (anon)"
system = (
    "You are an access-control testing agent (IDOR / BOLA / broken authz) — the highest-value bug class. "
    "You have these identities loaded: " + idlist + ". METHOD:\n"
    "1. For each candidate endpoint (especially ones with an object id/uuid or /me|/users|/orders|/account), "
    "request it as idA, then re-request the SAME url as idB (if present) and as anon (no identity).\n"
    "2. Compare the REAL responses. A bug exists ONLY when a different/absent identity receives another user's "
    "data, or a mutating action succeeds cross-tenant — a 200 with idA's private data returned to idB/anon.\n"
    "3. Same 401/403/empty for idB/anon = correctly protected, NOT a bug. Do not flag those.\n"
    "4. When you confirm a real access bug, call add_finding with the quoted diff as evidence.\n"
    "Be rigorous — most endpoints are correctly scoped. Keep requests safe (GET first). "
    "When done, give a short summary: endpoints tested, bugs found (with #index), and anything needing a "
    "second identity you don't have."
    + A.skill_for(by_name="hunt-idor", budget=2600) + A.skill_for(by_name="hunt-auth-bypass", budget=1400))
user = ("Test these endpoints for access-control bugs:\n" + A.json.dumps(endpoints)[:3000]
        + "\nTarget: " + str(run.get("target", "")))

reply, tlog, err = A.run_agent(system, user, tools, handlers, max_rounds=14, max_tokens=1800, timeout=70)
if not reply:
    A.emit({"ok": False, "error": "authtest agent unavailable: " + str(err or "")[:150],
            "added": added, "tool_calls": tlog})
A.emit({"ok": True, "summary": reply.strip(), "added": added, "tool_calls": tlog})
