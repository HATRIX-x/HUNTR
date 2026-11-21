#!/usr/bin/env python3
"""
agent-recon.py — on-demand attack-surface expansion.

Fetches pages and JS bundles with http_request, mines them for new endpoints, API routes,
parameters and leaked secrets, and reports the new surface. Confirmed client-side secrets are
recorded as info findings. Optionally seeds subdomain-enum for breadth.

stdin : {"focus":"<url or hint, optional>", "brute_subdomains":bool}
stdout: {"ok":true,"summary":"...","added":[idx...],"tool_calls":[...]}
"""
import agent_core as A

d = A.read_stdin_json()
run = A.read_run()
target = run.get("target", "")
focus = (d.get("focus") or "").strip()

# optional breadth: subdomain enumeration seed (fast, deterministic)
sub_note = ""
if d.get("brute_subdomains") and target:
    dom = A.re.sub(r"^https?://", "", str(target)).split("/")[0].lstrip("*.")
    out = A.run_engine_tool("subdomain-enum.py", ["--domain", dom, "--json"], timeout=90)
    sub_note = "\n\nsubdomain-enum output (digest):\n" + out[:1200]

known = run.get("endpoints") or []
seed = focus or (known[0].get("url") if known and isinstance(known[0], dict) else target)

added = []
def note_secret(inp):
    f = {"title": inp.get("title", "Secret exposed in client code"), "sev": (inp.get("sev") or "l")[:1],
         "endpoint": inp.get("location", ""), "cls": "Info/Source-leak", "verdict": "likely",
         "detail": inp.get("evidence", "")[:1000], "_det": True, "source": "recon-agent"}
    i = A.append_finding(f); added.append(i)
    return "recorded as finding #" + str(i)

tools = [
    A.http_tool_def(A.has_identity("session")),
    {"name": "note_secret", "description": "Record a sensitive secret genuinely leaked in client-side code "
     "(private API key, token, internal URL, credential). NOT public keys (reCAPTCHA site key, analytics "
     "project tokens, Sentry public DSN) — those are by-design public, skip them.",
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"}, "location": {"type": "string"},
         "sev": {"type": "string", "enum": ["c", "h", "m", "l"]},
         "evidence": {"type": "string"}}, "required": ["title", "location", "evidence"]}},
]
handlers = {"http_request": A.http_handler, "note_secret": note_secret}

system = (
    "You are a recon-expansion agent. Pull pages and JavaScript bundles with http_request and mine them for "
    "NEW attack surface: undocumented API routes, admin/internal endpoints, hidden parameters, GraphQL "
    "operations, and leaked secrets. METHOD: fetch the seed page, find .js bundle URLs in the HTML, fetch "
    "those, and extract fetch()/axios/XHR URLs, route tables, and secret-looking strings. Only record a "
    "secret (note_secret) if it is genuinely sensitive — skip public/publishable keys. Stay in scope. End "
    "with a concise bullet list of the NEW endpoints/params/routes you found that are worth active testing."
    + A.skill_for(by_name="hunt-js-analysis", budget=2200) + A.skill_for(by_name="hunt-shadow-api", budget=1400))
user = ("Expand recon on target " + str(target) + ". Seed: " + str(seed)
        + (("\nFocus hint: " + focus) if focus else "") + sub_note)

reply, tlog, err = A.run_agent(system, user, tools, handlers, max_rounds=12, max_tokens=1800, timeout=70)
if not reply:
    A.emit({"ok": False, "error": "recon agent unavailable: " + str(err or "")[:150], "added": added, "tool_calls": tlog})
A.emit({"ok": True, "summary": reply.strip(), "added": added, "tool_calls": tlog})
