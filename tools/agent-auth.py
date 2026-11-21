#!/usr/bin/env python3
"""
agent-auth.py — AUTOMATIC authentication. Gets HUNTR a logged-in session with zero human setup, so
the whole authenticated attack surface (IDOR/BOLA/privesc — the high-bounty classes) opens up by
itself. XBOW needs creds handed in; HUNTR can register and log in on its own.

An AI agent finds the auth flow, then — depending on what's available — registers an account, logs in
with provided creds, or walks an OAuth/magic-link flow, using real HTTP (and the browser for JS-heavy
SPAs). It captures the live session (Set-Cookie / bearer token) from the REAL response and saves it as
a named identity (identities.json), ready for exec-http / the auth-test agent. It can mint N identities
for cross-identity IDOR testing.

stdin : {"target":"...", "login_url"?:"...", "creds"?:{"username","password"}, "signup":bool, "identity":"session"}
stdout: {"ok":true,"authenticated":bool,"identity":"session","evidence":"...","reply","tool_calls"}
"""
import sys, os, json, re
import agent_core as A

d = A.read_stdin_json()
target = d.get("target", "")
login_url = d.get("login_url", "")
creds = d.get("creds") or {}
signup = bool(d.get("signup"))
idname = d.get("identity", "session")

captured = {"authorization": "", "cookie": "", "headers": {}}


def save_identity(inp):
    """Persist a captured session as a named identity for the rest of the engine to use."""
    name = inp.get("name") or idname
    auth = inp.get("authorization", "")
    cookie = inp.get("cookie", "")
    if not (auth or cookie):
        return "nothing to save — provide authorization or cookie"
    A.set_identity(name, cookie=cookie or None, authorization=auth or None, headers=inp.get("headers"))
    captured["authorization"] = auth; captured["cookie"] = cookie
    return f"identity '{name}' saved (auth={'yes' if auth else 'no'}, cookie={'yes' if cookie else 'no'})"


TOOLS = [
    A.http_tool_def(False),
    {"name": "save_identity", "description": ("Persist a captured session as a named identity so the engine "
        "can send authenticated requests. Provide the cookie (full Cookie header value) and/or the bearer "
        "token you extracted from the login response's Set-Cookie header or JSON body."),
     "input_schema": {"type": "object", "properties": {
         "name": {"type": "string"}, "cookie": {"type": "string"}, "authorization": {"type": "string"},
         "headers": {"type": "object"}}}},
]
handlers = {"http_request": A.http_handler, "save_identity": save_identity}

creds_line = ""
if creds.get("username"):
    creds_line = f"\nProvided credentials: username={creds.get('username')} password={creds.get('password','')}"
mode = "register a NEW account then log in" if signup else (
    "log in with the provided credentials" if creds.get("username") else "find the auth flow and establish a session")

system = (
    "You are HUNTR's authentication agent. Your goal: obtain a LIVE logged-in session for the target and save "
    "it as an identity, autonomously.\n"
    "METHOD: " + mode + ".\n"
    "1. Find the login (and signup) endpoint — try the given login_url, /login, /signin, /auth, /api/login, "
    "/api/auth/login, the SPA's XHR auth route.\n"
    "2. Handle the real mechanics: fetch the login page/endpoint, extract any CSRF token / nonce, then submit "
    "credentials with http_request (correct method, content-type form vs JSON).\n"
    "3. CAPTURE the session from the REAL response: the Set-Cookie header (take the session cookie), or a bearer "
    "token in the JSON body. Then call save_identity with exactly those values.\n"
    "4. VERIFY: request an authenticated-only endpoint (e.g. /me, /account, /api/user) sending the saved identity "
    "(use_session or identity) and confirm it returns the user's data (not a 401/redirect).\n"
    "Only report authenticated=true when a protected endpoint actually returned authed content with the saved "
    "session. If registration/login isn't possible (no signup, captcha, MFA), say exactly what blocked it.\n"
    + creds_line +
    "\nEND with STRICT JSON: AUTH={\"authenticated\": true|false, \"identity\":\"" + idname + "\", \"evidence\":"
    "\"<the protected content that proves the session works, or what blocked it>\"}"
)
user = f"Authenticate to target: {target}" + (f" (login at {login_url})" if login_url else "")

reply, tlog, err = A.run_agent(system, user, TOOLS, handlers, max_rounds=12, max_tokens=1600, timeout=80)
if not reply:
    A.emit({"ok": False, "error": "auth agent unavailable: " + str(err or "")[:150], "tool_calls": tlog})

authed, evidence = False, ""
m = re.search(r"AUTH\s*=\s*(\{.*\})", reply, re.S)
if m:
    try:
        aj = json.loads(m.group(1))
        authed = bool(aj.get("authenticated"))
        evidence = str(aj.get("evidence") or "")[:400]
    except Exception:
        pass
A.emit({"ok": True, "authenticated": authed, "identity": idname,
        "has_cookie": bool(captured["cookie"]), "has_token": bool(captured["authorization"]),
        "evidence": evidence, "reply": reply.strip(), "tool_calls": tlog})
