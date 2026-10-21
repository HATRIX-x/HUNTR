#!/usr/bin/env python3
"""
hunt-agent.py — AGENTIC assistant for the HUNTR dashboard terminal.

Unlike a plain chatbot, this gives Claude REAL tools and runs a tool-use loop
(via llm_client.call_llm_with_tools, Claude Pro OAuth — never the API key):

  • http_request   — scope-guarded live HTTP through exec-http.py (test redirects,
                     CORS, reflected params, API-key validity — for real)
  • reverify_finding — re-run the AI judge on one finding (verify-one.py)

So when the operator says "test #3", Claude actually sends the request and answers
from the real response. It is told NEVER to claim an action it did not run.

stdin : {"context":{...}, "message":"...", "history":[...], "session_cookie":"..."}
stdout: {"ok":true,"reply":"...","tool_calls":[{"name","input","result"}...]}
"""
import sys, os, json, subprocess, importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
HUNT_DIR = Path(os.environ.get("HUNT_DIR", "./.hunt"))
RUN = HUNT_DIR / "run.json"
IDS = HUNT_DIR / "identities.json"


def out(d):
    print(json.dumps(d)); sys.exit(0)


try:
    data = json.loads(sys.stdin.read() or "{}")
except Exception:
    out({"ok": False, "error": "bad stdin json"})

msg = (data.get("message") or "").strip()
if not msg:
    out({"ok": False, "error": "empty message"})
ctx = data.get("context", {})
history = data.get("history", []) or []
session_cookie = (data.get("session_cookie") or "").strip()

# stash the operator's session cookie as identity "session" so http_request can use it
# WITHOUT the cookie ever being sent to the model
has_session = False
if session_cookie:
    try:
        ids = {}
        if IDS.exists():
            ids = json.loads(IDS.read_text())
        ids["session"] = {"cookieHeader": session_cookie}
        IDS.write_text(json.dumps(ids))
        has_session = True
    except Exception:
        has_session = False
elif IDS.exists():
    try:
        has_session = "session" in json.loads(IDS.read_text())
    except Exception:
        has_session = False

try:
    spec = importlib.util.spec_from_file_location("agent_core", str(HERE / "agent_core.py"))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
except Exception as e:
    out({"ok": False, "error": "agent_core import failed: " + str(e)[:140]})


# ── tools ──
TOOLS = [
    {
        "name": "http_request",
        "description": ("Make a REAL HTTP request through scope-guard against an in-scope host. "
                        "Returns the status line, response headers, and a body snippet. Use this to "
                        "actually TEST findings — follow redirects to read the Location header, check "
                        "CORS Access-Control-Allow-Origin, see if a param is reflected, probe whether an "
                        "exposed key/endpoint responds. Out-of-scope hosts are refused automatically."),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]},
                "url": {"type": "string", "description": "full in-scope URL"},
                "data": {"type": "string", "description": "optional request body"},
                "use_session": {"type": "boolean", "description": "attach the operator's saved session cookie (only if available)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "reverify_finding",
        "description": ("Re-run the AI judge on finding #index: re-reads its evidence and sets a fresh "
                        "verdict + reproduction steps + impact + remediation. Returns the new verdict."),
        "input_schema": {
            "type": "object",
            "properties": {"index": {"type": "integer"}},
            "required": ["index"],
        },
    },
]

def _http_request(inp):
    import re as _re
    method = (inp.get("method") or "GET").upper()
    url = inp.get("url") or ""
    if not url:
        return "error: no url"
    a = ["--url", url, "--method", method]
    if inp.get("data"):
        a += ["--data", str(inp["data"])]
    if inp.get("use_session") and has_session:
        a += ["--identity", "session"]
    try:
        r = subprocess.run([sys.executable, str(HERE / "exec-http.py")] + a,
                           capture_output=True, text=True, timeout=45, env=os.environ)
    except subprocess.TimeoutExpired:
        return "error: tool timed out"
    summary = (r.stdout or r.stderr or "").strip()
    # exec-http saves the full response (curl -i → headers+body) to evidence/eN/
    # — read it back so the model sees the REAL headers (Location, ACAO, Set-Cookie…)
    resp_text = ""
    m = _re.search(r"\(([^)]*evidence[^)]*)\)", summary)
    if m:
        rp = Path(m.group(1).strip()) / "response.txt"
        if rp.exists():
            full = rp.read_text(errors="ignore")
            parts = full.split("\n\n", 1)
            heads = parts[0]
            body = (parts[1] if len(parts) > 1 else "")[:1400]
            resp_text = heads[:2000] + ("\n\n[body]\n" + body if body.strip() else "")
    out_s = summary + ("\n\n" + resp_text if resp_text else "")
    return out_s[:4500] or "(no output)"


def _reverify_finding(inp):
    idx = inp.get("index")
    try:
        r = subprocess.run([sys.executable, str(HERE / "verify-one.py"),
                            "--run", str(RUN), "--fi", str(idx), "--json"],
                           capture_output=True, text=True, timeout=170, env=os.environ)
    except subprocess.TimeoutExpired:
        return "error: tool timed out"
    return (r.stdout or r.stderr or "(no output)")[:1800]


handlers = {"http_request": _http_request, "reverify_finding": _reverify_finding}


sys_p = (
    "You are HUNTR, an expert bug-bounty agent embedded in a live hunt dashboard's terminal. "
    "You have REAL tools and a live connection to the target. CRITICAL RULES:\n"
    "1. NEVER claim you ran a test, sent a request, or will 'report back later'. You either call a "
    "tool NOW and state its actual result, or you say you haven't tested it. No fake progress.\n"
    "2. Judge ONLY from hard evidence in the actual response. Be skeptical — most scanner hits are "
    "false positives. Prefer 'NOT confirmed' unless the response proves exploitation. Confirmation bar "
    "per class:\n"
    "   • Open redirect: CONFIRMED only by a 3xx status whose Location header points to the EXTERNAL "
    "attacker domain, or a body meta/JS redirect to it. A 200 response, an x-middleware-rewrite header, "
    "a canonical-link reflection, or the param merely echoed in the body is NOT a redirect → NOT confirmed.\n"
    "   • CORS: CONFIRMED only if Access-Control-Allow-Origin reflects the attacker origin AND "
    "Access-Control-Allow-Credentials: true. ACAO: * without creds is informational, not a bug.\n"
    "   • XSS/SSTI: CONFIRMED only if the payload executes/evaluates unescaped in the response (e.g. raw "
    "<script> or the math product), not if it is HTML-escaped or merely reflected as text.\n"
    "   • Exposed secret: CONFIRMED only if the key is live (a tool call using it succeeds) or it is a "
    "secret type that is sensitive by definition; public/publishable keys (reCAPTCHA site key, Mixpanel "
    "project token, Sentry public DSN, WalletConnect project id) are by-design public → informational.\n"
    "If the evidence is ambiguous, say what ADDITIONAL request would settle it and offer to run it. "
    "Never upgrade 'reflected' or 'rewritten' to 'confirmed'.\n"
    "3. DOORS NOT WALLS: treat every 403/404/405/500/WAF as a signal and an opening, never a stop. 403 = the "
    "resource exists and is worth protecting → bypass (headers, path tricks, method swap, encoding). 404 = the "
    "route is hidden → find the sibling/versioned/shadow route. 500 = your input broke logic → that's an "
    "injection/logic signal, dig in. After you understand the target, HYPOTHESISE target-specific bugs (the "
    "invariant the dev assumed + the one request that breaks it), don't just run known checks.\n"
    "4. Be concise and technical — terminal output, short lines, no markdown headers or filler.\n"
    "4. Reference findings by their #index. Only *.arc.io scope is reachable.\n"
    + ("5. An operator session cookie IS available — pass use_session:true to test authenticated behavior.\n"
       if has_session else "5. No operator session is loaded, so authenticated tests aren't possible yet; say so if asked.\n")
    + "\nHUNT STATE:\n" + json.dumps(ctx)[:7000]
)

lines = []
for h in history[-8:]:
    role = h.get("role", "")
    txt = (h.get("text") or "").strip()
    if txt:
        lines.append(("Operator: " if role == "user" else "HUNTR: ") + txt)
lines.append("Operator: " + msg)
user = "\n".join(lines)

# run_agent already tries native tool-use first (Haiku then Sonnet) and falls back to the
# propose/harness-executes JSON loop under CLI-subscription mode — same mechanism proven
# live for the other dashboard agents, so this chat agent gets the same real tool access
# whether there's an API key or not, instead of going straight to "agent unavailable".
reply, tool_log, err = A.run_agent(sys_p, user, TOOLS, handlers, max_rounds=6, max_tokens=1500, timeout=60)

if not reply:
    out({"ok": False, "error": "agent unavailable: " + str(err or "")[:150], "tool_calls": tool_log})

out({"ok": True, "reply": reply.strip(), "tool_calls": tool_log})
