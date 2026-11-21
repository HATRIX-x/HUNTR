#!/usr/bin/env python3
"""
agent-browser.py — AI-led BROWSER-NATIVE exploitation agent (closes XBOW's one clear lead).

Drives a real logged-in Chrome over CDP to test and PROVE client-side bugs that curl can never
reach: DOM XSS, prototype pollution, client-side open redirect, postMessage/XS-leaks, SPA auth-flow
logic. The AI reasons about the sink; deterministic browser oracles ratify the proof (a payload that
actually EXECUTES in the DOM, a prototype that actually gets polluted).

Needs a Chrome with --remote-debugging-port=9222 open on the target (ideally the operator's logged-in
profile). Without it, it reports nobrowser honestly instead of guessing.

stdin : {"finding":{cls,endpoint,title,detail,param?}, "port"?}
stdout: {"ok":true,"proven":true|false|null,"method","evidence","reply","tool_calls"}
"""
import sys, os, json, subprocess, re
from pathlib import Path
import agent_core as A

HERE = Path(__file__).resolve().parent
d = A.read_stdin_json()
f = d.get("finding") or {}
if not f:
    A.emit({"ok": False, "error": "no finding"})
PORT = str(d.get("port", "9222"))
ep = f.get("endpoint", "")
cls = f.get("cls", "")
param = f.get("param", "")


def _cdp(args, timeout=50):
    try:
        r = subprocess.run([sys.executable, str(HERE / "exec-cdp.py")] + args,
                           capture_output=True, text=True, timeout=timeout, env=os.environ)
        return (r.stdout or r.stderr or "").strip()
    except Exception as e:
        return json.dumps({"error": str(e)[:120]})


def browser_eval(inp):
    url = inp.get("url") or ep
    js = inp.get("js") or "document.title"
    return _cdp(["--url", url, "--eval", js, "--port", PORT])


def domxss_proof(inp):
    url = inp.get("url") or ep
    a = ["--url", url, "--prove-domxss", "--port", PORT]
    if inp.get("param") or param:
        a += ["--param", inp.get("param") or param]
    return _cdp(a)


def client_pp_proof(inp):
    url = inp.get("url") or ep
    return _cdp(["--url", url, "--prove-client-pp", "--port", PORT])


def client_redirect_proof(inp):
    url = inp.get("url") or ep
    a = ["--url", url, "--prove-client-redirect", "--port", PORT]
    if inp.get("param") or param:
        a += ["--param", inp.get("param") or param]
    return _cdp(a)


TOOLS = [
    {"name": "browser_eval", "description": ("Navigate the real Chrome to a URL and run JavaScript in that "
        "page (Runtime.evaluate), returning the value. Use it to read the DOM, check window/location, set up "
        "and detect prototype pollution (Object.prototype.X), inspect postMessage handlers, or confirm a "
        "client-side redirect. Scope-gated."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "js": {"type": "string"}}, "required": ["js"]}},
    {"name": "domxss_proof", "description": ("Deterministic DOM-XSS oracle: injects a marker payload and "
        "confirms it EXECUTED in the page (a unique global is set), across the named param, a generic param, "
        "and the fragment. Returns {proven:true|false|null}."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}}}},
    {"name": "client_pp_proof", "description": ("Deterministic client-side prototype-pollution oracle: feeds "
        "__proto__/constructor.prototype gadgets through the query AND hash, then confirms Object.prototype "
        "was actually poisoned on a fresh object. Returns {proven:true|false|null}."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}}},
    {"name": "client_redirect_proof", "description": ("Deterministic client-side open-redirect oracle: feeds "
        "a canonical off-domain marker URL through the named param, generic redirect params, and the fragment, "
        "then confirms location.hostname actually navigated off-domain CLIENT-SIDE (a script, not a server "
        "302 — that's the server-side oracle's job). Returns {proven:true|false|null}."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "param": {"type": "string"}}}},
]
handlers = {"browser_eval": browser_eval, "domxss_proof": domxss_proof,
            "client_pp_proof": client_pp_proof, "client_redirect_proof": client_redirect_proof}

system = (
    "You are HUNTR's browser-native exploitation agent. You drive a real Chrome (CDP) to prove CLIENT-SIDE "
    "bugs that server-side tools miss. Reason about the sink, then PROVE with the browser tools and read the "
    "real result.\n"
    "PROOF bar (concrete, from a tool result only):\n"
    "  • DOM XSS: call domxss_proof — proven only if the marker global actually got set (executed), not reflected.\n"
    "  • Prototype pollution: call client_pp_proof — proven only if Object.prototype was actually poisoned on a "
    "fresh object, not merely echoed.\n"
    "  • Client-side open redirect: call client_redirect_proof — proven only if location.hostname actually left "
    "the app's origin client-side, not just reflected.\n"
    "  • postMessage / anything else novel: use browser_eval to register a listener probe and check if sensitive "
    "data is sent to an arbitrary origin — this is the one case with no deterministic oracle yet, so narrate "
    "exactly what you observed.\n"
    "Always try the matching deterministic oracle FIRST — it's cheaper and more trustworthy than hand-rolled "
    "browser_eval. Only fall back to browser_eval for cases the oracles don't cover.\n"
    "If Chrome isn't reachable (nobrowser), say so and return proven=null — never fake a browser result.\n"
    "END with one line of STRICT JSON: PROOF={\"proven\": true|false|null, \"method\":\"<how>\", \"evidence\":\"<the "
    "concrete browser signal>\"}"
    + A.skill_for((cls + " " + f.get("title", "")), budget=1500)
)
user = "Prove this client-side finding in the browser:\n" + json.dumps(
    {"cls": cls, "endpoint": ep, "title": f.get("title", ""), "param": param, "detail": (f.get("detail") or "")[:500]})

reply, tlog, err = A.run_agent(system, user, TOOLS, handlers, max_rounds=8, max_tokens=1400, timeout=70)
if not reply:
    A.emit({"ok": False, "error": "browser agent unavailable: " + str(err or "")[:150], "tool_calls": tlog})

proven, method, evidence = None, "browser-agent", ""
m = re.search(r"PROOF\s*=\s*(\{.*\})", reply, re.S)
if m:
    try:
        pj = json.loads(m.group(1))
        pv = pj.get("proven")
        proven = True if pv is True else (False if pv is False else None)
        method = str(pj.get("method") or "browser-agent")[:80]
        evidence = str(pj.get("evidence") or "")[:400]
    except Exception:
        pass

# deterministic gate: if the agent claims a class with a matching oracle proven, ratify with that
# oracle directly — the agent's narration never overrides a mechanical check it could have run itself.
_RATIFY = (("xss", "DOM XSS", domxss_proof), ("prototype", "prototype pollution", client_pp_proof),
           ("redirect", "client-side redirect", client_redirect_proof))
if proven is True:
    for kw, label, fn in _RATIFY:
        if kw in cls.lower():
            try:
                od = json.loads(fn({"url": ep, "param": param}).splitlines()[-1])
                if od.get("proven") is False:
                    proven = False; method = "oracle-disputed"
                    evidence = f"agent claimed {label} but the oracle did not confirm it executed"
                elif od.get("nobrowser"):
                    proven = None; evidence = "no browser available to ratify"
            except Exception:
                pass
            break

A.emit({"ok": True, "proven": proven, "method": method, "evidence": evidence,
        "reply": reply.strip(), "tool_calls": tlog})
