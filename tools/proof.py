#!/usr/bin/env python3
"""
proof.py — AI-led EXPLOITATION-PROOF agent (HUNTR's quality moat, XBOW-grade).

This is NOT a regex dispatcher. It is an LLM agent (Claude Pro OAuth) that is handed a finding
and has to PROVE it the way a human researcher would: reason about the class, run REAL
scope-guarded requests, call the deterministic class-probers for a hard signal, read the actual
responses, and conclude. It is held to one bar — proven=true ONLY when a tool result shows
concrete reproduction (server-side math product, payload executed unescaped, off-domain 3xx
Location, cross-identity data leak, file marker). "Looks plausible" is never proof.

The determinism lives in the TOOLS (verify-finding / exec-http evidence); the intelligence —
which payload, which parameter, how to adapt, when it's really proven — is the agent's.

stdin : {"finding":{cls,endpoint,title,detail,param?}, "session_token"?, "session_cookie"?}
stdout: {"ok":true,"proven":true|false|null,"method":"...","evidence":"...","reply":"...","tool_calls":[...]}
"""
import sys, json, subprocess, re
from pathlib import Path
import agent_core as A

HERE = Path(__file__).resolve().parent

d = A.read_stdin_json()
f = d.get("finding") or {}
if not f:
    A.emit({"ok": False, "error": "no finding"})
if d.get("session_cookie"):
    A.set_identity("session", cookie=d["session_cookie"])
elif d.get("session_token"):
    A.set_identity("session", authorization=d["session_token"])
has_sess = A.has_identity("session")

cls = f.get("cls", "")
ep = f.get("endpoint", "")
param = f.get("param", "")

# ── plugin oracles first (open ecosystem): a user-dropped prover can prove classes the core doesn't ──
try:
    pp = A.plugin_prove(f)
    if isinstance(pp, dict) and pp.get("proven") in (True, False):
        A.emit({"ok": True, "proven": pp.get("proven"), "method": "plugin:" + str(pp.get("method", "")),
                "evidence": pp.get("evidence", ""), "reply": "", "tool_calls": []})
except Exception:
    pass

# ── client-side classes route to the browser-native exploit agent (real Chrome via CDP) ──
_CLIENT_SIDE = ("dom xss", "dom-xss", "domxss", "prototype pollution", "prototype-pollution",
                "client-side", "client side", "postmessage", "post-message", "clickjack")
_cl = cls.lower()
if any(k in _cl for k in _CLIENT_SIDE):
    # FIRST try the deterministic CDP oracle (real Chrome) for classes that have a --prove mode —
    # a hard observed signal beats the LLM browser agent. Only on no-signal do we fall through.
    _prove_flag = None
    if "proto" in _cl and "pollution" in _cl:
        _prove_flag = "--prove-proto-pollution"
    elif "dom" in _cl and "xss" in _cl:
        _prove_flag = "--prove-domxss"
    if _prove_flag and ep.startswith("http"):
        try:
            cdp = subprocess.run([sys.executable, str(HERE / "exec-cdp.py"), "--url", ep, _prove_flag]
                                 + (["--param", param] if param else []),
                                 capture_output=True, text=True, timeout=90, env=A.os.environ)
            cd = json.loads((cdp.stdout or "").strip().splitlines()[-1])
            if cd.get("proven") is True:
                A.emit({"ok": True, "proven": True, "method": "cdp:" + _prove_flag.lstrip("-"),
                        "evidence": cd.get("evidence", ""), "reply": "", "tool_calls": []})
        except Exception:
            pass  # no debugged Chrome / no signal → fall through to the agent
    try:
        br = subprocess.run([sys.executable, str(HERE / "agent-browser.py")],
                            input=json.dumps({"finding": f}), capture_output=True, text=True, timeout=180, env=A.os.environ)
        bd = json.loads((br.stdout or "").strip().splitlines()[-1])
        if bd.get("ok"):
            A.emit({"ok": True, "proven": bd.get("proven"), "method": bd.get("method", "browser"),
                    "evidence": bd.get("evidence", ""), "reply": bd.get("reply", ""), "tool_calls": bd.get("tool_calls", [])})
    except Exception:
        pass  # fall through to the generic agent if the browser agent is unavailable

# ── tools the proof agent can drive ──
def class_prober(inp):
    """Deterministic per-class signal via verify-finding.py — the hard oracle the agent leans on."""
    url = inp.get("url") or ep
    pk = (inp.get("cls") or cls or "").lower()
    key = None
    # ORDER MATTERS: specific keys before their superstrings ("sql"⊂"nosql", "ssti"⊂"blind ssti").
    for lab, k in (("nosql", "nosqli"), ("prototype pollution", "prototype-pollution"),
                   ("prototype-pollution", "prototype-pollution"), ("web cache deception", "web-cache-deception"),
                   ("web-cache-deception", "web-cache-deception"), ("mass assignment", "mass-assignment"),
                   ("mass-assignment", "mass-assignment"), ("deserial", "deserialization"),
                   ("websocket", "websocket"), ("cswsh", "websocket"), ("request smuggl", "request-smuggling"),
                   ("saml", "saml"), ("xsw", "saml"), ("dns rebind", "dns-rebinding"),
                   ("file upload", "file-upload"), ("file-upload", "file-upload"), ("zip slip", "file-upload"),
                   ("ldap", "ldap"), ("xpath", "xpath"), ("csp", "csp"), ("oauth", "oauth"), ("oidc", "oauth"),
                   ("blind ssti", "blind-ssti"), ("ssti-rce", "ssti-rce"),
                   ("open redirect", "redirect"), ("response splitting", "crlf"),
                   ("host header", "host-header"), ("host-header", "host-header"),
                   ("cache poison", "cache-poison"), ("cache-poison", "cache-poison"),
                   ("command injection", "cmdi"), ("command-injection", "cmdi"), ("cmdi", "cmdi"),
                   ("remote code", "rce"), ("source-leak", "secret"), ("source leak", "secret"),
                   ("access control", "authz"), ("auth bypass", "authz"),
                   ("sql injection", "sqli"), ("sqli", "sqli"), ("sql", "sqli"), ("ssti", "ssti"), ("xss", "xss"),
                   ("cors", "cors"), ("lfi", "lfi"), ("traversal", "lfi"), ("ssrf", "ssrf"),
                   ("idor", "idor"), ("bola", "idor"), ("authz", "authz"), ("jwt", "jwt"),
                   ("graphql", "graphql"), ("gql", "graphql"),
                   ("secret", "secret"), ("credential", "secret"), ("info-leak", "secret"),
                   ("crlf", "crlf"), ("redirect", "redirect"),
                   ("clickjack", "clickjack"), ("csrf", "csrf"), ("xsrf", "csrf"),
                   ("rce", "rce"), ("xxe", "xxe")):
        if lab in pk:
            key = k; break
    if not key or not str(url).startswith("http"):
        return "no deterministic prober for this class/url — prove it manually with http_request"
    args = ["--url", url, "--cls", key, "--json"]
    if inp.get("param") or param:
        args += ["--param", inp.get("param") or param]
    if f.get("detail"):
        args += ["--detail", str(f["detail"])[:500]]
    try:
        r = subprocess.run([sys.executable, str(HERE / "verify-finding.py")] + args,
                           capture_output=True, text=True, timeout=45, env=A.os.environ)
        return (r.stdout or r.stderr or "(no output)")[:1500]
    except Exception as e:
        return "prober error: " + str(e)[:140]

TOOLS = [
    A.http_tool_def(has_sess),
    {"name": "class_prober", "description": ("Run the deterministic class oracle (SSTI math / XSS exec / SQLi "
        "boolean-error / open-redirect 3xx / CORS ACAO+creds / LFI marker). Returns {verified:true|false|null, "
        "method, evidence}. verified:true is HARD PROOF. Use it to get a concrete signal, then confirm with "
        "http_request if you need to see the raw response."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "cls": {"type": "string"}, "param": {"type": "string"}}}},
]
handlers = {"http_request": A.http_handler, "class_prober": class_prober}

system = (
    "You are HUNTR's exploitation-proof agent — an expert who PROVES a vulnerability is real by "
    "reproducing it, exactly like XBOW's validators but AI-driven. You get ONE finding. Your job: "
    "demonstrate it with real tools and report a verdict.\n"
    "METHOD: reason about the class, call class_prober for a deterministic signal, and/or craft your own "
    "http_request payloads and READ the real response. Adapt (try the right param, encodings, methods).\n"
    "THE BAR for proven=true — a concrete reproduced signal in a REAL tool result ONLY:\n"
    "  • SSTI: the unique math product appears server-rendered and the literal payload does not\n"
    "  • XSS: the payload lands unescaped in an executable context (raw <script>/event handler)\n"
    "  • SQLi: boolean-true vs boolean-false (or error) response divergence\n"
    "  • Open redirect: a 3xx whose Location points to the EXTERNAL attacker domain (200 / internal rewrite = NOT proven)\n"
    "  • CORS: Access-Control-Allow-Origin reflects the attacker origin AND Allow-Credentials: true\n"
    "  • LFI: a known file marker (e.g. root:x:) in the body\n"
    "  • IDOR/authz: another identity/anon receives data it must not (needs a session)\n"
    "If you cannot reproduce it, proven=false (say why). If the class can't be proven with the access you "
    "have (needs a 2nd account, OAST, etc.), proven=null and say exactly what's missing. NEVER claim proof "
    "you did not observe in a tool result.\n"
    "DOCTRINE — a 403/404/405/500 is a DOOR, not a wall: a blocked/hidden/erroring response means the thing "
    "behind it is worth protecting. Before giving up, try to walk through it (header spoof, path trick, method "
    "swap, encoding, sibling route) — a 500 on your input is an injection SIGNAL, not a dead end.\n"
    + ("An operator session is loaded (use_session:true) for authed proofs.\n" if has_sess else "")
    + "END your reply with a single line of STRICT JSON and nothing after it:\n"
    "PROOF={\"proven\": true|false|null, \"method\": \"<how>\", \"evidence\": \"<the concrete signal you observed>\"}"
    + A.skill_for((cls + " " + f.get("title", "")), budget=2000)
)
user = "Prove this finding:\n" + A.json.dumps({"cls": cls, "endpoint": ep, "title": f.get("title", ""),
        "param": param, "detail": (f.get("detail") or "")[:600]})

reply, tlog, err = A.run_agent(system, user, TOOLS, handlers, max_rounds=10, max_tokens=1500, timeout=70)
if not reply:
    A.emit({"ok": False, "error": "proof agent unavailable: " + str(err or "")[:150], "tool_calls": tlog})

# parse the PROOF={...} verdict the agent emits
proven, method, evidence = None, "agent", ""
m = re.search(r"PROOF\s*=\s*(\{.*\})", reply, re.S)
if m:
    try:
        pj = json.loads(m.group(1))
        pv = pj.get("proven")
        proven = True if pv is True else (False if pv is False else None)
        method = str(pj.get("method") or "agent")[:80]
        evidence = str(pj.get("evidence") or "")[:400]
    except Exception:
        pass

# ── DETERMINISTIC GATE (the XBOW lesson): the agent hunts, but a proven=true claim must be
# ratified by the hard oracle. For any class with a deterministic prover, the oracle is
# authoritative — the agent cannot call it proven if the oracle disagrees.
gated = False
if proven is True:
    oracle = class_prober({"url": ep, "cls": cls, "param": param})
    try:
        od = json.loads(oracle.strip().splitlines()[-1])
        ov = od.get("verified")
        if ov is False:
            proven = False; method = "oracle-disputed:" + str(od.get("method", ""))
            evidence = "agent claimed proof but the deterministic oracle disproved it: " + str(od.get("evidence", ""))[:300]
            gated = True
        elif ov is True:
            method = "oracle+agent:" + str(od.get("method", ""))
            evidence = (str(od.get("evidence", "")) + " · " + evidence)[:400]
            gated = True
        # ov is None → no deterministic prover for this class; agent's grounded claim stands (soft proof)
    except Exception:
        pass

A.emit({"ok": True, "proven": proven, "method": method, "evidence": evidence,
        "oracle_gated": gated, "reply": reply.strip(), "tool_calls": tlog})
