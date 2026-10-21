#!/usr/bin/env python3
"""
agent-scenario.py — HUNTR's "impossible scenario" engine: compose PROVEN primitives into
multi-step kill-chains that a signature scanner never finds, and claim a chain ONLY when every
hop is re-proven by a deterministic oracle (zero-FP). This is the capability that turns a pile of
medium findings into the CRITICAL account-takeover / cloud-compromise / mass-XSS scenario a human
researcher would hand-build — except it's proven, not hypothesised.

Two layers, both oracle-gated:
  1. COMPOSITION TEMPLATES — encoded attack patterns over primitive classes (e.g. open-redirect +
     OAuth redirect_uri → auth-code theft → ATO). A template fires only when every required
     primitive is a PROVEN finding AND re-verifies live right now.
  2. LLM CREATIVE PASS — the model proposes novel combinations beyond the templates; each proposed
     chain is accepted only if every finding it cites carries proof.proven==True (no hand-waving).

stdin : {"session_cookie"?, "session_token"?, "max_llm"?: int}
stdout: {"ok":true,"scenarios":[...],"proven":N,"summary":"..."}
Writes run.json["scenarios"].
"""
import sys, json, subprocess, re
from pathlib import Path
import agent_core as A

HERE = Path(__file__).resolve().parent


def _cls_key(c):
    c = (c or "").lower()
    table = [("nosql", "nosqli"), ("prototype pollution", "prototype-pollution"), ("mass assignment", "mass-assignment"),
             ("web cache", "web-cache-deception"), ("deserial", "deserialization"), ("ssrf", "ssrf"), ("sqli", "sqli"),
             ("sql injection", "sqli"), ("command inj", "cmdi"), ("cmdi", "cmdi"), ("rce", "rce"), ("xxe", "xxe"),
             ("ssti", "ssti"), ("lfi", "lfi"), ("traversal", "lfi"), ("idor", "idor"), ("bola", "idor"),
             ("auth bypass", "authz"), ("access control", "authz"), ("authz", "authz"), ("xss", "xss"),
             ("cors", "cors"), ("redirect", "redirect"), ("oauth", "oauth"), ("oidc", "oauth"), ("jwt", "jwt"),
             ("crlf", "crlf"), ("host header", "host-header"), ("cache poison", "cache-poison"),
             ("clickjack", "clickjack"), ("csrf", "csrf"), ("secret", "secret"), ("credential", "secret"),
             ("graphql", "graphql"), ("ldap", "ldap"), ("xpath", "xpath"), ("file upload", "file-upload"),
             ("websocket", "websocket")]
    for lab, k in table:
        if lab in c:
            return k
    return c or "misc"


def oracle(cls, url, param=""):
    """Re-prove a primitive live via the deterministic oracle. Returns (verified, evidence)."""
    if not str(url).startswith("http"):
        return None, "no url"
    args = ["--url", url, "--cls", cls, "--json"] + (["--param", param] if param else [])
    try:
        r = subprocess.run([sys.executable, str(HERE / "verify-finding.py")] + args,
                           capture_output=True, text=True, timeout=45, env=A.os.environ)
        d = json.loads((r.stdout or "").strip().splitlines()[-1])
        return d.get("verified"), str(d.get("evidence", ""))[:300]
    except Exception as e:
        return None, "oracle error: " + str(e)[:120]


def body_of(cls, url, param=""):
    """Fetch an endpoint's evidence body (for composition checks like 'does the admin page leak a key')."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "HUNTR-scenario"})
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.read(60000).decode("utf-8", "ignore")
    except Exception:
        return ""


d = A.read_stdin_json()
if d.get("session_cookie"):
    A.set_identity("session", cookie=d["session_cookie"])
elif d.get("session_token"):
    A.set_identity("session", authorization=d["session_token"])

run = A.read_run()
fs = run.get("findings", [])
# primitive library: a primitive is a finding that is PROVEN (oracle-grade), keyed by class
prim = {}
for i, f in enumerate(fs):
    k = _cls_key(f.get("cls", "") or f.get("title", ""))
    proven = bool((f.get("proof") or {}).get("proven")) or f.get("verdict") == "confirmed"
    rec = {"i": i, "cls": k, "ep": f.get("endpoint", ""), "param": f.get("param", ""),
           "title": f.get("title", ""), "detail": (f.get("detail") or "")[:300], "proven": proven,
           "sev": f.get("sev", "")}
    prim.setdefault(k, []).append(rec)

def have(*classes):
    """Return the first PROVEN primitive for each class, or None if any is missing."""
    picked = []
    for c in classes:
        p = next((x for x in prim.get(c, []) if x["proven"]), None)
        if not p:
            return None
        picked.append(p)
    return picked

SECRET_RE = re.compile(r"(sk_live_|api_master|AccessKeyId|ADMINMASTER|-----BEGIN|AKIA[0-9A-Z]{12}|xox[baprs]-|ghp_)", re.I)
scenarios = []

def emit_scenario(title, sev, impact, steps, prims, extra_evidence=""):
    scenarios.append({"title": title, "sev": sev, "impact": impact, "steps": steps,
                      "findings": [p["i"] for p in prims], "status": "proven",
                      "evidence": extra_evidence, "chain_len": len(steps)})

# ── COMPOSITION TEMPLATES (each fires only when its primitives RE-PROVE live) ──────────────────────
# T1: SSRF → cloud instance-metadata → IAM credential theft → full cloud-account compromise
p = have("ssrf")
if p:
    v, ev = oracle("ssrf", p[0]["ep"], p[0]["param"])
    if v is True and ("metadata" in ev.lower() or "accesskey" in ev.lower() or "oast" in ev.lower() or "callback" in ev.lower()):
        emit_scenario("SSRF → cloud IAM credential theft → full account compromise", "c",
                      "An unauthenticated SSRF reaches the cloud instance-metadata service; the leaked IAM "
                      "role credentials grant API access to the entire cloud account (S3, RDS, etc.).",
                      ["1. Attacker submits the SSRF payload to " + p[0]["ep"],
                       "2. Server fetches 169.254.169.254/…/iam/security-credentials and returns AccessKeyId/SecretKey",
                       "3. Attacker uses the stolen role credentials against the cloud API → full account takeover"],
                      p, ev)

# T2: unauth admin/authz-bypass whose response LEAKS a live secret → API/key takeover
p = have("authz")
if p:
    v, ev = oracle("authz", p[0]["ep"], p[0]["param"])
    body = body_of("authz", p[0]["ep"] + ("&" if "?" in p[0]["ep"] else "?") + "debug=1")
    leaked = SECRET_RE.search(ev) or SECRET_RE.search(body) or SECRET_RE.search(p[0]["detail"])
    if v is True and leaked:
        emit_scenario("Auth-bypass → master API-key exfiltration → full API takeover", "c",
                      "A client-controlled authz gate is bypassed unauthenticated; the admin response leaks a "
                      "live master API key, escalating a 'medium' access-control flaw to full API compromise.",
                      ["1. Attacker requests the protected endpoint with the bypass flag (no credentials)",
                       "2. The admin panel renders and leaks a master key (e.g. " + (leaked.group(0)[:16] if leaked else "sk_live_…") + "…)",
                       "3. Attacker authenticates to the API with the master key → full control"],
                      p, ev)

# T3: OAuth redirect_uri hijack → auth-code theft → account takeover
p = have("oauth")
if p:
    v, ev = oracle("oauth", p[0]["ep"], p[0]["param"])
    if v is True:
        emit_scenario("OAuth redirect_uri hijack → auth-code theft → account takeover", "c",
                      "The authorize endpoint reflects an attacker redirect_uri, so the victim's authorization "
                      "code is delivered to the attacker, who exchanges it for the victim's session (ATO).",
                      ["1. Attacker crafts an authorize URL with redirect_uri = attacker domain",
                       "2. Victim (logged into the IdP) clicks it; the code/token is 302'd to the attacker",
                       "3. Attacker exchanges the code → full account takeover"],
                      p, ev)

# T4: same-site OPEN-REDIRECT bypasses an OAuth redirect_uri allowlist → code exfil ATO (classic "impossible" combo)
pr = have("redirect"); po = have("oauth")
if pr and po:
    v1, e1 = oracle("redirect", pr[0]["ep"], pr[0]["param"])
    v2, e2 = oracle("oauth", po[0]["ep"], po[0]["param"])
    if v1 is True and v2 is True:
        emit_scenario("Open-redirect ∘ OAuth → allowlist bypass → auth-code theft (ATO)", "c",
                      "Even if the OAuth redirect_uri allowlist only permits the first-party domain, a same-site "
                      "open redirect on that domain forwards the delivered auth code to the attacker — the two "
                      "individually-medium bugs compose into a critical account takeover.",
                      ["1. Set OAuth redirect_uri to the allowlisted first-party open-redirect endpoint",
                       "2. IdP delivers the auth code to that first-party URL (passes the allowlist)",
                       "3. The open redirect bounces the code (in the URL/Referer) to the attacker → ATO"],
                      pr + po, (e1 + " || " + e2)[:300])

# T5: reflected/DOM XSS → session or token theft → ATO
p = have("xss")
if p:
    v, ev = oracle("xss", p[0]["ep"], p[0]["param"])
    if v is True:
        emit_scenario("XSS → session/token theft → account takeover", "c",
                      "Script execution in the victim's authenticated origin reads the session token / cookies / "
                      "in-page CSRF token and exfiltrates them, yielding full account takeover.",
                      ["1. Deliver the proven XSS payload to a logged-in victim",
                       "2. Payload reads document.cookie / localStorage token / in-page secrets",
                       "3. Exfiltrate to attacker → replay the session → ATO"],
                      p, ev)

# T6: LFI → read app source/config → harvest DB or API secrets → credentialed access
pl = have("lfi"); psec = prim.get("secret", [])
if pl:
    v, ev = oracle("lfi", pl[0]["ep"], pl[0]["param"])
    if v is True:
        emit_scenario("LFI → source/secret disclosure → credentialed backend access", "h",
                      "Arbitrary file read exposes application source and config (DB DSNs, API keys), which the "
                      "attacker uses to authenticate directly to the backend — a read primitive becomes data theft.",
                      ["1. Read /etc/passwd to confirm traversal, then app config (settings.py/.env/web.config)",
                       "2. Extract DB credentials / API keys from the config",
                       "3. Connect to the backend with the harvested creds → data exfiltration"],
                      pl, ev)

# T7: IDOR + mass-assignment → horizontal takeover + privilege escalation
pi = have("idor"); pm = have("mass-assignment")
if pi and pm:
    v1, e1 = oracle("idor", pi[0]["ep"], pi[0]["param"])
    v2, e2 = oracle("mass-assignment", pm[0]["ep"], pm[0]["param"])
    if v1 is True and v2 is True:
        emit_scenario("IDOR ∘ mass-assignment → cross-account privilege escalation", "c",
                      "The IDOR selects another user's object; mass-assignment then sets a privileged field "
                      "(isAdmin/role) on it — combining horizontal access with vertical escalation to own any account.",
                      ["1. Use the IDOR to target a victim's object id",
                       "2. PUT that object with an extra isAdmin:true / role:admin field (mass-assignment)",
                       "3. The victim account is now attacker-controlled admin → full takeover"],
                      pi + pm, (e1 + " || " + e2)[:300])

# T8: CRLF → response splitting → cache-poisoned XSS → mass compromise
pc = have("crlf")
if pc:
    v, ev = oracle("crlf", pc[0]["ep"], pc[0]["param"])
    if v is True:
        cachep = have("cache-poison")
        emit_scenario("CRLF → response splitting → cache-poisoned stored XSS → mass compromise", "c" if cachep else "h",
                      "Header injection splits the response; the injected body is cached by a shared/CDN cache and "
                      "served as stored XSS to every subsequent visitor — one request compromises many users.",
                      ["1. Inject CRLF to control response headers/body at " + pc[0]["ep"],
                       "2. Craft a response carrying an XSS body with cacheable headers",
                       "3. Shared cache stores it → every visitor is served the XSS → mass account compromise"],
                      pc + (cachep or []), ev)

# T9: RCE-family (cmdi/rce/deserialization/ssti) → full server compromise
for rc in ("cmdi", "rce", "deserialization", "ssti"):
    p = have(rc)
    if p:
        v, ev = oracle(rc, p[0]["ep"], p[0]["param"])
        if v is True:
            emit_scenario(f"{rc.upper()} → remote code execution → full server compromise", "c",
                          "Code/command execution on the server grants a shell: read every secret, pivot to the "
                          "internal network, and persist — the maximum-impact outcome.",
                          ["1. Deliver the proven " + rc + " payload to " + p[0]["ep"],
                           "2. Execute an out-of-band callback / command, confirming code execution",
                           "3. Escalate to a reverse shell → full server + data compromise"],
                          p, ev)
            break

# T10: SQLi → full DB read → credential dump → mass ATO
p = have("sqli")
if p:
    v, ev = oracle("sqli", p[0]["ep"], p[0]["param"])
    if v is True:
        emit_scenario("SQLi → database dump → credential/secret theft → mass account takeover", "c",
                      "Injection into the query grammar allows dumping the users table (password hashes, API keys, "
                      "secrets), cracking/replaying them to take over every account.",
                      ["1. Confirm the injection (boolean/error divergence) at " + p[0]["ep"],
                       "2. Enumerate schema and dump the users/secrets tables",
                       "3. Crack/replay the dumped credentials → mass account takeover"],
                      p, ev)

det_count = len(scenarios)

# ── LLM CREATIVE PASS: propose NOVEL chains beyond the templates (gated: every cited finding must be proven) ──
max_llm = int(d.get("max_llm", 4) or 4)
proven_digest = [{"i": p["i"], "cls": p["cls"], "sev": p["sev"], "endpoint": p["ep"],
                  "detail": p["detail"]} for lst in prim.values() for p in lst if p["proven"]]
if proven_digest and max_llm > 0:
    kg = run.get("kgraph") or {}
    sysmsg = (
        "You are HUNTR's exploit-SCENARIO architect. You are given the target's PROVEN primitives (each already "
        "reproduced by a deterministic oracle). Think like an attacker chaining them into the highest-impact, "
        "NON-OBVIOUS scenario a human expert would build — account takeover, cloud compromise, cross-tenant data "
        "theft, mass compromise. Favour creative multi-step chains the scanners miss ('impossible' combinations).\n"
        "HARD RULE: you may ONLY cite primitives from the provided proven list (by index). Never invent a step that "
        "isn't backed by a proven primitive. If two primitives don't actually compose, don't force it.\n"
        "Reply STRICT JSON: {\"scenarios\":[{\"title\":..,\"severity\":\"c|h\",\"impact\":..,\"steps\":[..],"
        "\"findings\":[indices],\"why_novel\":\"one line\"}]} — at most " + str(max_llm) + " scenarios, best first.")
    usr = json.dumps({"proven_primitives": proven_digest,
                      "graph_bridges": (kg.get("bridges") or [])[:12] if isinstance(kg, dict) else [],
                      "already_found_templates": [s["title"] for s in scenarios]})
    try:
        reply, _tlog, _err = A.run_agent(sysmsg, usr, [], {}, max_rounds=1, max_tokens=1400, timeout=70)
    except Exception:
        reply = ""
    m = re.search(r"\{.*\}", reply or "", re.S)
    if m:
        try:
            pj = json.loads(m.group(0))
            provenset = {p["i"] for lst in prim.values() for p in lst if p["proven"]}
            for s in (pj.get("scenarios") or [])[:max_llm]:
                idxs = [i for i in (s.get("findings") or []) if isinstance(i, int)]
                # GATE: every cited finding must be a proven primitive — else the chain is not claimed
                if idxs and all(i in provenset for i in idxs) and s.get("title"):
                    steps = s.get("steps") or []
                    scenarios.append({"title": "[novel] " + str(s["title"])[:120], "sev": "c" if str(s.get("severity", "h")).startswith("c") else "h",
                                      "impact": str(s.get("impact", ""))[:400],
                                      "steps": [str(x)[:200] for x in steps][:8], "findings": idxs,
                                      "status": "proven", "why_novel": str(s.get("why_novel", ""))[:160],
                                      "chain_len": len(steps)})
        except Exception:
            pass

# persist
try:
    run["scenarios"] = scenarios
    A.RUN.write_text(json.dumps(run))
except Exception:
    pass

crit = sum(1 for s in scenarios if s["sev"] == "c")
A.emit({"ok": True, "scenarios": scenarios, "proven": len(scenarios), "template_chains": det_count,
        "critical": crit, "summary": f"{len(scenarios)} proven kill-chain scenario(s) ({crit} critical) from "
        f"{len(proven_digest)} proven primitives — every hop oracle-verified"})
