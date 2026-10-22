#!/usr/bin/env python3
"""
attack-planner — build a TARGET-SPECIFIC attack plan + multi-step flows, instead of a fixed class matrix.

The old engine applied one static endpoint x class matrix to every target. This reads what the hunt
actually discovered (stack fingerprint, the real endpoint/API inventory, auth model, scope types, the
program's own severity table) and produces a plan tuned to THIS target:
  • targets[]  — endpoint x class cells ranked by (endpoint sensitivity x class ROI x stack fit), each
                 with method + body-param hints + a one-line rationale, so the sweep tests what matters.
  • flows[]    — multi-step business-logic / auth kill-chains matched to the discovered endpoints
                 (IDOR-read-order, withdraw-address swap, reset-token reuse, fee/discount abuse, …),
                 the thing a flat per-endpoint scan can never find.

Deterministic core always runs (keyword-driven sensitivity + flow templates matched to real endpoints).
An optional LLM pass (llm_client, sensitive=True, personal/free tier) re-ranks and proposes NOVEL flows,
but may only reference endpoints that were actually discovered — so it cannot hallucinate surface.

Usage:
  attack-planner.py --run <hunt_dir>/run.json [--program "CoinTR"] [--no-llm] [--json]
Writes <hunt_dir>/plan.json and prints a summary (or the plan with --json).
"""
import json, sys, os, re
from pathlib import Path

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv

# ── endpoint sensitivity: what the path touches (money/auth/pii/admin » public) ──────────────────
SENS = [
    (re.compile(r"withdraw|transfer|payout|redeem|cashout|remit|payment|fiat|deposit|recharge", re.I), 10, "funds-movement"),
    (re.compile(r"order|trade|swap|lever|margin|position|strategy|launchpool|finance|assets?|capital|balance|wallet", re.I), 9, "trading/assets"),
    (re.compile(r"api[-/]?key|apikey|passphrase|secret|token|oauth|sign|credential", re.I), 9, "api-credential"),
    (re.compile(r"kyc|identity|realname|passport|id[-_]?card|bind|verify|2fa|google|mobile|email|otp|sms|pwd|password|reset|login|security", re.I), 8, "auth/identity"),
    (re.compile(r"admin|internal|backend|manage|operator|broker|agent|sub[-/]?account|sub/api", re.I), 8, "privileged"),
    (re.compile(r"user|profile|account|address|bill|record|history|detail|info\b|overview|personal", re.I), 6, "user-data"),
    (re.compile(r"upload|file|image|avatar|export|download|report", re.I), 5, "file/export"),
    (re.compile(r"public|config|common|list|market|kline|banner|index|home|quote|ticker|coin|symbol|lang", re.I), 2, "public-read"),
]

# class ROI base (higher = test first). Tuned for authed fintech/exchange surface.
CLASS_ROI = {
    "idor": 10, "authz": 9, "mass-assignment": 8, "race": 8, "business-logic": 8,
    "sqli": 7, "ssrf": 7, "auth-bypass": 7, "jwt": 6, "ssti": 6, "lfi": 6,
    "nosqli": 6, "cmdi": 7, "xxe": 6, "param": 5, "oauth": 6, "file-upload": 6,
    "open-redirect": 3, "xss": 4, "cors": 3, "crlf": 3, "host-header": 3,
    "websocket": 5, "graphql": 6, "deserialization": 7,
}

def classes_for(path, sens_tag, is_write):
    """Which vuln classes apply to this endpoint, given what it touches + method."""
    low = path.lower()
    cl = set()
    has_id = bool(re.search(r"(byid|byuid|byuserid|/\d{3,}|[?&](id|uid|userid|orderid|addressid|recordid|key|token)=|detail|info|query|get)", low))
    # object-reference endpoints → IDOR/BOLA + authz
    if has_id or sens_tag in ("user-data", "trading/assets", "api-credential", "funds-movement", "privileged"):
        cl.update(["idor", "authz"])
    # write/state-changing → mass-assignment, race, business-logic, auth-bypass
    if is_write:
        cl.update(["mass-assignment", "business-logic", "authz"])
        if sens_tag in ("funds-movement", "trading/assets"):
            cl.update(["race", "business-logic"])
    # injection on any param-bearing endpoint
    cl.update(["sqli", "param"])
    if re.search(r"url|uri|callback|webhook|redirect|fetch|load|img|image|file|host|proxy|dest|next|return", low):
        cl.update(["ssrf", "open-redirect"])
    if re.search(r"search|query|q=|keyword|filter|name|title|content|remark|nick", low):
        cl.update(["xss", "nosqli"])
    if re.search(r"template|render|preview|report|export|mail|email", low):
        cl.add("ssti")
    if re.search(r"file|path|download|load|read|dir|upload", low):
        cl.update(["lfi", "file-upload"])
    if re.search(r"/ws|websocket|/socket|/stream|/stomp|/hub|/cable", low):
        cl.add("websocket")
    if re.search(r"graphql|/gql", low):
        cl.add("graphql")
    if re.search(r"oauth|/sso|openid|third|/sign\b|authorize", low):
        cl.add("oauth")
    if re.search(r"cmd|exec|command|ping|shell|run\b", low):
        cl.add("cmdi")
    return cl

def sensitivity(path):
    for rx, score, tag in SENS:
        if rx.search(path):
            return score, tag
    return 1, "generic"

# ── multi-step FLOW templates: fire only when the needed endpoints were discovered ───────────────
# each: (name, severity, [path-substring triggers all required], impact, steps-template)
FLOW_TEMPLATES = [
    ("IDOR read of another user's order/record", "high",
     ["orderinfo"], "Resolve another account's order/PII by guessable orderId from an unrelated session",
     ["auth as A", "list A's orders to learn id format", "from A's session call *orderInfo* with B's orderId", "if B's order returns → BOLA"]),
    ("IDOR/BFLA on API-key management", "high",
     ["sub/api"], "Read/modify/delete another user's exchange API key (full account-trading access)",
     ["auth as A", "call sub/api/detail|modify|delete with B's key id", "if B's key returns/changes → critical BFLA"]),
    ("Withdrawal-address swap / withdraw IDOR", "critical",
     ["withdraw"], "Bind or read a withdrawal address against another account → funds redirect",
     ["auth as A", "call addWithdrawAddr/withdrawAddrList/checkWithdrawAddr targeting B's uid/addr id", "verify B's data or A-controlled address bound to B"]),
    ("Password/trade-pwd reset token reuse", "high",
     ["reset"], "Re-use or cross-apply a reset/verify token to take over or reset another account",
     ["request reset for A (capture token)", "replay same token", "try token against B's identifier", "if accepted twice / cross-user → ATO"]),
    ("Fee / discount / reward business-logic abuse", "high",
     ["fee"], "Zero/negative fee, double reward, or discount stacking at scale (BEMIX 4.8)",
     ["observe fee/reward params in trade/withdraw/welfare calls", "tamper rate/amount/coupon/rewardX64", "measure illegitimate profit at scale"]),
    ("Race on redeem/transfer/withdraw (double-spend)", "high",
     ["redeem"], "Concurrent requests double-process a single balance (TOCTOU)",
     ["pick a stateful money op (redeem/transfer/withdraw/coupon)", "fire N concurrent with one balance", "check for duplicate credit/overspend"]),
    ("Mass-assignment / overposting on write", "medium",
     ["modify"], "Inject privileged fields (uid, role, isAgent, status, amount) into a write body",
     ["take a write endpoint", "add privileged keys to the JSON body", "check if the echoed/stored object accepts them"]),
    ("SSRF via callback/webhook param", "high",
     ["callback"], "Server fetches an attacker URL from a callback/webhook/notify param → internal reach",
     ["find url/callback/webhook/notify param", "point at collaborator + internal (169.254.169.254)", "confirm echo or OOB"]),
]

def build_plan(run, program, use_llm=True):
    hosts = run.get("hosts", [])
    eps = run.get("endpoints", [])
    api_paths = run.get("api_paths", [])
    scope_types = run.get("scope_types", [])
    stack = (run.get("stack") or "") + " " + json.dumps(run.get("fingerprint", {}))[:400]
    # unify endpoint inventory: crawled URLs + harvested API paths
    inv = []
    seen = set()
    apex = (run.get("target") or "").lstrip("*.").split("/")[0]
    base = None
    for h in hosts:
        if h.get("host") and h.get("scheme"):
            base = h["scheme"] + "://" + h["host"]; break
    base = base or ("https://" + apex)
    for e in eps:
        u = e.get("url") if isinstance(e, dict) else e
        if u and u not in seen:
            seen.add(u); inv.append(u)
    for p in api_paths:
        u = base + p
        if u not in seen:
            seen.add(u); inv.append(u)

    # ── deterministic target ranking ──
    WRITE_HINT = re.compile(r"add|set|modify|update|create|delete|bind|withdraw|transfer|redeem|trade|swap|order|submit|apply|save|reset|change|unlock|enable|disable|open|close|cancel|buy|sell|insert|upload|join|draw", re.I)
    targets = []
    for u in inv:
        path = re.sub(r"^https?://[^/]+", "", u) or "/"
        score, tag = sensitivity(path)
        is_write = bool(WRITE_HINT.search(path))
        method = "POST" if is_write or "/v1/" in path or "/api/" in path else "GET"
        for cls in classes_for(path, tag, is_write):
            roi = CLASS_ROI.get(cls, 3)
            prio = score * roi
            targets.append({"endpoint": u, "path": path, "method": method, "cls": cls,
                            "sens": tag, "priority": prio,
                            "why": f"{tag} endpoint; {cls} ROI {roi}" + (" (write)" if is_write else "")})
    # keep the sharpest cells per endpoint (don't explode): top 4 classes each, then global sort
    by_ep = {}
    for t in targets:
        by_ep.setdefault(t["endpoint"], []).append(t)
    pruned = []
    for ep, ts in by_ep.items():
        ts.sort(key=lambda x: -x["priority"])
        pruned += ts[:4]
    pruned.sort(key=lambda x: -x["priority"])

    # ── deterministic flows: fire a template only if its trigger endpoints exist ──
    low_inv = " ".join(inv).lower()
    flows = []
    for name, sev, trigs, impact, steps in FLOW_TEMPLATES:
        if all(t in low_inv for t in trigs):
            hits = [u for u in inv if any(t in u.lower() for t in trigs)][:4]
            flows.append({"name": name, "severity": sev, "impact": impact,
                          "steps": steps, "endpoints": hits, "source": "template"})

    plan = {
        "target": run.get("target"), "program": program,
        "stack": stack.strip()[:200], "scope_types": scope_types,
        "endpoint_count": len(inv), "target_count": min(len(pruned), 2000),
        "targets": pruned[:2000], "flows": flows,
        "note": "deterministic plan; LLM pass " + ("ran" if use_llm else "skipped"),
    }

    # ── optional LLM enrichment: re-rank + NOVEL flows, grounded in real endpoints only ──
    if use_llm:
        try:
            plan = _llm_enrich(plan, inv, program)
        except Exception as e:
            plan["llm_error"] = str(e)[:160]
    return plan

def _llm_enrich(plan, inv, program):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import llm_client
    except Exception:
        plan["note"] += " (llm_client unavailable)"; return plan
    sample = inv[:220]
    sysmsg = ("You are a senior bug-bounty strategist for an authenticated web/API target. You are given the "
              "REAL discovered endpoint inventory and the program. Propose target-specific MULTI-STEP attack "
              "flows (business logic, IDOR/BOLA chains, auth/reset abuse, fee/reward abuse, race) that a flat "
              "per-endpoint scanner would miss. RULES: reference ONLY endpoints from the given list (never "
              "invent paths); each flow = {name, severity(critical|high|medium), impact, steps[3-6], "
              "endpoints[from list]}. Output STRICT JSON {\"flows\":[...]} only.")
    usr = (f"PROGRAM: {program}\nSEVERITY FOCUS: funds loss, account takeover, cross-user data (IDOR/BOLA), "
           f"business-logic (fee/yield/reward abuse), auth bypass.\nENDPOINTS ({len(sample)} of {len(inv)}):\n"
           + "\n".join(sample))
    model = os.environ.get("HUNT_MODEL_STRONG", "claude-opus-5-5")
    txt, err = llm_client.call_llm(sysmsg, usr, model=model, max_tokens=2000)
    if err and not txt:
        plan["note"] += " (llm err: " + str(err)[:60] + ")"; return plan
    m = re.search(r"\{.*\}", txt or "", re.S)
    if not m:
        plan["note"] += " (llm no-json)"; return plan
    try:
        data = json.loads(m.group(0))
    except Exception:
        plan["note"] += " (llm bad-json)"; return plan
    valid_paths = set(inv) | {re.sub(r"^https?://[^/]+", "", u) for u in inv}
    for fl in data.get("flows", []):
        eps = [e for e in (fl.get("endpoints") or []) if e in valid_paths or any(e in u for u in inv)]
        if not eps:   # drop any flow not grounded in the real inventory
            continue
        flows_add = {"name": str(fl.get("name", "flow"))[:120], "severity": fl.get("severity", "medium"),
                     "impact": str(fl.get("impact", ""))[:300], "steps": [str(s)[:200] for s in (fl.get("steps") or [])][:6],
                     "endpoints": eps[:6], "source": "llm"}
        plan["flows"].append(flows_add)
    plan["note"] += f" · LLM added {sum(1 for f in plan['flows'] if f.get('source')=='llm')} flow(s)"
    return plan

def main():
    rp = arg("--run")
    if not rp or not Path(rp).exists():
        print(json.dumps({"error": "need --run <run.json>"})); sys.exit(1)
    run = json.loads(Path(rp).read_text())
    program = arg("--program") or run.get("program") or run.get("target") or ""
    plan = build_plan(run, program, use_llm=not flag("--no-llm"))
    out = Path(rp).parent / "plan.json"
    out.write_text(json.dumps(plan, indent=2))
    if flag("--json"):
        print(json.dumps(plan))
    else:
        print(f"PLAN · {plan['target']} · {plan['endpoint_count']} endpoints → {plan['target_count']} ranked cells · {len(plan['flows'])} flows")
        print("  top targets:")
        for t in plan["targets"][:12]:
            print(f"    [{t['priority']:>3}] {t['cls']:<16} {t['method']:<4} {t['path'][:64]}  ({t['sens']})")
        print("  flows:")
        for f in plan["flows"][:12]:
            print(f"    [{f['severity']:<8}] {f['name']}  ({f.get('source')})  ← {len(f['endpoints'])} ep")
        print(f"  written → {out}")

if __name__ == "__main__":
    main()
