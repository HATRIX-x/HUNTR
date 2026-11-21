#!/usr/bin/env python3
"""
biz-logic-map — LLM reads the discovered surface and produces a structured application model.

Top-tier hunters don't fire probes randomly. They first understand the application's domain:
what entities exist, what roles are defined, which flows have multiple steps, and where value
(money/credits/quota) is transferred. This tool produces that model from the discovered surface
so the engine can attack business logic directly instead of every endpoint uniformly.

Output keys:
  entities         — core domain objects found in the surface (User, Workspace, Order, ...)
  roles            — privilege levels inferred from endpoints/JS (anonymous, free, paid, admin)
  flows            — multi-step flows worth attacking (checkout, invite-flow, password-reset, ...)
  value_endpoints  — URLs where money/credits/quota move (primary race condition targets)
  admin_endpoints  — URLs that appear to be admin/staff-only (primary BFLA targets)
  trust_boundaries — what the app appears to trust implicitly (user-supplied IDs, JWT claims, ...)
  attack_hints     — ordered list of specific attack suggestions for this target

Usage:
  biz-logic-map.py --endpoints-json '[...]' --flows-json '[...]' --program acme.com --json
Exit: 0.
"""
import sys, os, re, json
from pathlib import Path

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

PROGRAM      = arg("--program", "")
EP_JSON      = arg("--endpoints-json", "[]")
FLOWS_JSON   = arg("--flows-json", "[]")
HUNT_DIR     = Path(os.environ.get("HUNT_DIR", "."))

try:
    endpoints = json.loads(EP_JSON or "[]")
except Exception:
    endpoints = []
try:
    spa_flows = json.loads(FLOWS_JSON or "[]")
except Exception:
    spa_flows = []

def out(d):
    print(json.dumps(d, default=str))
    sys.exit(0)

if not endpoints:
    out({"error": "no endpoints", "entities": [], "roles": [], "flows": [], "value_endpoints": [],
         "admin_endpoints": [], "trust_boundaries": [], "attack_hints": []})

# ── Deterministic pre-analysis (no LLM tokens) ───────────────────────────────────────────────
# These are fast O(N) pattern matches that are always run, regardless of LLM availability.

VALUE_RE   = re.compile(r"(redeem|coupon|voucher|order|checkout|cart|transfer|claim|withdraw|balance|credit|gift|refund|payout|purchase|payment|pay|charge|subscribe|subscription|upgrade|downgrade|renew|limit|quota|consume|unlock|activate|deactivate|bulk|batch|exchange|convert|merge|split|allocat|assign|grant|revoke)", re.I)
ADMIN_RE   = re.compile(r"(/admin|/internal|/debug|/actuator|/manage|/staff|/superuser|/sudo|/root|/system|/privileged)", re.I)
ENTITY_RE  = re.compile(r"/(?:api/|v\d+/)?(users?|accounts?|orgs?|workspaces?|projects?|teams?|orders?|invoices?|payments?|subscriptions?|customers?|members?|roles?|permissions?|groups?|tenants?|orgs?|repos?|files?|documents?|resources?|tickets?|tasks?|jobs?)", re.I)
FLOW_RE    = re.compile(r"(reset|forgot|confirm|verify|invite|signup|register|checkout|onboard|activate|oauth|authorize|callback|magic|login|refresh|mfa|2fa|otp)", re.I)
ID_RE      = re.compile(r"[?&](id|uid|user_id|account_id|order_id|org_id|resource_id|object_id|owner_id|member_id|tenant_id|customer_id|workspace_id)=", re.I)
TRUST_RE   = re.compile(r"[?&](user|account|role|admin|is_admin|permission|tenant|org|group|team)=", re.I)
WEBHOOK_RE = re.compile(r"(/webhook|/hooks?|/callback|/notify|/event|/subscribe|/push)", re.I)

value_eps, admin_eps, entities_found, flows_found, trust_signals = [], [], set(), set(), []
webhook_eps = []

for ep in endpoints:
    low = ep.lower()
    if VALUE_RE.search(low):
        value_eps.append(ep)
    if ADMIN_RE.search(low):
        admin_eps.append(ep)
    m = ENTITY_RE.search(ep)
    if m:
        entities_found.add(m.group(1).rstrip("s").capitalize())   # normalise plural→singular
    m2 = FLOW_RE.search(low)
    if m2:
        flows_found.add(m2.group(1).lower())
    if ID_RE.search(low):
        trust_signals.append(("user-supplied ID in query param", ep))
    if TRUST_RE.search(low):
        trust_signals.append(("privilege param in URL (mass assignment risk)", ep))
    if WEBHOOK_RE.search(low):
        webhook_eps.append(ep)

# ── Build the structural result WITHOUT LLM ───────────────────────────────────────────────────
result = {
    "entities": sorted(entities_found),
    "roles": ["anonymous", "user"],   # extended by LLM below
    "flows": sorted(flows_found),
    "value_endpoints": list(dict.fromkeys(value_eps))[:50],
    "admin_endpoints": list(dict.fromkeys(admin_eps))[:50],
    "webhook_endpoints": list(dict.fromkeys(webhook_eps))[:20],
    "trust_boundaries": [{"signal": s, "example_url": u} for s, u in trust_signals[:20]],
    "attack_hints": [],
}

# Quick structural attack hints (deterministic, no LLM)
hints = []
if value_eps:
    hints.append({"priority": 1, "class": "race", "why": f"{len(value_eps)} value-flow endpoint(s) found — concurrent requests may double-deduct or duplicate credits", "endpoints": value_eps[:5]})
if admin_eps:
    hints.append({"priority": 1, "class": "authz/BFLA", "why": f"{len(admin_eps)} admin/privileged endpoint(s) — test with a regular-user token", "endpoints": admin_eps[:5]})
if webhook_eps:
    hints.append({"priority": 2, "class": "IDOR+SSRF", "why": f"{len(webhook_eps)} webhook endpoint(s) — can you register to receive another user's events? Is the target URL fetched server-side (SSRF)?", "endpoints": webhook_eps[:5]})
if trust_signals:
    hints.append({"priority": 2, "class": "mass-assignment", "why": f"{len(trust_signals)} privilege/role param(s) in URLs — attempt mass assignment via API body", "endpoints": [u for _, u in trust_signals[:5]]})
gql_eps = [e for e in endpoints if "/graphql" in e.lower() or "/gql" in e.lower()]
if gql_eps:
    hints.append({"priority": 2, "class": "graphql", "why": "GraphQL endpoint found — test batch alias confusion + introspection for hidden fields", "endpoints": gql_eps[:3]})

result["attack_hints"] = hints

# ── LLM enrichment (optional — skipped if no LLM env) ────────────────────────────────────────
MODEL = os.environ.get("HUNT_MODEL_CHEAP") or os.environ.get("HUNT_MODEL_MID") or "claude-haiku-5-5"
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()

if ANTHROPIC_KEY and len(endpoints) >= 5:
    try:
        import anthropic
        _client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        ep_list = "\n".join(endpoints[:60])
        flow_list = "\n".join(str(f) for f in (spa_flows or [])[:20])
        structural_summary = json.dumps({
            "entities_found": sorted(entities_found),
            "flows_found": sorted(flows_found),
            "value_endpoints_count": len(value_eps),
            "admin_endpoints_count": len(admin_eps),
        })
        prompt = f"""You are a bug bounty hunter analyzing the attack surface of {PROGRAM}.

The pre-analysis already found these structural signals (you do NOT need to re-list them):
{structural_summary}

Discovered endpoints (first 60):
{ep_list}

SPA flow data (XHR/fetch calls captured from the live app):
{flow_list or "(none)"}

Your job: extend the structural model with:
1. roles — list ALL privilege levels you can infer (e.g. anonymous, free, paid, admin, super-admin, service-account). Just names, ordered low→high.
2. flows — multi-step flows with 2+ steps worth attacking. For each: name, steps (array), attack_idea, and the step most likely to be breakable.
3. trust_boundaries — what the app appears to trust WITHOUT verifying (user-controlled IDs, JWT claims the server doesn't re-check, tenant isolation that depends on a URL parameter, etc.).
4. attack_hints — up to 6 specific, actionable attack ideas ranked by likely bounty (priority 1=highest). Each: priority, class (race/idor/authz/mass-assignment/etc.), why (why THIS target is likely vulnerable), endpoints (1-3 relevant URLs from the list above).

Respond ONLY with a valid JSON object with keys: roles (array of strings), flows (array), trust_boundaries (array of strings), attack_hints (array).
Do NOT include markdown, commentary, or wrapper text. JSON only."""

        resp = _client.messages.create(
            model=MODEL,
            max_tokens=1200,
            messages=[{"role": "user", "content": prompt}]
        )
        llm_text = (resp.content[0].text or "").strip()
        if llm_text.startswith("{"):
            llm_data = json.loads(llm_text)
            result["roles"] = llm_data.get("roles") or result["roles"]
            # merge LLM flows with deterministic ones
            llm_flows = llm_data.get("flows") or []
            result["flows"] = llm_flows or sorted(flows_found)
            # merge trust boundaries
            llm_trust = llm_data.get("trust_boundaries") or []
            result["trust_boundaries"] = (result["trust_boundaries"] or []) + [{"signal": t, "example_url": ""} for t in llm_trust if isinstance(t, str)]
            # merge attack hints (LLM hints override structural ones if present)
            if llm_data.get("attack_hints"):
                result["attack_hints"] = llm_data["attack_hints"] + [h for h in hints if h["class"] not in {str(x.get("class")) for x in llm_data["attack_hints"]}]
    except Exception as _e:
        result["llm_error"] = str(_e)[:120]

out(result)
