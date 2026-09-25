#!/usr/bin/env python3
"""
adversarial-verify — try to KILL each finding before you trust it, then try to GROW its impact.

A finding you didn't attack is a finding you don't understand. This runs a class-specific
red-team pass on every candidate:
  1. FALSIFY   the standard ways this bug class is a false positive — each a concrete re-test.
  2. ESCALATE  the standard ways to raise its impact/severity — each a concrete next test.
  3. GATE      no captured request/response + control (negative) test + 2x reproduction ⇒ UNVERIFIED,
               whatever the class. No proof, no confirmation.

Two modes (mirrors the rest of the engine: the tool gates, the model executes the live tests):
  CHECKLIST (default)  print the falsification + escalation tests to run, and the evidence gaps.
  ADJUDICATE           re-run after testing, passing results → final verdict + suggested severity.

Verdicts: CONFIRMED · PLAUSIBLE (falsifiers still open) · UNVERIFIED (evidence missing) · REFUTED.

Usage:
  # checklist for a fresh finding
  adversarial-verify.py --class idor --endpoint /api/v1/orders/{id} --severity high
  # adjudicate after running the tests
  adversarial-verify.py --class idor --endpoint /api/v1/orders/{id} --severity high \
     --evidence ./.hunt/evidence/F1 --control --repro 2 \
     --passed victim-owned,unauth-only,empty-response --escalated write,cross-tenant
  # a falsifier that came back TRUE kills the finding:
  adversarial-verify.py --class ssrf --refuted no-egress
Exit: 0 CONFIRMED · 1 PLAUSIBLE/UNVERIFIED (more work) · 2 REFUTED.
"""
import sys, os, json
from pathlib import Path

SEV = ["info", "low", "medium", "high", "critical"]


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


def csv(n):
    v = arg(n)
    return [x.strip() for x in v.split(",")] if v else []


def norm(c):
    return (c or "").lower().strip().replace(" ", "").replace("-", "").replace("_", "")


def sev_max(*names):
    idx = max((SEV.index(s) for s in names if s in SEV), default=0)
    return SEV[idx]


# Per class: base severity, falsifiers (the FP traps), escalators (impact ladder → resulting sev).
# id = short slug you pass to --passed / --refuted / --escalated.
CLASSES = {
    "idor": {"base": "medium", "falsify": [
        ("victim-owned", "Is the target object actually the VICTIM's — not your own, public, or a shared demo record? Prove with two distinct accounts."),
        ("differential", "Did you test as a second AUTHENTICATED identity (B reads A's id), not just unauthenticated? Unauth ≠ IDOR."),
        ("empty-response", "Does the 200 actually return the victim's DATA, or an empty/uniform/placeholder body? Diff the response."),
        ("unguessable-id", "Is the id a random UUID/HMAC with no enumeration path? If so, impact is bounded — say how you obtain ids."),
        ("random-id-200", "Control: does a random NON-EXISTENT id also return 200? If yes, the 200 means nothing."),
    ], "escalate": [
        ("write", "Escalate read→WRITE: can B modify/delete A's object?", "high"),
        ("enumerate", "Sequential/low-entropy ids + no rate limit → bulk enumeration.", "high"),
        ("cross-tenant", "Object belongs to another TENANT/org, not just another user.", "high"),
        ("pii-bulk", "Enumeration yields PII at scale (emails, tokens, financial).", "critical"),
    ]},
    "authz": {"base": "medium", "falsify": [
        ("differential", "Prove the low-priv identity gets 200 where it must get 403 — with the control (admin 200, low-priv expected 403)."),
        ("client-only", "Is the restriction only a UI hide, with the API always open to everyone (still a bug, but frame it right)?"),
        ("action-effect", "Did the privileged ACTION actually take effect (state changed), or was it accepted then silently ignored?"),
    ], "escalate": [
        ("global-config", "Reaches GLOBAL settings (license, CA, scheduler) not id-scoped.", "high"),
        ("admin-action", "Performs a true admin action (create user, change role).", "high"),
        ("chain-data", "Chains to sensitive data / PII read or write.", "high"),
    ]},
    "bfla": {"base": "medium", "falsify": [
        ("reachable", "Confirm the admin/internal function is reachable by a NON-admin identity (not just anonymous 401)."),
        ("action-effect", "The function actually executed (verify the side effect), not just returned 200."),
    ], "escalate": [
        ("admin-action", "Full privileged action (user mgmt, config).", "high"),
        ("takeover", "Leads to account/tenant takeover.", "critical"),
    ]},
    "sqli": {"base": "high", "falsify": [
        ("error-only", "Is this a real injection or just a reflected DB error string with no control over the query?"),
        ("boolean-diff", "Prove with a TRUE/FALSE pair (1=1 vs 1=2) that changes the response — or a controlled time delay."),
        ("waf-echo", "Is the 'payload' just echoed by a WAF/error page, not executed?"),
    ], "escalate": [
        ("extract", "Extract real data (version, a table, a row).", "high"),
        ("authbypass", "Bypass auth / dump credentials.", "critical"),
        ("rce", "Stacked queries / file write / xp_cmdshell → RCE.", "critical"),
    ]},
    "ssrf": {"base": "medium", "falsify": [
        ("no-egress", "Did the SERVER actually make the request (OOB canary/Collaborator hit), or did it only parse the URL?"),
        ("blind-noimpact", "If blind and egress is firewalled (no internal reachability), impact is bounded — don't overclaim."),
        ("dns-only", "Is it only a DNS lookup with no TCP connect / response read?"),
    ], "escalate": [
        ("internal", "Reach an internal-only service/host.", "high"),
        ("metadata", "Hit cloud metadata (169.254.169.254) and read a response.", "critical"),
        ("creds", "Retrieve cloud credentials / secrets.", "critical"),
    ]},
    "xss": {"base": "medium", "falsify": [
        ("executes", "Does it actually EXECUTE (alert/DOM change), or is the input HTML-encoded/reflected inert?"),
        ("csp-block", "Is there a CSP that blocks execution? Show the bypass or downgrade the claim."),
        ("self-only", "Is it self-XSS (only in your own authenticated view, no cross-user vector)?"),
    ], "escalate": [
        ("stored", "Stored/persistent, fires for other users.", "high"),
        ("account-context", "Runs in a victim/admin session → data theft.", "high"),
        ("ato", "Steals session/token → account takeover.", "critical"),
    ]},
    "cors": {"base": "low", "falsify": [
        ("reflect-cred", "Confirm BOTH: origin is reflected AND Access-Control-Allow-Credentials:true."),
        ("sensitive-read", "Prove an ATTACKER page can read an AUTHENTICATED, sensitive response cross-origin — not just any response."),
        ("null-usable", "If it trusts Origin:null, show a realistic sandboxed-iframe delivery."),
    ], "escalate": [
        ("victim-data", "Cross-origin read of victim PII / token with credentials.", "medium"),
        ("ato", "Exfiltrated token/session replays into account takeover.", "high"),
    ]},
    "race": {"base": "medium", "falsify": [
        ("state-delta", "Did you get two real EFFECTS (double credit/redeem), not just two HTTP 200s? Verify the state delta."),
        ("idempotency", "Is there an idempotency key that silently deduped the second effect?"),
    ], "escalate": [
        ("value", "Repeatable value gain (double money / infinite coupon).", "high"),
        ("bypass-limit", "Bypasses a hard limit (seats, balance floor).", "high"),
    ]},
    "openredirect": {"base": "low", "falsify": [
        ("attacker-domain", "Redirects to a fully attacker-controlled domain (not same-site / allowlisted)."),
        ("real-sink", "It's a real 30x/JS redirect, not just a reflected parameter."),
    ], "escalate": [
        ("oauth-token", "Steals an OAuth code/token via redirect_uri.", "high"),
        ("chain-xss", "Chains to XSS via javascript:/data: sink.", "high"),
    ]},
    "authbypass": {"base": "high", "falsify": [
        ("protected-access", "Does the bypass actually reach a PROTECTED resource, or is it accepted then 403 on use?"),
        ("known-cve-applies", "If CVE-based (e.g. CVE-2025-29927), confirm the version/config is actually vulnerable."),
    ], "escalate": [
        ("admin", "Reaches admin functionality.", "critical"),
        ("data", "Reads/writes other users' data.", "high"),
    ]},
    "jwt": {"base": "high", "falsify": [
        ("accepted-and-used", "The forged/alg-none token is accepted AND authorizes a protected action (not just parsed)."),
        ("kid-real", "kid/jku/x5u manipulation actually changes the verified key."),
    ], "escalate": [
        ("impersonate", "Forge any user / admin.", "critical"),
    ]},
    "session": {"base": "medium", "falsify": [
        ("still-valid", "After disable/logout/pw-change, the OLD token still authorizes a request (e.g. /auth/keep-alive → 200)."),
        ("window-only", "Is it only a short grace window, or genuinely never revoked?"),
    ], "escalate": [
        ("persistent", "Access persists indefinitely after account is disabled.", "high"),
    ]},
    "logic": {"base": "medium", "falsify": [
        ("real-effect", "The abused flow produces a real, adverse business effect (value/state), not a cosmetic anomaly."),
        ("intended", "Confirm it isn't intended behavior / a documented feature."),
    ], "escalate": [
        ("value", "Monetary or trust-boundary impact.", "high"),
    ]},
}
GENERIC = {"base": "low", "falsify": [
    ("real-impact", "State the concrete security impact and who is harmed — not just anomalous behavior."),
    ("intended", "Rule out intended/by-design behavior."),
], "escalate": [("chain", "Chain into a higher-impact primitive (see capability-graph).", "medium")]}


def spec(cls):
    return CLASSES.get(cls, GENERIC)


def main():
    cls = norm(arg("--class"))
    if not cls:
        sys.exit("usage: adversarial-verify.py --class <c> [--endpoint ..] [--severity ..] "
                 "[--evidence PATH --control --repro N] [--passed a,b] [--refuted x] [--escalated y,z] [--json]")
    sp = spec(cls)
    ep = arg("--endpoint", "")
    claimed = norm(arg("--severity")) if arg("--severity") else sp["base"]
    ev_path = arg("--evidence")
    ev_exists = bool(ev_path and Path(ev_path).exists())
    control = flag("--control")
    try:
        repro = int(arg("--repro", "0") or 0)
    except ValueError:
        repro = 0
    passed = set(csv("--passed"))
    refuted = set(csv("--refuted"))
    escalated = set(csv("--escalated"))
    adjudicate = any(x in sys.argv for x in ("--passed", "--refuted", "--escalated", "--evidence", "--control", "--repro"))

    fals = sp["falsify"]
    open_fals = [f for f in fals if f[0] not in passed and f[0] not in refuted]
    esc = sp["escalate"]
    open_esc = [e for e in esc if e[0] not in escalated]

    # evidence gate
    gaps = []
    if not ev_exists:
        gaps.append("captured request/response (--evidence PATH)")
    if not control:
        gaps.append("a negative/control test (baseline without the bug) (--control)")
    if repro < 2:
        gaps.append(f"reproduce ≥2× (got {repro}) (--repro N)")
    ev_ok = not gaps

    # verdict
    if refuted:
        verdict = "REFUTED"
    elif not ev_ok:
        verdict = "UNVERIFIED"
    elif open_fals:
        verdict = "PLAUSIBLE"
    else:
        verdict = "CONFIRMED"

    # severity: for a CONFIRMED finding, ground it in class base + PROVEN escalators — ignore the
    # hunter's claim so an inflated claim (e.g. "high" CORS with no chain) is corrected DOWN.
    ach_sev = [e[2] for e in esc if e[0] in escalated]
    suggested = sev_max(sp["base"], *ach_sev) if verdict == "CONFIRMED" else sev_max(claimed, sp["base"])
    # confidence
    conf = 0.0
    if verdict == "CONFIRMED":
        conf = 1.0
    elif verdict == "PLAUSIBLE":
        conf = round((len(fals) - len(open_fals)) / len(fals) * (0.5 if ev_ok else 0.3), 2) if fals else 0.5
    elif verdict == "UNVERIFIED":
        conf = 0.15
    # REFUTED → 0

    if flag("--json"):
        print(json.dumps({"class": cls, "endpoint": ep, "verdict": verdict, "confidence": conf,
                          "claimed_severity": claimed, "suggested_severity": suggested,
                          "evidence_gaps": gaps, "open_falsifiers": [f[0] for f in open_fals],
                          "open_escalators": [e[0] for e in open_esc]}))
        sys.exit(0 if verdict == "CONFIRMED" else 2 if verdict == "REFUTED" else 1)

    icon = {"CONFIRMED": "✓", "PLAUSIBLE": "~", "UNVERIFIED": "◌", "REFUTED": "✗"}[verdict]
    print(f"[verify] {icon} {verdict}  ({conf:.2f})   hunt-{cls}  {ep}")
    if verdict == "CONFIRMED":
        d = SEV.index(suggested) - SEV.index(claimed)
        bump = "  ⬆ escalated by proven impact" if d > 0 else ("  ⬇ grounded — claim not supported by evidence" if d < 0 else "")
        print(f"         severity: claimed {claimed} → grounded {suggested}{bump}")
    else:
        print(f"         claimed severity: {claimed}")

    if verdict == "REFUTED":
        print(f"\n  ✗ A falsifier came back TRUE: {', '.join(refuted)} — drop this finding, don't report it.")
        sys.exit(2)

    if gaps:
        print("\n  EVIDENCE GATE — capture before this can be confirmed:")
        for g in gaps:
            print(f"    ◌ {g}")
    if open_fals:
        print("\n  FALSIFY — rule each out (then --passed <id>), or if one is TRUE, --refuted <id>:")
        for fid, q in open_fals:
            print(f"    ~ [{fid}] {q}")
    if open_esc:
        print("\n  ESCALATE — try to raise impact (then --escalated <id>):")
        for eid, q, s in open_esc:
            print(f"    ↑ [{eid}→{s}] {q}")
    if cls in ("idor", "authz", "bfla", "ssrf", "sqli", "openredirect"):
        print("\n  → also run capability-graph.py: this primitive may chain into a higher-severity path.")
    if verdict == "CONFIRMED":
        print("\n  ✓ Falsifiers ruled out + evidence complete. Safe to promote (dedup-check.py next).")
    else:
        print("\n  → not report-ready yet. Run the open tests above, then re-run --adjudicate with results.")
    sys.exit(0 if verdict == "CONFIRMED" else 1)


if __name__ == "__main__":
    main()
