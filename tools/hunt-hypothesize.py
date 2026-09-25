#!/usr/bin/env python3
"""
hunt-hypothesize — think like a hunter before touching the target.

Between RECON and HUNT, turn observed signals (stack, tech versions, endpoints, params, roles,
JS/error strings) into RANKED, FALSIFIABLE hypotheses — "this signal ⇒ likely THIS bug, here's the
test" — instead of blindly running 60 matrices. Each hypothesis is ordered by signal specificity ×
your paid history (outcome-check EV), so the highest-probability, highest-value bugs get tested first.

A hypothesis is falsifiable: it names the class, why it's suspected, and the concrete test that
confirms or kills it. Testing it updates the coverage ledger like any other cell.

Signals JSON:  {"tech":[..], "endpoints":[..], "fields":[..], "roles":[..], "notes":".."}

Usage:
  hunt-hypothesize.py --signals ./.hunt/signals.json --stack saas [--emit ./.hunt/hypotheses.tsv] [--top 15]
  echo '{"tech":["next.js 13"],...}' | hunt-hypothesize.py --stack saas
Exit: 0 ok.
"""
import sys, os, json, importlib.util
from pathlib import Path

TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def _outcome_mod():
    p = TOOLS / "outcome-check.py"
    if not p.exists():
        return None
    spec = importlib.util.spec_from_file_location("outcome_check", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# Each rule: (needle_test(hay, sig) -> bool, cls, weight, why, test)
# weight = signal specificity (0..1); a targeted CVE/role signal beats a generic keyword.
def has(*subs):
    return lambda hay, sig: any(s in hay for s in subs)


ACCESS_MARKERS = ("{id}", "/id", "id=", "/admin", "internal", "manage", "export", "settings",
                  "account", "profile", "/orders", "/users", "/org", "tenant", "workspace",
                  "member", "download", "report", "config", "license", "invoice", "document")


def multi_role(hay, sig):
    """Two identities available AND something worth access-controlling in the signals.
    (Differential access is only a lead when there's an object/privileged function to reach —
    otherwise it drowns the endpoint-specific signal, e.g. SSRF on ?url=.)"""
    r = [x.lower() for x in sig.get("roles", [])]
    have_two = len(set(r)) >= 2 or any(k in hay for k in ("tenant-a", "tenant-b", "low-priv", "two account"))
    return have_two and any(m in hay for m in ACCESS_MARKERS)


RULES = [
    # differential access — strongest when a 2nd identity exists
    (multi_role, "authz", 0.95, "two privilege tiers available → access-control shows only as a differential",
     "replay each privileged/global request as the low-priv identity; expect 403, look for 200"),
    (multi_role, "idor", 0.9, "two identities + id-scoped objects → cross-account object access",
     "as identity B, request A's object ids; expect denial, look for A's data"),
    (has("/{id}", "/orders/", "/users/", "/account", "/profile", "/documents/", "object"), "idor", 0.7,
     "id-bearing objects → BOLA by id swap", "swap the id to another user's; expect 403/404, look for 200 + their data"),
    (has("/admin", "/internal", "/manage", "/console", "/backoffice"), "bfla", 0.8,
     "privileged function present → BFLA", "call the admin/internal endpoint directly as a normal user"),
    (has("global", "settings", "config", "license", "activationcode"), "authz", 0.75,
     "global (non-id-scoped) settings often forget the privilege check", "read/write global settings as low-priv; diff vs admin"),
    # value / money logic
    (has("amount", "price", "qty", "quantity", "balance", "total", "cost"), "logic", 0.7,
     "client-controlled value fields → value/price integrity", "send negative/zero/huge/overflow/decimal; expect rejection"),
    (has("coupon", "promo", "voucher", "redeem", "gift", "code", "once", "single-use"), "race", 0.85,
     "single-use / redeemable token → double-redeem race", "fire N parallel redeems (race-fire.py --expect-one)"),
    (has("/transfer", "/withdraw", "/pay", "/topup", "/wallet", "/refund"), "race", 0.8,
     "money-moving endpoint → double-spend", "parallel-replay the same debit; expect one, look for two"),
    (has("/transfer", "/withdraw", "/pay", "amount"), "logic", 0.6,
     "money-moving flow → business-logic / step-skip", "skip a required prior step (verify/capture) and reach the next"),
    # framework / CVE surface
    (has("next.js 13", "next.js 14", "middleware", "x-middleware"), "authbypass", 0.9,
     "Next.js middleware auth gate → CVE-2025-29927 bypass", "send x-middleware-subrequest header to reach gated routes"),
    (has("spring", "actuator"), "misc", 0.7,
     "Spring Boot actuator → info/heapdump/env disclosure", "GET /actuator/{env,heapdump,mappings}"),
    (has("graphql", "/graphql", "apollo"), "authz", 0.7,
     "GraphQL → introspection + per-field authz gaps", "introspect; call sensitive fields/mutations as low-priv"),
    (has("jwt", "bearer ", "authorization:", "eyj"), "jwt", 0.7,
     "JWT in use → alg/kid/signature flaws", "try alg:none, kid path traversal, weak-secret crack, jku/x5u swap"),
    (has("saml", "samlresponse"), "saml", 0.7, "SAML → signature-wrap / comment injection",
     "XSW variants, unsigned assertion, comment-truncation on NameID"),
    (has("token", "keep-alive", "session", "/logout", "disable", "revoke", "/auth"), "session", 0.65,
     "auth/token surface → session-lifecycle (token not revoked on disable/pw-change)",
     "disable/pw-change the account, then reuse the old token (e.g. POST /auth/keep-alive); expect 401"),
    (has("oauth", "/authorize", "redirect_uri", "sso"), "oauth", 0.7,
     "OAuth flow → redirect_uri / state / code issues", "open-redirect on redirect_uri, missing state, code reuse/leak"),
    # injection / ssrf / upload
    (has("url=", "uri=", "webhook", "callback", "/fetch", "/proxy", "image_url", "next="), "ssrf", 0.75,
     "server-side URL fetch → SSRF", "point at 169.254.169.254 / internal host / redirector; watch for fetch"),
    (has("upload", "/file", "attachment", "avatar", "import"), "fileupload", 0.65,
     "file upload → type/path/content bypass", "svg/html for stored-XSS, double-ext, path traversal, polyglot"),
    (has("search", "q=", "filter", "sort", "query="), "sqli", 0.6,
     "search/filter parameter → SQL/NoSQL injection", "boolean/time payloads; error-based; ORDER BY probes"),
    (has("search", "q=", "message", "comment", "name", "title"), "xss", 0.5,
     "reflected/stored text field → XSS", "context-aware payloads; check reflection sink & CSP"),
    (has("xml", "soap", "svg", "docx", "xlsx"), "xxe", 0.6, "XML parser → XXE",
     "external entity + OOB exfil; parameter entities if blind"),
]


def hypotheses(signals, stack=None, oc=None):
    parts = []
    for key in ("tech", "endpoints", "fields", "roles"):
        parts += [str(x) for x in signals.get(key, [])]
    parts.append(str(signals.get("notes", "")))
    hay = " ".join(parts).lower()

    agg = None
    if oc is not None:
        agg = oc.all_classes_with_priors(oc.score(oc.load(oc.GLOBAL), [stack] if stack else None))

    out, seen = [], set()
    for pred, cls, w, why, test in RULES:
        try:
            ok = pred(hay, signals)
        except Exception:
            ok = False
        if not ok:
            continue
        ev = agg.get(cls, {}).get("ev", 0.0) if agg else 0.0
        # signal specificity, boosted by paid history for that class
        s = w * (1 + ev / 1000.0)
        key = (cls, why)
        if key in seen:
            continue
        seen.add(key)
        out.append({"cls": cls, "why": why, "test": test, "weight": round(w, 2),
                    "prior_ev": round(ev, 0), "score": round(s, 3), "status": "open"})
    out.sort(key=lambda h: -h["score"])
    return out


def read_signals():
    s = arg("--signals")
    if s:
        return json.loads(Path(s).read_text())
    if not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            return json.loads(raw)
    sys.exit("provide --signals <file.json> or pipe JSON on stdin")


def main():
    stack = arg("--stack")
    top = int(arg("--top", "15") or 15)
    emit = arg("--emit")
    sig = read_signals()
    oc = _outcome_mod()
    hyps = hypotheses(sig, stack, oc)[:top]

    print(f"[hypothesize] {len(hyps)} ranked hypotheses"
          f"{' · stack ' + stack if stack else ''}"
          f"{' · EV-weighted by paid history' if oc and oc.load(oc.GLOBAL) else ' · cold priors'}\n")
    print(f"{'#':>2} {'SCORE':>6} {'CLASS':<13}{'PRIOR$':>7}  WHY  →  TEST")
    for i, h in enumerate(hyps, 1):
        print(f"{i:>2} {h['score']:>6.2f} hunt-{h['cls']:<8}{h['prior_ev']:>7.0f}  {h['why']}\n"
              f"                             → {h['test']}")

    if emit:
        p = Path(emit)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# id\tclass\tscore\tprior_ev\tstatus\twhy\ttest\n")
        with p.open("a") as f:
            for i, h in enumerate(hyps, 1):
                f.write(f"H-{i}\t{h['cls']}\t{h['score']}\t{h['prior_ev']:.0f}\topen\t{h['why']}\t{h['test']}\n")
        print(f"\n[hypothesize] wrote {len(hyps)} → {p}  (mark each tested/confirmed/killed as you hunt)")


if __name__ == "__main__":
    main()
