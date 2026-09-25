#!/usr/bin/env python3
"""
assume-break — find the bug nobody scripted by modelling the developer's mind.

Playbooks catch known patterns. Elite hunters win on ASSUMPTIONS: for each feature, the developer
silently believed some invariants ("only the owner calls this", "the price is server-set", "this step
always runs first", "MFA is always enforced"). Every one of those is a bug if you can violate it. This
enumerates the assumptions behind a feature and the concrete way to break each — turning the engine
from a payload-matcher into a hypothesis generator.

Usage:
  assume-break.py --feature checkout --endpoint /api/v1/checkout --context "coupon, price, qty"
  assume-break.py --endpoint /api/v1/orders/{id}            # feature inferred from the endpoint
  assume-break.py --feature login --emit ./.hunt/hypotheses.tsv
Exit: 0.
"""
import sys, os, re
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))

# feature → list of (developer ASSUMPTION, how to BREAK it, bug class)
FEATURES = {
    "object": [
        ("only the owner can access this object", "swap the id/tenant header to another user's; expect denial, look for their data", "idor"),
        ("the object id is unguessable", "enumerate sequential/low-entropy ids; harvest ids leaked in other responses/JS", "idor"),
        ("the client only ever sends its own id", "send someone else's id in body/query/path/header", "idor"),
        ("read and write share the same auth", "if read is denied, retry the WRITE (PUT/PATCH/DELETE) — often ungated", "authz"),
    ],
    "payment": [
        ("the price/total is server-authoritative", "send your own price/amount/total in the body; round/negative/overflow/scientific-notation", "logic"),
        ("a coupon/credit redeems once", "replay + fire N concurrent redeems (race) — double value / stacking", "race"),
        ("amount is positive and in the account currency", "negative amount (refund→credit), 0, currency mismatch, sub-cent rounding", "logic"),
        ("payment is captured before fulfilment", "skip the capture/verify step and hit fulfilment/download directly", "logic"),
        ("quantity is bounded", "huge/negative/array quantity to underflow the total or exhaust stock", "logic"),
    ],
    "auth": [
        ("the credential check gates all access", "alg:none / weak-secret JWT, default creds, response-status confusion (200 then use)", "authbypass"),
        ("the reset/verify token is secret and user-bound", "reuse another user's token, omit it, reuse after use, host-header poisoning of the link", "auth"),
        ("MFA is always enforced on login", "try an alternate grant (ROPC/device-code), a different endpoint, or step-up skip", "authbypass"),
        ("the session dies on logout / disable / pw-change", "reuse the OLD token afterwards (e.g. /keep-alive) — expect 401", "session"),
        ("email/identifier is validated + unique", "unicode/case/whitespace collision, second account with same normalized email", "logic"),
    ],
    "upload": [
        ("extension/content-type is validated", "double extension, null byte, mismatched Content-Type, case, trailing dot", "fileupload"),
        ("the file is stored outside the web root", "path traversal in filename (../), absolute path, overwrite a sibling file", "fileupload"),
        ("only images are processed", "SVG (stored XSS), polyglot, XXE via office/xml, image-parser RCE", "fileupload"),
    ],
    "workflow": [
        ("each step runs only after the previous one", "call step N directly, skipping N-1 (verify/pay/approve)", "logic"),
        ("state moves one direction", "replay an earlier request to roll state back; re-trigger a completed action", "logic"),
    ],
    "admin": [
        ("the role check happens server-side", "call the admin/internal endpoint directly as a normal user", "bfla"),
        ("hiding it in the UI is enough", "forced-browse the route the UI never links; use the API directly", "bfla"),
        ("global/non-id-scoped settings are admin-only", "read/write global settings (license, CA, scheduler) as low-priv — often unchecked", "authz"),
    ],
    "input": [
        ("input is safe once it passed validation", "second-order injection; the value re-used later in SQL/HTML/template", "sqli"),
        ("the field is the type the schema says", "send an array/object where a string is expected (type juggling, operator injection)", "nosqli"),
        ("server-side rendering escapes output", "template metacharacters {{7*7}} → SSTI; context-breaking XSS", "ssti"),
    ],
    "url": [
        ("this URL/host is external and safe to fetch", "point it at 169.254.169.254 / internal host / redirector → SSRF", "ssrf"),
        ("the redirect target is ours", "swap to an attacker domain / javascript: → open redirect / token theft", "openredirect"),
    ],
    "ratelimit": [
        ("the limit is enforced per account", "parallelise; rotate IP/X-Forwarded-For; multiple accounts; case/param variants of the key", "logic"),
    ],
    "export": [
        ("the export is scoped to the caller", "request another tenant's/user's export; drop or swap the scope param", "idor"),
        ("the export contains no sensitive fields", "diff fields across roles; internal/PII fields leak in the full object", "idor"),
    ],
}
# always applies, whatever the feature
GENERIC = [
    ("the client only sends the fields it's supposed to", "MASS ASSIGNMENT: add role, isAdmin, ownerId, price, verified, status to the body", "logic"),
    ("the happy path is the only path", "malformed/empty/duplicate/out-of-order requests; wrong method; missing/extra fields", "logic"),
    ("whatever the client enforces is enforced", "do it server-side directly, bypassing the client entirely", "authz"),
    ("identifiers and tokens are unpredictable", "enumerate them; find them leaked in responses, JS bundles, or error messages", "idor"),
]

DETECT = [
    ("payment", ["checkout", "pay", "order", "cart", "coupon", "promo", "invoice", "billing", "refund", "wallet", "transfer", "price", "purchase", "subscription"]),
    ("auth", ["login", "signin", "auth", "token", "password", "reset", "forgot", "otp", "mfa", "2fa", "verify", "session", "oauth", "sso", "register", "signup"]),
    ("upload", ["upload", "file", "attachment", "avatar", "import", "media", "document"]),
    ("admin", ["admin", "internal", "manage", "config", "settings", "console", "backoffice", "role", "permission"]),
    ("url", ["url", "uri", "webhook", "callback", "fetch", "proxy", "redirect", "next", "return", "image_url"]),
    ("export", ["export", "report", "download", "statement", "backup"]),
    ("workflow", ["step", "wizard", "flow", "approve", "submit", "confirm", "activate", "onboard"]),
    ("ratelimit", ["limit", "otp", "attempt", "vote", "like", "invite"]),
    ("input", ["search", "query", "filter", "sort", "q=", "name", "comment", "message", "template"]),
    ("object", ["{id}", "/id", "id=", "user", "account", "profile", "order", "document", "record"]),
]


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def detect(hay):
    hits = []
    for feat, kws in DETECT:
        if any(k in hay for k in kws):
            hits.append(feat)
    return hits or ["object"]


def main():
    feature = (arg("--feature") or "").lower()
    ep = arg("--endpoint", "")
    ctx = arg("--context", "")
    hay = " ".join([feature, ep, ctx]).lower()
    feats = [feature] if feature in FEATURES else detect(hay)
    # de-dupe, keep order, cap
    seen, order = set(), []
    for f in feats:
        if f in FEATURES and f not in seen:
            seen.add(f); order.append(f)

    rows = []
    for f in order:
        for assume, brk, cls in FEATURES[f]:
            rows.append((f, assume, brk, cls))
    for assume, brk, cls in GENERIC:
        rows.append(("generic", assume, brk, cls))

    print(f"[assume-break] {ep or feature or 'feature'} → assumptions to violate "
          f"(features: {', '.join(order)}):\n")
    for i, (f, assume, brk, cls) in enumerate(rows, 1):
        print(f"  {i:>2}. DEV ASSUMES: {assume}")
        print(f"      BREAK IT ({cls}): {brk}")
    print(f"\n  {len(rows)} falsifiable leads. Each is a hypothesis — test it, capture evidence, verify.")

    emit = arg("--emit")
    if emit:
        p = Path(emit)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("# id\tclass\tscore\tprior_ev\tstatus\twhy\ttest\n")
        n = sum(1 for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#"))
        with p.open("a") as fh:
            for f, assume, brk, cls in rows:
                n += 1
                fh.write(f"AB-{n}\t{cls}\t\t\topen\tdev assumes: {assume}\t{brk}  (feature:{f}, ep:{ep})\n")
        print(f"  → appended {len(rows)} leads to {p}")


if __name__ == "__main__":
    main()
