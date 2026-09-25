#!/usr/bin/env python3
"""
reflect — self-critique a cell before you call it 'tested'. Kills shallow coverage and false negatives.

The failure mode of any hunter (human or model) is one probe → "tested" → move on. This is the critic:
given a class + what you actually tried, it scores completeness against the technique set that makes
that class DEEP, lists what you skipped, and refuses 'deep' without ≥2 attempts + captured evidence.
Run it per cell before marking TESTED — and again on anything that came back clean.

Usage:
  reflect.py --class idor --endpoint /api/v1/orders/{id} --tried id-swap --attempts 1
  reflect.py --class sqli --endpoint '/search?q=' --tried single-quote,error-based --attempts 2 --evidence ./.hunt/evidence/c12
Exit: 0 DEEP · 1 SHALLOW (more to try).
"""
import sys, os
from pathlib import Path

TECHS = {
    "idor": ["id-swap", "uuid-guess", "wrapped-id", "param-pollution", "method-swap", "sibling-endpoint",
             "negative-zero-id", "encoded-id", "second-identity-diff"],
    "authz": ["low-priv-diff", "tenant-b-diff", "method-swap", "forced-browsing", "mass-assignment-role",
              "global-vs-scoped"],
    "bfla": ["low-priv-call", "method-swap", "forced-browsing", "verify-side-effect"],
    "sqli": ["single-quote", "boolean-pair", "time-based", "union", "error-based", "order-by",
             "second-order", "json-body", "header-injection"],
    "ssrf": ["internal-ip", "metadata-endpoint", "dns-rebind", "redirect-follow", "gopher-file-proto",
             "blind-oob", "encoded-ip", "port-probe"],
    "xss": ["reflected-context", "attribute-breakout", "js-context", "stored", "dom-sink",
            "encoding-bypass", "svg-markdown", "csp-check"],
    "ssti": ["polyglot-probe", "arithmetic-eval", "engine-fingerprint", "sandbox-escape"],
    "cors": ["origin-reflect", "null-origin", "subdomain-trust", "credentials-check", "preflight-bypass",
             "sensitive-read"],
    "race": ["parallel-N", "single-packet-multiplex", "state-delta-check", "idempotency-strip"],
    "fileupload": ["ext-bypass", "content-type-bypass", "magic-bytes", "path-traversal-name", "svg-xss",
                   "polyglot", "size-limit"],
    "jwt": ["alg-none", "weak-secret-crack", "kid-injection", "jku-x5u-swap", "claim-tamper"],
    "session": ["reuse-after-logout", "reuse-after-disable", "reuse-after-pwchange", "fixation"],
    "openredirect": ["attacker-domain", "scheme-bypass", "crlf", "chain-oauth"],
    "logic": ["step-skip", "negative-value", "replay", "parameter-tamper", "state-machine-abuse"],
}
GENERIC = ["happy-path", "malformed-input", "boundary-values", "auth-variation", "method-variation"]


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def norm(c):
    return (c or "").lower().strip().replace(" ", "").replace("_", "").replace("-", "")


def main():
    cls = norm(arg("--class"))
    if not cls:
        sys.exit("usage: reflect.py --class <c> [--endpoint ..] [--tried a,b] [--attempts N] [--evidence PATH]")
    ep = arg("--endpoint", "")
    techs = None
    for k, v in TECHS.items():
        if norm(k) == cls:
            techs = v; break
    techs = techs or GENERIC
    tried_raw = [t.strip().lower() for t in (arg("--tried") or "").split(",") if t.strip()]
    tried = {t for t in tried_raw}
    done = [t for t in techs if t in tried]
    missing = [t for t in techs if t not in tried]
    try:
        attempts = int(arg("--attempts", str(len(tried_raw))) or 0)
    except ValueError:
        attempts = len(tried_raw)
    ev = arg("--evidence")
    ev_ok = bool(ev and Path(ev).exists())
    score = len(done) / len(techs) if techs else 0

    deep = score >= 0.6 and attempts >= 2 and ev_ok
    icon = "✓ DEEP" if deep else "◌ SHALLOW"
    print(f"[reflect] {icon}  hunt-{cls}  {ep}   coverage {len(done)}/{len(techs)} techniques ({score:.0%})")
    gaps = []
    if attempts < 2:
        gaps.append(f"only {attempts} attempt(s) — a class isn't 'tested' on one probe")
    if not ev_ok:
        gaps.append("no captured evidence (--evidence PATH) — unverifiable")
    for g in gaps:
        print(f"    ! {g}")
    if missing:
        shown = missing[:8]
        print(f"    untried: {', '.join(shown)}" + (f"  (+{len(missing)-len(shown)} more)" if len(missing) > len(shown) else ""))
    if deep:
        print("  ✓ enough depth + evidence — safe to mark TESTED (or FINDING).")
        sys.exit(0)
    print("  → run the untried techniques above before marking this cell tested. Real bugs hide in the depth.")
    sys.exit(1)


if __name__ == "__main__":
    main()
