#!/usr/bin/env python3
"""
smell — rank attack surface by how suspicious it looks, so you hunt the promising bits first.

Not all endpoints are equal. Legacy versions, debug/internal paths, exposed source/config, redirecty
URL params, id-bearing objects — these carry the smell of a bug. This scores each surface item by such
signals and sorts them, turning a flat URL dump into a prioritised worklist.

Input: a surface list (one item per line) via --file, or ./.hunt/signals.json (endpoints+hosts+secrets),
or stdin.

Usage:
  smell.py --file ./.hunt/surface.txt [--top 25]
  smell.py                              # reads ./.hunt/signals.json
  cat urls.txt | smell.py
Exit: 0.
"""
import sys, os, re, json
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))

# (regex, weight, reason) — higher weight = smellier
RULES = [
    (r"\.(bak|old|orig|swp|save|zip|tar|gz|sql)(\b|$)", 5, "backup/dump file exposed"),
    (r"(/\.git|/\.env|/\.svn|/\.DS_Store|\.js\.map\b)", 6, "source/secret/config exposed"),
    (r"(sk_[a-z0-9_]{6,}|akia[0-9a-z]{10,}|api[_-]?key|client_secret|password\s*[=:])", 7, "possible secret"),
    (r"(/admin|/internal|/manage|/console|/backoffice|/superuser)", 4, "privileged/internal path"),
    (r"(/debug|/test|/dev|/staging|/sandbox|/tmp|/temp|/_next/|/actuator|/jolokia)", 4, "debug/non-prod surface"),
    (r"(/v0/|/v1/|/beta/|/legacy/|/old/|/deprecated/|api_version=)", 3, "legacy/old API version"),
    (r"([?&](url|uri|redirect|redirect_uri|next|callback|dest|return|target|fetch|proxy|image_url)=)", 4, "SSRF/open-redirect-prone param"),
    (r"(/graphql|/api/graphql|\.wsdl|/soap|/swagger|/openapi|/api-docs)", 3, "introspectable/spec surface"),
    (r"(/\d+(/|$|\?)|/\{id\}|[?&](id|user_?id|account_?id|order_?id|doc_?id)=)", 3, "id-bearing (IDOR-prone)"),
    (r"([?&](file|path|template|include|page|load|doc)=)", 4, "LFI/path/template-prone param"),
    (r"(/upload|/import|/attachment|/avatar|/file)", 3, "file-upload surface"),
    (r"([?&](q|search|filter|sort|query|name|keyword)=)", 2, "injection-prone input"),
    (r"(/oauth|/authorize|/saml|/sso|/login|/token|/auth|/reset|/forgot)", 3, "auth/token surface"),
    (r"(/export|/report|/download|/backup)", 3, "bulk-data egress"),
    (r"(/webhook|/callback|/notify)", 3, "server-initiated request surface"),
    (r"(/internal|/private|/_|/config|/settings)", 2, "config/private surface"),
]


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def load_items():
    f = arg("--file")
    if f:
        return [l.strip() for l in Path(f).read_text(errors="replace").splitlines() if l.strip()]
    if not sys.stdin.isatty():
        piped = [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
        if piped:
            return piped
    sig = HUNT / "signals.json"
    if sig.exists():
        try:
            s = json.loads(sig.read_text())
            return list(dict.fromkeys((s.get("hosts", []) + s.get("endpoints", []) +
                                       [f"?{p}=" for p in s.get("fields", [])] + s.get("secrets", []))))
        except Exception:
            pass
    sys.exit("no input: --file, stdin, or ./.hunt/signals.json")


def score(item):
    hits, total = [], 0
    low = item.lower()
    for rx, w, reason in RULES:
        if re.search(rx, low):
            total += w
            hits.append((w, reason))
    hits.sort(reverse=True)
    return total, [r for _, r in hits]


def main():
    items = load_items()
    top = int(arg("--top", "25") or 25)
    scored = []
    for it in items:
        s, reasons = score(it)
        if s > 0:
            scored.append((s, it, reasons))
    scored.sort(key=lambda x: -x[0])
    if not scored:
        print(f"[smell] {len(items)} items, none matched a smell rule — nothing stands out.")
        return
    print(f"[smell] {len(scored)}/{len(items)} items carry a smell — hunt these first:\n")
    print(f"{'SMELL':>5}  ITEM")
    for s, it, reasons in scored[:top]:
        flag = "🔥" if s >= 7 else ("★" if s >= 4 else " ")
        print(f"{flag}{s:>4}  {it[:70]}")
        print(f"        {' · '.join(reasons[:3])}")
    print("\n  → feed the top items straight into hunt-hypothesize.py / the coverage ledger.")


if __name__ == "__main__":
    main()
