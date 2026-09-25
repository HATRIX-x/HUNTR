#!/usr/bin/env python3
"""
diff-oracle — DISCOVER access-control bugs by diffing two identities, not just testing declared ones.

The invariant miner tests rules you predicted. This finds the ones nobody predicted: capture the SAME
request as identity A and identity B, feed both here, and it flags BOLA / BFLA / tenant-bleed by
comparing them — B seeing A's data, a low-priv role reaching a privileged response, A's identifiers
leaking into B's response. This is where the hardest-to-find, highest-paying access bugs live.

Inputs are two saved responses (raw HTTP or just the body).

Usage:
  diff-oracle.py --a a.txt --b b.txt --expect deny          # B should have been denied
  diff-oracle.py --a a.txt --b b.txt --marker 'alice@corp'  # a string that must appear only for A
  diff-oracle.py --a a.txt --b b.txt --a-owner userA --b-owner userB
Exit: 0 no violation · 1 VIOLATION found.
"""
import sys, os, re, math
from collections import Counter
from pathlib import Path

EMAIL = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
IDFIELD = re.compile(r'"(?:id|user_?id|account_?id|owner_?id|customer_?id)"\s*:\s*"?([a-z0-9\-]{2,})"?', re.I)
TOKEN = re.compile(r"\b(?:ey[a-z0-9_\-]{10,}\.[a-z0-9_\-]{10,}|sk_[a-z0-9_]{8,}|[a-f0-9]{32,})\b", re.I)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def read(p):
    return Path(p).read_text(errors="replace")


def status_of(text):
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text.strip())
    return int(m.group(1)) if m else None


def body_of(text):
    # split headers/body on blank line if it looks like a raw HTTP response
    if re.match(r"HTTP/\d", text.strip()):
        parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
        return parts[1] if len(parts) > 1 else ""
    return text


def toks(t):
    t = t.lower()[:4000]
    return Counter(re.findall(r"[a-z0-9_]{2,}", t) + [t[i:i + 3] for i in range(max(0, len(t) - 2))])


def cosine(a, b):
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(v * v for v in a.values())); nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def idents(text):
    s = set()
    for rx in (EMAIL, UUID, TOKEN):
        s |= {m.group(0) for m in rx.finditer(text)}
    s |= {m.group(1) for m in IDFIELD.finditer(text)}
    return {x for x in s if len(x) >= 4}


def main():
    fa, fb = arg("--a"), arg("--b")
    if not fa or not fb:
        sys.exit("usage: diff-oracle.py --a a.txt --b b.txt [--expect deny] [--marker STR] [--a-owner N --b-owner N]")
    A, B = read(fa), read(fb)
    sa, sb = status_of(A), status_of(B)
    ba, bb = body_of(A), body_of(B)
    ao, bo = arg("--a-owner", "A"), arg("--b-owner", "B")
    expect = (arg("--expect") or "").lower()
    marker = arg("--marker")

    violations = []
    # 1) explicit marker (definitive bleed)
    if marker and marker in bb:
        violations.append(("DATA-BLEED", "critical", f"'{marker}' (only {ao} should see it) appears in {bo}'s response"))
    # 2) A's unique identifiers (email/uuid/token/id) showing up in B's response = cross-user bleed
    ia = idents(ba)
    leaked = {x for x in ia if x in bb}
    if leaked:
        sample = ", ".join(list(leaked)[:3])
        violations.append(("CROSS-USER-DATA", "high", f"{ao}'s identifiers appear in {bo}'s response: {sample}"))
    # 3) authorization: B reached something it shouldn't
    if expect == "deny":
        if sb is not None and 200 <= sb < 300:
            violations.append(("BFLA/AUTHZ", "high", f"{bo} expected DENY but got {sb} — privileged/other resource reachable"))
        elif sb is None and re.search(r'"(data|result|items|user|account)"', bb, re.I):
            violations.append(("BFLA/AUTHZ", "high", f"{bo} expected DENY but received a data payload"))
    # 4) same data returned to both (BOLA when B requested A's object)
    cos = cosine(toks(ba), toks(bb))
    if sa and sb and 200 <= sa < 300 and 200 <= sb < 300 and cos >= 0.9 and not violations:
        violations.append(("BOLA (likely)", "high", f"{bo}'s response is ~identical to {ao}'s (cosine {cos:.2f}) — "
                           f"if {bo} requested {ao}'s object, this is cross-account read"))

    print(f"[diff-oracle] A({ao})={sa or '?'}  B({bo})={sb or '?'}  body-similarity={cos:.2f}\n")
    if not violations:
        print("  ✓ no access-control violation detected on this pair.")
        print("    (B differs from A / was denied / shares no A-identifiers.)")
        sys.exit(0)
    order = {"critical": 0, "high": 1, "medium": 2}
    violations.sort(key=lambda v: order.get(v[1], 9))
    for kind, sev, why in violations:
        print(f"  ⚠ {kind}  [{sev.upper()}]\n      {why}")
    print("\n  → confirm with adversarial-verify.py --class " +
          ("idor" if any("BOLA" in v[0] or "CROSS" in v[0] for v in violations) else "authz") +
          " (evidence = these two captures + a control), then poc-synth.py.")
    sys.exit(1)


if __name__ == "__main__":
    main()
