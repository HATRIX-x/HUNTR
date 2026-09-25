#!/usr/bin/env python3
"""
dedup-check — is this finding already known? Run BEFORE promoting a finding to a report.

A duplicate earns nothing and dents your signal. This checks a finding's signature against
what's already known for the target:
  ./.hunt/known.md         disclosed reports / hacktivity for this program (free text; from hunt-program-intel)
  ./.hunt/submitted.jsonl  your own prior submissions on this target ({class,endpoint,param,title,ref})

It is a assist, not an oracle: it surfaces candidates so you decide UNIQUE vs DUP with eyes open.

Usage:
  dedup-check.py --class idor --endpoint /api/v1/orders/{id} [--param id] [--title "..."]
Exit: 0 no candidates (likely unique) · 1 candidates found (review before reporting).
"""
import sys, os, json, re
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))


def arg(name, default=""):
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default


def norm_ep(ep):
    ep = ep.lower().split("?")[0]
    ep = re.sub(r"/\d+", "/{id}", ep)
    ep = re.sub(r"/[0-9a-f]{8,}", "/{id}", ep)
    return ep


def tokens(ep):
    return {t for t in re.split(r"[/_\-.]", norm_ep(ep)) if len(t) > 2 and t != "{id}"}


def main():
    cls = arg("--class").lower().strip()
    ep = arg("--endpoint")
    param = arg("--param").lower().strip()
    if not cls or not ep:
        sys.stderr.write("usage: dedup-check.py --class <c> --endpoint <path> [--param p] [--title t]\n")
        sys.exit(2)
    nep, toks = norm_ep(ep), tokens(ep)
    cands = []

    sub = HUNT / "submitted.jsonl"
    if sub.exists():
        for line in sub.read_text().splitlines():
            try:
                r = json.loads(line)
            except Exception:
                continue
            same_cls = cls in (r.get("class", "").lower())
            ov = toks & tokens(r.get("endpoint", ""))
            same_ep = norm_ep(r.get("endpoint", "")) == nep
            if same_ep and same_cls:
                cands.append(("YOUR SUBMISSION", 0.95, r.get("ref") or r.get("title", "")))
            elif (ov and same_cls):
                cands.append(("your submission (partial)", 0.5 + 0.1 * len(ov), r.get("title", r.get("ref", ""))))

    known = HUNT / "known.md"
    if known.exists():
        for i, line in enumerate(known.read_text().splitlines(), 1):
            l = line.lower()
            if not l.strip() or l.strip().startswith("#"):
                continue
            ov = toks & set(re.split(r"[\s/_\-.]", l))
            cls_hit = cls in l or any(cls in w for w in l.split())
            if cls_hit and ov:
                cands.append((f"disclosed:known.md:{i}", 0.4 + 0.12 * len(ov), line.strip()[:90]))

    cands.sort(key=lambda c: -c[1])
    if not cands:
        print(f"[dedup] UNIQUE (no candidate matches) — class={cls} endpoint={nep}")
        n_known = len((known.read_text().splitlines()) if known.exists() else [])
        print(f"        checked: known.md ({n_known} lines), submitted.jsonl "
              f"({'present' if sub.exists() else 'none'}). Safe to proceed to report.")
        sys.exit(0)
    print(f"[dedup] {len(cands)} CANDIDATE(S) — review before reporting  (class={cls} endpoint={nep})")
    for src, score, txt in cands[:8]:
        flag = "‼ LIKELY DUP" if score >= 0.9 else "~ possible"
        print(f"  {flag}  [{score:.2f}]  {src}\n        {txt}")
    print("  → If genuinely different (different param/impact/root cause), say why in the report; else drop it.")
    sys.exit(1)


if __name__ == "__main__":
    main()
