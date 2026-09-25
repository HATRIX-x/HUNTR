#!/usr/bin/env python3
"""
hunt-export — your moat is the DATA, so own it, back it up, carry it.

The tools are copyable; the defensible asset is the accumulated brain: paid-outcome history, recalled
situations, learned rules, and validated wins. This bundles all of it into one portable archive you
own (and can restore anywhere). Losing it = losing the edge; a competitor can't reproduce it.

Usage:
  hunt-export.py                       # write ~/.huntr/exports/brain-<date>.tar.gz
  hunt-export.py --out /path/brain.tar.gz
  hunt-export.py --import brain.tar.gz # restore the brain (merges, backs up current first)
  hunt-export.py --stats               # what the moat currently holds
Exit: 0.
"""
import sys, os, tarfile, time, json
from pathlib import Path

HOME = Path.home()
CORPUS = HOME / ".claude" / "hunt-corpus"
BENCH = HOME / ".claude" / "hunt-bench"
EXPORTS = Path(os.environ.get("HUNTR_HOME", str(HOME / ".huntr"))) / "exports"
ASSETS = [CORPUS / "outcomes.jsonl", CORPUS / "memory.jsonl", CORPUS / "learned.jsonl",
          CORPUS / "packs.json", BENCH / "wins.jsonl", BENCH / "results.jsonl"]


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def cnt(p):
    return sum(1 for ln in p.read_text().splitlines() if ln.strip()) if p.exists() else 0


def cmd_stats():
    print("══ your moat (the data a competitor can't copy) ══")
    print(f"  paid/verdict outcomes : {cnt(CORPUS/'outcomes.jsonl')}")
    print(f"  recallable situations : {cnt(CORPUS/'memory.jsonl')}")
    print(f"  learned rules         : {cnt(CORPUS/'learned.jsonl')}")
    print(f"  validated wins        : {cnt(BENCH/'wins.jsonl')}")
    paid = 0.0
    for f in (CORPUS / "outcomes.jsonl",):
        if f.exists():
            for ln in f.read_text().splitlines():
                try: paid += float(json.loads(ln).get("reward", 0) or 0)
                except Exception: pass
    print(f"  recorded reward $/€   : {paid:.0f}")
    print("  → back this up: hunt-export.py")


def cmd_export():
    out = Path(arg("--out") or (EXPORTS / f"brain-{time.strftime('%Y%m%d-%H%M')}.tar.gz"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as tar:
        for a in ASSETS:
            if a.exists():
                tar.add(a, arcname=a.name)
    n = sum(1 for a in ASSETS if a.exists())
    print(f"[export] {n} brain files → {out}  ({out.stat().st_size} bytes)")
    print("  this archive IS the product's defensibility — store it safely (git-crypt / offline / your cloud).")


def cmd_import():
    src = arg("--import")
    if not src or not Path(src).exists():
        sys.exit("usage: --import <brain.tar.gz>")
    # back up current brain first
    CORPUS.mkdir(parents=True, exist_ok=True); BENCH.mkdir(parents=True, exist_ok=True)
    bak = EXPORTS / f"pre-import-{time.strftime('%Y%m%d-%H%M%S')}"
    bak.mkdir(parents=True, exist_ok=True)
    for a in ASSETS:
        if a.exists():
            (bak / a.name).write_bytes(a.read_bytes())
    dest = {"outcomes.jsonl": CORPUS, "memory.jsonl": CORPUS, "learned.jsonl": CORPUS,
            "packs.json": CORPUS, "wins.jsonl": BENCH, "results.jsonl": BENCH}
    merged = 0
    with tarfile.open(src, "r:gz") as tar:
        for m in tar.getmembers():
            name = os.path.basename(m.name)
            if name not in dest:
                continue
            data = tar.extractfile(m).read().decode("utf-8", "replace")
            tgt = dest[name] / name
            if name.endswith(".jsonl") and tgt.exists():  # merge jsonl, dedup lines
                have = set(tgt.read_text().splitlines())
                add = [l for l in data.splitlines() if l.strip() and l not in have]
                with tgt.open("a") as f:
                    for l in add:
                        f.write(l + "\n")
                merged += len(add)
            else:
                tgt.write_text(data)
    print(f"[import] merged {merged} new records (current brain backed up → {bak}).")


def main():
    if "--stats" in sys.argv:
        return cmd_stats()
    if "--import" in sys.argv:
        return cmd_import()
    return cmd_export()


if __name__ == "__main__":
    main()
