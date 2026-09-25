#!/usr/bin/env python3
"""
hunt-corpus — a reusable library of invariant/edge hypotheses so the model instantiates known rules
instead of imagining them, and so a novel rule you find once is proposed automatically ever after.

Two sources:
  packs.json    domain packs (generic, fintech, ecommerce, saas, auth) — curated rule templates
  learned.jsonl rules you promote from confirmed findings (--learn) — institutional memory

Usage:
  hunt-corpus.py --list
  hunt-corpus.py --suggest --stack fintech,saas [--host https://api.x] [--emit ./.hunt/invariants.tsv]
  hunt-corpus.py --learn --type once --fam "Gift-card split" --stack fintech --note "split redeem races"
"""
import sys, os, json, time, importlib.util
from pathlib import Path

CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
PACKS = CORPUS / "packs.json"
LEARNED = CORPUS / "learned.jsonl"

# corpus rule 'type' → candidate bug classes (for EV lookup from outcome history)
TYPE2CLS = {
    "noaccess": ["idor", "authz"], "deny": ["authz", "bfla", "auth"],
    "rejects": ["logic"], "once": ["race", "logic"], "lifecycle": ["session", "auth"],
}


def _outcome_mod():
    """Load outcome-check.py (hyphenated → importlib) for its EV scorer; None if absent."""
    p = Path(__file__).with_name("outcome-check.py")
    if not p.exists():
        return None
    spec = importlib.util.spec_from_file_location("outcome_check", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rule_ev(agg, rtype, fam):
    """Best EV among the classes a corpus rule could produce (0 if no scorer)."""
    if not agg:
        return 0.0
    cands = TYPE2CLS.get(rtype, [])
    return max((agg.get(c, {}).get("ev", 0.0) for c in cands), default=0.0)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def load_packs():
    return json.loads(PACKS.read_text()) if PACKS.exists() else {}


def load_learned():
    out = []
    if LEARNED.exists():
        for ln in LEARNED.read_text().splitlines():
            if ln.strip():
                try: out.append(json.loads(ln))
                except Exception: pass
    return out


def cmd_list():
    packs = load_packs()
    print("packs:")
    for k, v in packs.items():
        print(f"  {k:<12} {len(v)} rules")
    print(f"learned: {len(load_learned())} rules  ({LEARNED})")


def cmd_learn():
    rec = {"type": arg("--type", ""), "fam": arg("--fam", ""), "stack": arg("--stack", "generic"),
           "note": arg("--note", ""), "url": arg("--url", ""), "ts": time.strftime("%Y-%m-%d")}
    if not rec["type"] or not rec["note"]:
        sys.exit("usage: --learn --type <t> --note <n> [--fam ..] [--stack ..] [--url ..]")
    CORPUS.mkdir(parents=True, exist_ok=True)
    with LEARNED.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[corpus] learned: {rec['fam'] or rec['type']} — will be suggested on future {rec['stack']} hunts.")


def cmd_suggest():
    stacks = [s.strip() for s in (arg("--stack", "generic") or "generic").split(",")]
    if "generic" not in stacks:
        stacks = ["generic"] + stacks
    host = (arg("--host", "") or "").rstrip("/")
    emit = arg("--emit")
    ranked = "--rank" in sys.argv
    packs = load_packs()
    rows = []
    for st in stacks:
        for r in packs.get(st, []):
            rows.append((st, r["type"], r.get("fam", ""), r.get("hint", ""), r["note"]))
    for r in load_learned():
        if r.get("stack") in stacks or r.get("stack") == "generic":
            rows.append((r.get("stack", "learned") + "*", r["type"], r.get("fam", ""), r.get("url", ""), r["note"]))

    agg = None
    if ranked:
        m = _outcome_mod()
        if m:
            agg = m.all_classes_with_priors(m.score(m.load(m.GLOBAL), stacks))
            rows.sort(key=lambda r: -rule_ev(agg, r[1], r[2]))

    label = "hypotheses (ranked by your paid history)" if agg else "hypotheses"
    print(f"[corpus] {len(rows)} {label} for stacks: {', '.join(stacks)}\n")
    head = f"{'EV/att':>7}  " if agg else ""
    print(f"{head}{'STACK':<11}{'TYPE':<9}{'FAMILY':<22}HINT / NOTE")
    for st, t, fam, hint, note in rows:
        pre = f"${rule_ev(agg, t, fam):>6.0f}  " if agg else ""
        print(f"{pre}{st:<11}{t:<9}{fam:<22}{hint}  —  {note}")
    if emit:
        p = Path(emit)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("# id\ttype\tmethod\turl\theader\tmarker\tnote\n")
        n = sum(1 for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#"))
        with p.open("a") as f:
            for st, t, fam, hint, note in rows:
                n += 1
                url = host + "/<fill-endpoint>" if host else "<fill-endpoint>"
                f.write(f"CORP-{n}\t{t}\tGET\t{url}\t\t\t{fam}: {note} [hint:{hint}] [source=corpus:{st}]\n")
        print(f"\n[corpus] appended {len(rows)} candidate rows → {p}  (fill in real endpoints/identities, then invariant-check.py --run)")


def main():
    if "--list" in sys.argv:
        return cmd_list()
    if "--learn" in sys.argv:
        return cmd_learn()
    if "--suggest" in sys.argv:
        return cmd_suggest()
    print(__doc__)


if __name__ == "__main__":
    main()
