#!/usr/bin/env python3
"""
self-improve — the engine that sharpens itself. A nightly meta-loop over the whole brain.

Run it on a schedule (cron) or after every session. It: (1) runs hunt-eval and guards against regression,
(2) reports how the brain grew (outcomes/memory/learned/packs), (3) flags classes that keep getting
DUPED or N-A'd (deprioritise) and classes with a strong hit-rate (lean in), (4) surfaces pending
verdicts to record and disclosed reports to ingest, (5) suggests skills to build from recent findings.
It changes nothing on its own except the eval baseline — it tells YOU what to feed it.

Usage:  self-improve.py [--stack saas]
Exit: 0 · 1 if hunt-eval regressed.
"""
import sys, os, json, subprocess
from pathlib import Path
from collections import Counter

CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def jload(p):
    out = []
    if p.exists():
        for ln in p.read_text().splitlines():
            if ln.strip():
                try:
                    out.append(json.loads(ln))
                except Exception:
                    pass
    return out


def main():
    print("══ SELF-IMPROVE — nightly brain review ══════════════════\n")

    # 1) eval regression guard
    print("① eval (regression guard):")
    r = subprocess.run([sys.executable, str(TOOLS / "hunt-eval.py"), "--save"], capture_output=True, text=True)
    for ln in (r.stdout or "").strip().splitlines()[-4:]:
        print("   " + ln)
    regressed = r.returncode == 1

    # 2) brain size
    outc = jload(CORPUS / "outcomes.jsonl")
    mem = jload(CORPUS / "memory.jsonl")
    learned = jload(CORPUS / "learned.jsonl")
    packs = json.loads((CORPUS / "packs.json").read_text()) if (CORPUS / "packs.json").exists() else {}
    print(f"\n② brain: {len(outc)} outcomes · {len(mem)} memories · {len(learned)} learned-rules · "
          f"{sum(len(v) for v in packs.values())} pack-rules")

    # 3) class signal from outcomes
    if outc:
        acc = Counter(); dup = Counter(); na = Counter(); n = Counter()
        for o in outc:
            c = o.get("cls", "?"); n[c] += 1
            v = o.get("verdict")
            if v in ("paid", "accepted"):
                acc[c] += 1
            elif v == "duplicate":
                dup[c] += 1
            elif v in ("na", "informative", "rejected"):
                na[c] += 1
        print("\n③ what your history says:")
        strong = [c for c in n if n[c] >= 2 and acc[c] / n[c] >= 0.6]
        crowded = [c for c in n if dup[c] and dup[c] / n[c] >= 0.4]
        weak = [c for c in n if na[c] and na[c] / n[c] >= 0.5]
        if strong:
            print(f"   ✓ LEAN IN (high hit-rate): {', '.join(sorted(strong))}")
        if crowded:
            print(f"   = CROWDED (often duped — hunt first-to-report or skip): {', '.join(sorted(crowded))}")
        if weak:
            print(f"   ✗ DEPRIORITISE (often N-A/info): {', '.join(sorted(weak))}")
        untried_high = [c for c in ("rce", "deserialization", "sqli", "ssti", "ssrf") if c not in n]
        if untried_high:
            print(f"   ? NO DATA on high-value classes: {', '.join(untried_high)} — targeted practice would pay.")

    # 4) pending feed-ins
    print("\n④ feed the brain:")
    sub = Path("./.hunt/submitted.jsonl")
    if sub.exists():
        subs = jload(sub)
        done = {(o.get("cls"), o.get("endpoint")) for o in outc}
        pending = [s for s in subs if (s.get("class"), s.get("endpoint")) not in done]
        if pending:
            print(f"   • {len(pending)} submission(s) awaiting a verdict → outcome-check.py --sync-submitted, then --record each")
    print("   • read a good writeup today? corpus-ingest.py --file it (learn from the community)")
    print("   • new verdict landed? outcome-check.py --record + hunt-memory.py --add the situation")

    # 5) skill suggestions from memory classes not yet covered by a hunt skill
    if mem:
        by = Counter(m.get("cls", "?") for m in mem)
        print("\n⑤ skills: your most-seen classes → ensure a sharp hunt-<class> playbook exists")
        print("   " + ", ".join(f"{c}({k})" for c, k in by.most_common(6)))
        print("   → for any weak/high-frequency class: skill-builder.py to mine/refresh it.")

    print("\n" + ("✗ REGRESSION in eval — investigate before shipping engine changes." if regressed
                  else "✓ no regression. Brain is intact and growing."))
    sys.exit(1 if regressed else 0)


if __name__ == "__main__":
    main()
