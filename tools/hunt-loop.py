#!/usr/bin/env python3
"""
hunt-loop — the autonomous driver. Reads ./.hunt state, tells you exactly which phase you're in and
the next command to run. The engine's spine: it sequences the whole pipeline so nothing is skipped or
re-done, and it survives compaction (state is on disk, not in the model's head).

It doesn't fire network requests (scope-guard + the model do that) — it orchestrates: at each call it
inspects the state files, decides the phase, and prints the next tool invocation(s) + the model tier to
use (route-model) + the checkpoint. Run it whenever you're unsure what to do next.

Usage:  hunt-loop.py [--target api.acme.com]
Exit: 0 pipeline complete · 1 more work (next step printed).
"""
import sys, os, json
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def exists(name):
    p = HUNT / name
    return p.exists() and p.stat().st_size > 0


def nonempty_lines(name):
    p = HUNT / name
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#"))


def findings_count():
    d = HUNT / "findings"
    return len(list(d.glob("F*.md"))) if d.exists() else 0


def coverage_todo():
    p = HUNT / "coverage.tsv"
    if not p.exists():
        return None
    todo = tested = 0
    for ln in p.read_text().splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        for c in [x.strip() for x in s.split("\t")[1:]]:
            cu = c.upper()
            if "@" in c or cu.startswith(("TESTED", "FINDING")):
                tested += 1
            elif cu in ("TODO", "PARTIAL") or cu.startswith(("TODO", "PARTIAL")):
                todo += 1
            # anything else (blanks, '.', 'na', header labels, class names) is not a cell status
    return {"todo": todo, "tested": tested}


def step(phase, why, cmds, tier, checkpoint=None):
    tname, task = tier if isinstance(tier, tuple) else (tier, tier)
    print(f"\n══ PHASE {phase} ══════════════════════════════════════════")
    print(f"  {why}\n")
    for c in cmds:
        print(f"    $ {c}")
    print(f"\n  model tier: {tname}   (route-model.py --task {task})")
    if checkpoint:
        print(f"  ⛔ checkpoint: {checkpoint}")
    print("\n  → run the above, then re-run hunt-loop.py for the next step.")


def main():
    t = arg("--target", "<target>")
    HUNT.mkdir(parents=True, exist_ok=True)

    if not exists("scope.allow"):
        step("0 · BOOT", "No scope yet. Paste the program page (or init scope) before anything fires.",
             ["pbpaste | hunt-intake.py         # paste overview+scope → scope.allow/deny, signals.json, program.md",
              "# or:  scope-guard.py --init  then fill scope.allow"],
             ("cheap", "intake"), "REVIEW scope.allow before hunting")
        sys.exit(1)

    if not exists("signals.json") or not exists("surface.txt"):
        step("2 · RECON", "Scope is set. Build the surface map — more signal in = smarter hypotheses out.",
             [f"recon-aggregate.py --urls gau.txt --js app.js --openapi swagger.json --subs subs.txt --stack <domains>",
              "# feeds signals.json + surface.txt"], ("cheap", "recon"))
        sys.exit(1)

    if not exists("hypotheses.tsv"):
        step("3b · HYPOTHESIZE", "Reason before fuzzing. Recall analogous past hunts, then generate ranked leads.",
             ["hunt-memory.py --recall --file <a-key-response> --stack <domains>   # what paid on situations like this",
              "hunt-hypothesize.py --signals ./.hunt/signals.json --stack <domains> --emit ./.hunt/hypotheses.tsv",
              "hunt-corpus.py --suggest --rank --stack <domains>",
              "smell.py --file ./.hunt/surface.txt          # hunt the smelly surface first"],
             ("strong", "hypothesis"))
        sys.exit(1)

    if not exists("coverage.tsv"):
        step("3 · ENUMERATE", "Turn surface × applicable-class into a coverage ledger; order classes by EV.",
             ["# build ./.hunt/coverage.tsv (every surface item × class = a TODO cell)  [hunt-coverage]",
              "outcome-check.py --rank --stack <domains>    # class hunt-order by paid history"],
             ("cheap", "recon"))
        sys.exit(1)

    cov = coverage_todo()
    if cov and cov["todo"] > 0:
        step("5 · HUNT", f"{cov['todo']} cell(s) still TODO ({cov['tested']} tested). Depth-first, evidence-bound.",
             ["hunt-status.py                 # exact next untested / shallow cell",
              "# run hunt-<class> matrix on the cell; capture req/resp to evidence/",
              "diff-oracle.py --a A.txt --b B.txt --expect deny   # auto-find access bugs across 2 identities",
              "reflect.py --class <c> --endpoint <e> --tried <..> --attempts <n> --evidence <path>   # before marking TESTED"],
             ("strong", "exploit"))
        sys.exit(1)

    fc = findings_count()
    caps = nonempty_lines("capabilities.tsv")
    if caps:
        step("5d · CHAIN", "Primitives proven — plan the escalation to a WIN, don't stop at the primitive.",
             ["capability-graph.py            # reachability",
              "chain-plan.py                  # goal-driven: ATO/RCE/PII/funds → ACHIEVED/ONE-AWAY/BLOCKED + next edge"],
             ("strong", "chain"))
        sys.exit(1)

    if fc > 0:
        step("6 · VALIDATE → 8 · REPORT", f"{fc} finding(s). Attack each before trusting it, then make it report-ready.",
             ["adversarial-verify.py --class <c> --endpoint <e> --evidence <p> --control --repro 2   # falsify + escalate + ground severity",
              "# run TWO independent reasoning passes on hard exploits; reconcile (debate)",
              "dedup-check.py --class <c> --endpoint <e>",
              "poc-synth.py --class <c> --url <full-url>      # runnable PoC + writeup",
              "report + log to submitted.jsonl"],
             ("strong", "verify"), "never auto-submit — checkpoint each report")
        sys.exit(1)

    step("✓ COMPLETE / MONITOR", "No open cells, chains, or unvalidated findings. Keep watching for new surface.",
         [f"hunt-monitor.py --target {t} --surface fresh.txt --stack <domains> --emit ./.hunt/hypotheses.tsv",
          "# after platform verdicts: outcome-check.py --record ... ; hunt-memory.py --add ...  (close the loop)",
          "hunt-eval.py                   # confirm the engine didn't regress"],
         ("cheap", "summarize"))
    sys.exit(0)


if __name__ == "__main__":
    main()
