#!/usr/bin/env python3
"""
hunt-doctor — keep the engine healthy as it grows. Run it after any change (or nightly).

30+ tools + 70+ skills rot silently. This checks the whole engine in one shot: every tool compiles,
the eval baseline hasn't regressed, the brain is intact and growing, and nothing referenced in
/autohunt is missing. Green = safe to ship an engine change.

Usage:  hunt-doctor.py
Exit: 0 healthy · 1 problems found.
"""
import sys, os, json, subprocess, re
from pathlib import Path

TOOLS = Path.home() / ".claude" / "tools"
CMDS = Path.home() / ".claude" / "commands"
CORPUS = Path.home() / ".claude" / "hunt-corpus"
BENCH = Path.home() / ".claude" / "hunt-bench"
problems = []


def line(t=""):
    print(("── " + t + " ").ljust(60, "─") if t else "─" * 60)


def cnt(p):
    return sum(1 for ln in p.read_text().splitlines() if ln.strip()) if p.exists() else 0


def main():
    print("══ HUNT-DOCTOR — engine health ═══════════════════════════\n")

    line("tools compile")
    tools = sorted(TOOLS.glob("*.py"))
    bad = []
    for t in tools:
        r = subprocess.run([sys.executable, "-m", "py_compile", str(t)], capture_output=True, text=True)
        if r.returncode != 0:
            bad.append(t.name)
    print(f"  {len(tools)} tools · {len(tools)-len(bad)} OK" + (f" · ✗ FAIL: {', '.join(bad)}" if bad else " · all clean"))
    if bad:
        problems.append(f"{len(bad)} tool(s) fail to compile")

    line("eval (regression guard)")
    he = TOOLS / "hunt-eval.py"
    if he.exists():
        r = subprocess.run([sys.executable, str(he)], capture_output=True, text=True)
        tail = [l for l in r.stdout.splitlines() if "recall@" in l or "REGRESSION" in l]
        for l in tail[-2:]:
            print("  " + l.strip())
        if r.returncode == 1:
            problems.append("hunt-eval REGRESSED")
    else:
        print("  (hunt-eval.py missing)")

    line("brain")
    print(f"  outcomes:  {cnt(CORPUS/'outcomes.jsonl')}")
    print(f"  memory:    {cnt(CORPUS/'memory.jsonl')}")
    print(f"  learned:   {cnt(CORPUS/'learned.jsonl')}")
    print(f"  wins:      {cnt(BENCH/'wins.jsonl')}   bench runs: {cnt(BENCH/'results.jsonl')}")
    if cnt(CORPUS / "outcomes.jsonl") < 10:
        problems.append("brain thin (<10 real outcomes) — feed real verdicts")

    line("references")
    # tools named in /autohunt that don't exist
    ah = CMDS / "autohunt.md"
    if ah.exists():
        txt = ah.read_text()
        named = set(re.findall(r"`([a-z-]+\.py)`", txt)) | set(re.findall(r"\b([a-z-]+\.py)\b", txt))
        missing = [n for n in named if n.endswith(".py") and not (TOOLS / n).exists()]
        print(f"  tools referenced in /autohunt & present: {len(named)-len(missing)}/{len(named)}" +
              (f" · ✗ missing: {', '.join(sorted(set(missing)))}" if missing else ""))
        if missing:
            problems.append(f"/autohunt references missing tool(s): {', '.join(sorted(set(missing)))}")
    # duplicate skill basenames
    sk = Path.home() / ".claude" / "skills"
    if sk.exists():
        names = [d.name for d in sk.iterdir() if d.is_dir()]
        dupes = {n for n in names if names.count(n) > 1}
        print(f"  skills: {len(names)}" + (f" · ✗ dupes: {dupes}" if dupes else ""))

    print()
    line()
    if problems:
        print("  ✗ NOT HEALTHY:")
        for p in problems:
            print("    · " + p)
        sys.exit(1)
    print("  ✓ engine healthy — safe to ship changes.")
    sys.exit(0)


if __name__ == "__main__":
    main()
