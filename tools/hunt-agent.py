#!/usr/bin/env python3
"""
hunt-agent — the self-driving loop. Runs the deterministic 'thinking' pipeline end-to-end on its own,
and stops (checkpoints) only where a human decision or a live packet is required.

It reads ./.hunt state, auto-runs every SAFE, non-network tool for the current phase (smell,
hypothesize, corpus rank, memory recall, assume-break, capability-graph, chain-plan), advancing until
it reaches a gate it must not cross autonomously — HUNT (live requests), VALIDATE/REPORT (judgment),
or a missing input. Then it prints a briefing + the exact next human action. Safe by construction:
it never sends a request (that's exec-http through scope-guard) and never submits.

Usage:  hunt-agent.py [--stack saas,fintech] [--recall-file some-response.txt] [--endpoint /api/..]
Exit: 0 reached a natural checkpoint (briefing printed).
"""
import sys, os, subprocess
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def has(name):
    p = HUNT / name
    return p.exists() and p.stat().st_size > 0


def run(title, cmd):
    cmd = [str(c) for c in cmd]
    if cmd and cmd[0].endswith(".py"):
        cmd = [sys.executable] + cmd
    print(f"\n▶ {title}\n  $ {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    for ln in out.strip().splitlines():
        print("  " + ln)
    return r.returncode, out


def T(name):
    return str(TOOLS / name)


def main():
    stack = arg("--stack", "generic")
    print("══ HUNT-AGENT — autonomous analysis run ══════════════════")
    print(f"  state: {HUNT}   stack: {stack}")

    if not has("scope.allow"):
        print("\n⛔ CHECKPOINT (needs you): no scope.\n"
              "  → paste the program page:  pbpaste | hunt-intake.py\n"
              "  (I can't fetch scope or fire anything until scope.allow exists.)")
        return

    ran = []

    if not has("signals.json"):
        print("\n⛔ CHECKPOINT (needs recon input): scope set but no signals.json.\n"
              "  → run recon and feed it:  recon-aggregate.py --urls gau.txt --js app.js --subs subs.txt --stack " + stack)
        return

    # PHASE 3b — HYPOTHESIZE bundle (all safe, no network)
    if has("surface.txt"):
        run("smell — rank surface by suspicion", [T("smell.py"), "--file", str(HUNT / "surface.txt"), "--top", "15"])
        ran.append("smell")
    rf = arg("--recall-file")
    if rf and Path(rf).exists():
        run("memory — recall analogous past hunts", [T("hunt-memory.py"), "--recall", "--file", rf, "--stack", stack, "--k", "5"])
        ran.append("memory-recall")
    run("hypothesize — signal ⇒ likely bug ⇒ test", [T("hunt-hypothesize.py"), "--signals", str(HUNT / "signals.json"),
        "--stack", stack, "--emit", str(HUNT / "hypotheses.tsv"), "--top", "20"])
    ran.append("hypothesize")
    run("corpus — EV-ranked suggestions from paid history", [T("hunt-corpus.py"), "--suggest", "--rank", "--stack", stack])
    ran.append("corpus-rank")
    run("outcome — class hunt-order by expected value", [T("outcome-check.py"), "--rank", "--stack", stack, "--top", "10"])
    ran.append("ev-rank")
    ep = arg("--endpoint")
    if ep:
        run("assume-break — violate the developer's assumptions on this feature",
            [T("assume-break.py"), "--endpoint", ep, "--emit", str(HUNT / "hypotheses.tsv")])
        ran.append("assume-break")

    # PHASE 5d — CHAIN (safe: reads capabilities.tsv)
    if has("capabilities.tsv"):
        run("capability-graph — reachable impact", [T("capability-graph.py")])
        run("chain-plan — goal-driven next primitive", [T("chain-plan.py")])
        ran.append("chain-plan")

    # Now the gate the agent must not cross autonomously
    print("\n" + "═" * 58)
    print(f"✓ autonomous analysis done — ran: {', '.join(ran)}")
    print("\n⛔ CHECKPOINT (needs you / live requests): HUNT phase.")
    print("  The plan is in ./.hunt/hypotheses.tsv, ranked. To execute (evidence-bound, scope-gated):")
    print("    exec-http.py --url <in-scope-url> --identity <name>            # single, auto-captured")
    print("    exec-http.py --url <url> --diff admin,low-priv --expect deny   # run as 2 identities → auto access-bug check")
    print("    exec-http.py --url '<url>?p=' --waf '<payload>'                # bypass a WAF block")
    print("    reflect.py --class <c> --endpoint <e> --tried ... --attempts N --evidence <path>  # before marking TESTED")
    print("  Then: adversarial-verify.py → poc-synth.py → dedup-check.py → report.")
    print("\n  (I stop here on purpose: firing packets and submitting are your call, not mine.)")


if __name__ == "__main__":
    main()
