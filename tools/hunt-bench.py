#!/usr/bin/env python3
"""
hunt-bench — turn "it only worked on Shiji" into a measured, growing track record.

The engine's edge can't be one anecdote. This runs the safe analysis pipeline across every target
workspace, logs a per-target scorecard, and — the real metric — records validated WINS: a bug the
engine surfaced that your old workflow missed. Over 5-10 programs, the aggregate is the proof.

Stores: ~/.claude/hunt-bench/results.jsonl (per-run scorecards) · wins.jsonl (validated edge)

Usage:
  hunt-bench.py --run [--home ~/.huntr] [--stack generic]      # analyse every target workspace, log scores
  hunt-bench.py --record-win --target shiji --sev high --note "F60 ATO the manual pass missed" [--reward 0]
  hunt-bench.py --report                                        # aggregate track record
Exit: 0.
"""
import sys, os, json, time, subprocess
from pathlib import Path

TOOLS = Path(__file__).parent
BENCH = Path(os.environ.get("HUNT_BENCH", str(Path.home() / ".claude" / "hunt-bench")))
RESULTS = BENCH / "results.jsonl"
WINS = BENCH / "wins.jsonl"
HOME = Path(os.environ.get("HUNTR_HOME", str(Path.home() / ".huntr"))) / "targets"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def jl(p):
    out = []
    if p.exists():
        for ln in p.read_text().splitlines():
            if ln.strip():
                try: out.append(json.loads(ln))
                except Exception: pass
    return out


def count_lines(p):
    return sum(1 for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")) if p.exists() else 0


def workspaces():
    if arg("--targets"):
        return [(l.strip(), None) for l in Path(arg("--targets")).read_text().splitlines() if l.strip()]
    out = []
    if HOME.exists():
        for d in sorted(HOME.iterdir()):
            if (d / ".hunt").exists():
                out.append((d.name, d / ".hunt"))
    return out


def cmd_run():
    stack = arg("--stack", "generic")
    ws = workspaces()
    if not ws:
        sys.exit(f"[bench] no target workspaces under {HOME}. Create some via hunt-intake / the app first.")
    BENCH.mkdir(parents=True, exist_ok=True)
    print(f"[bench] analysing {len(ws)} target(s)…\n")
    for name, hd in ws:
        if hd is None:
            continue
        env = dict(os.environ, HUNT_DIR=str(hd))
        t0 = time.time()
        subprocess.run([sys.executable, str(TOOLS / "hunt-agent.py"), "--stack", stack],
                       capture_output=True, text=True, env=env, timeout=180)
        hyps = count_lines(hd / "hypotheses.tsv")
        finds = len(list((hd / "findings").glob("F*.md"))) if (hd / "findings").exists() else 0
        rec = {"target": name, "hypotheses": hyps, "findings": finds,
               "secs": round(time.time() - t0, 1), "ts": time.strftime("%Y-%m-%d %H:%M")}
        with RESULTS.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        print(f"  {name:<28} {hyps:>3} leads · {finds:>2} findings · {rec['secs']}s")
    print("\n[bench] logged → results.jsonl. Record any real edge with --record-win.")


def cmd_win():
    BENCH.mkdir(parents=True, exist_ok=True)
    rec = {"target": arg("--target", "?"), "sev": arg("--sev", "?"), "note": arg("--note", ""),
           "reward": float(arg("--reward", "0") or 0), "ts": time.strftime("%Y-%m-%d")}
    if rec["target"] == "?" or not rec["note"]:
        sys.exit("usage: --record-win --target T --sev high --note 'what it found that the old way missed'")
    with WINS.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[bench] ✓ win recorded: {rec['target']} · {rec['sev']} · {rec['note']}")


def cmd_report():
    res = jl(RESULTS); wins = jl(WINS)
    targets = sorted({r["target"] for r in res})
    print("══ HUNT-BENCH — track record ══════════════════════════════")
    print(f"  targets analysed: {len(targets)}   runs: {len(res)}   validated wins: {len(wins)}")
    if res:
        latest = {}
        for r in res:
            latest[r["target"]] = r
        tot_h = sum(r["hypotheses"] for r in latest.values())
        tot_f = sum(r["findings"] for r in latest.values())
        print(f"  leads generated: {tot_h}   findings: {tot_f}   avg leads/target: {tot_h/max(1,len(latest)):.1f}\n")
        print(f"  {'TARGET':<28}{'leads':>6}{'findings':>10}{'last run':>18}")
        for t in sorted(latest):
            r = latest[t]
            print(f"  {t[:27]:<28}{r['hypotheses']:>6}{r['findings']:>10}{r['ts']:>18}")
    if wins:
        paid = sum(w["reward"] for w in wins)
        print(f"\n  ── validated edge ({len(wins)} wins{', $%.0f' % paid if paid else ''}) ──")
        for w in wins:
            print(f"   ✓ [{w['sev']}] {w['target']}: {w['note']}{'  $%.0f' % w['reward'] if w['reward'] else ''}")
    else:
        print("\n  (no validated wins yet — as you confirm bugs the engine found that you'd have missed,")
        print("   log them: hunt-bench.py --record-win … — that aggregate IS the proof.)")
    n = len(targets)
    print("\n  " + ("✓ breadth building — keep adding targets." if n >= 5 else
                    f"⚠ only {n} target(s). Run 5-10 varied programs before claiming the edge generalises."))


def main():
    if "--run" in sys.argv: return cmd_run()
    if "--record-win" in sys.argv: return cmd_win()
    if "--report" in sys.argv: return cmd_report()
    print(__doc__)


if __name__ == "__main__":
    main()
