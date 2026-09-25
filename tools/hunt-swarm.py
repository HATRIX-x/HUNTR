#!/usr/bin/env python3
"""
hunt-swarm — one brain, many hands. Fan the autonomous analysis out across a whole scope in parallel.

A single hunter is one mind; a swarm covers a 50-host scope at once. This sets up an isolated ./.hunt-<host>/
per in-scope host and runs hunt-agent on each concurrently. They all share ONE brain — the global corpus,
memory, and outcome history (~/.claude/hunt-corpus) — so a technique that pays on host A instantly informs
host B. Then it aggregates a per-host briefing.

Each worker is safe by construction (hunt-agent never fires packets or submits — it stops at the HUNT gate).

Usage:
  hunt-swarm.py --scope scope.txt [--stack saas] [--parallel 4] [--signals-dir ./recon]
     scope.txt      one host per line (or reuse ./.hunt/scope.allow)
     --signals-dir  optional dir with <host>.signals.json produced by recon-aggregate per host
Exit: 0.
"""
import sys, os, re, json, subprocess, time
from pathlib import Path

TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def safe(h):
    return re.sub(r"[^a-z0-9.-]+", "_", h.lower())


def hosts():
    f = arg("--scope")
    if f:
        return [l.strip() for l in Path(f).read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    al = Path("./.hunt/scope.allow")
    if al.exists():
        return [l.strip() for l in al.read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    sys.exit("provide --scope hosts.txt or run from a dir with ./.hunt/scope.allow")


def main():
    hs = hosts()
    stack = arg("--stack", "generic")
    par = int(arg("--parallel", "4") or 4)
    sigdir = arg("--signals-dir")
    base = Path(".")
    print(f"══ HUNT-SWARM — {len(hs)} host(s), up to {par} in parallel, shared brain ══\n")

    jobs = []
    for h in hs:
        hd = base / f".hunt-{safe(h)}"
        (hd).mkdir(exist_ok=True)
        (hd / "scope.allow").write_text(h + "\n")
        # per-host signals: from recon dir if given, else a minimal stub so hypothesize still runs
        sig = hd / "signals.json"
        src = Path(sigdir) / f"{safe(h)}.signals.json" if sigdir else None
        if src and src.exists():
            sig.write_text(src.read_text())
        elif not sig.exists():
            sig.write_text(json.dumps({"tech": [], "endpoints": [], "fields": [], "roles": [],
                                       "notes": f"host={h}; stack={stack}"}))
        jobs.append((h, hd))

    running, done = [], []
    i = 0
    while i < len(jobs) or running:
        while i < len(jobs) and len(running) < par:
            h, hd = jobs[i]; i += 1
            env = dict(os.environ, HUNT_DIR=str(hd))
            log = open(hd / "agent.log", "w")
            p = subprocess.Popen([sys.executable, str(TOOLS / "hunt-agent.py"), "--stack", stack],
                                 stdout=log, stderr=subprocess.STDOUT, env=env)
            running.append((h, hd, p, log))
            print(f"  ▶ launched worker: {h}  → {hd}")
        for tup in running[:]:
            h, hd, p, log = tup
            if p.poll() is not None:
                log.close(); running.remove(tup); done.append((h, hd))
        time.sleep(0.3)

    print(f"\n══ AGGREGATE ({len(done)} workers finished) ══")
    for h, hd in done:
        hyp = hd / "hypotheses.tsv"
        n = sum(1 for ln in hyp.read_text().splitlines() if ln.strip() and not ln.startswith("#")) if hyp.exists() else 0
        tail = ""
        alog = hd / "agent.log"
        if alog.exists():
            for ln in alog.read_text().splitlines():
                if "CHECKPOINT" in ln:
                    tail = ln.strip(); break
        print(f"  {h:<32} {n:>3} leads   {tail or 'see ' + str(hd / 'agent.log')}")
    print("\n  shared brain: all workers read/write the same corpus+memory+outcomes — cross-host learning is automatic.")
    print("  → pick the host with the most/highest-EV leads, cd to its .hunt dir, and drive exec-http.py from there.")


if __name__ == "__main__":
    main()
