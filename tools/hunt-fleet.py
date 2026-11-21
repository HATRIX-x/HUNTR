#!/usr/bin/env python3
"""
hunt-fleet — the distributed fleet controller (XBOW-scale parallelism, self-hosted).

Enqueues targets into the shared sqlite queue and launches N worker processes that each run the FULL
agentic engine, pulling jobs until the queue drains. Workers share one brain (hunt-corpus/hunt-brain)
and ONE bounded LLM slot pool (so N parallel hunts never blow the account rate limit). The same queue
(HUNTR_FLEET_DB on shared storage) can be worked by workers on other machines/cloud nodes — scale out
by adding workers, nothing else changes.

Usage:
  hunt-fleet.py --targets targets.txt --workers 8 [--llm-slots 4] [--budget 3600] [--mode grey]
  hunt-fleet.py --target a.com --target b.com --workers 4
  hunt-fleet.py --status              # show the live queue
"""
import sys, os, json, time, subprocess, re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def args_all(n):
    return [sys.argv[i + 1] for i, x in enumerate(sys.argv) if x == n and i + 1 < len(sys.argv)]


def q(*a):
    r = subprocess.run([sys.executable, str(HERE / "hunt-queue.py")] + list(a), capture_output=True, text=True, timeout=40)
    try:
        return json.loads((r.stdout or "{}").strip().splitlines()[-1])
    except Exception:
        return {}


def main():
    if "--status" in sys.argv:
        subprocess.run([sys.executable, str(HERE / "hunt-queue.py"), "status"])
        return

    # enqueue
    targets = args_all("--target")
    added = 0
    if arg("--targets"):
        q("add", "--file", arg("--targets"), "--mode", arg("--mode", "grey"), "--budget", arg("--budget", "3600"))
    for t in targets:
        q("add", "--target", t, "--mode", arg("--mode", "grey"), "--budget", arg("--budget", "3600"),
          "--program", arg("--program", ""))
    st = q("status", "--json")
    queued = st.get("counts", {}).get("queued", 0)
    if not queued:
        print("nothing queued"); return

    workers = int(arg("--workers", "4") or 4)
    llm_slots = int(arg("--llm-slots", str(min(workers, 4))) or 4)
    print("fleet: %d queued · %d workers · LLM pool=%d slots" % (queued, workers, llm_slots), flush=True)

    env = dict(os.environ, HUNTR_LLM_SLOTS=str(llm_slots))
    procs = []
    logdir = Path.home() / ".huntr" / "fleet" / "logs"; logdir.mkdir(parents=True, exist_ok=True)
    for i in range(workers):
        lf = open(logdir / ("worker%d.log" % i), "a")
        p = subprocess.Popen([sys.executable, str(HERE / "hunt-worker.py"), "--worker", "w%d" % i],
                             stdout=lf, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        procs.append(p); time.sleep(0.4)

    # monitor until all workers exit (queue drained)
    try:
        while any(p.poll() is None for p in procs):
            time.sleep(10)
            s = q("status", "--json")
            c = s.get("counts", {})
            print("  …running=%s queued=%s done=%s" % (c.get("running", 0), c.get("queued", 0), c.get("done", 0)), flush=True)
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()

    s = q("status", "--json")
    jobs = s.get("jobs", [])
    done = [j for j in jobs if j.get("status") == "done" and j.get("result")]
    tf = sum(j["result"].get("findings", 0) for j in done)
    tp = sum(j["result"].get("proven", 0) for j in done)
    print("\n=== FLEET DONE ===", flush=True)
    print("  %d targets · %d findings · %d PROVEN" % (len(done), tf, tp), flush=True)
    for j in jobs:
        res = j.get("result") or {}
        print("  #%-3d %-26s %-8s findings=%s proven=%s" % (j["id"], str(j["target"])[:26], j["status"],
              res.get("findings", "?"), res.get("proven", "?")), flush=True)


if __name__ == "__main__":
    main()
