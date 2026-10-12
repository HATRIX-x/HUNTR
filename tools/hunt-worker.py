#!/usr/bin/env python3
"""
hunt-worker — a fleet worker. Pulls jobs from the shared queue and runs the FULL agentic engine on
each (not a lite worker), then reports the result. Run many of these — on one box or across machines
pointed at the same queue (HUNTR_FLEET_DB on shared storage) — for XBOW-scale parallelism. All
workers share one brain (hunt-corpus/hunt-brain) so a win on one target instantly informs the rest,
and one global LLM slot pool (HUNTR_LLM_SLOTS) so N workers never blow the account rate limit.

Usage: hunt-worker.py --worker w1 [--forever] [--poll 10]
"""
import sys, os, json, time, subprocess, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path.home()
TARGETS = HOME / ".huntr" / "targets"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


def safe(t):
    s = re.sub(r"[^a-z0-9._-]+", "_", (t or "default").lower()).strip("_") or "default"
    # Bound the workspace dir name: a pasted program page (thousands of chars) as the "target" made
    # mkdir() raise "File name too long" and crash. Cap length and append a short hash of the full
    # input so distinct long inputs stay unique. Keep in sync with huntr-server.py:safe.
    if len(s) > 80:
        import hashlib
        s = s[:72] + "_" + hashlib.sha1((t or "").encode("utf-8", "ignore")).hexdigest()[:8]
    return s


WORKER = arg("--worker", "w" + str(os.getpid()))
POLL = int(arg("--poll", "10") or 10)


def q(*a):
    try:
        r = subprocess.run([sys.executable, str(HERE / "hunt-queue.py")] + list(a), capture_output=True, text=True, timeout=40)
        return json.loads((r.stdout or "{}").strip().splitlines()[-1])
    except Exception:
        return {}


def run_job(job):
    t = job["target"]; hd = TARGETS / safe(t) / ".hunt"; hd.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HUNT_DIR=str(hd))
    a = [sys.executable, str(HERE / "hunt-run.py"), "--target", t, "--mode", job.get("mode", "grey"),
         "--budget-sec", str(job.get("budget", 3600))]
    if job.get("program"):
        a += ["--program", job["program"]]
    lf = open(hd / "run.log", "a")
    try:
        subprocess.run(a, stdout=lf, stderr=lf, env=env, timeout=int(job.get("budget", 3600)) + 900)
        status = "done"
    except Exception as e:
        status = "error:" + str(e)[:60]
    res = {"findings": 0, "confirmed": 0, "proven": 0}
    try:
        d = json.loads((hd / "run.json").read_text()); fs = d.get("findings", [])
        res = {"findings": len(fs),
               "confirmed": sum(1 for f in fs if f.get("verdict") in ("confirmed", "likely")),
               "proven": sum(1 for f in fs if f.get("proven")),
               "status": d.get("status", status)}
    except Exception:
        pass
    q("complete", "--id", str(job["id"]), "--status", status, "--result", json.dumps(res))
    return res


def main():
    print("worker %s online" % WORKER, flush=True)
    idle = 0
    while True:
        job = q("claim", "--worker", WORKER)
        if not job or "id" not in job:
            if not flag("--forever"):
                print("worker %s: queue empty, exiting" % WORKER, flush=True); return
            idle += 1
            time.sleep(POLL); continue
        idle = 0
        print("worker %s → job #%s %s" % (WORKER, job["id"], job["target"]), flush=True)
        res = run_job(job)
        print("worker %s ✓ #%s %s findings=%s proven=%s" % (WORKER, job["id"], job["target"],
              res.get("findings"), res.get("proven")), flush=True)


if __name__ == "__main__":
    main()
