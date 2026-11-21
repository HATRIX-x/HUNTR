#!/usr/bin/env python3
"""
hunt-queue — the distributed fleet's job queue (sqlite, atomic claims).

A durable, concurrency-safe work queue so MANY workers — on one box or across machines/cloud (point
them at shared storage) — pull targets and run the full engine without stepping on each other. This is
the backbone that turns HUNTR from "one hunt at a time" into XBOW-scale parallelism.

DB: ~/.huntr/fleet/queue.db   (override with HUNTR_FLEET_DB)
Usage:
  hunt-queue.py add --target acme.com [--program P] [--mode grey] [--budget 3600]
  hunt-queue.py add --file targets.txt
  hunt-queue.py claim --worker w1        # atomic: marks one queued job 'running', prints it (JSON) or {}
  hunt-queue.py complete --id 7 --status done --result '{"findings":3,"proven":2}'
  hunt-queue.py status [--json]
  hunt-queue.py reset  --id 7            # requeue a stuck job
"""
import sys, os, json, time, sqlite3, re
from pathlib import Path

DB = Path(os.environ.get("HUNTR_FLEET_DB", str(Path.home() / ".huntr" / "fleet" / "queue.db")))
DB.parent.mkdir(parents=True, exist_ok=True)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def db():
    c = sqlite3.connect(str(DB), timeout=30)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS jobs(
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, program TEXT, mode TEXT,
        budget INTEGER, status TEXT DEFAULT 'queued', worker TEXT,
        queued REAL, started REAL, finished REAL, result TEXT, attempts INTEGER DEFAULT 0)""")
    return c


def cmd_add():
    c = db(); n = 0
    targets = []
    if arg("--file") and Path(arg("--file")).exists():
        targets += [l.strip() for l in Path(arg("--file")).read_text().splitlines() if l.strip() and not l.startswith("#")]
    if arg("--target"):
        targets.append(arg("--target"))
    for t in dict.fromkeys(targets):
        c.execute("INSERT INTO jobs(target,program,mode,budget,status,queued) VALUES(?,?,?,?, 'queued', ?)",
                  (t, arg("--program", ""), arg("--mode", "grey"), int(arg("--budget", "3600") or 3600), time.time()))
        n += 1
    c.commit()
    print(json.dumps({"ok": True, "added": n}))


def cmd_claim():
    worker = arg("--worker", "w?")
    c = db()
    # atomic claim: one UPDATE grabs the oldest queued row for this worker
    cur = c.execute("""UPDATE jobs SET status='running', worker=?, started=?, attempts=attempts+1
                       WHERE id=(SELECT id FROM jobs WHERE status='queued' ORDER BY id LIMIT 1)
                       RETURNING id,target,program,mode,budget""", (worker, time.time()))
    row = cur.fetchone()
    c.commit()
    if not row:
        print(json.dumps({})); return
    print(json.dumps({"id": row[0], "target": row[1], "program": row[2], "mode": row[3], "budget": row[4]}))


def cmd_complete():
    c = db()
    c.execute("UPDATE jobs SET status=?, finished=?, result=? WHERE id=?",
              (arg("--status", "done"), time.time(), arg("--result", "{}"), int(arg("--id"))))
    c.commit()
    print(json.dumps({"ok": True}))


def cmd_reset():
    c = db()
    c.execute("UPDATE jobs SET status='queued', worker=NULL WHERE id=?", (int(arg("--id")),))
    c.commit()
    print(json.dumps({"ok": True}))


def cmd_status():
    c = db()
    rows = c.execute("SELECT id,target,status,worker,result FROM jobs ORDER BY id").fetchall()
    counts = {}
    for r in rows:
        counts[r[2]] = counts.get(r[2], 0) + 1
    agg = {"ok": True, "total": len(rows), "counts": counts,
           "jobs": [{"id": r[0], "target": r[1], "status": r[2], "worker": r[3],
                     "result": (json.loads(r[4]) if r[4] else None)} for r in rows]}
    if "--json" in sys.argv:
        print(json.dumps(agg)); return
    print("fleet queue: %d jobs · %s" % (len(rows), ", ".join("%s=%d" % kv for kv in counts.items())))
    for j in agg["jobs"]:
        res = j["result"] or {}
        print("  #%-3d %-26s %-9s %s  %s" % (j["id"], str(j["target"])[:26], j["status"], j["worker"] or "",
              ("findings=%s proven=%s" % (res.get("findings", "?"), res.get("proven", "?")) if res else "")))


CMDS = {"add": cmd_add, "claim": cmd_claim, "complete": cmd_complete, "reset": cmd_reset, "status": cmd_status}
if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else "status"
    (CMDS.get(c) or cmd_status)()
