#!/usr/bin/env python3
"""
hunt-watch — CONTINUOUS monitoring: watch a target's attack surface, re-hunt on a schedule, and
alert on drift (XBOW-style ASM, self-hosted).

Each cycle it refreshes the surface (a light recon/resume of the engine), diffs it against the stored
baseline, and when NEW endpoints or NEW findings appear it fires an alert (notify.py → Slack/Discord/
webhook) and — with --auto-hunt — launches a focused hunt on exactly the new surface. New surface is
where first-to-report bounties live, so "it appeared → you were told → it was hunted" is the whole point.

Writes live state to <hunt>/watch.json so the dashboard can show the monitor.

Usage:
  hunt-watch.py --target acme.com --interval 3600 [--auto-hunt] [--budget-sec 600] [--once]
"""
import sys, os, json, time, subprocess, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path.home()


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


TARGET = arg("--target")
if not TARGET:
    print(json.dumps({"ok": False, "error": "need --target"})); sys.exit(1)
INTERVAL = int(arg("--interval", "3600") or 3600)
BUDGET = int(arg("--budget-sec", "600") or 600)
AUTO = flag("--auto-hunt")
HD = HOME / ".huntr" / "targets" / safe(TARGET) / ".hunt"
HD.mkdir(parents=True, exist_ok=True)
RUN = HD / "run.json"
WATCH = HD / "watch.json"
BASE = HD / "watch_baseline.json"


def read_run():
    try:
        return json.loads(RUN.read_text())
    except Exception:
        return {}


def surface(d):
    eps = set(e if isinstance(e, str) else e.get("url", "") for e in (d.get("endpoints") or []))
    finds = set((f.get("title", ""), f.get("endpoint", "")) for f in (d.get("findings") or [])
                if f.get("verdict") != "false_positive")
    return eps, finds


def alert(title, text, sev="info"):
    try:
        subprocess.run([sys.executable, str(HERE / "notify.py"), "--title", title, "--text", text,
                        "--severity", sev], capture_output=True, text=True, timeout=20, env=os.environ)
    except Exception:
        pass


def refresh():
    """Light engine refresh — resume the hunt with a short budget so it re-recons and picks up new surface."""
    env = dict(os.environ, HUNT_DIR=str(HD))
    a = [sys.executable, str(HERE / "hunt-run.py"), "--target", TARGET, "--budget-sec", str(BUDGET), "--no-polish"]
    try:
        subprocess.run(a, capture_output=True, text=True, timeout=BUDGET + 300, env=env)
    except Exception:
        pass


def state(status, extra=None):
    s = {"target": TARGET, "status": status, "interval": INTERVAL, "auto_hunt": AUTO,
         "updated": int(time.time())}
    if extra:
        s.update(extra)
    try:
        WATCH.write_text(json.dumps(s))
    except Exception:
        pass


def cycle():
    state("refreshing")
    refresh()
    d = read_run()
    cur_eps, cur_finds = surface(d)
    try:
        base = json.loads(BASE.read_text()) if BASE.exists() else None
    except Exception:
        base = None
    if base is None:
        BASE.write_text(json.dumps({"ts": int(time.time()), "endpoints": sorted(cur_eps),
                                    "findings": [list(x) for x in cur_finds]}))
        state("baseline-set", {"endpoints": len(cur_eps), "findings": len(cur_finds)})
        return {"baseline": True}
    b_eps = set(base.get("endpoints") or [])
    b_finds = set(tuple(x) for x in (base.get("findings") or []))
    new_eps = sorted(cur_eps - b_eps)
    new_finds = [{"title": t, "endpoint": e} for (t, e) in (cur_finds - b_finds)]
    if new_eps or new_finds:
        msg = ("%d new endpoint(s), %d new finding(s) on %s" % (len(new_eps), len(new_finds), TARGET))
        alert("HUNTR drift: " + TARGET, msg + "\n" +
              "\n".join(new_eps[:15]) + ("\n…" if len(new_eps) > 15 else ""),
              sev="high" if new_finds else "info")
        if AUTO and new_eps:
            # focused hunt on the new surface only
            env = dict(os.environ, HUNT_DIR=str(HD))
            try:
                subprocess.Popen([sys.executable, str(HERE / "hunt-run.py"), "--target", TARGET,
                                  "--budget-sec", str(BUDGET)], env=env,
                                 stdout=open(HD / "run.log", "a"), stderr=subprocess.STDOUT)
            except Exception:
                pass
    # update baseline to current
    BASE.write_text(json.dumps({"ts": int(time.time()), "endpoints": sorted(cur_eps),
                                "findings": [list(x) for x in cur_finds]}))
    state("watching", {"endpoints": len(cur_eps), "findings": len(cur_finds),
                       "last_new_endpoints": len(new_eps), "last_new_findings": len(new_finds)})
    return {"new_endpoints": new_eps, "new_findings": new_finds}


def main():
    if flag("--once"):
        r = cycle()
        print(json.dumps({"ok": True, **r})); return
    state("watching")
    (HD / "watch.pid").write_text(str(os.getpid()))
    while True:
        try:
            cycle()
        except Exception as e:
            state("error", {"error": str(e)[:160]})
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
