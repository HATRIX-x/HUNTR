#!/usr/bin/env python3
"""
rate-governor — a global + per-program traffic budget that sits ABOVE every probe,
so an automated hunt can never hammer a target or blow a program's rate rules.

Token-bucket per scope (global + per-program), persisted so concurrent tools share
one budget. A tool asks to spend N requests; the governor grants what the bucket
allows and returns how long to wait for the rest. Refill is continuous.

State: $HUNT_RATE or ~/.claude/hunt-rate/buckets.json
Config a bucket:  --set --program acme --rps 3 --burst 30
Ask to spend:     --acquire 10 --program acme        → {granted, wait_seconds, ...}
Inspect:          --status [--program acme]
Reset:            --reset [--program acme]

Defaults (if no bucket configured): global rps=8 burst=40, program rps=4 burst=20.

Usage:
  rate-governor.py --acquire 5 --program acme [--json]
Exit: 0 fully granted · 1 partially/deferred (wait_seconds>0).
"""
import sys, os, json, time
from pathlib import Path

STATE = Path(os.environ.get("HUNT_RATE", str(Path.home() / ".claude" / "hunt-rate")))
BUCKETS = STATE / "buckets.json"
DEFAULT_GLOBAL = {"rps": 8.0, "burst": 40.0}
DEFAULT_PROGRAM = {"rps": 4.0, "burst": 20.0}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def load():
    if BUCKETS.exists():
        try:
            return json.loads(BUCKETS.read_text())
        except Exception:
            pass
    return {"buckets": {}}


def save(state):
    STATE.mkdir(parents=True, exist_ok=True)
    BUCKETS.write_text(json.dumps(state, indent=2))


def get_bucket(state, key, default):
    b = state["buckets"].get(key)
    if not b:
        b = {"rps": default["rps"], "burst": default["burst"],
             "tokens": default["burst"], "ts": time.time()}
        state["buckets"][key] = b
    return b


def refill(b):
    now = time.time()
    elapsed = max(0.0, now - b.get("ts", now))
    b["tokens"] = min(b["burst"], b.get("tokens", 0.0) + elapsed * b["rps"])
    b["ts"] = now


def main():
    program = arg("--program")
    state = load()

    if flag("--set"):
        key = f"program:{program}" if program else "global"
        default = DEFAULT_PROGRAM if program else DEFAULT_GLOBAL
        b = get_bucket(state, key, default)
        if arg("--rps"): b["rps"] = float(arg("--rps"))
        if arg("--burst"): b["burst"] = float(arg("--burst"))
        b["tokens"] = min(b["tokens"], b["burst"])
        save(state)
        out = {"ok": True, "set": key, "rps": b["rps"], "burst": b["burst"]}
        print(json.dumps(out) if flag("--json") else f"set {key}: rps={b['rps']} burst={b['burst']}")
        sys.exit(0)

    if flag("--reset"):
        if program:
            state["buckets"].pop(f"program:{program}", None)
        else:
            state["buckets"] = {}
        save(state)
        print(json.dumps({"ok": True, "reset": program or "all"}) if flag("--json")
              else f"reset {program or 'all'}")
        sys.exit(0)

    if flag("--status"):
        keys = [f"program:{program}"] if program else list(state["buckets"].keys()) or ["global"]
        rows = []
        for key in keys:
            default = DEFAULT_PROGRAM if key.startswith("program:") else DEFAULT_GLOBAL
            b = get_bucket(state, key, default)
            refill(b)
            rows.append({"scope": key, "rps": b["rps"], "burst": b["burst"],
                         "tokens": round(b["tokens"], 2)})
        save(state)
        print(json.dumps({"ok": True, "buckets": rows}) if flag("--json")
              else "\n".join(f"  {r['scope']:<20} tokens {r['tokens']:.1f}/{r['burst']} @ {r['rps']}rps" for r in rows))
        sys.exit(0)

    # default action: acquire
    want = float(arg("--acquire", "1"))
    scopes = [("global", DEFAULT_GLOBAL)]
    if program:
        scopes.append((f"program:{program}", DEFAULT_PROGRAM))

    granted = want
    waits = []
    for key, default in scopes:
        b = get_bucket(state, key, default)
        refill(b)
        can = min(want, b["tokens"])
        granted = min(granted, can)
        if want > b["tokens"]:
            waits.append((want - b["tokens"]) / b["rps"])

    granted = max(0.0, int(granted))
    for key, default in scopes:
        b = get_bucket(state, key, default)
        b["tokens"] = max(0.0, b["tokens"] - granted)
    save(state)

    wait_seconds = round(max(waits), 2) if waits else 0.0
    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "program": program, "requested": want,
        "granted": granted, "deferred": want - granted,
        "wait_seconds": wait_seconds,
        "advice": "spend granted now; sleep wait_seconds then re-acquire the rest",
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0 if wait_seconds == 0 else 1)

    print(f"granted {granted}/{int(want)}  wait {wait_seconds}s"
          + (f"  (program {program})" if program else ""))
    sys.exit(0 if wait_seconds == 0 else 1)


if __name__ == "__main__":
    main()
