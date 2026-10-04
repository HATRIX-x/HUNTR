#!/usr/bin/env python3
"""
hunt-learn — the fleet learning loop.

Aggregates operator-reported finding OUTCOMES (accepted / duplicate / n-a / rejected / paid)
into calibrated priors per vuln-class and per class|stack:
  • p_accept   — share of decided outcomes that were accepted (or paid)
  • p_dup      — share that were duplicates
  • avg_bounty — mean paid bounty (when paid outcomes carry an amount)

The economics brain (phase_economics) and the chain planner read these priors, so HUNTR's
EV ranking and escalation choices get sharper with every hunt — per stack and per program.
Outcomes are real, operator-reported results; this calibrates from them, it does not invent.

Store (global, so it compounds across every target — the single-user form of the fleet loop):
  ~/.huntr/corpus/outcomes.jsonl   (one JSON record per line, appended by /api/outcome)
  ~/.huntr/corpus/priors.json      (this tool's output)

Usage:  hunt-learn.py [--outcomes PATH] [--out PATH] [--json]
"""
import sys, os, json, time
from pathlib import Path

ROOT = Path(os.environ.get("HUNTR_HOME", str(Path.home() / ".huntr")))
CORP = ROOT / "corpus"
try:
    CORP.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


OUTC = Path(arg("--outcomes", str(CORP / "outcomes.jsonl")))
PRI = Path(arg("--out", str(CORP / "priors.json")))
DECIDED = {"accepted", "paid", "duplicate", "na", "rejected"}


def aggregate(records):
    buckets = {}

    def bk(key):
        return buckets.setdefault(key, {"n": 0, "accepted": 0, "duplicate": 0, "na": 0, "rejected": 0, "paid_n": 0, "paid_sum": 0.0})

    for r in records:
        o = (r.get("outcome") or "").lower()
        if o not in DECIDED:
            continue
        cls = (r.get("cls") or "misc").lower().strip() or "misc"
        stack = (r.get("stack") or "").lower().strip()
        keys = ["cls|" + cls, "global"]
        if stack:
            keys.append("cs|" + cls + "|" + stack)
        for k in keys:
            d = bk(k); d["n"] += 1
            if o in ("accepted", "paid"):
                d["accepted"] += 1
            if o == "duplicate":
                d["duplicate"] += 1
            if o == "na":
                d["na"] += 1
            if o == "rejected":
                d["rejected"] += 1
            if o == "paid":
                try:
                    amt = float(r.get("bounty") or 0)
                except Exception:
                    amt = 0.0
                if amt > 0:
                    d["paid_n"] += 1; d["paid_sum"] += amt

    out = {}
    for k, d in buckets.items():
        n = d["n"] or 1
        out[k] = {"n": d["n"],
                  "p_accept": round(d["accepted"] / n, 3),
                  "p_dup": round(d["duplicate"] / n, 3),
                  "avg_bounty": int(round(d["paid_sum"] / d["paid_n"])) if d["paid_n"] else None}
    return out


def main():
    recs = []
    if OUTC.exists():
        for ln in OUTC.read_text(errors="ignore").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                recs.append(json.loads(ln))
            except Exception:
                pass
    decided = [r for r in recs if (r.get("outcome") or "").lower() in DECIDED]
    priors = {"generated": time.time(), "total": len(decided), "buckets": aggregate(recs)}
    try:
        PRI.write_text(json.dumps(priors, indent=2))
    except Exception as e:
        print("[hunt-learn] write failed: " + str(e)[:120]); return
    if "--json" in sys.argv:
        print(json.dumps(priors))
    else:
        print("[hunt-learn] " + str(priors["total"]) + " decided outcome(s) → " +
              str(len(priors["buckets"])) + " calibrated bucket(s) → " + str(PRI))


if __name__ == "__main__":
    main()
