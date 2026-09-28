#!/usr/bin/env python3
"""
funnel — turn "detection accuracy" from a guess into a measured number.

Logs each finding through its real lifecycle and computes the rates that matter:

    flagged ─▶ confirmed ─▶ submitted ─▶ ┬─ accepted (real & unique)
                                          ├─ dupe     (real, not first)
                                          └─ rejected (N/A / informative → false positive)

From that it derives:
  · false-positive rate  = rejected / (accepted + dupe + rejected)   — of everything a
    program adjudicated, how much it deemed not-a-bug. This is the honest FP number.
  · acceptance rate      = accepted / submitted
  · unique rate          = accepted / (accepted + dupe)
  · flag→submit ratio    = submitted / flagged   — how much raw output you filter by hand
  · total paid

Append-only log (survives everything): $HUNTR_FUNNEL, else ~/.claude/huntr/funnel.jsonl.
Current state of a finding = its furthest-progressed event.

Usage:
  funnel.py --log --id F1 --target acme --tool mass-assign --class idor --stage flagged
  funnel.py --log --id F1 --target acme --stage accepted --amount 500
  funnel.py --stats [--target acme] [--json]
  funnel.py --list  [--target acme] [--json]
Exit: 0.
"""
import os, json, time
from pathlib import Path
import huntrlib as H

STORE = Path(os.environ.get("HUNTR_FUNNEL", str(Path.home() / ".claude" / "huntr" / "funnel.jsonl")))
STAGES = ["flagged", "confirmed", "submitted", "dupe", "rejected", "accepted", "paid"]
RANK = {s: i for i, s in enumerate(STAGES)}
TERMINAL = {"accepted", "dupe", "rejected", "paid"}


def load_events():
    if not STORE.exists():
        return []
    out = []
    for line in STORE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def current_state(events, target=None):
    """Fold the event log to the furthest stage per finding key (target:id)."""
    best = {}
    for e in events:
        if target and e.get("target") != target:
            continue
        key = f"{e.get('target','?')}:{e.get('id','?')}"
        cur = best.get(key)
        r = RANK.get(e.get("stage"), -1)
        if cur is None or r > cur["_rank"] or (r == cur["_rank"] and e.get("ts", "") >= cur.get("ts", "")):
            rec = dict(e)
            rec["_rank"] = r
            # carry a paid amount forward even if a later non-paid event wins rank
            if cur and cur.get("amount") and not rec.get("amount"):
                rec["amount"] = cur["amount"]
            best[key] = rec
    return best


def compute(states):
    def norm(stage):
        return "accepted" if stage == "paid" else stage
    reached = {s: 0 for s in STAGES}
    for rec in states.values():
        st = rec.get("stage")
        # count reach: a finding that's accepted was also flagged/confirmed/submitted
        r = RANK.get(st, -1)
        for s in STAGES:
            if RANK[s] <= r and s not in TERMINAL:
                reached[s] += 1
        reached[norm(st)] = reached.get(norm(st), 0) + (1 if st in TERMINAL else 0)

    accepted = sum(1 for r in states.values() if norm(r.get("stage")) == "accepted")
    dupe = sum(1 for r in states.values() if r.get("stage") == "dupe")
    rejected = sum(1 for r in states.values() if r.get("stage") == "rejected")
    submitted = sum(1 for r in states.values() if RANK.get(r.get("stage"), -1) >= RANK["submitted"])
    flagged = len(states)
    confirmed = sum(1 for r in states.values() if RANK.get(r.get("stage"), -1) >= RANK["confirmed"])
    adjudicated = accepted + dupe + rejected
    paid_total = sum(float(r.get("amount") or 0) for r in states.values())

    def rate(a, b):
        return round(a / b, 3) if b else None

    return {
        "flagged": flagged, "confirmed": confirmed, "submitted": submitted,
        "accepted": accepted, "dupe": dupe, "rejected": rejected,
        "adjudicated": adjudicated, "paid_total": round(paid_total, 2),
        "false_positive_rate": rate(rejected, adjudicated),
        "acceptance_rate": rate(accepted, submitted),
        "unique_rate": rate(accepted, accepted + dupe),
        "flag_to_submit": rate(submitted, flagged),
    }


def fp_by_class(events, target=None):
    states = current_state(events, target)
    byc = {}
    for rec in states.values():
        cls = rec.get("class", "?")
        st = "accepted" if rec.get("stage") == "paid" else rec.get("stage")
        if st in ("accepted", "dupe", "rejected"):
            d = byc.setdefault(cls, {"accepted": 0, "dupe": 0, "rejected": 0})
            d[st] += 1
    rows = []
    for cls, d in byc.items():
        adj = d["accepted"] + d["dupe"] + d["rejected"]
        rows.append({"class": cls, **d, "fp_rate": round(d["rejected"] / adj, 3) if adj else None})
    return sorted(rows, key=lambda r: -(r["fp_rate"] or 0))


def main():
    events = load_events()

    if H.flag("--log"):
        stage = H.arg("--stage")
        if stage not in STAGES:
            H.emit({"ok": False, "error": f"--stage must be one of {STAGES}"}, code=2)
        rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
               "id": H.arg("--id", "?"), "target": H.arg("--target", "default"),
               "tool": H.arg("--tool", ""), "class": H.arg("--class", ""),
               "stage": stage}
        if H.arg("--amount"):
            rec["amount"] = H.arg("--amount")
        if H.arg("--note"):
            rec["note"] = H.arg("--note")
        STORE.parent.mkdir(parents=True, exist_ok=True)
        with STORE.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        H.emit({"ok": True, "logged": rec}, human=f"logged {rec['target']}:{rec['id']} → {stage}", code=0)

    if H.flag("--list"):
        states = current_state(events, H.arg("--target"))
        rows = sorted(({"target": r.get("target"), "id": r.get("id"), "class": r.get("class"),
                        "tool": r.get("tool"), "stage": r.get("stage"), "amount": r.get("amount")}
                       for r in states.values()), key=lambda r: (r["target"] or "", r["id"] or ""))
        if H.flag("--json"):
            H.emit({"ok": True, "findings": rows}, code=0)
        print(f"\n== funnel · {len(rows)} findings ==")
        for r in rows:
            amt = f"  ${r['amount']}" if r.get("amount") else ""
            print(f"  {(r['target'] or '?'):<12} {(r['id'] or '?'):<8} [{r['stage']:<9}] {r.get('class','') or '':<10}{amt}")
        raise SystemExit(0)

    # default: stats
    target = H.arg("--target")
    states = current_state(events, target)
    m = compute(states)
    byc = fp_by_class(events, target)
    result = {"ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
              "target": target or "all", "metrics": m, "fp_by_class": byc}

    if H.flag("--json"):
        H.emit(result, code=0)

    fp = m["false_positive_rate"]
    print(f"\n══ detection funnel · {target or 'all targets'} ══")
    print(f"  flagged {m['flagged']}  →  confirmed {m['confirmed']}  →  submitted {m['submitted']}")
    print(f"  accepted {m['accepted']}   dupe {m['dupe']}   rejected {m['rejected']}   (adjudicated {m['adjudicated']})")
    print(f"  ── rates ──")
    print(f"  false-positive rate : {('%.0f%%' % (fp*100)) if fp is not None else 'n/a (nothing adjudicated yet)'}")
    print(f"  acceptance rate     : {('%.0f%%' % (m['acceptance_rate']*100)) if m['acceptance_rate'] is not None else 'n/a'}")
    print(f"  unique rate         : {('%.0f%%' % (m['unique_rate']*100)) if m['unique_rate'] is not None else 'n/a'}")
    print(f"  flag→submit ratio   : {('%.0f%%' % (m['flag_to_submit']*100)) if m['flag_to_submit'] is not None else 'n/a'}")
    print(f"  paid total          : ${m['paid_total']}")
    if byc:
        print(f"  ── FP rate by class (noisiest first) ──")
        for r in byc:
            print(f"    {r['class']:<12} {('%.0f%%' % (r['fp_rate']*100)) if r['fp_rate'] is not None else 'n/a':>5}  (a{r['accepted']}/d{r['dupe']}/r{r['rejected']})")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
