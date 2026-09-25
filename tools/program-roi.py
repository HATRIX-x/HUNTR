#!/usr/bin/env python3
"""
program-roi — the earnings brain: which program should I hunt RIGHT NOW.

Every hunter's real question isn't "is there a bug" — it's "where does my next hour earn most." This
ranks your programs by expected value tuned to YOU: your paid history on that stack/program, the
payout tier, how crowded it is, dup-rate, triage speed (cashflow), and whether scope/bounties just
changed (fresh = uncrowded = money). This is the wedge an enterprise pentest tool structurally can't
have — it optimises the hunter's income, not an asset-owner's compliance.

Registry: ~/.claude/hunt-programs/programs.jsonl
  {name, platform, stack, max_bounty, typical_bounty, avg_triage_days, dup_rate,
   reports_per_week, scope_count, last_scope_change:"YYYY-MM-DD", est_hours, notes}

Usage:
  program-roi.py --add --name "Acme" --platform HackerOne --stack saas --max 5000 --typical 1200 \
                 --triage-days 14 --dup-rate 0.15 --reports-week 6 --last-change 2026-09-20 --hours 8
  program-roi.py --rank [--stack saas] [--top 15]      # the "hunt this now" board
  program-roi.py --seed                                 # example rows to see it work
Exit: 0.
"""
import sys, os, json, time, importlib.util
from datetime import date
from pathlib import Path

REG = Path(os.environ.get("HUNT_PROGRAMS", str(Path.home() / ".claude" / "hunt-programs"))) / "programs.jsonl"
TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def fnum(n, d=0.0):
    v = arg(n)
    try:
        return float(v) if v is not None else d
    except ValueError:
        return d


def load(p):
    out = []
    if p.exists():
        for ln in p.read_text().splitlines():
            if ln.strip():
                try: out.append(json.loads(ln))
                except Exception: pass
    return out


def oc_mod():
    p = TOOLS / "outcome-check.py"
    if not p.exists():
        return None
    spec = importlib.util.spec_from_file_location("outcome_check", p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def days_since(s):
    try:
        y, m, d = [int(x) for x in s.split("-")]
        return (date.today() - date(y, m, d)).days
    except Exception:
        return 9999


def cmd_add():
    REG.parent.mkdir(parents=True, exist_ok=True)
    rec = {"name": arg("--name", ""), "platform": arg("--platform", "?"), "stack": (arg("--stack", "generic") or "generic").lower(),
           "max_bounty": fnum("--max"), "typical_bounty": fnum("--typical"), "avg_triage_days": fnum("--triage-days", 21),
           "dup_rate": fnum("--dup-rate", 0.15), "reports_per_week": fnum("--reports-week", 5),
           "scope_count": fnum("--scope", 1), "last_scope_change": arg("--last-change", ""),
           "est_hours": fnum("--hours", 8), "notes": arg("--notes", ""), "ts": time.strftime("%Y-%m-%d")}
    if not rec["name"]:
        sys.exit("usage: --add --name X --platform H1 --stack saas --max N --typical N [--triage-days --dup-rate --reports-week --last-change --hours]")
    progs = [p for p in load(REG) if p.get("name") != rec["name"]]  # upsert
    progs.append(rec)
    REG.write_text("\n".join(json.dumps(p) for p in progs) + "\n")
    print(f"[roi] saved program: {rec['name']} ({rec['platform']}, {rec['stack']})")


def cmd_seed():
    REG.parent.mkdir(parents=True, exist_ok=True)
    if load(REG):
        print("[roi] registry already has programs — skipping seed."); return
    ex = [
        {"name": "Acme Corp", "platform": "HackerOne", "stack": "saas", "max_bounty": 5000, "typical_bounty": 1200,
         "avg_triage_days": 12, "dup_rate": 0.12, "reports_per_week": 5, "scope_count": 8, "last_scope_change": "", "est_hours": 8},
        {"name": "PayFlow", "platform": "Bugcrowd", "stack": "fintech", "max_bounty": 15000, "typical_bounty": 2500,
         "avg_triage_days": 25, "dup_rate": 0.3, "reports_per_week": 20, "scope_count": 4, "last_scope_change": "", "est_hours": 12},
        {"name": "ShopNow", "platform": "Intigriti", "stack": "ecommerce", "max_bounty": 3000, "typical_bounty": 600,
         "avg_triage_days": 8, "dup_rate": 0.1, "reports_per_week": 3, "scope_count": 12,
         "last_scope_change": time.strftime("%Y-%m-%d"), "est_hours": 6},
    ]
    REG.write_text("\n".join(json.dumps(p) for p in ex) + "\n")
    print(f"[roi] seeded {len(ex)} example programs → {REG}")


def cmd_rank():
    progs = load(REG)
    if not progs:
        sys.exit("[roi] no programs. Add them (--add) or --seed. Intake can seed rewards; you fill dup/competition.")
    stack_filter = (arg("--stack") or "").lower()
    top = int(arg("--top", "15") or 15)
    oc = oc_mod()
    outcomes = oc.load(oc.GLOBAL) if oc else []

    rows = []
    for p in progs:
        if stack_filter and p.get("stack") != stack_filter:
            continue
        stack = p.get("stack", "generic")
        # YOUR fit: real landing prob on this program if enough data, else stack EV proxy
        mine = [o for o in outcomes if o.get("program") == p["name"]]
        acc = sum(1 for o in mine if o.get("verdict") in ("paid", "accepted"))
        dups = sum(1 for o in mine if o.get("verdict") == "duplicate")
        if len(mine) >= 3:
            fit = (acc + 1) / (len(mine) + 2)
            hist = f"{acc}/{len(mine)} landed"
        elif oc:
            agg = oc.all_classes_with_priors(oc.score(outcomes, [stack]))
            evs = sorted((a["ev"] for a in agg.values()), reverse=True)[:3]
            fit = min(0.9, (sum(evs) / len(evs)) / 1500) if evs else 0.25   # stack EV → 0..0.9 proxy
            hist = "stack-proxy"
        else:
            fit = 0.25; hist = "no data"
        typ = p.get("typical_bounty") or (p.get("max_bounty", 0) * 0.35) or 300
        dup = p.get("dup_rate", 0.15)
        if len(mine) >= 3 and len(mine):
            dup = max(dup, dups / len(mine))
        rpw = p.get("reports_per_week", 5)
        comp = 1.0 / (1.0 + rpw / 10.0)                       # crowded → lower
        triage = 1.0 / (1.0 + p.get("avg_triage_days", 21) / 30.0)  # slow pay → lower (cashflow)
        fresh = 1.35 if p.get("last_scope_change") and days_since(p["last_scope_change"]) <= 30 else 1.0
        roi = typ * fit * (1 - dup) * comp * triage * fresh   # expected $ per hunt, your-adjusted
        hours = p.get("est_hours", 8) or 8
        perhr = roi / hours
        rows.append({"p": p, "fit": fit, "dup": dup, "comp": comp, "fresh": fresh, "roi": roi,
                     "perhr": perhr, "hist": hist})
    rows.sort(key=lambda r: -r["perhr"])

    if "--json" in sys.argv:
        out = [{"name": r["p"]["name"], "platform": r["p"].get("platform", "?"),
                "typical": float(typint(r["p"])), "fit": round(r["fit"], 2), "dup": round(r["dup"], 2),
                "reports_week": r["p"].get("reports_per_week", 5), "fresh": r["fresh"] > 1,
                "roi_per_hunt": round(r["roi"]), "per_hr": round(r["perhr"]), "hist": r["hist"]} for r in rows[:top]]
        print(json.dumps({"programs": out}))
        return

    print(f"[roi] hunt-next-by-money{' · '+stack_filter if stack_filter else ''}  (tuned to your paid history)\n")
    print(f"  {'PROGRAM':<20}{'plat':<10}{'typ$':>6}{'fit':>6}{'dup':>6}{'crowd':>7}{'fresh':>7}{'$/hunt':>9}{'$/hr':>8}")
    for r in rows[:top]:
        p = r["p"]
        crowd = f"{p.get('reports_per_week',5):.0f}/wk"
        fr = "NEW" if r["fresh"] > 1 else "—"
        print(f"  {p['name'][:19]:<20}{p.get('platform','?')[:9]:<10}{typint(p):>6}{r['fit']:>6.2f}"
              f"{r['dup']*100:>5.0f}%{crowd:>7}{fr:>7}{r['roi']:>9.0f}{r['perhr']:>8.0f}")
    if rows:
        b = rows[0]["p"]
        why = []
        if rows[0]["fresh"] > 1: why.append("fresh scope/bounty (uncrowded)")
        if rows[0]["fit"] >= 0.5: why.append("you land bugs here")
        if rows[0]["comp"] >= 0.6: why.append("low competition")
        if rows[0]["dup"] <= 0.15: why.append("low dup-rate")
        print(f"\n  ➜ HUNT NOW: {b['name']} — ~${rows[0]['perhr']:.0f}/hr expected"
              + (f"  ({', '.join(why)})" if why else ""))
    print("\n  fit = your real landing prob (or stack-EV proxy) · crowd = reports/week · fresh = scope changed ≤30d")


def typint(p):
    return f"{(p.get('typical_bounty') or p.get('max_bounty',0)*0.35 or 300):.0f}"


def main():
    if "--add" in sys.argv: return cmd_add()
    if "--seed" in sys.argv: return cmd_seed()
    if "--rank" in sys.argv: return cmd_rank()
    print(__doc__)


if __name__ == "__main__":
    main()
