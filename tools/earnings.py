#!/usr/bin/env python3
"""
earnings — your bounty business in one ledger: payouts, pipeline, and tax set-aside.

This is the lock-in layer: the hunter's whole income lives here. Log every payout and pending report,
see YTD by program/platform/month, know what's still in triage, and get a tax estimate + a CSV your
accountant accepts. Honest by design — it keeps each currency separate (no invented FX rates) and
labels the tax number an estimate.

Ledger: ~/.claude/hunt-earnings/ledger.jsonl
  {date, program, platform, title, sev, amount, currency, status(paid|pending|dispute), fee, note}

Usage:
  earnings.py --add --program "Acme" --platform HackerOne --amount 1500 --currency USD --sev high \
              --title "IDOR /orders" [--status paid] [--date 2026-09-20] [--fee 0]
  earnings.py --import-outcomes [--currency EUR]     # bootstrap from paid/accepted outcomes
  earnings.py --report [--year 2026] [--tax-rate 25]
  earnings.py --export --csv ~/earnings-2026.csv [--year 2026]
Exit: 0.
"""
import sys, os, json, csv, time
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get("HUNT_EARNINGS", str(Path.home() / ".claude" / "hunt-earnings")))
LEDGER = ROOT / "ledger.jsonl"
CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
SYM = {"USD": "$", "EUR": "€", "GBP": "£"}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def fnum(n, d=0.0):
    v = arg(n)
    try:
        return float(v) if v is not None else d
    except ValueError:
        return d


def load():
    out = []
    if LEDGER.exists():
        for ln in LEDGER.read_text().splitlines():
            if ln.strip():
                try: out.append(json.loads(ln))
                except Exception: pass
    return out


def money(cur, amt):
    return f"{SYM.get(cur, cur+' ')}{amt:,.0f}"


def cmd_add():
    ROOT.mkdir(parents=True, exist_ok=True)
    rec = {"date": arg("--date", time.strftime("%Y-%m-%d")), "program": arg("--program", "?"),
           "platform": arg("--platform", "?"), "title": arg("--title", ""), "sev": arg("--sev", ""),
           "amount": fnum("--amount"), "currency": (arg("--currency", "USD") or "USD").upper(),
           "status": arg("--status", "paid"), "fee": fnum("--fee"), "note": arg("--note", ""),
           "src": "manual"}
    with LEDGER.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[earnings] +{money(rec['currency'], rec['amount'])} {rec['status']} · {rec['program']} · {rec['title'][:40]}")


def cmd_import():
    ROOT.mkdir(parents=True, exist_ok=True)
    oc = CORPUS / "outcomes.jsonl"
    if not oc.exists():
        sys.exit("no outcomes.jsonl to import")
    cur = (arg("--currency", "USD") or "USD").upper()
    have = {(r.get("program"), r.get("title"), r.get("amount")) for r in load()}
    n = 0
    for ln in oc.read_text().splitlines():
        if not ln.strip():
            continue
        try: o = json.loads(ln)
        except Exception: continue
        if o.get("verdict") in ("paid", "accepted") and float(o.get("reward", 0) or 0) > 0:
            rec = {"date": o.get("ts", time.strftime("%Y-%m-%d")), "program": o.get("program", "?"),
                   "platform": "?", "title": o.get("title", o.get("cls", "")), "sev": "",
                   "amount": float(o["reward"]), "currency": cur, "status": "paid", "fee": 0,
                   "note": "imported from outcomes", "src": "outcome"}
            key = (rec["program"], rec["title"], rec["amount"])
            if key in have:
                continue
            have.add(key)
            with LEDGER.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            n += 1
    print(f"[earnings] imported {n} paid outcome(s) as {cur}. Edit currency/platform in ledger.jsonl if needed.")


def cmd_report():
    rows = load()
    year = arg("--year")
    if year:
        rows = [r for r in rows if str(r.get("date", "")).startswith(year)]
    if not rows:
        print("[earnings] ledger empty. Log payouts (--add) or --import-outcomes."); return
    rate = fnum("--tax-rate", 0)

    paid = [r for r in rows if r.get("status") == "paid"]
    pending = [r for r in rows if r.get("status") == "pending"]
    by_cur = defaultdict(float); net_cur = defaultdict(float)
    for r in paid:
        by_cur[r["currency"]] += r["amount"]; net_cur[r["currency"]] += r["amount"] - r.get("fee", 0)
    pend_cur = defaultdict(float)
    for r in pending:
        pend_cur[r["currency"]] += r["amount"]

    print(f"══ EARNINGS{' · ' + year if year else ''} ═══════════════════════════════")
    print(f"  {len(paid)} paid · {len(pending)} pending · {len({r['program'] for r in rows})} programs\n")
    print("  PAID (gross / net after fees):")
    for c in sorted(by_cur):
        print(f"    {money(c, by_cur[c])}   net {money(c, net_cur[c])}")
    if pend_cur:
        print("  PIPELINE (pending triage):")
        for c in sorted(pend_cur):
            print(f"    {money(c, pend_cur[c])}")
    if rate:
        print("  TAX SET-ASIDE (estimate — confirm with an accountant):")
        for c in sorted(by_cur):
            print(f"    {money(c, by_cur[c]*rate/100)}  ({rate:.0f}% of paid)")

    plat = defaultdict(lambda: defaultdict(float))
    for r in paid:
        plat[r["platform"]][r["currency"]] += r["amount"]
    print("\n  by platform:")
    for p in sorted(plat, key=lambda p: -sum(plat[p].values())):
        print(f"    {p:<14}" + "  ".join(money(c, v) for c, v in sorted(plat[p].items())))

    prog = defaultdict(lambda: defaultdict(float))
    for r in paid:
        prog[r["program"]][r["currency"]] += r["amount"]
    top = sorted(prog, key=lambda p: -sum(prog[p].values()))[:8]
    print("\n  top programs:")
    for p in top:
        print(f"    {p[:22]:<24}" + "  ".join(money(c, v) for c, v in sorted(prog[p].items())))

    # monthly (current year view)
    mon = defaultdict(lambda: defaultdict(float))
    for r in paid:
        mon[str(r["date"])[:7]][r["currency"]] += r["amount"]
    if len(mon) > 1:
        print("\n  by month:")
        for m in sorted(mon):
            print(f"    {m}   " + "  ".join(money(c, v) for c, v in sorted(mon[m].items())))


def cmd_export():
    rows = load()
    year = arg("--year")
    if year:
        rows = [r for r in rows if str(r.get("date", "")).startswith(year)]
    out = Path(arg("--csv") or (ROOT / f"earnings-{year or 'all'}.csv"))
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = ["date", "program", "platform", "title", "sev", "amount", "currency", "fee", "status", "note"]
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in sorted(rows, key=lambda r: r.get("date", "")):
            w.writerow(r)
    print(f"[earnings] exported {len(rows)} rows → {out}  (hand to your accountant)")


def cmd_json():
    rows = load()
    paid = [r for r in rows if r.get("status") == "paid"]
    pending = [r for r in rows if r.get("status") == "pending"]
    by_cur = defaultdict(float); pend = defaultdict(float)
    for r in paid: by_cur[r["currency"]] += r["amount"]
    for r in pending: pend[r["currency"]] += r["amount"]
    ytd = time.strftime("%Y")
    ytd_cur = defaultdict(float)
    for r in paid:
        if str(r.get("date", "")).startswith(ytd):
            ytd_cur[r["currency"]] += r["amount"]
    print(json.dumps({"paid": by_cur, "pending": pend, "ytd": ytd_cur,
                      "counts": {"paid": len(paid), "pending": len(pending),
                                 "programs": len({r["program"] for r in rows})}}))


def cmd_json_full():
    rows = load()
    paid = [r for r in rows if r.get("status") == "paid"]
    pending = [r for r in rows if r.get("status") == "pending"]
    dispute = [r for r in rows if r.get("status") == "dispute"]
    ytd = time.strftime("%Y")
    # totals
    by_cur = defaultdict(float); pend = defaultdict(float); ytd_cur = defaultdict(float)
    for r in paid: by_cur[r["currency"]] += r["amount"]
    for r in pending: pend[r["currency"]] += r["amount"]
    for r in paid:
        if str(r.get("date", "")).startswith(ytd):
            ytd_cur[r["currency"]] += r["amount"]
    # per-program
    by_prog = defaultdict(lambda: defaultdict(float))
    for r in paid: by_prog[r["program"]][r["currency"]] += r["amount"]
    # per-platform
    by_plat = defaultdict(lambda: defaultdict(float))
    for r in paid: by_plat[r["platform"]][r["currency"]] += r["amount"]
    # per-month
    by_mon = defaultdict(lambda: defaultdict(float))
    for r in paid: by_mon[str(r.get("date",""))[:7]][r["currency"]] += r["amount"]
    # per-severity
    by_sev = defaultdict(lambda: defaultdict(float))
    for r in paid:
        s = (r.get("sev") or "unknown").lower()
        by_sev[s][r["currency"]] += r["amount"]
    # recent 20 rows (all statuses, newest first)
    recent = sorted(rows, key=lambda r: r.get("date",""), reverse=True)[:20]
    print(json.dumps({
        "paid": dict(by_cur), "pending": dict(pend), "ytd": dict(ytd_cur),
        "counts": {"paid": len(paid), "pending": len(pending), "dispute": len(dispute),
                   "programs": len({r["program"] for r in rows})},
        "by_program": {k: dict(v) for k, v in sorted(by_prog.items(), key=lambda x: -sum(x[1].values()))},
        "by_platform": {k: dict(v) for k, v in sorted(by_plat.items(), key=lambda x: -sum(x[1].values()))},
        "by_month": {k: dict(v) for k, v in sorted(by_mon.items())},
        "by_severity": {k: dict(v) for k, v in sorted(by_sev.items(),
                        key=lambda x: ["critical","high","medium","low","info","unknown"].index(x[0])
                        if x[0] in ["critical","high","medium","low","info","unknown"] else 99)},
        "recent": recent,
    }))


def main():
    if "--add" in sys.argv: return cmd_add()
    if "--import-outcomes" in sys.argv: return cmd_import()
    if "--export" in sys.argv: return cmd_export()
    if "--json-full" in sys.argv: return cmd_json_full()
    if "--json" in sys.argv: return cmd_json()
    if "--report" in sys.argv: return cmd_report()
    print(__doc__)


if __name__ == "__main__":
    main()
