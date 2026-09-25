#!/usr/bin/env python3
"""
hunt-status — rebuild situational awareness for a hunt from disk.

Long hunts overflow the context window; when it compacts, in-context memory of what's
tested / found / in-progress is lost and the engine silently re-does or drops work.
The cure is to keep all durable state in ./.hunt/ files and reload it. Run this at
session start, after /compact, or any time you need "where were we?" — it reads the
files and prints a compact, trustworthy snapshot. It writes nothing.

State layout (./.hunt/):
  coverage.tsv        the ledger (surface_item x vuln-class cells)   [hunt-coverage]
  findings/F*.md      one file per finding (durable)
  evidence/**         captured request/response artifacts            [hunt-coverage E1]
  chains.md           partial multi-step chains / hypotheses in flight
  state.md            free-form: engagement type, current focus, next actions
  audit.jsonl         every request decision                          [hunt-scope-guard]

Usage:  hunt-status.py [--dir ./.hunt] [--next N]
"""
import sys, os, json, glob, re
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
NEXT = 8
args = sys.argv[1:]
if "--dir" in args:
    HUNT = Path(args[args.index("--dir") + 1])
if "--next" in args:
    NEXT = int(args[args.index("--next") + 1])


def rule(t=""):
    print(("── " + t + " ").ljust(64, "─") if t else "─" * 64)


def parse_ledger(p):
    cols, rows, hdr = [], [], []
    for line in p.read_text().splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("# columns:"):
            cols = [c.strip() for c in s.split(":", 1)[1].split("|")]
            continue
        if s.startswith("#"):
            hdr.append(s.lstrip("# ").strip())
            continue
        rows.append(line.split("\t"))
    return cols, rows, hdr


def classify(v):
    v = (v or "").strip()
    if v in (".", ""):
        return None
    up = v.upper()
    ev = "@" in v
    m = re.search(r"#T(\d)", up)
    tier = int(m.group(1)) if m else None
    if up.startswith("TODO"):
        return ("todo", False, 0)
    if up.startswith("PARTIAL"):
        return ("partial", False, tier or 1)
    if up.startswith("TESTED-"):
        return ("tested", ev, tier or 2)
    if up.startswith("FINDING"):
        return ("finding", ev, tier or 2)
    if up.startswith("N/A"):
        return ("na", True, None)
    return ("todo", False, 0)


def main():
    if not HUNT.exists():
        print(f"[hunt-status] no state dir at {HUNT} — this hunt hasn't been initialized.")
        print("  start it: scope-guard.py --init  (scope), then build coverage.tsv (hunt-coverage).")
        return

    led = HUNT / "coverage.tsv"
    print()
    rule("HUNT STATUS  (" + str(HUNT) + ")")
    if led.exists():
        cols, rows, hdr = parse_ledger(led)
        for h in hdr[:2]:
            print("  " + h)
        # class columns = everything between 'type' and 'notes' (or cols[2:-1]); fallback: cols 2..-1
        if cols:
            start = 2
            end = len(cols) - 1 if cols[-1].lower().startswith(("note", "evidence")) else len(cols)
            classcols = list(range(start, end))
        else:
            classcols = None
        tot = res = ver = todo = part = find = deep = 0
        todo_list, partial_list, shallow_list = [], [], []
        for r in rows:
            item = r[0] if r else "?"
            idxs = classcols if classcols is not None else range(2, len(r) - 1)
            for i in idxs:
                if i >= len(r):
                    continue
                c = classify(r[i])
                if not c:
                    continue
                st, ev, tier = c
                tot += 1
                cls = cols[i] if cols and i < len(cols) else f"col{i}"
                if st in ("tested", "finding", "na"):
                    res += 1
                    if ev:
                        ver += 1
                    if st == "na" or (tier or 0) >= 2:
                        deep += 1
                    elif (tier or 0) == 1:
                        shallow_list.append(f"{item}  ×  {cls}  (T1 — deepen to T2+)")
                if st == "finding":
                    find += 1
                if st == "todo":
                    todo += 1
                    todo_list.append(f"{item}  ×  {cls}")
                if st == "partial":
                    part += 1
                    partial_list.append(f"{item}  ×  {cls}" + (f"  (T{tier})" if tier else ""))
        pct = round(res / tot * 100) if tot else 0
        vpct = round(ver / tot * 100) if tot else 0
        dpct = round(deep / tot * 100) if tot else 0
        print()
        print(f"  breadth  : {res}/{tot} cells  ({pct}%)   verified: {vpct}%   findings: {find}")
        print(f"  depth    : {deep}/{tot} cells at >=T2  ({dpct}%)" + ("   ⚠ breadth>>depth: surface touched, not understood" if pct - dpct >= 25 else ""))
        print(f"  remaining: {todo} TODO · {part} PARTIAL")
        exhausted = (todo + part) == 0 and vpct == 100 and dpct == 100
        if exhausted:
            verdict = "EXHAUSTED — 0 cells left, 100% verified, all at depth"
        elif (todo + part) == 0 and vpct == 100:
            verdict = f"breadth done but depth {dpct}% — deepen T1 cells before calling it exhausted"
        else:
            verdict = "NOT exhausted — keep working"
        print(f"  verdict  : {verdict}")
        if partial_list:
            rule("IN PROGRESS (finish these first)")
            for x in partial_list[:NEXT]:
                print("  ~ " + x)
        if shallow_list:
            rule(f"SHALLOW — deepen to T2+ ({len(shallow_list)})")
            for x in shallow_list[:NEXT]:
                print("  ▲ " + x)
        if todo_list:
            rule(f"NEXT UNTESTED (top {min(NEXT, len(todo_list))})")
            for x in todo_list[:NEXT]:
                print("  □ " + x)
    else:
        print("  no coverage.tsv yet — enumerate the surface first (hunt-coverage).")

    fdir = HUNT / "findings"
    fs = sorted(glob.glob(str(fdir / "*.md"))) if fdir.exists() else []
    if fs:
        rule(f"FINDINGS ({len(fs)})")
        for f in fs:
            first = ""
            try:
                for line in Path(f).read_text().splitlines():
                    if line.strip():
                        first = line.strip().lstrip("# ").strip()
                        break
            except Exception:
                pass
            print(f"  {Path(f).stem}: {first}")

    ev = HUNT / "evidence"
    nev = len(glob.glob(str(ev / "**"), recursive=True)) if ev.exists() else 0
    chains = HUNT / "chains.md"
    if chains.exists() and chains.read_text().strip():
        rule("OPEN CHAINS / HYPOTHESES")
        print("  " + chains.read_text().strip().replace("\n", "\n  "))
    state = HUNT / "state.md"
    if state.exists() and state.read_text().strip():
        rule("STATE NOTES")
        print("  " + state.read_text().strip().replace("\n", "\n  "))

    au = HUNT / "audit.jsonl"
    if au.exists():
        lines = au.read_text().splitlines()
        dec = {}
        for ln in lines:
            try:
                dec[json.loads(ln).get("decision", "?")] = dec.get(json.loads(ln).get("decision", "?"), 0) + 1
            except Exception:
                pass
        rule("REQUEST AUDIT")
        print(f"  {len(lines)} requests · " + " · ".join(f"{k}={v}" for k, v in sorted(dec.items())) + f" · evidence files: {nev}")
    bud = HUNT / "budget"
    if bud.exists():
        cfg = {}
        for ln in bud.read_text().splitlines():
            if "=" in ln and not ln.strip().startswith("#"):
                k, v = ln.split("=", 1)
                try:
                    cfg[k.strip()] = int(v.strip())
                except ValueError:
                    pass
        nreq = len((HUNT / "audit.jsonl").read_text().splitlines()) if (HUNT / "audit.jsonl").exists() else 0
        rule("BUDGET")
        halt = False
        if cfg.get("max_requests"):
            pctb = round(nreq / cfg["max_requests"] * 100)
            halt = halt or nreq >= cfg["max_requests"]
            print(f"  requests: {nreq}/{cfg['max_requests']}  ({pctb}%)")
        if cfg.get("est_tokens_per_req"):
            print(f"  est. tokens: ~{nreq * cfg['est_tokens_per_req']:,}")
        print(f"  status  : {'⛔ BUDGET REACHED — checkpoint with the operator before continuing' if halt else 'within budget'}")
    print()
    rule("RESUME")
    print("  Reload complete. Continue from IN PROGRESS, then NEXT UNTESTED.")
    print("  Trust these files, not chat memory. Re-run hunt-status.py after any /compact.")
    print()


if __name__ == "__main__":
    main()
