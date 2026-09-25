#!/usr/bin/env python3
"""
hunt-next — there is ALWAYS a next move. The tool that removes you from the loop.

The engine used to stop and wait for "keep digging". This decides the single highest-value next
action from disk state, so a driver (/loop or hunt-agent) never dead-stops — it only stops when this
returns EXHAUSTED (the coverage ledger is truly complete) or hits a real human gate.

Priority (greedy hunter order):
  1 ESCALATE   a confirmed finding not yet run through the greedy critic (a Medium may be a Critical)
  2 CHAIN      a near-miss: one unproven edge stands between you and ATO/RCE/PII (capabilities.tsv)
  3 DEEPEN     a shallow cell (PARTIAL / single-probe) — real bugs hide in the untested depth
  4 HUNT       the next TODO cell, ordered by your paid-history EV
  5 TEST       the next open hypothesis in hypotheses.tsv
  6 GENERATE   leads ran dry → assume-break a feature you haven't interrogated
  0 EXHAUSTED  nothing left (hunt-status confirms 100% depth + 0 open chains)

Usage:
  hunt-next.py [--stack saas] [--json]
  hunt-next.py --mark-critiqued F60      # the driver calls this after it escalates a finding
Exit: 0 an action returned · 3 EXHAUSTED.
"""
import sys, os, re, json, subprocess
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
TOOLS = Path(__file__).parent
CRITIC = HUNT / "critic.jsonl"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def read(p):
    return p.read_text(errors="replace") if p.exists() else ""


def critiqued():
    done = set()
    for ln in read(CRITIC).splitlines():
        try:
            done.add(json.loads(ln).get("id"))
        except Exception:
            pass
    return done


def findings():
    d = HUNT / "findings"
    out = []
    if d.exists():
        for f in sorted(d.glob("F*.md")):
            txt = f.read_text(errors="replace")
            title = next((l.lstrip("# ").strip() for l in txt.splitlines() if l.strip()), f.stem)
            sev = ""
            m = re.search(r"\b(critical|high|medium|low|info)\b", txt, re.I)
            if m:
                sev = m.group(1).lower()
            out.append({"id": f.stem, "title": title[:80], "sev": sev})
    return out


def coverage():
    p = HUNT / "coverage.tsv"
    if not p.exists():
        return None
    classes, rows = [], []
    for ln in read(p).splitlines():
        s = ln.rstrip("\n")
        if s.strip().startswith("# columns:"):
            classes = [c.strip() for c in s.split(":", 1)[1].split("|")][1:]
            continue
        if not s.strip() or s.strip().startswith("#"):
            continue
        rows.append(s.split("\t"))
    if rows and not classes:  # header row fallback
        classes = [c.strip() for c in rows[0][1:]]
        rows = rows[1:]
    todo, shallow = [], []
    for r in rows:
        item = r[0].strip()
        for i, cell in enumerate(r[1:]):
            cls = classes[i] if i < len(classes) else f"c{i}"
            cu = cell.strip().upper()
            if cu in ("TODO",) or cu.startswith("TODO"):
                todo.append((item, cls))
            elif cu.startswith("PARTIAL") or "#T1" in cu:
                shallow.append((item, cls))
    return {"todo": todo, "shallow": shallow, "classes": classes}


def chain_near_miss():
    p = HUNT / "capabilities.tsv"
    if not p.exists():
        return None
    for ln in read(p).splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        c = s.split("\t")
        if len(c) >= 4 and c[3].strip().lower() in ("partial", "unproven"):
            return {"prim": c[1].strip(), "frm": c[0].strip(), "to": c[2].strip(), "status": c[3].strip()}
    return None


def open_hypothesis():
    p = HUNT / "hypotheses.tsv"
    best = None
    for ln in read(p).splitlines():
        if not ln.strip() or ln.startswith("#"):
            continue
        c = ln.split("\t")
        if len(c) >= 7 and c[4].strip().lower() == "open":
            score = 0.0
            try:
                score = float(c[2]) if c[2].strip() else 0.0
            except ValueError:
                pass
            if best is None or score > best[0]:
                best = (score, {"id": c[0], "cls": c[1], "why": c[5][:80], "test": c[6][:120]})
    return best[1] if best else None


def ev_order(stack):
    try:
        r = subprocess.run([sys.executable, str(TOOLS / "outcome-check.py"), "--rank",
                            "--stack", stack or "generic", "--top", "20"], capture_output=True, text=True)
        return [m.group(1) for m in re.finditer(r"hunt-([a-z]+)", r.stdout)]
    except Exception:
        return []


def emit(kind, why, cmds, extra=None):
    obj = {"action": kind, "why": why, "commands": cmds}
    if extra:
        obj.update(extra)
    if "--json" in sys.argv:
        print(json.dumps(obj))
    else:
        print(f"NEXT ▸ {kind}\n  {why}")
        for c in cmds:
            print(f"    $ {c}")
    sys.exit(3 if kind == "EXHAUSTED" else 0)


def main():
    if "--mark-critiqued" in sys.argv:
        HUNT.mkdir(parents=True, exist_ok=True)
        with CRITIC.open("a") as f:
            f.write(json.dumps({"id": arg("--mark-critiqued")}) + "\n")
        print(f"[hunt-next] marked {arg('--mark-critiqued')} critiqued.")
        return
    stack = arg("--stack", "generic")

    # 1 ESCALATE — any finding not yet greedily interrogated
    done = critiqued()
    for f in findings():
        if f["id"] not in done:
            emit("ESCALATE", f"finding {f['id']} ({f['sev'] or 'sev?'}) not yet pushed — a {f['sev'] or 'med'} may be a critical: {f['title']}",
                 [f"adversarial-verify.py --class <c> --endpoint <e> --evidence <p> --control --repro 2  # run its ESCALATORS",
                  f"chain-plan.py                      # can it reach ATO/RCE/PII?",
                  f"hunt-next.py --mark-critiqued {f['id']}   # only after you've tried to escalate + chain it"],
                 {"finding": f["id"]})

    # 2 CHAIN — one edge from a win
    nm = chain_near_miss()
    if nm:
        emit("CHAIN", f"one edge from impact: prove [{nm['prim']}] {nm['frm']}→{nm['to']} ({nm['status']})",
             ["chain-plan.py", f"exec-http.py --url <edge-endpoint> --identity <id>   # prove the primitive"],
             {"edge": nm})

    cov = coverage()
    # 3 DEEPEN — shallow cells first
    if cov and cov["shallow"]:
        item, cls = cov["shallow"][0]
        emit("DEEPEN", f"shallow cell {item} × {cls} — one probe isn't tested; run the rest of the matrix",
             [f"reflect.py --class {cls} --endpoint {item}   # see untried techniques",
              f"exec-http.py --url <{item}> --identity <id>   # run them, capture evidence"],
             {"cell": [item, cls]})

    # 4 HUNT — next TODO cell, EV-ordered
    if cov and cov["todo"]:
        order = ev_order(stack)
        def rank(c):
            cl = c.lower()
            return next((i for i, o in enumerate(order) if o in cl or cl in o), 99)
        todo = sorted(cov["todo"], key=lambda ic: rank(ic[1]))
        item, cls = todo[0]
        emit("HUNT", f"next untested cell (top EV class first): {item} × {cls}",
             [f"exec-http.py --url <{item}> --identity <id> --diff admin,low-priv --expect deny",
              f"reflect.py --class {cls} --endpoint {item} --tried .. --attempts N --evidence <p>"],
             {"cell": [item, cls]})

    # 5 TEST — open hypothesis
    h = open_hypothesis()
    if h:
        emit("TEST", f"open hypothesis {h['id']} ({h['cls']}): {h['why']}",
             [f"# {h['test']}", "exec-http.py --url <endpoint> --identity <id>"],
             {"hypothesis": h})

    # 6 GENERATE — leads dry → manufacture new ones
    sig = HUNT / "signals.json"
    if sig.exists():
        emit("GENERATE", "leads ran dry — manufacture new ones by breaking developer assumptions on each feature",
             ["assume-break.py --endpoint <a-feature-endpoint> --emit ./.hunt/hypotheses.tsv",
              "smell.py --file ./.hunt/surface.txt   # any suspicious surface not yet in coverage?",
              "recon-aggregate.py --urls more-urls.txt   # widen the surface if recon was thin"])

    # 0 EXHAUSTED
    emit("EXHAUSTED", "coverage ledger complete, all findings escalated, no open chains/hypotheses. Verify with hunt-status.py.",
         ["hunt-status.py    # confirm breadth/depth 100% before you believe this"])


if __name__ == "__main__":
    main()
