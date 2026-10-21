#!/usr/bin/env python3
"""
novelty-gate — decide whether a finding is a genuine ZERO-DAY (unknown to the vendor)
or just an n-day / duplicate. Run BEFORE a finding counts toward the "HUNTR finds
zero-days" claim (i.e. before zeroday-ledger.py add).

A finding is 0day-eligible ("novel") only when ALL hold:
  1. It did NOT come from a known signature — no nuclei template-id, no CVE id, no
     "cve"/"cves" tag. A matched template is deterministic proof of a KNOWN bug (n-day),
     not a zero-day. This is the hard gate scanners can't pass.
  2. It is not a duplicate of a disclosed report or your own prior submission
     (delegated to dedup-check.py: a LIKELY DUP, score >= 0.9, fails).
  3. It is verified — verdict == "confirmed" (an unproven hypothesis is not a finding).

Verdicts emitted:
  novel        → unknown to vendor + verified + unique      → 0day-eligible   (exit 0)
  known_nday   → matched a template/CVE signature           → not a zero-day  (exit 1)
  duplicate    → already disclosed or already submitted      → not a zero-day  (exit 1)
  unverified   → novel-looking but verdict != confirmed      → not yet         (exit 2)

Usage:
  novelty-gate.py --class idor --endpoint /api/v1/orders/{id} --verdict confirmed \
                  [--param id] [--title "..."] [--template ""] [--cve ""] \
                  [--tags "logic,auth"] [--source agent-zeroday] [--json]
  # or feed a finding dict straight from a run:
  echo '{"cls":"idor","endpoint":"/x","verdict":"confirmed",...}' | novelty-gate.py --stdin [--json]
"""
import sys, os, json, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def arg(name, default=""):
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default


def load_finding():
    """Build the finding dict from --stdin JSON or from flags."""
    if "--stdin" in sys.argv:
        raw = sys.stdin.read().strip()
        f = json.loads(raw) if raw else {}
    else:
        f = {}
    # flags override / fill
    m = {
        "cls": arg("--class") or f.get("cls") or f.get("class", ""),
        "endpoint": arg("--endpoint") or f.get("endpoint", ""),
        "param": arg("--param") or f.get("param", ""),
        "title": arg("--title") or f.get("title", ""),
        "verdict": arg("--verdict") or f.get("verdict", ""),
        "template": arg("--template") or f.get("template", ""),
        "cve": arg("--cve") or f.get("cve_id") or f.get("cve", ""),
        "source": arg("--source") or f.get("source", ""),
    }
    tags = arg("--tags") or f.get("tags", "")
    if isinstance(tags, list):
        tags = ",".join(tags)
    m["tags"] = [t.strip().lower() for t in str(tags).split(",") if t.strip()]
    return m


def signature_known(f):
    """Return (is_known, reason) — did this finding match a KNOWN-bug signature?"""
    if f["template"]:
        return True, f"matched nuclei template-id '{f['template']}' — a known bug, not a zero-day"
    if f["cve"]:
        return True, f"carries CVE id '{f['cve']}' — a published vulnerability (n-day)"
    if any(t in ("cve", "cves") for t in f["tags"]):
        return True, "tagged 'cve' — sourced from a known-CVE signature set"
    # scanner-sourced findings are n-day by default unless explicitly researcher-found
    if f["source"] in ("nuclei", "nuclei-run", "template", "scanner"):
        return True, f"source '{f['source']}' is a signature scanner — known-bug territory"
    return False, ""


def dedup_candidates(f):
    """Delegate to dedup-check.py; return (is_likely_dup, top_line)."""
    tool = HERE / "dedup-check.py"
    if not tool.exists() or not f["endpoint"] or not f["cls"]:
        return False, ""
    cmd = [sys.executable, "-I", str(tool), "--class", f["cls"], "--endpoint", f["endpoint"]]
    if f["param"]:
        cmd += ["--param", f["param"]]
    if f["title"]:
        cmd += ["--title", f["title"]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=os.environ)
    except Exception as e:
        return False, f"(dedup-check unavailable: {e})"
    out = (r.stdout or "") + (r.stderr or "")
    # exit 1 == candidates found; "LIKELY DUP" marks score >= 0.9
    if r.returncode == 1 and "LIKELY DUP" in out:
        line = next((l.strip() for l in out.splitlines() if "LIKELY DUP" in l), "duplicate candidate")
        return True, line
    return False, ""


def main():
    f = load_finding()
    reasons = []

    if not f["cls"] or not f["endpoint"]:
        sys.stderr.write("novelty-gate: need at least --class and --endpoint (or --stdin finding)\n")
        sys.exit(3)

    verdict = "novel"
    score = 1.0

    known, why = signature_known(f)
    if known:
        verdict, score = "known_nday", 0.0
        reasons.append(why)
    else:
        reasons.append("no known signature (no template-id / CVE / cve-tag / scanner source)")

    if verdict == "novel":
        is_dup, dline = dedup_candidates(f)
        if is_dup:
            verdict, score = "duplicate", 0.1
            reasons.append(f"dedup-check: {dline}")
        else:
            reasons.append("dedup-check: unique (no disclosed/submitted match)")

    if verdict == "novel" and f["verdict"].lower() != "confirmed":
        verdict, score = "unverified", 0.5
        reasons.append(f"verdict is '{f['verdict'] or 'none'}', not 'confirmed' — prove it before claiming it")
    elif verdict == "novel":
        reasons.append("verified (verdict=confirmed)")

    result = {
        "novel": verdict == "novel",
        "verdict": verdict,
        "score": round(score, 2),
        "class": f["cls"],
        "endpoint": f["endpoint"],
        "reasons": reasons,
    }

    if "--json" in sys.argv:
        print(json.dumps(result))
    else:
        sym = {"novel": "★ ZERO-DAY ELIGIBLE", "known_nday": "✗ KNOWN n-day",
               "duplicate": "✗ DUPLICATE", "unverified": "? UNVERIFIED"}[verdict]
        print(f"[novelty] {sym}  (score {score:.2f})  class={f['cls']} endpoint={f['endpoint']}")
        for r in reasons:
            print(f"          · {r}")
        if verdict == "novel":
            print("  → eligible for zeroday-ledger.py add")

    sys.exit({"novel": 0, "known_nday": 1, "duplicate": 1, "unverified": 2}[verdict])


if __name__ == "__main__":
    main()
