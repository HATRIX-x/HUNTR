#!/usr/bin/env python3
"""
zeroday-ledger — the receipts behind "HUNTR finds zero-days".

A zero-day claim is only as good as the evidence. This is an append-only ledger of
genuinely-novel, verified vulnerabilities HUNTR discovered on real targets — each with
the proof a skeptic will demand: target, class, a repro/PoC reference, and (as they
land) a CVE id, a disclosed report URL, and the bounty paid.

Every `add` is forced through novelty-gate.py: a finding that matched a known
template/CVE, duplicates a disclosed report, or isn't verified CANNOT enter the ledger
(use --force only with an explicit human-written reason). That is what keeps the public
count honest — it's novel-and-verified by construction, not by assertion.

Ledger: ~/.claude/hunt-zeroday/ledger.jsonl  (override with HUNT_ZERODAY_DIR)

Usage:
  zeroday-ledger.py add --target acme.com --class idor --endpoint /api/orders/{id} \
       --title "Cross-tenant IDOR" --severity high --verdict confirmed \
       --proof proofs/acme-idor.http [--cve CVE-2026-1234] [--report https://hackerone.com/reports/123] \
       [--bounty 2500] [--status disclosed] [--force "reason"]
  zeroday-ledger.py list [--target acme.com] [--status disclosed] [--json]
  zeroday-ledger.py stats [--json]          # the numbers for the claim
  zeroday-ledger.py export [--out site.json]  # public proof blob for the landing page
"""
import sys, os, json, subprocess, hashlib
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("HUNT_ZERODAY_DIR", Path.home() / ".claude" / "hunt-zeroday"))
LEDGER = ROOT / "ledger.jsonl"

VALID_STATUS = ("discovered", "reported", "triaged", "disclosed", "cve-assigned", "duplicate-retracted")


def arg(name, default=""):
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default


def read_ledger():
    if not LEDGER.exists():
        return []
    out = []
    for line in LEDGER.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def entry_id(target, cls, endpoint):
    h = hashlib.sha1(f"{target}|{cls}|{endpoint}".encode()).hexdigest()[:10]
    return f"zd_{h}"


def run_gate(cls, endpoint, param, title, verdict, template, cve, source):
    """Call novelty-gate.py; return the result dict (or None if gate missing)."""
    tool = HERE / "novelty-gate.py"
    if not tool.exists():
        return None
    cmd = [sys.executable, "-I", str(tool), "--json",
           "--class", cls, "--endpoint", endpoint, "--verdict", verdict or ""]
    for flag, val in (("--param", param), ("--title", title),
                      ("--template", template), ("--cve", cve), ("--source", source)):
        if val:
            cmd += [flag, val]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=45, env=os.environ)
        return json.loads((r.stdout or "").strip().splitlines()[-1])
    except Exception as e:
        sys.stderr.write(f"zeroday-ledger: novelty-gate failed ({e})\n")
        return None


def cmd_add():
    target = arg("--target")
    cls = arg("--class")
    endpoint = arg("--endpoint")
    if not target or not cls or not endpoint:
        sys.stderr.write("add: --target, --class and --endpoint are required\n")
        sys.exit(2)
    verdict = arg("--verdict", "confirmed")
    force = "--force" in sys.argv
    force_reason = arg("--force") if force else ""

    # NOTE: do NOT forward --cve to the gate. On a nuclei finding, cve_id is a
    # PRE-EXISTING known CVE (an n-day signature → the gate rejects it, correctly).
    # On the ledger, --cve is the CVE ASSIGNED to our disclosed 0day — an outcome that
    # PROVES novelty, not a signature. Forwarding it would reject our own zero-days.
    gate = run_gate(cls, endpoint, arg("--param"), arg("--title"),
                    verdict, arg("--template"), "", arg("--source"))
    if gate is not None and not gate.get("novel"):
        if not force:
            sys.stderr.write(
                f"✗ REFUSED — novelty gate says '{gate['verdict']}', not a zero-day.\n"
                f"  reasons: {'; '.join(gate.get('reasons', []))}\n"
                f"  This protects the public count. Override only with a written reason:\n"
                f"    --force \"why this is genuinely novel despite the gate\"\n")
            sys.exit(1)
        else:
            if not force_reason or force_reason.startswith("--"):
                sys.stderr.write("--force requires a reason string: --force \"...\"\n")
                sys.exit(2)

    proof = arg("--proof")
    if not proof and not force:
        sys.stderr.write("add: --proof <repro/PoC path or url> is required (no proof, no claim). "
                          "Use --force \"reason\" to override.\n")
        sys.exit(2)

    status = (arg("--status", "discovered") or "discovered").lower()
    if status not in VALID_STATUS:
        sys.stderr.write(f"add: --status must be one of {VALID_STATUS}\n")
        sys.exit(2)

    eid = entry_id(target, cls, endpoint)
    existing = {e.get("id") for e in read_ledger()}
    if eid in existing:
        sys.stderr.write(f"add: entry {eid} already exists for {target} {cls} {endpoint} — "
                         f"edit the ledger directly to update status/cve/bounty.\n")
        sys.exit(1)

    rec = {
        "id": eid,
        "date": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "class": cls,
        "endpoint": endpoint,
        "param": arg("--param"),
        "title": arg("--title"),
        "severity": (arg("--severity", "unknown") or "unknown").lower(),
        "verdict": verdict,
        "proof": proof,
        "cve": arg("--cve"),
        "report_url": arg("--report"),
        "bounty": float(arg("--bounty", "0") or 0),
        "status": status,
        "novelty_gate": gate.get("verdict") if gate else "unchecked",
        "forced": force_reason if force else "",
    }
    ROOT.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    tag = "★ novel" if (gate and gate.get("novel")) else f"⚠ FORCED ({gate['verdict'] if gate else 'no-gate'})"
    print(f"[zeroday-ledger] + {rec['id']}  {tag}  {target} · {cls} · {endpoint}")
    print(f"                 status={status} cve={rec['cve'] or '—'} bounty=${rec['bounty']:.0f}")


def cmd_list():
    rows = read_ledger()
    ft, fs = arg("--target"), arg("--status")
    if ft:
        rows = [r for r in rows if r.get("target") == ft]
    if fs:
        rows = [r for r in rows if r.get("status") == fs]
    if "--json" in sys.argv:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("[zeroday-ledger] empty — no zero-days recorded yet.")
        return
    for r in rows:
        print(f"  {r['id']}  [{r.get('severity','?'):>4}]  {r.get('target',''):<22} "
              f"{r.get('class',''):<10} {r.get('status','')}")
        print(f"        {r.get('title','') or r.get('endpoint','')}"
              f"{'  · ' + r['cve'] if r.get('cve') else ''}"
              f"{'  · $' + format(r.get('bounty',0), '.0f') if r.get('bounty') else ''}")


def cmd_stats():
    rows = read_ledger()
    # only genuinely-novel entries count toward the claim (forced non-novel ones don't inflate it)
    novel = [r for r in rows if r.get("novelty_gate") == "novel" or (r.get("novelty_gate") == "unchecked")]
    active = [r for r in novel if r.get("status") != "duplicate-retracted"]
    with_cve = [r for r in active if r.get("cve")]
    disclosed = [r for r in active if r.get("status") in ("disclosed", "cve-assigned")]
    programs = {r.get("target") for r in active}
    total_bounty = sum(r.get("bounty", 0) for r in active)
    stats = {
        "zero_days": len(active),
        "programs": len(programs),
        "cve_assigned": len(with_cve),
        "disclosed": len(disclosed),
        "total_bounty_usd": round(total_bounty, 2),
        "by_severity": {s: sum(1 for r in active if r.get("severity") == s)
                        for s in ("critical", "high", "medium", "low", "unknown")},
    }
    if "--json" in sys.argv:
        print(json.dumps(stats, indent=2))
        return
    print("── HUNTR zero-day ledger ──────────────────────────────")
    print(f"  Zero-days found:   {stats['zero_days']}  across {stats['programs']} programs")
    print(f"  CVEs assigned:     {stats['cve_assigned']}")
    print(f"  Publicly disclosed:{stats['disclosed']}")
    print(f"  Bounties earned:   ${stats['total_bounty_usd']:,.0f}")
    sv = stats["by_severity"]
    print(f"  Severity:          crit {sv['critical']} · high {sv['high']} · "
          f"med {sv['medium']} · low {sv['low']}")
    print("  (only novel+verified entries counted; retracted dups excluded)")


def cmd_export():
    """Public proof blob for the landing page — only disclosable, verified, novel entries."""
    rows = read_ledger()
    pub = []
    for r in rows:
        if r.get("status") == "duplicate-retracted":
            continue
        if r.get("novelty_gate") not in ("novel", "unchecked"):
            continue
        pub.append({
            "target": r.get("target"),
            "class": r.get("class"),
            "severity": r.get("severity"),
            "title": r.get("title"),
            "cve": r.get("cve"),
            "report_url": r.get("report_url"),
            "status": r.get("status"),
            "date": r.get("date", "")[:10],
        })
    blob = {"generated": datetime.now(timezone.utc).isoformat(), "count": len(pub), "zero_days": pub}
    out = arg("--out")
    if out:
        Path(out).write_text(json.dumps(blob, indent=2))
        print(f"[zeroday-ledger] exported {len(pub)} public entries → {out}")
    else:
        print(json.dumps(blob, indent=2))


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    cmd = sys.argv[1]
    {"add": cmd_add, "list": cmd_list, "stats": cmd_stats, "export": cmd_export}.get(
        cmd, lambda: (sys.stderr.write(f"unknown command '{cmd}'\n"), sys.exit(2)))()


if __name__ == "__main__":
    main()
