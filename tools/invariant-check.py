#!/usr/bin/env python3
"""
invariant-check — property/oracle tester for logic bugs.

A logic bug IS a broken invariant. Instead of hoping the model "notices," you declare the
rule the app must uphold and a deterministic checker asserts it against real traffic. Every
send goes through scope-guard.py (so scope + safe-method + audit still apply), and each
result is captured as evidence — a VIOLATION is a finding backed by request/response.

Oracle types:
  deny      request MUST be refused for this identity   → PASS if 401/403 ; VIOLATION if 200
  noaccess  attacker MUST NOT read a victim resource     → VIOLATION if 200 and (marker present / no marker set)
  rejects   app MUST reject this input                   → PASS if 4xx ; VIOLATION if 200 (accepted)
  once      2nd identical action MUST fail (idempotency) → runs twice; VIOLATION if both 200
  allow     sanity: identity SHOULD work                 → expect 200 (confirms creds before trusting deny/noaccess)

Usage:
  invariant-check.py --run ./.hunt/invariants.tsv
  invariant-check.py --id F --type noaccess --url https://api.x/api/v1/orders/1337 \
        --header 'Authorization: Bearer <attacker>' --marker 'victim@corp.com'
  invariant-check.py --selftest        # verify oracle logic (no network)
  invariant-check.py --run f --dry      # print planned checks, send nothing

invariants.tsv columns (tab-separated; '#' comments):
  id   type   method   url   header   marker   note
Exit: 0 all held · 1 one+ VIOLATION · 2 usage/scope error.
"""
import sys, os, subprocess, json, time
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
GUARD = str(Path(__file__).with_name("scope-guard.py"))


def evaluate(otype, status, body, marker=""):
    """Pure oracle logic → (verdict, why). verdict in {PASS, VIOLATION, INFO}."""
    b = (body or "")
    hit = (marker in b) if marker else None
    if otype == "deny":
        if status in (401, 403):
            return "PASS", f"denied ({status}) as required"
        if status == 200:
            return "VIOLATION", "request was ALLOWED (expected 401/403) — broken authorization"
        return "INFO", f"ambiguous status {status}"
    if otype == "noaccess":
        if status == 200 and (hit or marker == ""):
            return "VIOLATION", ("victim marker present in 200 response" if hit else "200 OK returned protected resource")
        if status in (401, 403, 404):
            return "PASS", f"no access ({status})"
        if status == 200 and hit is False:
            return "PASS", "200 but victim marker absent (not victim's data)"
        return "INFO", f"status {status}"
    if otype == "rejects":
        if 400 <= status < 500:
            return "PASS", f"rejected ({status}) as required"
        if status == 200:
            return "VIOLATION", "malformed/over-limit input was ACCEPTED (200)"
        return "INFO", f"status {status}"
    if otype == "allow":
        return ("PASS", "identity works (200)") if status == 200 else ("INFO", f"expected 200, got {status}")
    return "INFO", "unknown oracle type"


def send(method, url, header):
    cmd = [sys.executable, GUARD, method, url]
    if header:
        cmd += ["--", "-H", header]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode in (2, 3, 4):  # scope/method/circuit block
        return None, r.stderr.strip(), ""
    out = r.stdout
    status = 0
    for tok in (out.split("\n", 1)[0] if out else "").split():
        if tok.isdigit() and len(tok) == 3:
            status = int(tok); break
    return status, "", out


def save_evidence(iid, out):
    d = HUNT / "evidence" / "invariants"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{iid}.http").write_text(out or "")
    return f"evidence/invariants/{iid}.http"


def selftest():
    cases = [
        ("deny", 200, "", "", "VIOLATION"),
        ("deny", 403, "", "", "PASS"),
        ("noaccess", 200, '{"owner":"victim@corp.com"}', "victim@corp.com", "VIOLATION"),
        ("noaccess", 200, '{"owner":"me"}', "victim@corp.com", "PASS"),
        ("noaccess", 403, "", "victim@corp.com", "PASS"),
        ("rejects", 200, "", "", "VIOLATION"),
        ("rejects", 422, "", "", "PASS"),
        ("allow", 200, "", "", "PASS"),
    ]
    ok = True
    for otype, st, body, mk, exp in cases:
        v, _ = evaluate(otype, st, body, mk)
        flag = "ok" if v == exp else "FAIL"
        if v != exp:
            ok = False
        print(f"  [{flag}] {otype} status={st} marker={mk!r} -> {v} (expected {exp})")
    print("selftest:", "PASS" if ok else "FAILED")
    sys.exit(0 if ok else 1)


def run_rows(rows, dry):
    HUNT.mkdir(parents=True, exist_ok=True)
    res = HUNT / "invariants.results.jsonl"
    violations = 0
    print(f"{'INVARIANT':<10} {'TYPE':<9} VERDICT   detail")
    for row in rows:
        iid, otype, method, url, header, marker, note = (row + [""] * 7)[:7]
        method = (method or "GET").upper()
        if dry:
            print(f"{iid:<10} {otype:<9} DRY       would {method} {url}")
            continue
        runs = 2 if otype == "once" else 1
        statuses, out_last = [], ""
        for _ in range(runs):
            st, err, out = send(method, url, header)
            if st is None:
                print(f"{iid:<10} {otype:<9} BLOCKED   {err}")
                out_last = err
                break
            statuses.append(st); out_last = out
        if statuses and otype == "once":
            v = ("VIOLATION", "2nd identical action also succeeded (not idempotent)") if statuses[:2] == [200, 200] else ("PASS", f"2nd action blocked (statuses {statuses})")
        elif statuses:
            v = evaluate(otype, statuses[-1], out_last, marker)
        else:
            v = ("INFO", "no response")
        verdict, why = v
        ev = save_evidence(iid, out_last) if statuses else ""
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "id": iid, "type": otype, "url": url,
               "verdict": verdict, "why": why, "evidence": ev, "note": note}
        with res.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        if verdict == "VIOLATION":
            violations += 1
        mark = "‼" if verdict == "VIOLATION" else ("✓" if verdict == "PASS" else "·")
        print(f"{iid:<10} {otype:<9} {mark} {verdict:<7} {why}")
    print(f"\n{violations} violation(s). " + ("Each is a candidate finding — evidence in .hunt/evidence/invariants/." if violations else "All invariants held."))
    sys.exit(1 if violations else 0)


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); sys.exit(0)
    if a[0] == "--selftest":
        selftest()
    dry = "--dry" in a
    if a[0] == "--run":
        p = Path(a[1])
        if not p.exists():
            sys.exit(f"[invariant-check] no such file: {p}")
        rows = [ln.split("\t") for ln in p.read_text().splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        return run_rows(rows, dry)
    # single inline invariant
    def arg(n, d=""):
        return a[a.index(n) + 1] if n in a else d
    row = [arg("--id", "inv"), arg("--type"), arg("--method", "GET"),
           arg("--url"), arg("--header"), arg("--marker"), arg("--note")]
    if not row[1] or not row[3]:
        sys.exit("usage: --id .. --type deny|noaccess|rejects|once|allow --url .. [--header ..] [--marker ..]")
    return run_rows([row], dry)


if __name__ == "__main__":
    main()
