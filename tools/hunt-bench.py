#!/usr/bin/env python3
"""
hunt-bench.py — HUNTR benchmark harness.

Runs the real engine (hunt-run.py) against a suite of known-vulnerable targets and scores it against
exact ground truth. Turns "we think we're differentiated" into numbers:

  • recall        — of the planted vulns, how many did HUNTR find?           (the headline find-rate)
  • precision     — of the findings, how many were expected bugs?            (unexpected ones listed, not punished blindly)
  • EV-accuracy   — of the REAL bugs found, how many did the economics brain route to reco=submit?
                    plus a false-submit check (did any unexpected finding get reco=submit?)
  • chains        — did the Chain-to-Impact planner escalate the chainable classes?
  • time          — wall-clock per target vs budget

Local-lab suites have planted bugs (ground truth certain); public suites use a documented subset.

Usage:
  hunt-bench.py [--suite local-lab] [--all] [--spec bench/benchmark.json]
                [--out bench/scorecard.json] [--html bench/scorecard.html] [--keep]
"""
import sys, os, re, json, time, signal, subprocess, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
# repo root holds bench/ ; fall back to ~/HUNTR
ROOT = Path(os.environ.get("HUNTR_REPO", str(Path.home() / "HUNTR")))

# reuse the engine's class normalizer so matching is identical to how findings are tagged
sys.path.insert(0, str(HERE))
try:
    import importlib.util as _il
    _spec = _il.spec_from_file_location("hr", str(HERE / "hunt-run.py"))
    _hr = _il.module_from_spec(_spec); _spec.loader.exec_module(_hr)
    _cls_key = _hr._cls_key
except Exception:
    def _cls_key(c):  # minimal fallback
        c = (c or "").lower()
        for k in ("sqli", "ssti", "ssrf", "xss", "idor", "authz", "jwt", "cors", "redirect", "race", "param"):
            if k in c:
                return k
        return "misconfig"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

def flag(n):
    return n in sys.argv


def wait_health(host, path, timeout=20):
    url = "http://" + host + path
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if getattr(r, "status", 200) < 500:
                    return True
        except Exception:
            pass
        time.sleep(0.6)
    return False


def run_hunt(target, mode, scope_types, budget_sec):
    """Run hunt-run.py to completion against target; return the parsed run.json (or None)."""
    hd = Path.home() / ".huntr" / "targets" / ("_bench_" + re.sub(r"[^a-z0-9]+", "_", target.lower())) / ".hunt"
    if hd.exists():
        import shutil; shutil.rmtree(hd, ignore_errors=True)
    hd.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, HUNT_DIR=str(hd))
    log = open(hd / "run.log", "w")
    proc = subprocess.Popen([sys.executable, str(HERE / "hunt-run.py"), "--target", target,
                             "--mode", mode, "--scope-types", scope_types, "--budget-sec", str(budget_sec)],
                            stdout=log, stderr=subprocess.STDOUT, env=env)
    runf = hd / "run.json"
    hard_cap = budget_sec + 400   # recon/surface/judge/chain run outside the budget; give slack
    t0 = time.time()
    while time.time() - t0 < hard_cap:
        if runf.exists():
            try:
                r = json.loads(runf.read_text())
                if r.get("status") in ("done", "error", "stopped"):
                    proc.wait(timeout=10)
                    return r
            except Exception:
                pass
        if proc.poll() is not None:
            time.sleep(1)
            try:
                return json.loads(runf.read_text())
            except Exception:
                return None
        time.sleep(4)
    proc.kill()
    try:
        return json.loads(runf.read_text())
    except Exception:
        return None


def score_suite(suite, run):
    """Compare run findings against the suite's ground truth."""
    expected = suite.get("expected", [])
    findings = (run or {}).get("findings", [])
    chains = (run or {}).get("chains", [])
    # match each expected vuln to a finding: same normalized class AND path appears in the finding endpoint
    exp_rows, matched_fi = [], set()
    for ex in expected:
        hit = None
        for i, f in enumerate(findings):
            if i in matched_fi:
                continue
            if _cls_key(f.get("cls")) == ex["class"] and ex["path"].lower() in (f.get("endpoint", "") or "").lower():
                hit = (i, f); break
        if hit:
            matched_fi.add(hit[0])
            exp_rows.append({**ex, "found": True, "verdict": hit[1].get("verdict"), "reco": hit[1].get("reco"), "ev": hit[1].get("ev")})
        else:
            exp_rows.append({**ex, "found": False})
    found = [e for e in exp_rows if e["found"]]
    recall = round(len(found) / len(expected), 3) if expected else None
    # findings that matched no expected row = "unexpected" (could be real extras or FPs — listed, not punished)
    unexpected = [{"title": f.get("title"), "cls": f.get("cls"), "endpoint": f.get("endpoint"),
                   "reco": f.get("reco"), "ev": f.get("ev")} for i, f in enumerate(findings) if i not in matched_fi]
    precision = round(len(matched_fi) / len(findings), 3) if findings else None
    # EV-accuracy: of the REAL bugs found, how many were routed to submit?
    real_to_submit = sum(1 for e in found if e.get("reco") == "submit")
    ev_recall = round(real_to_submit / len(found), 3) if found else None
    # "unexpected" findings are mostly the SAME bug detected via another tool/vector (e.g. SQLi seen
    # through a redirect, or reflected+verified+OOB XSS on one param). Classify by whether their class
    # was among the planted set → dup-of-known (noise, not a false positive) vs truly-unknown.
    found_classes = {e["class"] for e in found}
    dup_of_known = [u for u in unexpected if _cls_key(u.get("cls")) in found_classes]
    truly_unknown = [u for u in unexpected if _cls_key(u.get("cls")) not in found_classes]
    unknown_submits = [u for u in truly_unknown if u.get("reco") == "submit"]
    noise_ratio = round(len(findings) / len(found), 2) if found else None  # findings per real bug (lower = cleaner)
    chain_names = [c.get("name", "") if isinstance(c, dict) else str(c) for c in chains]
    return {
        "suite": suite["name"], "target": suite["target"],
        "endpoints": len((run or {}).get("endpoints", [])),
        "expected": len(expected), "found": len(found), "total_findings": len(findings),
        "recall": recall, "precision": precision, "noise_ratio": noise_ratio,
        "ev_recall": ev_recall, "real_routed_to_submit": real_to_submit,
        "dup_of_known": len(dup_of_known), "truly_unknown": len(truly_unknown),
        "unknown_submit_findings": len(unknown_submits),
        "chains": len(chains), "chain_names": chain_names[:5],
        "pipeline_ev": (run or {}).get("economics", {}).get("pipeline_ev"),
        "coverage": (run or {}).get("coverage", {}).get("breadth"),
        "status": (run or {}).get("status"),
        "detail": exp_rows, "unexpected": unexpected,
    }


def launch_local(suite):
    """Serve the vulnerable lab IN-PROCESS as a daemon thread (robust: no subprocess lifecycle races,
    stays up for the whole hunt, dies with the harness). Returns a stop() callable or None."""
    lc = suite["launch"]
    mod = ROOT / lc["module"] if not os.path.isabs(lc["module"]) else Path(lc["module"])
    host, port = suite["target"].split(":")[0], int(lc["port"])
    try:
        import threading
        import importlib.util as il
        from werkzeug.serving import make_server
        sp = il.spec_from_file_location("labs_" + str(port), str(mod))
        labs = il.module_from_spec(sp); sp.loader.exec_module(labs)
        app = labs.make_app() if hasattr(labs, "make_app") else labs.app
        srv = make_server(host, port, app, threaded=True)
        th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
    except Exception as e:
        print("  lab failed to start in-process: " + str(e)[:160], flush=True)
        return None
    if not wait_health(host + ":" + str(port), lc.get("health", "/"), timeout=15):
        try: srv.shutdown()
        except Exception: pass
        print("  lab did not pass health check", flush=True)
        return None
    print("  lab up in-process on %s:%d" % (host, port), flush=True)
    return srv.shutdown


def main():
    spec_path = Path(arg("--spec", str(ROOT / "bench" / "benchmark.json")))
    spec = json.loads(spec_path.read_text())
    only = arg("--suite")
    run_all = flag("--all")
    keep = flag("--keep")
    suites = []
    for s in spec.get("suites", []):
        if only:
            if s["name"] == only:
                suites.append(s)
        elif run_all or s.get("type") == "local" or s.get("enabled", True) is True:
            if s.get("enabled", True) is not False or run_all:
                suites.append(s)
    # default (no flags): local suites only
    if not only and not run_all:
        suites = [s for s in spec.get("suites", []) if s.get("type") == "local"]

    results = []
    for s in suites:
        print("\n=== suite: %s  (%s) ===" % (s["name"], s["target"]), flush=True)
        stop = None
        if s.get("type") == "local":
            print("  launching lab…", flush=True)
            stop = launch_local(s)
            if not stop:
                print("  ✗ lab did not come up — skipping", flush=True)
                results.append({"suite": s["name"], "target": s["target"], "status": "lab-down", "recall": None})
                continue
        try:
            budget = int(arg("--budget", str(s.get("budget_sec", 600))))
            print("  running hunt (budget %ss)…" % budget, flush=True)
            t0 = time.time()
            run = run_hunt(s["target"], s.get("mode", "black"), s.get("scope_types", "web,api"), budget)
            elapsed = int(time.time() - t0)
            sc = score_suite(s, run)
            sc["elapsed_sec"] = elapsed
            results.append(sc)
            print("  recall %s · found %d/%d · ev-recall %s · noise %sx · chains %d · %ss · status %s" %
                  (sc["recall"], sc["found"], sc["expected"], sc["ev_recall"], sc["noise_ratio"], sc["chains"], elapsed, sc["status"]), flush=True)
            for e in sc["detail"]:
                mark = "✓" if e["found"] else "✗ MISS"
                extra = (" verdict=%s reco=%s ev=$%s" % (e.get("verdict"), e.get("reco"), e.get("ev"))) if e["found"] else ""
                print("     %-7s %-9s %s%s" % (mark, e["class"], e["path"], extra), flush=True)
            if sc["unexpected"]:
                print("     (+%d duplicate detections of the same bugs, +%d truly-unknown [%d submit-ready])" %
                      (sc["dup_of_known"], sc["truly_unknown"], sc["unknown_submit_findings"]), flush=True)
        finally:
            if stop and not keep:
                try: stop()
                except Exception: pass

    # aggregate
    scored = [r for r in results if r.get("recall") is not None]
    agg = {}
    if scored:
        tot_exp = sum(r["expected"] for r in scored)
        tot_found = sum(r["found"] for r in scored)
        tot_real_submit = sum(r.get("real_routed_to_submit", 0) for r in scored)
        tot_unknown_submit = sum(r.get("unknown_submit_findings", 0) for r in scored)
        tot_findings = sum(r.get("total_findings", 0) for r in scored)
        agg = {
            "suites": len(scored),
            "overall_recall": round(tot_found / tot_exp, 3) if tot_exp else None,
            "overall_ev_recall": round(tot_real_submit / tot_found, 3) if tot_found else None,
            "total_expected": tot_exp, "total_found": tot_found, "total_findings": tot_findings,
            "noise_ratio": round(tot_findings / tot_found, 2) if tot_found else None,
            "unknown_submit_findings": tot_unknown_submit,
        }
    scorecard = {"benchmark": spec.get("name"), "generated": time.time(),
                 "aggregate": agg, "results": results}

    out = Path(arg("--out", str(ROOT / "bench" / "scorecard.json")))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(scorecard, indent=2))
    print("\n=== AGGREGATE ===", flush=True)
    if agg:
        print("  overall recall:    %s  (%d/%d planted vulns found)" % (agg["overall_recall"], agg["total_found"], agg["total_expected"]), flush=True)
        print("  overall EV-recall: %s  (real bugs routed to submit)" % agg["overall_ev_recall"], flush=True)
        print("  noise ratio:       %sx (%d findings for %d bugs — intra-hunt dedup opportunity)" % (agg["noise_ratio"], agg["total_findings"], agg["total_found"]), flush=True)
        print("  unknown submits:   %d  (submit-ready findings outside the planted set)" % agg["unknown_submit_findings"], flush=True)
    print("  scorecard → %s" % out, flush=True)

    html = arg("--html")
    if html:
        _write_html(scorecard, Path(html))
        print("  html → %s" % html, flush=True)
    sys.stdout.flush()
    os._exit(0)   # force clean exit — the in-process lab server thread can otherwise keep us alive


def _write_html(sc, path):
    rows = ""
    for r in sc["results"]:
        if r.get("recall") is None:
            rows += "<tr><td>" + str(r["suite"]) + "</td><td colspan=6>" + str(r.get("status", "skipped")) + "</td></tr>"
            continue
        det = "".join("<div class='" + ("ok" if e["found"] else "miss") + "'>" +
                      ("✓" if e["found"] else "✗") + " " + str(e["class"]) + " " + str(e["path"]) +
                      ((" → " + str(e.get("reco"))) if e["found"] else "") + "</div>" for e in r["detail"])
        rows += ("<tr><td><b>" + str(r["suite"]) + "</b><br><span class=t>" + str(r["target"]) + "</span></td>"
                 "<td class=big>" + str(r["recall"] if r["recall"] is not None else "-") + "</td>"
                 "<td>" + str(r["found"]) + "/" + str(r["expected"]) + "</td>"
                 "<td>" + str(r.get("ev_recall")) + "</td><td>" + str(r.get("noise_ratio")) + "</td>"
                 "<td>" + str(r["chains"]) + "</td><td>" + str(r.get("status")) + "</td></tr>"
                 "<tr><td colspan=7 class=det>" + det + "</td></tr>")
    a = sc.get("aggregate", {})

    def g(k):
        return str(a.get(k)) if a and a.get(k) is not None else "-"
    # NOTE: build with .replace(), NOT %-formatting — the CSS contains literal % (e.g. width:100%)
    tpl = """<!doctype html><meta charset=utf-8><title>HUNTR Benchmark</title>
<style>body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0A0B0D;color:#E7E9EC;margin:0;padding:28px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8A9099;margin-bottom:20px}
.kpis{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.kpi{background:#14161A;border:1px solid #232730;border-radius:8px;padding:14px 18px;min-width:150px}
.kpi .n{font-size:26px;font-weight:700;color:#4ADE80}.kpi .l{color:#8A9099;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse}td{border-top:1px solid #232730;padding:9px 10px;vertical-align:top}
.big{font-size:18px;font-weight:700;color:#A78BFA}.t{color:#8A9099;font-size:12px}
.det{padding-top:0}.det div{display:inline-block;margin:2px 10px 2px 0;font-size:12px}
.ok{color:#4ADE80}.miss{color:#F87171}</style>
<h1>HUNTR Benchmark Scorecard</h1><div class=sub>@@BENCH@@</div>
<div class=kpis>
<div class=kpi><div class=n>@@RECALL@@</div><div class=l>overall recall</div></div>
<div class=kpi><div class=n>@@EVREC@@</div><div class=l>EV-recall</div></div>
<div class=kpi><div class=n>@@FOUND@@/@@EXP@@</div><div class=l>vulns found</div></div>
<div class=kpi><div class=n>@@NOISE@@x</div><div class=l>noise ratio</div></div>
</div>
<table><tr><td>suite</td><td>recall</td><td>found</td><td>ev-recall</td><td>noise</td><td>chains</td><td>status</td></tr>
@@ROWS@@</table>"""
    html = (tpl.replace("@@BENCH@@", str(sc.get("benchmark", "HUNTR")))
               .replace("@@RECALL@@", g("overall_recall")).replace("@@EVREC@@", g("overall_ev_recall"))
               .replace("@@FOUND@@", g("total_found")).replace("@@EXP@@", g("total_expected"))
               .replace("@@NOISE@@", g("noise_ratio")).replace("@@ROWS@@", rows))
    path.write_text(html)


if __name__ == "__main__":
    main()
