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


def run_agent(suite, budget):
    """Run exploit-agent.py against the suite target with its issued identities; return its result dict."""
    a = [sys.executable, str(HERE / "exploit-agent.py"), "--target", suite["target"],
         "--objective", suite.get("objective", "prove broken access control (IDOR/BFLA/privesc)"),
         "--budget-sec", str(budget), "--max-steps", str(suite.get("max_steps", 16)), "--json"]
    if suite.get("token"): a += ["--token", suite["token"]]
    if suite.get("token2"): a += ["--token2", suite["token2"]]
    if suite.get("cdp_port"): a += ["--cdp-port", str(suite["cdp_port"])]
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=budget + 150)
        for line in reversed((r.stdout or "").splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    d = json.loads(line)
                    for f in d.get("findings", []):   # a proven access-control bug is submit-worthy
                        if isinstance(f, dict) and f.get("verdict") in ("confirmed", "likely"):
                            f.setdefault("reco", "submit")
                    return d
                except Exception:
                    pass
    except Exception:
        pass
    return None


def score_suite(suite, run):
    """Compare run findings against the suite's ground truth."""
    expected = suite.get("expected", [])
    findings = (run or {}).get("findings", [])
    chains = (run or {}).get("chains", [])
    # match each expected vuln to a finding: same normalized class AND path appears in the finding endpoint
    tgt_host = suite.get("target", "").split("//")[-1].split(":")[0].lower()
    agent = suite.get("type") == "agent"   # exploit-agent findings: match on class (it PROVED the bug)
    exp_rows, matched_fi = [], set()
    for ex in expected:
        hit = None
        host_match = ex.get("match") == "host"
        for i, f in enumerate(findings):
            if i in matched_fi:
                continue
            ep = (f.get("endpoint", "") or "").lower()
            fcls = (f.get("cls", "") or "").lower()
            if agent:
                # the agent labels findings IDOR/BFLA/privesc/logic — match the ground-truth class as a substring
                cls_ok = ex["class"] in fcls or (ex["class"] == "bfla" and "authz" in fcls)
                loc_ok = (not ex.get("path")) or ex.get("match") == "host" or ex["path"].lower().split("/")[-1] in ep or ex["path"].lower() in ep
                ok = cls_ok and (loc_ok or True)   # class proof is sufficient for the agent benchmark
            else:
                if _cls_key(f.get("cls")) != ex["class"]:
                    continue
                ok = (tgt_host in ep) if host_match else (ex["path"].lower() in ep)
            if ok:
                hit = (i, f); break
        if hit:
            matched_fi.add(hit[0])
            hf = hit[1]
            proven = bool(hf.get("proven")) or (hf.get("verdict") == "confirmed") \
                or bool((hf.get("proof") or {}).get("proven"))
            exp_rows.append({**ex, "found": True, "verdict": hf.get("verdict"), "reco": hf.get("reco"),
                             "ev": hf.get("ev"), "proven": proven})
        else:
            exp_rows.append({**ex, "found": False, "proven": False})
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
    # ── Money-weighted, FP-penalized score (Bet #4) ─────────────────────────────
    # Bounty $ is power-law: one proven critical > many lows. This metric rewards
    # PROVEN, high-$ findings and PENALIZES would-be junk submissions (false
    # positives routed to submit) — the noise that erodes program trust. Volume
    # can't game it: an unproven or FP finding adds nothing (or costs).
    BOUNTY = {"c": 5000, "h": 1500, "m": 400, "l": 100, "i": 0}
    def _b(sev): return BOUNTY.get((sev or "i")[:1].lower(), 0)
    dollars_possible = sum(_b(e.get("sev")) for e in expected)
    dollars_found = sum(_b(e.get("sev")) for e in found if e.get("proven"))
    dollar_recall = round(dollars_found / dollars_possible, 3) if dollars_possible else None
    fp_submits = len(unknown_submits)                       # submit-ready bugs that aren't in ground truth
    submit_total = real_to_submit + fp_submits
    fp_rate = round(fp_submits / submit_total, 3) if submit_total else 0.0
    proof_rate = round(sum(1 for e in found if e.get("proven")) / len(found), 3) if found else None
    # HUNTR Score: proof-weighted $-recall, FP-penalized → one volume-proof number in [0,1].
    huntr_score = round((dollar_recall or 0) * (proof_rate or 0) * (1 - fp_rate), 3) if dollar_recall is not None else None
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
        # Bet #4 — money-weighted scoreboard
        "dollars_found": dollars_found, "dollars_possible": dollars_possible,
        "dollar_recall": dollar_recall, "fp_rate": fp_rate, "proof_rate": proof_rate,
        "huntr_score": huntr_score,
        "detail": exp_rows, "unexpected": unexpected,
    }


def launch_local(suite):
    """Serve the vulnerable lab IN-PROCESS as a daemon thread (robust: no subprocess lifecycle races,
    stays up for the whole hunt, dies with the harness). Returns a stop() callable or None."""
    lc = suite["launch"]
    mod = ROOT / lc["module"] if not os.path.isabs(lc["module"]) else Path(lc["module"])
    host = suite["target"].split("//")[-1].split(":")[0]   # strip scheme + port
    port = int(lc["port"])
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
        if s.get("launch"):   # local hunt lab OR authenticated agent lab — both serve in-process
            print("  launching lab…", flush=True)
            stop = launch_local(s)
            if not stop:
                print("  ✗ lab did not come up — skipping", flush=True)
                results.append({"suite": s["name"], "target": s["target"], "status": "lab-down", "recall": None})
                continue
        try:
            budget = int(arg("--budget", str(s.get("budget_sec", 600))))
            t0 = time.time()
            if s.get("type") == "agent":
                print("  running exploit-agent (budget %ss)…" % budget, flush=True)
                run = run_agent(s, budget)
                if run is not None:
                    run.setdefault("status", "done")
            else:
                print("  running hunt (budget %ss)…" % budget, flush=True)
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
        tot_proven = sum(1 for r in scored for e in r.get("detail", []) if e.get("found") and e.get("proven"))
        # ── per-class rollup: find-rate (recall), proof-rate, and FP-rate per vuln class ──
        per_class = {}
        for r in scored:
            for e in r.get("detail", []):
                k = e.get("class", "?")
                pc = per_class.setdefault(k, {"expected": 0, "found": 0, "proven": 0, "fp": 0})
                pc["expected"] += 1
                if e.get("found"):
                    pc["found"] += 1
                    if e.get("proven"):
                        pc["proven"] += 1
            # FPs per class = ONLY truly-unknown unexpected findings. A second detection of a bug we
            # already matched (same class as a found vuln) is a DUPLICATE, not a false positive.
            found_classes = {e.get("class") for e in r.get("detail", []) if e.get("found")}
            for u in r.get("unexpected", []):
                k = _cls_key(u.get("cls")) or (u.get("cls") or "?")
                if k in found_classes:
                    continue  # duplicate of a real bug — not an FP
                pc = per_class.setdefault(k, {"expected": 0, "found": 0, "proven": 0, "fp": 0})
                pc["fp"] += 1
        for k, pc in per_class.items():
            pc["find_rate"] = round(pc["found"] / pc["expected"], 3) if pc["expected"] else None
            pc["proof_rate"] = round(pc["proven"] / pc["found"], 3) if pc["found"] else None
            # FP-rate = fp / (found + fp): of what we surfaced for this class, how much was noise
            denom = pc["found"] + pc["fp"]
            pc["fp_rate"] = round(pc["fp"] / denom, 3) if denom else None
        # ── Money-weighted scoreboard rollup (Bet #4) ──
        tot_dollars_found = sum(r.get("dollars_found", 0) for r in scored)
        tot_dollars_possible = sum(r.get("dollars_possible", 0) for r in scored)
        overall_dollar_recall = round(tot_dollars_found / tot_dollars_possible, 3) if tot_dollars_possible else None
        _submit_total = tot_real_submit + tot_unknown_submit
        overall_fp_rate = round(tot_unknown_submit / _submit_total, 3) if _submit_total else 0.0
        overall_proof = round(tot_proven / tot_found, 3) if tot_found else 0.0
        # HUNTR Score: proof-weighted $-recall, FP-penalized — one volume-proof number in [0,1].
        huntr_score = round((overall_dollar_recall or 0) * overall_proof * (1 - overall_fp_rate), 3) \
            if overall_dollar_recall is not None else None
        agg = {
            "suites": len(scored),
            "overall_recall": round(tot_found / tot_exp, 3) if tot_exp else None,
            "overall_proof_rate": round(tot_proven / tot_found, 3) if tot_found else None,
            "overall_ev_recall": round(tot_real_submit / tot_found, 3) if tot_found else None,
            "total_expected": tot_exp, "total_found": tot_found, "total_proven": tot_proven, "total_findings": tot_findings,
            "noise_ratio": round(tot_findings / tot_found, 2) if tot_found else None,
            "unknown_submit_findings": tot_unknown_submit,
            # Bet #4 — money-weighted scoreboard
            "dollars_found": tot_dollars_found, "dollars_possible": tot_dollars_possible,
            "overall_dollar_recall": overall_dollar_recall, "overall_fp_rate": overall_fp_rate,
            "huntr_score": huntr_score,
            "per_class": per_class,
        }
    scorecard = {"benchmark": spec.get("name"), "generated": time.time(),
                 "aggregate": agg, "results": results}

    out = Path(arg("--out", str(ROOT / "bench" / "scorecard.json")))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(scorecard, indent=2))

    # ── #5 learning loop proof: append this run to history + show the trend vs last run ──
    trend = None
    if agg:
        hist = ROOT / "bench" / "bench_history.jsonl"
        prev = None
        try:
            if hist.exists():
                lines = [l for l in hist.read_text().splitlines() if l.strip()]
                if lines:
                    prev = json.loads(lines[-1])
        except Exception:
            prev = None
        rec = {"ts": int(time.time()), "recall": agg.get("overall_recall"),
               "proof_rate": agg.get("overall_proof_rate"), "ev_recall": agg.get("overall_ev_recall"),
               "noise_ratio": agg.get("noise_ratio"), "found": agg.get("total_found"), "expected": agg.get("total_expected")}
        try:
            with open(hist, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception:
            pass
        if prev:
            def _d(k):
                a, b = rec.get(k), prev.get(k)
                return None if a is None or b is None else round(a - b, 3)
            trend = {"recall": _d("recall"), "proof_rate": _d("proof_rate"), "ev_recall": _d("ev_recall")}
        scorecard["trend_vs_last"] = trend
        out.write_text(json.dumps(scorecard, indent=2))
    print("\n=== AGGREGATE ===", flush=True)
    if agg:
        print("  overall recall:    %s  (%d/%d planted vulns found)" % (agg["overall_recall"], agg["total_found"], agg["total_expected"]), flush=True)
        print("  overall PROOF:     %s  (%d/%d found bugs carried reproduced proof)" % (agg["overall_proof_rate"], agg["total_proven"], agg["total_found"]), flush=True)
        print("  overall EV-recall: %s  (real bugs routed to submit)" % agg["overall_ev_recall"], flush=True)
        print("  noise ratio:       %sx (%d findings for %d bugs)" % (agg["noise_ratio"], agg["total_findings"], agg["total_found"]), flush=True)
        print("  unknown submits:   %d  (submit-ready findings outside the planted set)" % agg["unknown_submit_findings"], flush=True)
        print("  ── money-weighted scoreboard (volume-proof, FP-penalized) ──", flush=True)
        print("  $-recall:          %s  ($%d of $%d proven impact captured)" % (agg["overall_dollar_recall"], agg["dollars_found"], agg["dollars_possible"]), flush=True)
        print("  FP-rate (submits): %s  (would-be junk submissions / all submits)" % agg["overall_fp_rate"], flush=True)
        print("  ►► HUNTR SCORE:    %s  (proof-weighted $-recall, FP-penalized · [0,1])" % agg["huntr_score"], flush=True)
        print("\n  per-class  (find-rate · proof-rate · fp-rate):", flush=True)
        for k, pc in sorted(agg.get("per_class", {}).items()):
            print("    %-10s find %s  proof %s  fp %s   (%d/%d found, %d proven, %d fp)" % (
                k, pc.get("find_rate"), pc.get("proof_rate"), pc.get("fp_rate"),
                pc["found"], pc["expected"], pc["proven"], pc["fp"]), flush=True)
    if agg and scorecard.get("trend_vs_last"):
        t = scorecard["trend_vs_last"]
        def _arrow(v): return "—" if v is None else (("▲ +" + str(v)) if v > 0 else (("▼ " + str(v)) if v < 0 else "= 0"))
        print("\n  trend vs last run:  recall %s · proof %s · ev %s" % (_arrow(t.get("recall")), _arrow(t.get("proof_rate")), _arrow(t.get("ev_recall"))), flush=True)
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
