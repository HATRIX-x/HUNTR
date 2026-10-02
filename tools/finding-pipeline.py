#!/usr/bin/env python3
"""
finding-pipeline — the connective tissue: take one raw probe hit and run it all
the way to a submit-or-hold decision, chaining the tools that already exist.

Stages (each degrades gracefully / can be skipped):
  1. VERIFY    retest.py re-fires the stored request; adversarial-verify.py adds the
               class-specific falsifier checklist + evidence gate. A bug that no longer
               reproduces → HOLD before you waste a submission.
  2. DEDUP     dup-score.py → duplicate probability + SUBMIT/REVIEW/HOLD.
  3. EVIDENCE  evidence-bundle.py assembles request/response/repro/screenshot (if an
               evidence id with a captured request exists).
  4. DRAFT     report-draft.py writes the platform report — only when it's worth it
               (verified and not a likely dup).
  5. VERDICT   combine into SUBMIT · REVIEW · HOLD with reasons. Never auto-submits.

Input finding JSON (any HUNTR probe's finding, or hand-written) may include:
  url, method, data, attack/test/class, endpoint, param, title, severity,
  match/response_snippet/snippet, status, id (evidence dir), program, stack.

Usage:
  finding-pipeline.py --finding-file f.json [--program acme] [--stack saas] \
        [--template h1] [--model claude-sonnet-4-6] [--token JWT] \
        [--class idor] [--no-verify] [--no-draft] [--skip-evidence] [--json]
Exit: 0 SUBMIT · 1 REVIEW · 2 HOLD.
"""
import sys, os, re, json, time, subprocess
from pathlib import Path
from urllib.parse import urlparse

# sync is optional — works without cloud config
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import sync as _sync
    _HAS_SYNC = True
except ImportError:
    _HAS_SYNC = False

TOOLS = Path(__file__).resolve().parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def run_tool(name, args, stdin=None, timeout=120):
    try:
        r = subprocess.run([sys.executable, str(TOOLS / name)] + args,
                           capture_output=True, text=True, input=stdin, timeout=timeout)
        out = r.stdout.strip()
        parsed = None
        if out:
            try:
                parsed = json.loads(out)
            except Exception:
                parsed = None
        return {"code": r.returncode, "out": out, "err": r.stderr.strip(), "json": parsed}
    except subprocess.TimeoutExpired:
        return {"code": -1, "out": "", "err": "timeout", "json": None}
    except FileNotFoundError:
        return {"code": -1, "out": "", "err": f"tool not found: {name}", "json": None}


CLASS_MAP = [
    ("idor", "idor"), ("bola", "idor"),
    ("auth_bypass", "authbypass"), ("missing_auth", "authbypass"), ("authbypass", "authbypass"),
    ("oauth", "oauth"), ("redirect_uri", "oauth"), ("pkce", "oauth"), ("scope_escal", "oauth"),
    ("auth_code", "oauth"), ("state", "oauth"), ("implicit", "oauth"),
    ("open_redirect", "openredirect"), ("redirect", "openredirect"),
    ("ssrf", "ssrf"), ("ssti", "ssti"), ("cors", "cors"), ("jwt", "jwt"),
    ("sqli", "sqli"), ("rce", "rce"), ("xss", "xss"), ("csrf", "csrf"),
    ("race", "race"), ("cswsh", "session"), ("session", "session"),
    ("logic", "logic"), ("numeric", "logic"), ("sequential", "logic"),
    ("hashed", "logic"), ("mass_assign", "logic"), ("rate_limit", "misc"),
    ("takeover", "misc"), ("graphql", "misc"),
]


def derive_class(finding, override):
    if override:
        return override
    raw = (finding.get("class") or finding.get("attack") or finding.get("test")
           or finding.get("category") or "").lower()
    for needle, cls in CLASS_MAP:
        if needle in raw:
            return cls
    return "misc"


def derive_endpoint(finding):
    ep = finding.get("endpoint")
    if ep:
        return ep
    url = finding.get("url") or finding.get("base_url") or finding.get("poc_url") or ""
    p = urlparse(url).path or url
    return re.sub(r"/\d+", "/{id}", p)


def main():
    ff = arg("--finding-file")
    if not ff or not Path(ff).exists():
        print(__doc__)
        sys.exit(0)
    try:
        finding = json.loads(Path(ff).read_text())
    except Exception as ex:
        out = {"ok": False, "error": f"bad finding json: {ex}"}
        print(json.dumps(out) if flag("--json") else out["error"])
        sys.exit(0)

    program = arg("--program", finding.get("program", ""))
    stack = arg("--stack", finding.get("stack", "generic"))
    template = arg("--template", "h1")
    model = arg("--model")
    token = arg("--token")
    cls = derive_class(finding, arg("--class"))
    endpoint = derive_endpoint(finding)
    param = finding.get("param", "")
    title = finding.get("title", "")
    severity = finding.get("severity") or finding.get("estimated_severity") or "medium"
    fid = finding.get("id")
    match = finding.get("match") or finding.get("response_snippet") or finding.get("snippet") or ""

    stages = {}
    reasons = []

    # ── 1. VERIFY ──────────────────────────────────────────────────────
    verify_state = "skipped"
    if not flag("--no-verify"):
        rt_args = ["--finding-file", ff, "--json"]
        if match:
            rt_args += ["--match", match]
        if token:
            rt_args += ["--token", token]
        rt = run_tool("retest.py", rt_args, timeout=60)
        rj = rt["json"] or {}
        verify_state = rj.get("verdict", "INCONCLUSIVE") if rj.get("ok", True) else "ERROR"
        stages["verify"] = {
            "reproduced": rj.get("verdict"),
            "current_status": rj.get("current_status"),
            "original_status": rj.get("original_status"),
            "proof_present": rj.get("proof_present"),
        }
        # advisory falsifier checklist (no network)
        av = run_tool("adversarial-verify.py",
                      ["--class", cls, "--endpoint", endpoint, "--severity", severity, "--json"],
                      timeout=30)
        if av["json"]:
            stages["verify"]["adversarial"] = av["json"]

        if verify_state == "STILL_VULNERABLE":
            reasons.append("verified: bug re-fired with proof present")
        elif verify_state == "FIXED":
            reasons.append("could not reproduce: proof gone on re-fire")
        elif verify_state in ("INCONCLUSIVE", "ERROR"):
            reasons.append("verification inconclusive (target unreachable or no proof set)")

    # ── 2. DEDUP ───────────────────────────────────────────────────────
    ds_args = ["--class", cls, "--endpoint", endpoint, "--json"]
    if param:
        ds_args += ["--param", param]
    if title:
        ds_args += ["--title", title]
    if program:
        ds_args += ["--program", program]
    if stack:
        ds_args += ["--stack", stack]
    ds = run_tool("dup-score.py", ds_args, timeout=60)
    dj = ds["json"] or {}
    dup_prob = dj.get("prob")
    dup_verdict = dj.get("verdict", "REVIEW")
    stages["dedup"] = {"prob": dup_prob, "verdict": dup_verdict, "nearest": dj.get("nearest", "")}
    if dup_verdict == "HOLD":
        reasons.append(f"likely duplicate ({dup_prob}%): {dj.get('nearest','')[:60]}")
    elif dup_verdict == "REVIEW":
        reasons.append(f"differentiate first ({dup_prob}% dup): {dj.get('nearest','')[:60]}")
    else:
        reasons.append(f"looks unique ({dup_prob}% dup)")

    # ── 5a. VERDICT (decide before spending a model call on the draft) ──
    if verify_state == "FIXED":
        verdict = "HOLD"
    elif dup_verdict == "HOLD":
        verdict = "HOLD"
    elif dup_verdict == "REVIEW":
        verdict = "REVIEW"
    elif verify_state in ("INCONCLUSIVE", "ERROR", "skipped"):
        verdict = "REVIEW"
    else:  # STILL_VULNERABLE + SUBMIT
        verdict = "SUBMIT"

    # ── 3. EVIDENCE ────────────────────────────────────────────────────
    if not flag("--skip-evidence") and fid:
        eb = run_tool("evidence-bundle.py", ["--id", str(fid), "--finding-file", ff, "--json"], timeout=90)
        ej = eb["json"] or {}
        stages["evidence"] = {"bundle": ej.get("bundle"), "included": ej.get("included", []),
                              "warnings": ej.get("warnings", [])}
    else:
        stages["evidence"] = {"skipped": True,
                              "note": "no finding id / evidence dir — capture with exec-http first"}

    # ── 4. DRAFT (only when it's worth submitting or differentiating) ──
    report_md = ""
    if not flag("--no-draft") and verdict in ("SUBMIT", "REVIEW"):
        rd_args = ["--finding-file", ff, "--template", template, "--json"]
        if model:
            rd_args += ["--model", model]
        rd = run_tool("report-draft.py", rd_args, timeout=90)
        rj = rd["json"] or {}
        if rj.get("ok"):
            report_md = rj.get("report_markdown", "")
            stages["draft"] = {"title": rj.get("title"), "score": rj.get("score"),
                               "word_count": rj.get("word_count"), "template": template}
        else:
            stages["draft"] = {"error": rj.get("error") or rd["err"][:200]}
            reasons.append("report draft unavailable (set ANTHROPIC_API_KEY)")
    else:
        stages["draft"] = {"skipped": True, "why": "verdict HOLD or --no-draft"}

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "class": cls, "endpoint": endpoint, "severity": severity,
        "verdict": verdict, "reasons": reasons,
        "dup_prob": dup_prob,
        "stages": stages,
        "report_markdown": report_md,
    }

    # ── SYNC to cloud (non-blocking; queues offline) ───────────────────
    sync_result = {"ok": False, "skipped": True}
    if _HAS_SYNC and not flag("--no-sync") and verdict in ("SUBMIT", "REVIEW"):
        sync_payload = {**finding, "class": cls, "endpoint": endpoint,
                        "severity": severity, "verdict": verdict,
                        "dup_prob": dup_prob, "report_score": stages.get("draft", {}).get("score")}
        sync_result = _sync.push_finding(sync_payload, program=program)
    result["sync"] = sync_result

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0 if verdict == "SUBMIT" else 1 if verdict == "REVIEW" else 2)

    icon = {"SUBMIT": "✓", "REVIEW": "~", "HOLD": "⛔"}[verdict]
    print(f"\n══ finding-pipeline · {cls} @ {endpoint} ══")
    print(f"  {icon} VERDICT: {verdict}")
    for r in reasons:
        print(f"     · {r}")
    v = stages.get("verify", {})
    if v and not v.get("skipped"):
        print(f"  verify:   {v.get('reproduced')}  (HTTP {v.get('original_status')}→{v.get('current_status')})")
    d = stages["dedup"]
    print(f"  dedup:    {d['verdict']}  {d['prob']}% dup  {d.get('nearest','')[:50]}")
    e = stages["evidence"]
    print(f"  evidence: {'—' if e.get('skipped') else e.get('bundle')}")
    dr = stages["draft"]
    if dr.get("title"):
        print(f"  draft:    “{dr['title']}”  score {dr.get('score')}/100")
    if report_md:
        print("\n" + "─" * 60 + "\n" + report_md)
    if sync_result.get("ok"):
        print("  cloud:    synced ✓")
    elif sync_result.get("queued"):
        print("  cloud:    offline — queued for retry")
    elif not sync_result.get("skipped"):
        print(f"  cloud:    not configured (run: huntr config set-token <token>)")
    print("\n  [pipeline] never auto-submits — review before sending.")
    sys.exit(0 if verdict == "SUBMIT" else 1 if verdict == "REVIEW" else 2)


if __name__ == "__main__":
    main()
