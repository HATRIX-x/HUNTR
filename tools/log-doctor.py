#!/usr/bin/env python3
"""
log-doctor — the HUNTR self-healing agent.

Reads the engine's logs (server log, per-hunt run.log / run.json), detects problems
(missing tools, tracebacks, timeouts, auth failures, tool errors), DIAGNOSES them with
Claude (via llm_auth — your linked account or API key), auto-fixes the safe ones, and
reports the rest with a concrete fix.

Usage:
  log-doctor.py [--json] [--dry] [--tail N] [--no-llm]
    --json     machine-readable report (for /api/log-doctor)
    --dry      diagnose only; never apply a fix
    --tail N   lines to read from each log (default 400)
    --no-llm   skip the Claude diagnosis, heuristics only
"""
import sys, os, re, json, glob, shutil, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = Path.home()
TOOLS = HOME / ".claude" / "tools"
AGENT_TOOLS = HOME / ".huntr-agent" / "tools"
ROOT = Path(os.environ.get("HUNTR_HOME", str(HOME / ".huntr")))
TARGETS = ROOT / "targets"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


TAIL = int(arg("--tail", "400") or 400)
DRY = flag("--dry")
JSON_OUT = flag("--json")
NO_LLM = flag("--no-llm")


def tail(path, n=TAIL):
    try:
        with open(path, errors="ignore") as f:
            return f.readlines()[-n:]
    except OSError:
        return []


def log_sources():
    srcs = []
    for p in ("/tmp/huntr-server.log", str(HOME / ".huntr" / "server.log")):
        if os.path.exists(p):
            srcs.append(p)
    for rl in glob.glob(str(TARGETS / "*" / ".hunt" / "run.log")):
        srcs.append(rl)
    return srcs


def detect():
    """Heuristic problem detection across all logs. Returns list of problem dicts."""
    problems = []
    seen = set()
    missing_tools = set()

    def add(kind, sig, detail, src, sev="medium", tool=None):
        key = kind + "|" + sig
        if key in seen:
            for p in problems:
                if p["_key"] == key:
                    p["count"] += 1
            return
        seen.add(key)
        problems.append({"_key": key, "kind": kind, "signature": sig, "detail": detail[:300],
                         "source": os.path.basename(os.path.dirname(os.path.dirname(src))) or src,
                         "severity": sev, "count": 1, "tool": tool})

    for src in log_sources():
        lines = tail(src)
        text = "".join(lines)
        for m in re.finditer(r"tool not found:\s*([\w.-]+\.py)", text):
            t = m.group(1); missing_tools.add(t); add("missing-tool", t, "engine could not find " + t, src, "high", t)
        for m in re.finditer(r"No such file or directory[^\n]*?([\w-]+\.py)", text):
            t = m.group(1)
            if (AGENT_TOOLS / t).exists() or (TOOLS / t).exists():
                missing_tools.add(t); add("missing-tool", t, m.group(0), src, "high", t)
        for m in re.finditer(r"ModuleNotFoundError: No module named '([\w.]+)'", text):
            add("missing-module", m.group(1), m.group(0), src, "high")
        if "Traceback (most recent call last)" in text:
            for i, ln in enumerate(lines):
                if ln.startswith("Traceback"):
                    exc = ""
                    for j in range(i + 1, min(i + 25, len(lines))):
                        if re.match(r"^[A-Za-z_][\w.]*(Error|Exception|Warning):", lines[j]):
                            exc = lines[j].strip(); break
                    add("traceback", exc or "traceback", exc or ln.strip(), src, "high")
        for m in re.finditer(r"✗ runner error:\s*(.+)", text):
            add("runner-error", m.group(1).strip()[:60], m.group(1).strip(), src, "high")
        for m in re.finditer(r"(timeout|timed out)", text, re.I):
            add("timeout", "tool timeout", "a tool hit its time limit", src, "low")
        for m in re.finditer(r"\b(401|403)\b[^\n]{0,60}(unauth|forbidden|token|expired)", text, re.I):
            add("auth", "auth failure", m.group(0)[:120], src, "medium")
        for m in re.finditer(r"HTTP\s*(5\d\d)", text):
            add("server-5xx", "HTTP " + m.group(1), m.group(0), src, "medium")
    for p in problems:
        p.pop("_key", None)
    return problems, missing_tools


def autofix(problems, missing_tools):
    """Apply only safe, well-understood fixes. Returns list of applied fixes."""
    applied = []
    for t in sorted(missing_tools):
        dst = TOOLS / t; src = AGENT_TOOLS / t
        if not dst.exists() and src.exists():
            if DRY:
                applied.append({"problem": "missing-tool " + t, "fix": "copy " + str(src) + " -> " + str(dst), "applied": False})
            else:
                try:
                    shutil.copy2(src, dst)
                    applied.append({"problem": "missing-tool " + t, "fix": "copied " + t + " into ~/.claude/tools/", "applied": True})
                except Exception as e:
                    applied.append({"problem": "missing-tool " + t, "fix": "copy failed: " + str(e)[:80], "applied": False})
    return applied


def llm_diagnose(problems):
    if NO_LLM or not problems:
        return []
    try:
        sys.path.insert(0, str(TOOLS))
        from llm_auth import llm_headers
        import urllib.request
        hdrs, mode = llm_headers()
        if not hdrs:
            return []
        hdrs["content-type"] = "application/json"
        digest = "\n".join(f"- [{p['kind']}/{p['severity']}] {p['signature']} (x{p['count']}) :: {p['detail']}" for p in problems[:20])
        sysmsg = ("You are an SRE for a local bug-bounty engine (Python HTTP server that shells out to "
                  "scanner tools in ~/.claude/tools, driven by a web dashboard). Given log problems, return "
                  "STRICT JSON: {\"diagnoses\":[{\"signature\":\"...\",\"root_cause\":\"...\",\"fix\":\"concrete step\",\"auto_fixable\":true|false}]}. "
                  "Be specific and terse. No prose outside JSON.")
        body = json.dumps({"model": "claude-haiku-4-5", "max_tokens": 1200,
                           "system": sysmsg, "messages": [{"role": "user", "content": "Problems:\n" + digest}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read())
        txt = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        m = re.search(r"\{.*\}", txt, re.S)
        return json.loads(m.group(0)).get("diagnoses", []) if m else []
    except Exception:
        return []


def main():
    problems, missing_tools = detect()
    applied = autofix(problems, missing_tools)
    diagnoses = llm_diagnose(problems)
    # merge LLM diagnosis onto problems by signature
    dmap = {d.get("signature", ""): d for d in diagnoses}
    for p in problems:
        d = dmap.get(p["signature"])
        if d:
            p["root_cause"] = d.get("root_cause", "")
            p["fix"] = d.get("fix", "")
            p["auto_fixable"] = d.get("auto_fixable", False)
    report = {"ok": True, "problems": problems, "fixes_applied": applied,
              "summary": {"problems": len(problems), "fixed": sum(1 for a in applied if a.get("applied")),
                          "sources": len(log_sources())}}
    if JSON_OUT:
        print(json.dumps(report)); return
    print("── log-doctor ──")
    print(f"scanned {report['summary']['sources']} log source(s) · {len(problems)} problem(s) · {report['summary']['fixed']} auto-fixed")
    for a in applied:
        print(("  ✓ " if a.get("applied") else "  • ") + a["problem"] + " → " + a["fix"])
    for p in problems:
        print(f"\n  [{p['severity']}] {p['kind']}: {p['signature']}  (x{p['count']})")
        if p.get("root_cause"): print("    cause: " + p["root_cause"])
        if p.get("fix"): print("    fix:   " + p["fix"])
    if not problems and not applied:
        print("  ✓ no problems found in the logs")


if __name__ == "__main__":
    main()
