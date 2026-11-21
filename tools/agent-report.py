#!/usr/bin/env python3
"""
agent-report.py — writes a submission-grade report for ONE finding.

Reads the finding (+ evidence), optionally re-checks one request live, and produces a
HackerOne/YesWeHack-ready markdown report: title, severity + CVSS vector, summary, steps
to reproduce, impact, remediation. Saves it to finding.report and returns it.

stdin : {"fi": <index>, "program": "...", "session_cookie": "..."}
stdout: {"ok":true,"report":"<markdown>","tool_calls":[...]}
"""
import agent_core as A

d = A.read_stdin_json()
fi = d.get("fi")
if fi is None:
    A.emit({"ok": False, "error": "need fi"})
fs = A.findings()
try:
    fi = int(fi)
except Exception:
    A.emit({"ok": False, "error": "bad fi"})
if not (0 <= fi < len(fs)):
    A.emit({"ok": False, "error": "fi out of range"})
f = fs[fi]
program = d.get("program") or A.read_run().get("program") or ""

if d.get("session_cookie"):
    A.set_identity("session", cookie=d["session_cookie"])
has_sess = A.has_identity("session")

# platform: from explicit arg, else infer from program text, else HackerOne
plat = (d.get("platform") or "").strip()
if not plat:
    pl = (str(program) + " " + str(A.read_run().get("program_platform", ""))).lower()
    plat = ("Intigriti" if "intigriti" in pl else "Bugcrowd" if "bugcrowd" in pl else
            "Immunefi" if "immunefi" in pl else "YesWeHack" if ("yeswehack" in pl or "ywh" in pl) else "HackerOne")

tools = [A.http_tool_def(has_sess)]
handlers = {"http_request": A.http_handler}

TEMPLATE = (
    "# " + plat + " Submission: <Program> - <Short Descriptive Title>\n\n"
    "**Program:** <name>  \n**Platform:** " + plat + "  \n"
    "**Severity:** <Critical/High/Medium/Low> (CVSS <score>)  \n"
    "**Bounty Estimate:** $<low>-$<high>  \n**Asset:** <affected host(s)>  \n"
    "**Weakness:** CWE-<id> (<name>)\n\n---\n\n"
    "## Title\n<[Bug Class] in [Endpoint] allows [actor] to [impact] — the title FORMULA>\n\n"
    "## Severity\n<level>  \nCVSS:3.1/<full vector string>\n\n"
    "## Description\n<IMPACT-FIRST: sentence 1 = what the attacker gets. 2-4 sentences, concrete, no hedging.>\n\n"
    "## Steps to Reproduce\n"
    "**Step 1:** <action>\n```bash\n<exact copy-pasteable curl/http request>\n```\n"
    "<the real response line(s) that PROVE impact — actual data, not '200 OK'>\n\n"
    "**Step 2:** <...>\n\n"
    "## Impact\n<quantified: who/how many affected, what data/action, GDPR/$ where relevant>\n\n"
    "## Remediation\n<1-2 specific sentences>\n")

system = (
    "You are HUNTR's senior bug-bounty report writer. Produce a SUBMISSION-READY report for ONE finding "
    "in the EXACT template below, grounded ONLY in real evidence. You may call http_request to capture the "
    "real request/response that proves the bug, but NEVER invent a response.\n"
    "OUTPUT ONLY THE REPORT MARKDOWN — it MUST start with '# " + plat + " Submission:' as the very first "
    "characters. No preamble, no meta-commentary, no notes about tools or truncation, nothing after the "
    "Remediation section.\n\n"
    "OUTPUT EXACTLY THIS STRUCTURE (fill every placeholder, keep the header block and '---'):\n" + TEMPLATE +
    "\nHARD RULES (from the /report playbook):\n"
    "• Title formula: '[Bug Class] in [Endpoint] allows [actor] to [impact]'.\n"
    "• Impact-first: first Description sentence states what the attacker GAINS, not what the bug is.\n"
    "• NEVER write 'could potentially', 'may allow', 'might be possible'. State it plainly.\n"
    "• PROVE it: show the actual returned data/action in Steps, never just a status code.\n"
    "• CVSS 3.1: give the full vector string AND score; match severity to real impact — do NOT inflate. "
    "Publishable/public keys (reCAPTCHA site key, analytics project token, Sentry public DSN) are LOW/info.\n"
    "• Pick the correct CWE. Give a realistic Bounty Estimate range for this platform/severity.\n"
    "• Keep it under ~600 words. Write to a human triager.\n"
    "• If the finding is weak/unconfirmed, lower the severity and say so plainly in Description — do not dress it up.\n"
    "Program: " + str(program)[:160] + " · Platform: " + plat +
    A.skill_for(by_name="report-writing", budget=1800) +
    A.skill_for((f.get("cls", "") + " " + f.get("title", "")), budget=1600)
)
user = ("Write the " + plat + " report for this finding. Capture the proving request/response with "
        "http_request if it helps:\n" + A.json.dumps(f)[:5000])

reply, tlog, err = A.run_agent(system, user, tools, handlers, max_rounds=4, max_tokens=1800)
if not reply:
    A.emit({"ok": False, "error": "report agent unavailable: " + str(err or "")[:150], "tool_calls": tlog})

# strip any preamble before the report header, and any trailing meta after it
rep = reply.strip()
m = A.re.search(r"^#\s+\S+\s+Submission:", rep, A.re.M)
if m:
    rep = rep[m.start():].strip()
A.update_finding(fi, {"report": rep, "ai_report": True})
A.emit({"ok": True, "report": rep, "tool_calls": tlog})
