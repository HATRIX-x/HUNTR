#!/usr/bin/env python3
"""
report-draft — draft a full vulnerability report for a single finding, formatted
for the target platform. Drafts only; it never submits. Review before sending.

Templates:
  h1  = HackerOne  (markdown)
  ywh = YesWeHack  (structured sections)
  bc  = Bugcrowd   (VRT-oriented markdown)
  ing = Intigriti  (markdown)

Reads HUNT_LLM_API_KEY from env (or --api-key). Uses llm_client for provider abstraction.
Zero deps beyond stdlib.

Usage:
  report-draft.py --finding-file finding.json \
                  [--template h1] [--model nvidia/nemotron-3-ultra-550b-a55b] [--json]

Output: {ok, title, severity, report_markdown, word_count, score}
"""
import sys, os, json, time
from pathlib import Path

# Use the unified LLM client
sys.path.insert(0, os.path.dirname(__file__))
import llm_client

# Report writing is prose-shaping over evidence already proven by the pipeline, not reasoning about
# new evidence — Haiku 5.5 is fast/cheap and, held to the STRUCTURE contract below, matches Sonnet on
# this task. --model/--provider on the command line still override.
REPORT_MODEL = "claude-haiku-5-5"
REPORT_PROVIDER = "anthropic"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


# Platform-specific tweaks LAYERED ON TOP of STRUCTURE (below). STRUCTURE is the real spec.
TEMPLATES = {
    "h1":  "Platform: HackerOne (GitHub-flavored Markdown).",
    "ywh": "Platform: YesWeHack. Keep the same structure; formal tone; CVSS vector is mandatory.",
    "bc":  "Platform: Bugcrowd. After the metadata block add a line '**VRT:** <best-guess VRT category>'.",
    "ing": "Platform: Intigriti (Markdown).",
}

# The report CONTRACT — this is what turns a 'paragraph' into a real, submittable report.
# Modeled on senior human reports: a metadata block, a tight Summary, the mechanism, then a
# numbered PoC where EVERY step shows the literal request AND the real response/output.
STRUCTURE = (
    "Produce a COMPLETE vulnerability report with EXACTLY this structure. Do not collapse it into prose.\n"
    "\n"
    "1. H1 title line: `# <Vulnerability class>: <specific, concrete one-liner>` "
    "(e.g. '# Server-Side Request Forgery (SSRF) via /commonService/checkUrlConnectivity'). "
    "If the finding has an id/ref, prefix it: '# F<NN> — <class>: <one-liner>'.\n"
    "2. A metadata block of bold key/value lines, each on its own line ending with two spaces:\n"
    "   **Target:** <full URL or host>  ·  **Endpoint:** <method + path>  ·  **Severity:** <Critical/High/Medium/Low>  ·  "
    "**CVSS:** <3.1 vector string> (<score>)  ·  **Class:** <class>. Include every field you have evidence for; omit none you do.\n"
    "3. `---` separator.\n"
    "4. `## Summary` — 2-4 sentences: what the bug is, where, who can trigger it, and the concrete security consequence. "
    "No hedging words ('could potentially', 'may be possible'): state what IS proven.\n"
    "5. `## Mechanism` (or `## Core Insight`) — WHY it works: the broken assumption, the missing control, the exact root cause. "
    "If the finding chains or compounds, explain both halves.\n"
    "6. `## Proof of Concept` — NUMBERED steps. EACH step MUST contain, in fenced code blocks:\n"
    "   - the literal HTTP request (method, path, key headers, body) OR a copy-pasteable curl command, and\n"
    "   - the ACTUAL observed response: status line + the decisive body/header snippet, taken VERBATIM from the "
    "finding's proof/evidence/detail. Show the discriminating signal (timing, status diff, reflected marker, leaked value).\n"
    "   Build from a baseline request to the exploited request so the difference is undeniable.\n"
    "7. `## Impact` — concrete, attacker-POV, business-relevant. What an attacker reads/writes/escalates. No generic boilerplate.\n"
    "8. `## Remediation` — specific, actionable fix for THIS root cause (not 'add validation').\n"
    "\n"
    "HARD RULES: Use ONLY evidence present in the finding JSON (proof.evidence, detail, repro, endpoint, cvss) — "
    "reproduce requests/responses/values VERBATIM; never fabricate a header, token, response body, or output that is not in the data. "
    "If a datum (e.g. CVSS vector) is missing, derive a reasonable one from the class/impact and mark it, but never invent evidence. "
    "Return ONLY the report body in Markdown, starting at the H1."
)


def quick_score(md, finding):
    """Reward the structure of a REAL report (metadata block, numbered PoC with request+response,
    code fences, CVSS vector), not just the presence of a few keywords. A generic paragraph scores low."""
    import re
    s = 10
    low = md.lower()
    # core sections
    for kw, pts in (("## summary", 10), ("## proof of concept", 12), ("## impact", 10),
                    ("## remediation", 8), ("mechanism", 6), ("core insight", 6)):
        if kw in low:
            s += pts
    # metadata block
    if "**severity:**" in low or re.search(r"\*\*severity\*\*", low):
        s += 6
    if "cvss" in low and re.search(r"(av:[nalp])", low):   # a real CVSS vector, not just the word
        s += 10
    if "**target:**" in low or "**endpoint:**" in low:
        s += 6
    # reproducibility: numbered steps + fenced code + an actual request AND response
    if re.search(r"(?m)^\s*1\.", md) and re.search(r"(?m)^\s*2\.", md):
        s += 8
    fences = md.count("```")
    if fences >= 4:
        s += 10
    elif fences >= 2:
        s += 5
    if re.search(r"(?mi)^(GET|POST|PUT|DELETE|PATCH) /", md) or "curl " in low:
        s += 6   # a literal request
    if re.search(r"(?mi)(HTTP/\d|→ *HTTP|\b[2345]\d\d\b.*(OK|error|forbidden|internal))", md):
        s += 6   # an actual response
    # no-hedge bonus (impact-first writing)
    if "could potentially" not in low and "may be possible" not in low:
        s += 4
    # length: a real report is substantial
    wc = len(md.split())
    if wc >= 350:
        s += 8
    elif wc >= 180:
        s += 4
    return min(100, s)


SYSTEM_BASE = (
    "You are a senior bug-bounty researcher writing a submittable vulnerability report for an "
    "authorized program — the kind a triager accepts without asking for more. Precise, reproducible, "
    "impact-first; never exaggerate and never invent evidence not present in the finding.\n\n"
    + STRUCTURE + "\n\n"
)


def main():
    ff = arg("--finding-file")
    template = arg("--template", "h1")
    model = arg("--model")
    provider = arg("--provider")
    api_key = arg("--api-key")
    if not model:              # no explicit override → default to Haiku 5.5 (and its provider, so the
        model = REPORT_MODEL   # model id isn't sent to whatever provider HUNT_LLM_PROVIDER happens to be)
        provider = provider or REPORT_PROVIDER

    if not ff:
        print(__doc__)
        sys.exit(0)

    try:
        finding = json.loads(Path(ff).read_text())
    except Exception as ex:
        out = {"ok": False, "error": f"cannot read finding: {ex}"}
        print(json.dumps(out) if flag("--json") else out["error"])
        sys.exit(2)

    tpl = TEMPLATES.get(template, TEMPLATES["h1"])
    title_guess = finding.get("title") or finding.get("attack") or finding.get("test") or "Vulnerability"
    severity = finding.get("severity") or finding.get("estimated_severity") or "medium"

    user = ("Finding JSON:\n" + json.dumps(finding, indent=2)[:6000] +
            f"\n\nWrite the report. Start with a one-line H1 title. Severity: {severity}.")

    print(f"[report-draft] model={model or llm_client.get_provider_config()['model']} "
          f"provider={provider or llm_client.get_provider_config()['provider']} template={template}", file=sys.stderr)
    md, err = llm_client.call_llm(SYSTEM_BASE + tpl, user, model=model, api_key=api_key, provider=provider)

    if err:
        out = {"ok": False, "error": err}
        print(json.dumps(out) if flag("--json") else f"[report-draft] error: {err}")
        sys.exit(2)

    title = title_guess
    for line in md.splitlines():
        st = line.strip().lstrip("#").strip()
        if st:
            title = st
            break

    score = quick_score(md, finding)
    wc = len(md.split())

    result = {"ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"), "template": template,
              "model": model or "auto", "title": title, "severity": severity,
              "report_markdown": md, "word_count": wc, "score": score}

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"Title: {title}")
    print(f"Severity: {severity}  |  Score: {score}  |  Words: {wc}")
    print("\n" + "=" * 60)
    print(md)
    sys.exit(0)


if __name__ == "__main__":
    import time
    main()