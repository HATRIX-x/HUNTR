#!/usr/bin/env python3
"""
report-draft — draft a full vulnerability report for a single finding, formatted
for the target platform. Drafts only; it never submits. Review before sending.

Templates:
  h1  = HackerOne  (markdown)
  ywh = YesWeHack  (structured sections)
  bc  = Bugcrowd   (VRT-oriented markdown)
  ing = Intigriti  (markdown)

Reads ANTHROPIC_API_KEY from env (or --api-key). Zero deps beyond urllib.

Usage:
  report-draft.py --finding-file finding.json \
                  [--template h1] [--model claude-sonnet-4-6] [--json]

Output: {ok, title, severity, report_markdown, word_count, score}
"""
import sys, os, json, time, ssl
from pathlib import Path
from urllib.request import Request, urlopen

MODELS = {"strong": "claude-opus-4-8", "mid": "claude-sonnet-4-6",
          "cheap": "claude-haiku-4-5-20251001"}

TEMPLATES = {
    "h1":  "HackerOne. Markdown. Sections: **Summary**, **Steps To Reproduce** "
           "(numbered), **Impact**, **Remediation**. Concise, evidence-first.",
    "ywh": "YesWeHack. Structured sections: Description, Reproduction steps, "
           "Impact, CVSS vector, Remediation. Formal tone.",
    "bc":  "Bugcrowd. Markdown mapped to VRT. Sections: Summary, Steps to "
           "Reproduce, Impact (business), Recommended Fix.",
    "ing": "Intigriti. Markdown. Sections: Summary, Proof of Concept (steps), "
           "Impact, Suggested remediation. Include a clear one-line title.",
}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def call_claude(model, system, user, api_key, max_tokens=2500):
    if not api_key:
        return None, "no ANTHROPIC_API_KEY set (export it or pass --api-key)"
    payload = json.dumps({
        "model": model, "max_tokens": max_tokens, "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode()
    req = Request("https://api.anthropic.com/v1/messages", data=payload, headers={
        "content-type": "application/json", "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }, method="POST")
    try:
        with urlopen(req, timeout=90, context=ssl.create_default_context()) as r:
            data = json.loads(r.read())
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        return "".join(parts).strip(), None
    except Exception as ex:
        detail = ""
        try:
            detail = ex.read().decode("utf-8", "ignore")[:300]
        except Exception:
            pass
        return None, f"{type(ex).__name__}: {ex} {detail}".strip()


def quick_score(md, finding):
    s = 40
    low = md.lower()
    for kw, pts in (("step", 12), ("impact", 12), ("remediat", 12),
                    ("summary", 8), ("http", 8)):
        if kw in low:
            s += pts
    if finding.get("severity"):
        s += 4
    wc = len(md.split())
    if 120 <= wc <= 900:
        s += 4
    return min(100, s)


SYSTEM_BASE = (
    "You are a bug-bounty report writer for authorized programs. Write a complete, "
    "submittable vulnerability report from the finding JSON. Be precise, reproducible, "
    "and impact-driven; do not exaggerate or invent evidence not present in the finding. "
    "Return ONLY the report body in Markdown (no preamble). Follow this platform format: "
)


def main():
    ff = arg("--finding-file")
    template = arg("--template", "h1")
    model = arg("--model", MODELS["mid"])
    model = MODELS.get(model, model)
    api_key = arg("--api-key") or os.environ.get("ANTHROPIC_API_KEY")

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

    print(f"[report-draft] model={model} template={template}", file=sys.stderr)
    md, err = call_claude(model, SYSTEM_BASE + tpl, user, api_key)

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

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "template": template, "model": model,
        "title": title[:160], "severity": severity,
        "report_markdown": md,
        "word_count": len(md.split()),
        "score": quick_score(md, finding),
    }

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"\n== report draft · {template} · score {result['score']}/100 · "
          f"{result['word_count']} words ==\n")
    print(md)
    print("\n[report-draft] draft only — review and submit manually.")
    sys.exit(0)


if __name__ == "__main__":
    main()
