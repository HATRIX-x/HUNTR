#!/usr/bin/env python3
"""
scope-parse.py — turn a pasted bug-bounty PROGRAM PAGE into a clean, structured scope with the LLM.

Paste the whole program (scope table, out-of-scope, rewards, rules, UA requirement, …) and this extracts:
  • in_scope assets, each classified web | api | mobile | source | other
  • out_of_scope assets (→ deny list, so the hunt STICKS to scope)
  • rewards summary, any required User-Agent, and a one-line rules note
So the operator pastes once and the engine is pointed at exactly the right assets, nothing out of scope.

Usage:  scope-parse.py --text "<program page>"   (or pipe text on stdin)   [--json]
Emits:  {"in_scope":[{"asset","type"}], "out_of_scope":[..], "rewards":"", "ua_required":"", "notes":""}
"""
import sys, os, re, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Use the unified LLM client
import llm_client


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def out(d):
    print(json.dumps(d)); sys.exit(0)


TEXT = arg("--text") or (sys.stdin.read() if not sys.stdin.isatty() else "")

if not TEXT.strip():
    out({"in_scope": [], "out_of_scope": [], "error": "no text"})


# Program-page parsing is a cheap, public-data summarization task → Haiku 5.5 (operator choice).
INTAKE_MODEL = os.environ.get("HUNT_MODEL_INTAKE", "claude-haiku-5-5")

_LAST_ERR = {"e": ""}

def llm(system, user, max_tokens=1800, timeout=120):
    text, err = llm_client.call_llm(system, user, model=INTAKE_MODEL, max_tokens=max_tokens, timeout=timeout)
    if err:
        _LAST_ERR["e"] = str(err)
    return text


def ljson(system, user, **kw):
    txt = llm(system, user, **kw)
    if not txt:
        return None
    t = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", txt.strip(), flags=re.I | re.M).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    m = re.search(r"\{.*\}", t, re.S)
    if m:
        try: return json.loads(m.group(0))
        except Exception: return None
    return None


def regex_fallback(text):
    """No LLM available → best-effort regex extraction so paste still works offline."""
    assets = re.findall(r"(?:https?://)?(?:\*\.)?[a-z0-9.-]+\.[a-z]{2,}(?:/[\w./-]*)?", text, re.I)
    # crude in/out split by nearest heading
    low = text.lower()
    out_start = low.find("out of scope") if "out of scope" in low else low.find("out-of-scope")
    in_scope, out_scope = [], []
    for a in dict.fromkeys(assets):
        pos = text.find(a)
        (out_scope if out_start >= 0 and pos > out_start else in_scope).append(a)
    def typ(a):
        al = a.lower()
        if "github.com" in al or "gitlab.com" in al: return "source"
        if "api" in al or al.startswith("http") and "/api" in al: return "api"
        return "web"
    return {"in_scope": [{"asset": a, "type": typ(a)} for a in in_scope[:40]],
            "out_of_scope": out_scope[:40], "rewards": "", "ua_required": "", "notes": "(regex fallback — LLM unavailable)"}


SYS = ("You are a bug-bounty intake analyst. Turn a pasted PROGRAM PAGE into a precise, machine-usable "
       "summary. Extract ONLY what the program EXPLICITLY lists — never invent, and NEVER treat page noise "
       "as scope: ignore navigation menus, the top-hackers/leaderboard, stats, analytics/cookie domains "
       "(_ga, utm, anything from a cookie file), and generic mentions of the company name. An in-scope asset "
       "is one that appears in the program's SCOPE / ASSETS / 'In Scope' list with an eligibility or reward.\n"
       "For EACH in-scope asset give: asset (the exact identifier — a domain, wildcard kept verbatim, API "
       "name, app name, or repo), type in {web, api, mobile, source, executable, other} (REST API→api; "
       "CLI/Agent/Desktop binaries→executable; mobile/iOS/Android app→mobile; SDK/MCP→other; GitHub/GitLab "
       "repo→source; site/domain/web app→web), and cap = the asset's max severity if the page states one "
       "(Critical/High/Medium/Low) else \"\". DEDUPE assets. Put every asset the page marks out-of-scope / "
       "excluded / ineligible in out_of_scope (with a brief reason).\n"
       "`targets` = clean, ready-to-hunt strings an operator pastes to start (bare hosts/wildcards/repo URLs "
       "from the WEB/API/source assets; omit client-app/SDK/executable entries that aren't a URL).\n"
       "Return ONLY this JSON, no prose, no code fences:\n"
       "{\"program\":\"\",\"platform\":\"\",\"in_scope\":[{\"asset\":\"\",\"type\":\"\",\"cap\":\"\"}],"
       "\"out_of_scope\":[],\"targets\":[],\"rewards\":\"\",\"severity_rewards\":[{\"severity\":\"\",\"amount\":\"\"}],"
       "\"focus\":[],\"rules\":[],\"poc_required\":false,\"rate_limit\":\"\",\"ua_required\":\"\","
       "\"ai_policy\":\"\",\"summary\":\"\"}\n"
       "`rewards` = the overall range (e.g. '$250–$50,000'); `severity_rewards` = the per-tier table if given. "
       "`rate_limit` = any request-rate cap (e.g. '2 req/s'). `rules` = the 4-8 MOST important do/don'ts "
       "(PoC requirement, trial-setup/registration tokens like [BUGBOUNTY], no-DoS, no customer-data/testing, "
       "tool bans e.g. no Burp screenshots, disclosure, AI-report policy). `focus` = vuln classes the program "
       "says it values. `summary` = 2-3 sentence operator briefing. Absent → \"\" / [] / false.")


def main():
    if not TEXT.strip():
        out({"in_scope": [], "out_of_scope": [], "error": "no text"})

    # Program pages are long — the asset table, rewards, and rules often sit in the LAST third (a 15k cut
    # dropped them entirely on Files.com). Claude handles 48k fine. Strip an appended Netscape cookie file
    # (the "# Netscape HTTP Cookie File" block) so cookie domains aren't mistaken for in-scope assets.
    body = TEXT
    cut = body.find("# Netscape HTTP Cookie File")
    if cut > 500:
        body = body[:cut]
    body = body[:48000]
    parsed = ljson(SYS, body, max_tokens=2600)
    if not parsed:
        parsed = ljson(SYS, body, max_tokens=3500)
    if not parsed:
        # If the LLM was rate-limited / auth-blocked, say so clearly instead of returning a garbage
        # regex summary that looks like a real parse.
        le = _LAST_ERR["e"].lower()
        if any(k in le for k in ("limit", "resets", "/login", "rate", "quota", "credit")):
            out({"in_scope": [], "out_of_scope": [], "targets": [],
                 "error": "LLM unavailable (session limit / auth). " + _LAST_ERR["e"][:160] +
                          " — wait for reset or switch the intake account."})
        out(regex_fallback(TEXT))

    # Ensure keys + types
    for k in ("in_scope", "out_of_scope", "targets", "severity_rewards", "focus", "rules"):
        if not isinstance(parsed.get(k), list):
            parsed[k] = []
    for k in ("program", "platform", "rewards", "ua_required", "ai_policy", "rate_limit", "summary", "notes"):
        parsed.setdefault(k, "")
    parsed.setdefault("poc_required", False)

    # Derive clean targets if the model didn't: bare hosts/wildcards/repos from in_scope.
    if not parsed["targets"] and parsed["in_scope"]:
        for a in parsed["in_scope"]:
            asset = (a.get("asset") if isinstance(a, dict) else str(a)).strip()
            if asset:
                parsed["targets"].append(re.sub(r"^https?://", "", asset).rstrip("/"))
    parsed["model"] = INTAKE_MODEL
    out(parsed)


if __name__ == "__main__":
    main()