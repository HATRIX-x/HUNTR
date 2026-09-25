#!/usr/bin/env python3
"""
report-score — score a report before submit and get specific improvements.

Triagers reject or downgrade reports for predictable reasons: vague impact,
missing PoC, wrong CVSS, no evidence. This tool scores your draft 0–100
across 6 dimensions and tells you exactly what to fix before you hit submit.

Usage:
  report-score.py --title T --class C --cvss 7.5 --sev high --their-sev medium \
                  --impact "any user reads any order" --repro "1. login 2. GET /api/orders/OTHER_ID" \
                  --endpoint /api/orders/{id} [--has-poc] [--has-evidence] [--has-video] \
                  [--program "Acme Corp"] [--json]
Exit: 0 SUBMIT · 1 POLISH · 2 HOLD.
"""
import sys, re, json

SEV_ORDER = ["info","low","medium","high","critical"]
SEV_CVSS  = {"info":(0,0),"low":(0.1,3.9),"medium":(4.0,6.9),"high":(7.0,8.9),"critical":(9.0,10.0)}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def flag(n): return n in sys.argv


# ── dimension scorers ─────────────────────────────────────────────────────────

def score_title(title, cls):
    if not title: return 0, ["Title is missing — required."]
    score = 0; tips = []
    # length
    if len(title) >= 20: score += 3
    else: tips.append("Title too short — include the vuln class, endpoint, and impact in <80 chars.")
    # contains class or common keyword
    cls_words = {"idor","bola","bfla","xss","sqli","ssrf","rce","csrf","ssti","xxe","ato","lfi","rfi","cors","jwt","authbypass","openredirect","injection"}
    title_l = title.lower()
    if any(k in title_l for k in cls_words) or (cls and cls.lower() in title_l): score += 4
    else: tips.append("Add the vulnerability class to the title (e.g. IDOR, SSRF, ATO).")
    # endpoint or context
    if re.search(r"/[a-z]|https?://|via|on|in|through", title_l): score += 3
    else: tips.append("Add the endpoint or context (e.g. 'IDOR on /api/orders/{id}').")
    return score, tips  # max 10

def score_cvss(cvss_str, sev):
    if not cvss_str: return 0, ["CVSS score missing — required for severity justification."]
    tips = []
    try: cvss = float(cvss_str)
    except ValueError: return 0, ["CVSS must be a number (e.g. 7.5)."]
    score = 5
    if sev and sev.lower() in SEV_CVSS:
        lo, hi = SEV_CVSS[sev.lower()]
        if not (lo <= cvss <= hi):
            score = 2
            tips.append(f"CVSS {cvss} doesn't match severity {sev.upper()} ({lo}–{hi}). Fix the vector or the severity label.")
        else:
            score = 10
    if cvss == round(cvss):  # exact integer is suspicious
        score = max(score-2,0)
        tips.append("Integer CVSS is unusual — compute the full vector string (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).")
    return score, tips  # max 10

def score_impact(impact, cls, endpoint):
    if not impact: return 0, ["Impact statement missing — this is the most important section."]
    score = 0; tips = []
    w = impact.lower()
    # who is harmed
    if re.search(r"\b(user|victim|attacker|account|customer|admin|tenant|any|all)\b", w): score += 5
    else: tips.append("Impact must name WHO is harmed (e.g. 'any authenticated user', 'all accounts').")
    # what is exposed/possible
    if re.search(r"\b(read|write|access|leak|steal|modify|delete|escalat|takeover|bypass|execute|inject|exfiltrat|pivot)\b", w): score += 5
    else: tips.append("Describe WHAT the attacker can do (read PII, delete records, escalate to admin).")
    # scale / blast radius
    if re.search(r"\b(all|any|every|million|thousands|enumerate|mass|bulk|complete|full)\b", w): score += 5
    else: tips.append("Quantify the blast radius — how many users/records are at risk?")
    # business impact
    if re.search(r"\b(pii|gdpr|financial|account.?takeover|credential|payment|regulatory|compliance|breach|reputation)\b", w): score += 5
    else: tips.append("Add business context: GDPR, financial loss, credential theft, account takeover.")
    return score, tips  # max 20

def score_repro(repro, endpoint):
    if not repro: return 0, ["Reproduction steps missing — triager cannot verify without them."]
    score = 0; tips = []
    steps = re.findall(r"(?:\d+[\.\)]\s*|\n-\s*|\n\*\s*).+", repro)
    if len(steps) >= 3: score += 8
    elif len(steps) >= 1: score += 4; tips.append("Add more numbered steps — aim for ≥4 copy-paste steps.")
    else: tips.append("Number your steps (1. login as user A 2. send request 3. observe response).")
    # HTTP request
    if re.search(r"(GET|POST|PUT|PATCH|DELETE)\s+/|curl |http", repro, re.I): score += 5
    else: tips.append("Include the raw HTTP request (method + path + key headers + body).")
    # two identities / cross-user
    if re.search(r"(two|second|another|victim|user.?a|user.?b|account.?a|account.?b|attacker|logged.?in|jwt|token|cookie)", repro, re.I): score += 4
    else: tips.append("If cross-user: show two accounts/tokens and prove the boundary violation.")
    # expected vs actual
    if re.search(r"(expect|should|actual|instead|but|however|response|result)", repro, re.I): score += 3
    else: tips.append("Add expected vs actual outcome at the end of your steps.")
    return score, tips  # max 20

def score_poc(has_poc, has_evidence, cls):
    score = 0; tips = []
    if has_poc: score += 12
    else:
        tips.append("No PoC flag set — attach a captured request/response proving the vulnerability.")
        score += 0
    if has_evidence: score += 8
    else:
        tips.append("No evidence flag — attach screenshots or raw HTTP dump showing impact.")
    return score, tips  # max 20

def score_completeness(has_video, endpoint, impact, title):
    score = 0; tips = []
    # endpoint listed
    if endpoint: score += 4
    else: tips.append("Endpoint missing — specify the exact URL/path affected.")
    # video / second account demo
    if has_video: score += 4
    else: tips.append("No video — a 60s screen recording reproducing the issue removes all doubt (especially for ATO/chain).")
    # title + impact both present
    if title and impact: score += 2
    return score, tips  # max 10


def main():
    title    = arg("--title","")
    cls      = arg("--class","")
    cvss_s   = arg("--cvss","")
    sev      = arg("--sev","")
    their_sev= arg("--their-sev","")
    impact   = arg("--impact","")
    repro    = arg("--repro","")
    endpoint = arg("--endpoint","")
    has_poc  = flag("--has-poc")
    has_ev   = flag("--has-evidence")
    has_vid  = flag("--has-video")

    s_title, t_title   = score_title(title, cls)
    s_cvss,  t_cvss    = score_cvss(cvss_s, sev)
    s_impact,t_impact  = score_impact(impact, cls, endpoint)
    s_repro, t_repro   = score_repro(repro, endpoint)
    s_poc,   t_poc     = score_poc(has_poc, has_ev, cls)
    s_comp,  t_comp    = score_completeness(has_vid, endpoint, impact, title)

    total = s_title + s_cvss + s_impact + s_repro + s_poc + s_comp
    max_s = 10 + 10 + 20 + 20 + 20 + 10  # 90 points

    pct = int(total / max_s * 100)

    all_tips = t_title + t_cvss + t_impact + t_repro + t_poc + t_comp

    if pct >= 80:   verdict, exit_c = "SUBMIT", 0
    elif pct >= 60: verdict, exit_c = "POLISH", 1
    else:           verdict, exit_c = "HOLD",   2

    # severity mismatch note
    sev_note = ""
    if sev and their_sev and sev.lower() in SEV_ORDER and their_sev.lower() in SEV_ORDER:
        if SEV_ORDER.index(their_sev.lower()) < SEV_ORDER.index(sev.lower()):
            sev_note = f"Triager rated {their_sev.upper()} vs your {sev.upper()} — include CVSS vector and impact evidence to push back."
            all_tips.append(sev_note)

    result = {
        "score": pct, "verdict": verdict,
        "dimensions": {
            "title":   {"score": s_title,  "max": 10, "tips": t_title},
            "cvss":    {"score": s_cvss,   "max": 10, "tips": t_cvss},
            "impact":  {"score": s_impact, "max": 20, "tips": t_impact},
            "repro":   {"score": s_repro,  "max": 20, "tips": t_repro},
            "poc":     {"score": s_poc,    "max": 20, "tips": t_poc},
            "complete":{"score": s_comp,   "max": 10, "tips": t_comp},
        },
        "tips": all_tips,
    }

    if flag("--json"):
        print(json.dumps(result)); sys.exit(exit_c)

    icon = {"SUBMIT":"✓","POLISH":"⚠","HOLD":"✗"}[verdict]
    col  = {"SUBMIT":"","POLISH":"","HOLD":""}[verdict]
    bar  = "█" * (pct//10) + "░" * (10 - pct//10)

    print(f"\n[report-score] {icon} {verdict}  {pct}/100  {bar}")
    print(f"\n  Dimensions:")
    for k,(s,mx) in [("title",(s_title,10)),("cvss",(s_cvss,10)),("impact",(s_impact,20)),
                      ("repro",(s_repro,20)),("poc",(s_poc,20)),("complete",(s_comp,10))]:
        bar_d = "█"*(s*8//mx)+"░"*(8-s*8//mx) if mx else ""
        print(f"    {k:<10} {bar_d}  {s:2}/{mx}")

    if all_tips:
        print(f"\n  What to fix ({len(all_tips)} items):")
        for i,tip in enumerate(all_tips,1):
            print(f"    {i}. {tip}")

    print(f"\n  Verdict: {icon} {verdict} — {'ready to submit.' if verdict=='SUBMIT' else 'fix the items above before submitting.' if verdict=='POLISH' else 'too many gaps — triager will reject. Fix all items.'}")
    sys.exit(exit_c)

if __name__ == "__main__":
    main()
