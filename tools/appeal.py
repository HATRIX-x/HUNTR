#!/usr/bin/env python3
"""
appeal — fight the downgrade, but only when you should.

Triagers close reports N/A, Informative, duplicate, or downgrade severity — often wrongly, sometimes
rightly. This reads the triager's reason, classifies the pattern, decides APPEAL / PROVIDE-INFO / DROP
(don't burn goodwill or your signal on a call you'll lose), and drafts an impact-first, evidence-led
rebuttal tuned to exactly what they said.

Usage:
  appeal.py --reason "no real security impact shown" --class idor --severity high --their-severity low \
            --endpoint /api/v1/orders/{id} --impact "any user reads any order incl. PII, enumerable"
  appeal.py --reason "working as intended" --class cors --severity medium --endpoint /api/data
Exit: 0 appeal drafted · 1 provide-info · 2 drop advised.
"""
import sys, re

def arg(n, d=""):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


SEV = ["info", "low", "medium", "high", "critical"]

# pattern → (label, decision, counter-paragraph builder)
def counters(ctx):
    cls, ep, imp, sev, their = ctx["cls"], ctx["ep"], ctx["impact"], ctx["sev"], ctx["their"]
    imp = imp or f"a concrete, attacker-reachable impact on {ep or 'this endpoint'}"
    return [
        (r"out[\s-]?of[\s-]?scope|not in scope|oos", "out-of-scope", "DROP",
         "Re-check the scope page: if the asset/endpoint is genuinely excluded, this is lost — don't dispute. "
         "Only reply if you can cite the exact in-scope clause that covers it."),
        (r"intended|by design|expected behaviou?r|works as", "intended-design", "APPEAL",
         f"'Intended' describes the feature, not its safety. The behaviour still lets {imp}, which crosses a "
         f"security/privacy boundary a user would not expect. Design intent doesn't remove the impact — here is the "
         f"attacker who benefits and the data/action they gain."),
        (r"no .*impact|not .*impact|theoretical|informational|informative|not exploitable|lack of impact", "no-impact", "APPEAL",
         f"Concrete impact, not theory: {imp}. Attacker precondition is minimal (an authenticated low-priv account / "
         f"a crafted request), and the outcome is " +
         ("unauthorized access to other users' data" if cls in ("idor", "authz", "bfla") else "a real, reproducible security effect") +
         ". PoC + captured request/response attached; reproduced 2×."),
        (r"duplicate|already reported|dup", "duplicate", "PROVIDE-INFO",
         "If it's the SAME root cause + endpoint + impact, accept it. Otherwise state the difference precisely: "
         "different parameter / endpoint / root cause / higher impact than the referenced report — and ask for the "
         "dup link to compare. Vague 'not a dup' loses; a specific delta wins."),
        (r"need (more )?info|nmi|cannot reproduce|couldn'?t reproduce|more detail", "needs-info", "PROVIDE-INFO",
         f"This isn't a dispute — give them exactly what unblocks triage: the precise steps against {ep or 'the endpoint'}, "
         f"the two identities/tokens used, the raw request+response, and a short video. Remove any ambiguity; make it copy-paste reproducible."),
        (r"self[\s-]?xss", "self-xss", "APPEAL",
         "Not self-XSS: show the delivery vector — the payload reaches a victim via {stored context / a shareable URL / "
         "a cross-user field}, executing in their session, not only mine. Attach the victim-side reproduction."),
        (r"rate.?limit", "rate-limit", "APPEAL",
         "Rate-limiting matters here because it guards an auth-sensitive flow (login/OTP/reset): its absence enables "
         "credential brute-force / OTP bypass / enumeration at scale — that's the impact, not the missing header itself."),
        (r"user enumeration|username enum|account enum", "user-enum", "APPEAL",
         "This enumeration exposes sensitive PII / confirms high-value accounts and chains into targeted ATO — not a "
         "generic 'usernames exist' info leak. Show the sensitive data returned and the chain it enables."),
        (r"cors", "cors", "DROP",
         "CORS reflection alone is Low/N-A without a chain (your own rule). DROP unless you can show an authenticated, "
         "sensitive cross-origin read that leads to token/session theft — if you can, lead the rebuttal with that chain."),
        (r"downgrad|severity|cvss|lowered|reduced", "severity", "APPEAL", None),  # handled specially below
    ]


def cvss_argument(sev, their):
    if not sev or not their or sev not in SEV or their not in SEV:
        return ("Your CVSS is justified by real impact metrics; ask which specific metric they lowered and why, and "
                "map each back to the demonstrated behaviour (Scope, Confidentiality, Integrity, Availability).")
    if SEV.index(their) >= SEV.index(sev):
        return "They didn't actually downgrade below your claim — no severity appeal needed."
    return (f"They rated it {their.upper()}; it warrants {sev.upper()}. Argue the exact CVSS metrics: if they lowered "
            f"Confidentiality/Integrity despite full data read/write, or set Scope:Unchanged where the impact crosses a "
            f"trust boundary (e.g. into other tenants / another service), those are the metrics to contest — tie each to "
            f"the captured evidence. Provide the vector you claim and the one-line impact per metric.")


def main():
    reason = arg("--reason")
    cls = (arg("--class") or "").lower()
    ep = arg("--endpoint")
    if not reason:
        sys.exit("usage: appeal.py --reason \"triager's closing text\" --class C [--severity][--their-severity][--endpoint][--impact][--program]")
    sev = (arg("--severity") or "").lower()
    their = (arg("--their-severity") or "").lower()
    ctx = {"cls": cls, "ep": ep, "impact": arg("--impact"), "sev": sev, "their": their}

    low = reason.lower()
    clist = counters(ctx)
    hit = None
    # class override: CORS without a proven chain is a losing appeal, whatever they wrote
    if cls == "cors" and not re.search(r"chain|token|session|ato|takeover", (ctx["impact"] or "").lower()):
        hit = next(((l, d, p) for rx, l, d, p in clist if l == "cors"), None)
    if not hit:
        for rx, label, decision, para in clist:
            if re.search(rx, low):
                hit = (label, decision, para); break
    if not hit:
        hit = ("generic", "APPEAL",
               f"Restate the impact plainly and lead with it: {ctx['impact'] or 'a concrete security effect'}. "
               f"Attach PoC + evidence and ask for the specific reason the impact is insufficient.")
    label, decision, para = hit
    if label == "severity":
        para = cvss_argument(sev, their)

    title = arg("--title") or f"{cls.upper() or 'Finding'} on {ep or 'endpoint'}"
    draft = (f"Subject: Request for re-evaluation — {title}\n\n"
             f"Hi team, thanks for taking the time to review this. I'd like to respectfully clarify before it's closed.\n\n"
             f"Impact: {ctx['impact'] or '<state the concrete impact, who is harmed, at what scale>'}.\n\n"
             f"On your note (\"{reason.strip()[:160]}\"): {para}\n\n"
             f"Reproduction + evidence: the captured request/response and step-by-step PoC are in the report; "
             f"I reproduced it 2× and can supply a short video or a second-account demo on request.\n\n"
             f"If I've missed a scope or context detail, I'm glad to be corrected. Otherwise I believe the severity "
             f"reflects the demonstrated impact. Thank you.")

    icon = {"APPEAL": "✎", "PROVIDE-INFO": "＋", "DROP": "✗"}[decision]
    if "--json" in sys.argv:
        import json
        print(json.dumps({"pattern": label, "decision": decision, "guidance": para, "draft": draft}))
        sys.exit({"APPEAL": 0, "PROVIDE-INFO": 1, "DROP": 2}[decision])

    print(f"[appeal] pattern: {label}   →   {icon} {decision}\n")
    if decision == "DROP":
        print("  ⚠ Likely a losing appeal. " + para)
        print("\n  Disputing a correct call burns triager goodwill and your signal. Move on unless the condition above holds.")
        sys.exit(2)
    if decision == "PROVIDE-INFO":
        print("  This isn't a fight — supply what they need:\n  " + para)
    print("\n" + "─" * 58 + "\n" + draft + "\n" + "─" * 58)
    print("\n  Tips: lead with impact, quote their exact words, attach evidence, stay courteous, one strong reply > many.")
    sys.exit(0 if decision == "APPEAL" else 1)


if __name__ == "__main__":
    main()
