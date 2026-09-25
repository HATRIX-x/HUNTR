#!/usr/bin/env python3
"""
dup-score — the pre-submit gut check as a real number: how likely is this a duplicate?

dedup-check surfaces candidate matches; this turns the whole picture into a calibrated probability so
you don't burn a submission (a dup earns $0 and dents your signal). It blends four signals:
  • similarity to disclosed reports (known.md) + your own submissions (submitted.jsonl)   [strongest]
  • class dup-prior — CORS/redirect/clickjacking dup constantly; RCE/logic rarely
  • program crowding — reports/week + dup-rate from the program-roi registry
  • endpoint obviousness — /login, /search, /users, /me, /graphql dup more than deep paths
Verdict: HOLD (likely dup) · REVIEW (differentiate first) · SUBMIT (looks unique).

Usage:
  dup-score.py --class idor --endpoint /api/v1/orders/{id} [--param id] [--title "..."] [--program "Acme"] [--stack saas]
Exit: 0 SUBMIT · 1 REVIEW · 2 HOLD.
"""
import sys, os, re, json, math
from collections import Counter
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
REG = Path(os.environ.get("HUNT_PROGRAMS", str(Path.home() / ".claude" / "hunt-programs"))) / "programs.jsonl"

# base probability a finding of this class is a duplicate on a public program
CLASS_PRIOR = {
    "cors": 0.55, "openredirect": 0.52, "clickjacking": 0.58, "xss": 0.42, "csrf": 0.38,
    "infoleak": 0.6, "misconfig": 0.5, "idor": 0.32, "ssrf": 0.3, "authbypass": 0.24,
    "sqli": 0.2, "rce": 0.12, "ssti": 0.15, "logic": 0.16, "race": 0.22, "jwt": 0.26,
    "oauth": 0.3, "saml": 0.2, "session": 0.26, "fileupload": 0.3, "misc": 0.42,
}
OBVIOUS = ("/login", "/signin", "/register", "/search", "/users", "/me", "/profile", "/graphql",
           "/oauth", "/reset", "/forgot", "/admin", "/api/v1/users", "/account", "/password")


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def norm(c):
    return (c or "").lower().strip().replace(" ", "").replace("-", "").replace("_", "")


def norm_ep(ep):
    ep = (ep or "").lower().split("?")[0]
    ep = re.sub(r"/\d+", "/{id}", ep)
    return re.sub(r"/[0-9a-f]{8,}", "/{id}", ep)


def toks(t):
    t = (t or "").lower()
    return Counter(re.split(r"[/_\-.?=&\s]+", t)) + Counter(t[i:i+3] for i in range(max(0, len(t) - 2)))


def cos(a, b):
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(v * v for v in a.values())); nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def jl(p):
    out = []
    if p.exists():
        for ln in p.read_text().splitlines():
            if ln.strip():
                try: out.append(json.loads(ln))
                except Exception: pass
    return out


def main():
    cls = norm(arg("--class"))
    ep = arg("--endpoint", "")
    if not cls or not ep:
        sys.exit("usage: dup-score.py --class <c> --endpoint <path> [--param p] [--title t] [--program P] [--stack s]")
    title = arg("--title", "")
    program = arg("--program", "")
    q = toks(cls + " " + ep + " " + (arg("--param", "") or "") + " " + title)
    nep = norm_ep(ep)

    # 1) similarity to known disclosed reports + your submissions
    sim, nearest = 0.0, ""
    kn = HUNT / "known.md"
    if kn.exists():
        for line in kn.read_text().splitlines():
            l = line.strip()
            if not l or l.startswith("#"):
                continue
            c = cos(q, toks(l))
            # class must plausibly match to count as a dup signal
            if (cls in norm(l) or cls[:4] in norm(l)) and c > sim:
                sim, nearest = c, "disclosed: " + l[:80]
    for r in jl(HUNT / "submitted.jsonl"):
        same = cls in norm(r.get("class", "")) and norm_ep(r.get("endpoint", "")) == nep
        c = cos(q, toks(r.get("class", "") + " " + r.get("endpoint", "") + " " + r.get("title", "")))
        if same:
            c = max(c, 0.9)
        if c > sim:
            sim, nearest = c, "your submission: " + (r.get("title") or r.get("endpoint") or "")[:80]

    # 2) class dup-prior; blended with YOUR real dup-rate for this class if you have data
    prior = CLASS_PRIOR.get(cls, CLASS_PRIOR["misc"])
    outs = [o for o in jl(CORPUS / "outcomes.jsonl") if norm(o.get("cls")) == cls]
    if len(outs) >= 3:
        yr = sum(1 for o in outs if o.get("verdict") == "duplicate") / len(outs)
        prior = 0.5 * prior + 0.5 * yr

    # 3) program crowding from the ROI registry
    crowd = 0.35
    if program:
        for p in jl(REG):
            if p.get("name") == program:
                rpw = p.get("reports_per_week", 5); dr = p.get("dup_rate", 0.15)
                crowd = min(0.95, 0.5 * min(1.0, rpw / 20.0) + 0.5 * dr / 0.4)
                break

    # 4) endpoint obviousness
    obvious = 1.0 if any(o in nep for o in OBVIOUS) else 0.3

    # weighted blend → probability
    W = {"sim": 0.45, "prior": 0.25, "crowd": 0.20, "obvious": 0.10}
    p = W["sim"] * sim + W["prior"] * prior + W["crowd"] * crowd + W["obvious"] * obvious
    p = max(0.03, min(0.96, p))
    pct = round(p * 100)

    verdict = "HOLD" if p >= 0.6 else ("REVIEW" if p >= 0.35 else "SUBMIT")
    icon = {"HOLD": "⛔", "REVIEW": "~", "SUBMIT": "✓"}[verdict]

    if "--json" in sys.argv:
        print(json.dumps({"prob": pct, "verdict": verdict, "nearest": nearest,
                          "factors": {"similarity": round(sim, 2), "class_prior": round(prior, 2),
                                      "crowding": round(crowd, 2), "obvious": obvious}}))
        sys.exit(0 if verdict == "SUBMIT" else 1 if verdict == "REVIEW" else 2)

    print(f"[dup-score] {icon} {pct}% likely duplicate → {verdict}   (class={cls}  {nep})")
    facs = sorted([("similar to a known report", W['sim'] * sim), ("class dups often", W['prior'] * prior),
                   ("crowded program", W['crowd'] * crowd), ("obvious endpoint", W['obvious'] * obvious)],
                  key=lambda x: -x[1])
    print("  drivers: " + " · ".join(f"{n} ({v*100:.0f}%)" for n, v in facs if v > 0.02))
    if nearest and sim >= 0.2:
        print(f"  nearest: {nearest}")
    if verdict == "HOLD":
        print("  → likely a dup. Don't burn it — unless you have a genuinely different param, impact, or root cause.")
    elif verdict == "REVIEW":
        print("  → borderline. Submit only if you can state what makes yours different in the report.")
    else:
        print("  → looks unique. Safe to submit (still run dedup-check for exact matches).")
    sys.exit(0 if verdict == "SUBMIT" else 1 if verdict == "REVIEW" else 2)


if __name__ == "__main__":
    main()
