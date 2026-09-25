#!/usr/bin/env python3
"""
hunt-intake — paste the whole program page; get a ready-to-hunt engagement.

Instead of hand-filling scope, paste the program's overview + scope + out-of-scope + rewards + rules
(exactly what you'd drop into a chat). This parses it into everything the engine needs:
  ./.hunt/scope.allow   in-scope host globs  (feeds scope-guard — nothing fires out of these)
  ./.hunt/scope.deny    out-of-scope host globs
  ./.hunt/program.md    overview + reward tiers + rules/constraints (rate limit, UA, test-accts)
  ./.hunt/signals.json  stack/tech + any endpoints seen → feeds hunt-hypothesize & hunt-monitor
It never fires a request. It flags anything ambiguous so you confirm before hunting.

Usage:
  pbpaste | hunt-intake.py                       # paste on stdin (the usual way)
  hunt-intake.py --file program.txt
  hunt-intake.py --file program.txt --stack fintech,saas   # force stack if you already know it
Exit: 0 ok · 2 nothing parseable.
"""
import sys, os, re, json
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))

# platforms / infra we should never auto-add to scope even if mentioned
NOISE = {"example.com", "hackerone.com", "wearehackerone.com", "bugcrowd.com", "bugcrowdninja.com",
         "intigriti.com", "intigriti.me", "yeswehack.com", "yeswehack.ninja", "github.com",
         "google.com", "gmail.com", "cloudflare.com", "w3.org", "mozilla.org", "owasp.org",
         "linkedin.com", "twitter.com", "x.com", "facebook.com", "youtube.com", "apple.com"}
OOS_HEAD = re.compile(r"(out[\s-]?of[\s-]?scope|not\s+in\s+scope|excluded|exclusions|ineligible|do\s+not\s+test)", re.I)
INS_HEAD = re.compile(r"(in[\s-]?scope|^scope\b|targets?|assets?|domains?|eligible)", re.I)
WILDCARD = re.compile(r"\*\.(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)
HOST = re.compile(r"(?<![\w.@/])((?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,})(?![\w])", re.I)
URLPATH = re.compile(r"https?://[^\s)>\]]+", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
PKG = re.compile(r"\b(?:com|io|org|net)\.[a-z0-9_]+\.[a-z0-9_]+(?:\.[a-z0-9_]+)*\b", re.I)
FILE_SUFFIX = {"js", "ts", "jsx", "tsx", "json", "css", "html", "htm", "php", "xml", "yml", "yaml",
               "md", "txt", "py", "rb", "go", "java", "sh", "png", "jpg", "jpeg", "gif", "svg",
               "map", "lock", "env", "ico", "woff", "woff2", "min", "chunk"}


def extract_hosts(line):
    """Return (hosts, packages) from a line; preserve wildcards, drop file/tech tokens & pkg parts,
    and drop ancestor domains implied by a more specific wildcard on the same line."""
    hosts, pkgs = set(), set()
    for m in PKG.finditer(line):
        pkgs.add(m.group(0).lower())
    for m in URLPATH.finditer(line):
        h = re.sub(r"^https?://", "", m.group(0)).split("/")[0].split(":")[0].lower()
        if h:
            hosts.add(h)
    wilds = {m.group(0).lower() for m in WILDCARD.finditer(line)}
    hosts |= wilds
    for m in IP.finditer(line):
        hosts.add(m.group(0))
    for m in HOST.finditer(line):
        h = m.group(1).lower()
        if h.rsplit(".", 1)[-1] in FILE_SUFFIX:
            continue
        if any(h == p or ("." + h) in ("." + p) and p.endswith(h) for p in pkgs):
            continue
        hosts.add(h)
    # drop plain hosts that are strict ancestors of a wildcard base (e.g. acme.com from *.mkt.acme.com)
    bases = {w[2:] for w in wilds}
    pruned = set()
    for h in hosts:
        if h.startswith("*."):
            pruned.add(h); continue
        if any(b != h and b.endswith("." + h) for b in bases):
            continue  # ancestor of a wildcard base — skip
        pruned.add(h)
    return pruned, pkgs
MONEY = re.compile(r"(critical|high|medium|low|p1|p2|p3|p4)\b[^\n$€£]{0,40}?[$€£]\s?[\d,]+(?:\s?[-–]\s?[$€£]?\s?[\d,]+)?|[$€£]\s?[\d,]+[^\n]{0,30}?(critical|high|medium|low|p1|p2|p3|p4)\b", re.I)
TECH = ["nginx", "apache", "node.js", "nodejs", "express", "django", "flask", "laravel", "php",
        "spring", "spring boot", "java", ".net", "asp.net", "ruby", "rails", "go ", "golang",
        "next.js", "nextjs", "react", "angular", "vue", "graphql", "grpc", "wordpress", "drupal",
        "kubernetes", "k8s", "docker", "aws", "gcp", "azure", "s3", "postgres", "mysql", "mongodb",
        "redis", "kafka", "keycloak", "okta", "auth0", "oauth", "saml", "jwt", "salesforce",
        "sap", "magento", "shopify", "sfcc", "jamf", "citrix", "vmware"]
RATE = re.compile(r"(\d+)\s*(?:req(?:uest)?s?)\s*(?:per|/)\s*(sec(?:ond)?|min(?:ute)?|s|m)", re.I)
UA = re.compile(r"(user[\s-]?agent|UA)[^\n]{0,60}?(must|should|include|contain|append|suffix)[^\n]{0,80}", re.I)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def read_text():
    f = arg("--file")
    if f:
        return Path(f).read_text(errors="replace")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    sys.exit("paste the program text on stdin, or pass --file program.txt")


def base_domain(d):
    d = d.lower().lstrip("*.")
    return d


def classify_scope(text):
    """Walk lines, track in/out-of-scope mode by heading, bucket domains + mobile packages."""
    allow, deny, ambiguous, packages = set(), set(), set(), set()
    mode = "in"  # default: unheaded domains treated as in-scope candidates
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if OOS_HEAD.search(low) and len(line) < 60:
            mode = "out"
            continue
        if INS_HEAD.search(low) and len(line) < 60 and not OOS_HEAD.search(low):
            mode = "in"
            continue
        hosts, pkgs = extract_hosts(line)
        packages |= pkgs
        for h in hosts:
            if base_domain(h) in NOISE:
                continue
            (deny if mode == "out" else allow).add(h)
    both = allow & deny
    allow -= both  # deny wins on conflict
    for b in both:
        ambiguous.add(b + " (listed in both in- and out-of-scope)")
    return sorted(allow), sorted(deny), sorted(ambiguous), sorted(packages)


def parse_rewards(text):
    out = []
    for m in MONEY.finditer(text):
        out.append(re.sub(r"\s+", " ", m.group(0).strip()))
    # dedupe, keep order
    seen, res = set(), []
    for r in out:
        k = r.lower()
        if k not in seen:
            seen.add(k)
            res.append(r)
    return res[:12]


def parse_rules(text):
    rules = []
    for m in RATE.finditer(text):
        rules.append(f"rate limit: {m.group(1)} req/{m.group(2)}")
    for m in UA.finditer(text):
        rules.append("UA requirement: " + re.sub(r"\s+", " ", m.group(0).strip())[:120])
    low = text.lower()
    for kw, label in [("no scanning", "no automated scanning"), ("no scanner", "no scanners"),
                      ("no dos", "no DoS/DDoS"), ("denial of service", "no DoS"),
                      ("social engineering", "no social engineering"), ("test account", "use test accounts only"),
                      ("do not", "explicit do-not rules present"), ("phishing", "no phishing")]:
        if kw in low and label not in rules:
            rules.append(label)
    return rules


def detect_stack(text):
    forced = arg("--stack")
    if forced:
        return [s.strip() for s in forced.split(",") if s.strip()]
    low = text.lower()
    hits = sorted({t.strip().rstrip(".") for t in TECH if t in low})
    # map to corpus stacks
    stacks = set()
    if any(k in low for k in ("bank", "payment", "wallet", "fintech", "trading", "crypto", "ledger", "transfer")):
        stacks.add("fintech")
    if any(k in low for k in ("cart", "checkout", "coupon", "ecommerce", "shop", "store", "order")):
        stacks.add("ecommerce")
    if any(k in low for k in ("tenant", "workspace", "org", "saas", "dashboard", "subscription", "seat")):
        stacks.add("saas")
    if any(k in low for k in ("login", "sso", "oauth", "saml", "auth")):
        stacks.add("auth")
    return sorted(stacks) or ["generic"], hits


def endpoints_in(text):
    eps = set()
    for m in URLPATH.finditer(text):
        p = re.sub(r"^https?://[^/]+", "", m.group(0))
        if p and p != "/":
            eps.add(p.split("#")[0])
    for m in re.finditer(r"(?<![\w.])/[a-z0-9][a-z0-9/_{}.-]{2,}", text, re.I):
        eps.add(m.group(0))
    return sorted(eps)[:60]


def main():
    text = read_text()
    if not text.strip():
        sys.exit(2)
    HUNT.mkdir(parents=True, exist_ok=True)
    allow, deny, ambiguous, packages = classify_scope(text)
    wildcards = [a for a in allow if a.startswith("*.")]
    rewards = parse_rewards(text)
    rules = parse_rules(text)
    stacks, tech = detect_stack(text)
    eps = endpoints_in(text)

    if not allow:
        print("[intake] ⚠ no in-scope hosts parsed — check the text has a scope/targets section.")
    # write scope files
    (HUNT / "scope.allow").write_text("# in-scope host globs (auto-parsed by hunt-intake — REVIEW before hunting)\n"
                                      + "\n".join(allow) + ("\n" if allow else ""))
    (HUNT / "scope.deny").write_text("# out-of-scope host globs\n" + "\n".join(deny) + ("\n" if deny else ""))
    # program.md
    def bullets(items, empty):
        return [f"- {x}" for x in items] if items else [f"- {empty}"]
    pm = ["# Program intake\n", "## In scope", *bullets(allow, "(none parsed)"),
          "\n## Out of scope", *bullets(deny, "(none parsed)"),
          "\n## Rewards", *bullets(rewards, "(not parsed)"),
          "\n## Rules / constraints", *bullets(rules, "(none parsed — read the page)"),
          "\n## Stack (guessed)", f"- corpus stacks: {', '.join(stacks)}", f"- tech seen: {', '.join(tech) or '—'}"]
    if packages:
        pm += ["\n## Mobile / non-web assets (test separately — not host-scoped)", *[f"- {p}" for p in packages]]
    if ambiguous:
        pm += ["\n## ⚠ Ambiguous — confirm manually", *[f"- {a}" for a in ambiguous]]
    (HUNT / "program.md").write_text("\n".join(pm) + "\n")
    # signals.json (seed for hypothesize/monitor)
    signals = {"tech": tech, "endpoints": eps, "fields": [], "roles": [],
               "notes": f"stacks={','.join(stacks)}; rewards={'; '.join(rewards[:4])}"}
    (HUNT / "signals.json").write_text(json.dumps(signals, indent=2))
    # rules.json — guardrails scope-guard auto-enforces (rate limit, required UA, no-scan)
    rate = None
    for r in rules:
        m = re.search(r"rate limit:\s*(\d+)\s*req/(sec|second|s|min|minute|m)", r, re.I)
        if m:
            n = int(m.group(1)); rate = n if m.group(2).lower().startswith("s") else round(n / 60.0, 3)
    ua = None
    for r in rules:
        m = re.search(r"UA requirement:.*?(include|contain|append|suffix)\s+(.+)", r, re.I)
        if m:
            ua = "researcher-UA: set your handle (program requires it)"
    rules_json = {"rate_rps": rate, "ua": None, "ua_note": ua,
                  "no_scan": any("scan" in r.lower() for r in rules),
                  "test_accounts_only": any("test account" in r.lower() for r in rules),
                  "blocked_paths": [], "raw_rules": rules}
    (HUNT / "rules.json").write_text(json.dumps(rules_json, indent=2))

    print(f"[intake] parsed → {HUNT}/  (scope.allow, scope.deny, program.md, signals.json)\n")
    print(f"  IN SCOPE   ({len(allow)}): " + (", ".join(allow[:8]) + (" …" if len(allow) > 8 else "")))
    if wildcards:
        print(f"  wildcards  ({len(wildcards)}): {', '.join(wildcards)}")
    print(f"  OUT SCOPE  ({len(deny)}): " + (", ".join(deny[:6]) + (" …" if len(deny) > 6 else "") if deny else "—"))
    if packages:
        print(f"  MOBILE     ({len(packages)}): {', '.join(packages)}  (test separately)")
    print(f"  STACK      : {', '.join(stacks)}   tech: {', '.join(tech[:8]) or '—'}")
    print(f"  REWARDS    : {'; '.join(rewards[:4]) or '— (read the page)'}")
    print(f"  RULES      : {'; '.join(rules) or '— (read the page)'}")
    print(f"  ENDPOINTS  : {len(eps)} seen → signals.json")
    if ambiguous:
        print("\n  ⚠ CONFIRM: " + "; ".join(ambiguous))
    print("\n  → review scope.allow, then: hunt-hypothesize.py --signals ./.hunt/signals.json --stack "
          + ",".join(stacks) + "   ·   /autohunt reads this state directly.")


if __name__ == "__main__":
    main()
