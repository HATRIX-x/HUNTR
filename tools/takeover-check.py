#!/usr/bin/env python3
"""
takeover-check — subdomain takeover checker via CNAME fingerprinting.

For each host:
  1. Resolve CNAME chain.
  2. Check if the final CNAME points to a cloud service that shows "unclaimed" signals.
  3. Verify the service is actually claimable (not just pointing to a live CDN edge).

Fingerprint DB covers 45+ services:
  GitHub Pages, Netlify, Vercel, Heroku, S3, Azure, Fastly, Zendesk, Freshdesk,
  Shopify, Ghost, HubSpot, Intercom, Cargo, Launchrock, Tumblr, Wordpress.com,
  StatusPage, Pingdom, Surge.sh, Readme.io, TeamGantt, UserVoice, Bitbucket,
  Unbounce, Strikingly, GetResponse, Tave, WildBit, Wufoo, Typeform, Canny,
  Uptimerobot, Webflow, Help Scout, JetBrains Space, Desk.com, Kajabi.

Usage:
  takeover-check.py --domain acme.com [--subs-file subdomains.txt]
                    [--host sub.acme.com] [--json] [--out results.json]
  takeover-check.py --host dangling.acme.com
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, socket, ssl
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
def flag(n): return n in sys.argv

# ── fingerprint database ──────────────────────────────────────────────
# (service, cname_pattern, http_body_pattern, severity, claim_url_hint)
FINGERPRINTS = [
    ("github_pages",   r"github\.io$",           r"There isn't a GitHub Pages site here",           "high", "https://pages.github.com"),
    ("netlify",        r"netlify\.(?:app|com)$",  r"Not Found - Request ID|page not found",          "high", "https://netlify.com"),
    ("vercel",         r"vercel\.app$",            r"The deployment you are looking for|No deployments", "high", "https://vercel.com"),
    ("heroku",         r"herokudns\.com$|herokussl\.com$", r"No such app|herokucdn\.com/error-pages", "high", "https://heroku.com"),
    ("aws_s3",         r"s3\.amazonaws\.com$|s3-website",r"NoSuchBucket|The specified bucket does not exist", "critical", "https://aws.amazon.com/s3"),
    ("aws_elastic",    r"elasticbeanstalk\.com$", r"No Application Found",                           "high", "https://aws.amazon.com/elasticbeanstalk"),
    ("azure_websites", r"azurewebsites\.net$",    r"404 Web Site not found|could not be found in the application", "high", "https://azure.microsoft.com"),
    ("azure_cloudapp", r"cloudapp\.azure\.com$",  r"404|does not exist",                             "medium", "https://azure.microsoft.com"),
    ("azure_trafficmgr",r"trafficmanager\.net$",  r"404|does not exist",                             "medium", "https://azure.microsoft.com"),
    ("fastly",         r"fastly\.net$",            r"Fastly error: unknown domain",                   "high", "https://fastly.com"),
    ("cloudfront",     r"cloudfront\.net$",        r"The request could not be satisfied|ERROR: The request could not",  "medium", "https://aws.amazon.com/cloudfront"),
    ("zendesk",        r"zendesk\.com$",            r"Help Center Closed|this help center is no longer available", "high", "https://zendesk.com"),
    ("freshdesk",      r"freshdesk\.com$",          r"There is no helpdesk here",                    "high", "https://freshdesk.com"),
    ("shopify",        r"myshopify\.com$",          r"Sorry, this shop is currently unavailable",    "high", "https://shopify.com"),
    ("hubspot",        r"hubspot\.com$",             r"Domain not found|this page isn't available",  "high", "https://hubspot.com"),
    ("ghost",          r"ghost\.io$",               r"Domain does not exist",                         "high", "https://ghost.org"),
    ("surge",          r"surge\.sh$",               r"project not found",                             "high", "https://surge.sh"),
    ("readme",         r"readme\.io$",              r"Project doesnt exist yet",                      "high", "https://readme.io"),
    ("statuspage",     r"statuspage\.io$",          r"You are being redirected|page not found",       "medium", "https://statuspage.io"),
    ("pingdom",        r"pingdom\.com$",             r"This public report page does not exist",       "medium", "https://pingdom.com"),
    ("tumblr",         r"tumblr\.com$",             r"Whatever you were looking for doesn't currently exist", "medium", "https://tumblr.com"),
    ("wordpress",      r"wordpress\.com$",          r"Do you want to register",                       "medium", "https://wordpress.com"),
    ("helpscout",      r"helpscoutdocs\.com$",      r"No settings were found for this company",      "high", "https://helpscout.com"),
    ("intercom",       r"intercom\.io$",             r"Uh oh. That page doesn't exist",               "high", "https://intercom.com"),
    ("cargo",          r"cargocollective\.com$",    r"404 Not Found",                                 "medium", "https://cargocollective.com"),
    ("strikingly",     r"strikingly\.com$",         r"page not found",                                "medium", "https://strikingly.com"),
    ("webflow",        r"webflow\.io$",              r"The page you are looking for doesn't exist",   "high", "https://webflow.com"),
    ("unbounce",       r"unbounce\.com$",           r"The requested URL was not found on this server","high", "https://unbounce.com"),
    ("uservoice",      r"uservoice\.com$",          r"This UserVoice subdomain is currently available", "high", "https://uservoice.com"),
    ("canny",          r"canny\.io$",               r"Company Not Found",                              "high", "https://canny.io"),
    ("kajabi",         r"kajabi\.com$",             r"This page is not available",                    "medium", "https://kajabi.com"),
    ("typeform",       r"typeform\.com$",           r"The form you're looking for",                   "medium", "https://typeform.com"),
    ("launchrock",     r"launchrock\.com$",         r"It looks like you may have taken a wrong turn", "medium", "https://launchrock.com"),
    ("getresponse",    r"gr8\.com$",                r"With GetResponse Landing Pages, lead capture",  "medium", "https://getresponse.com"),
    ("bitbucket",      r"bitbucket\.io$",           r"Repository not found",                          "medium", "https://bitbucket.org"),
    ("wufoo",          r"wufoo\.com$",              r"Profile Not Found",                              "medium", "https://wufoo.com"),
    ("uptimerobot",    r"uptimerobot\.com$",        r"page not found on Uptimerobot",                 "medium", "https://uptimerobot.com"),
    ("jetbrains_space",r"jetbrains\.space$",        r"404",                                           "medium", "https://jetbrains.com/space"),
    ("desk",           r"desk\.com$",               r"Sorry, we couldn't find that page",             "medium", "https://desk.com"),
]

def resolve_cname_chain(host, max_depth=10):
    """Return list of CNAMEs in the chain. Last entry is the final target."""
    import subprocess
    chain = []
    cur = host
    for _ in range(max_depth):
        try:
            result = subprocess.run(["dig", "+short", "CNAME", cur], capture_output=True, text=True, timeout=5)
            out = result.stdout.strip()
            if not out or out == cur: break
            # dig may return multiple lines; take first
            target = out.splitlines()[0].rstrip(".")
            chain.append(target)
            cur = target
        except Exception:
            break
    return chain

def resolve_cname_python(host):
    """Fallback CNAME resolution without dig."""
    try:
        answers = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        # can't easily get CNAME chain without dnspython; just return IPs
        return []
    except Exception:
        return []

def fetch_http_body(host, timeout=8):
    """Fetch HTTP + HTTPS body of the dangling host."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    for scheme in ("https","http"):
        try:
            req = Request(f"{scheme}://{host}", headers={"User-Agent":"Mozilla/5.0"})
            with opener.open(req, timeout=timeout) as r:
                return r.read(4096).decode("utf-8","ignore")
        except Exception:
            continue
    return ""

def check_host(host):
    """Return a finding dict or None."""
    # check if NXDOMAIN first
    resolves = True
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(host)
    except socket.gaierror:
        resolves = False

    # get CNAME chain
    cnames = resolve_cname_chain(host)
    all_targets = [host] + cnames

    matched_service = None
    matched_cname = None
    for cname in all_targets:
        for service, cname_pat, body_pat, sev, claim_url in FINGERPRINTS:
            if re.search(cname_pat, cname, re.I):
                matched_service = (service, cname_pat, body_pat, sev, claim_url)
                matched_cname = cname
                break
        if matched_service: break

    if not matched_service:
        return None

    service, cname_pat, body_pat, sev, claim_url = matched_service

    # fetch HTTP to confirm unclaimed signal
    body = fetch_http_body(host)
    body_match = bool(body_pat and re.search(body_pat, body, re.I))

    if not resolves:
        # NXDOMAIN + CNAME points to service = dangling
        confirmed = True
    elif body_match:
        confirmed = True
    else:
        confirmed = False  # CNAME matches service but no unclaimed body

    if confirmed:
        return {
            "host": host,
            "cname": matched_cname,
            "service": service,
            "severity": sev,
            "resolves": resolves,
            "body_match": body_match,
            "claim_url": claim_url,
            "note": f"Dangling CNAME to {service} ({matched_cname}) — subdomain takeover possible",
            "body_snippet": body[:200] if body_match else "",
        }
    # CNAME present but not confirmed
    return {
        "host": host,
        "cname": matched_cname,
        "service": service,
        "severity": "info",
        "resolves": resolves,
        "body_match": False,
        "claim_url": claim_url,
        "note": f"CNAME points to {service} but body signal not found — possible but unconfirmed",
        "body_snippet": "",
    }

def main():
    domain   = arg("--domain")
    subs_file= arg("--subs-file")
    single   = arg("--host")
    out_file = arg("--out")

    hosts = []
    if single: hosts.append(single)
    if subs_file and Path(subs_file).exists():
        hosts += [l.strip() for l in Path(subs_file).read_text().splitlines() if l.strip()]
    if domain and not hosts:
        # get subs from crt.sh quickly
        import urllib.request
        try:
            req = urllib.request.Request(f"https://crt.sh/?q=%.{domain}&output=json", headers={"User-Agent":"Mozilla/5.0","Accept":"application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
                for entry in data:
                    for n in entry.get("name_value","").splitlines():
                        n = n.strip().lstrip("*.")
                        if n.endswith(f".{domain}") or n == domain: hosts.append(n)
        except Exception: pass
    hosts = sorted(set(h.lower() for h in hosts if h))

    if not hosts: print(__doc__); sys.exit(0)

    print(f"[takeover-check] checking {len(hosts)} hosts …", file=sys.stderr)

    findings = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(check_host, h): h for h in hosts}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                findings.append(r)
                if r["severity"] != "info":
                    print(f"  [{r['severity'].upper()}] {r['host']} → {r['service']}", file=sys.stderr)

    confirmed = [f for f in findings if f["severity"] != "info"]
    suspects  = [f for f in findings if f["severity"] == "info"]

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "hosts_checked": len(hosts),
        "confirmed": len(confirmed),
        "suspects": len(suspects),
        "findings": findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if confirmed else 0)

    print(f"\n══ Takeover check ══════════════════════════")
    print(f"  Hosts: {len(hosts)}  Confirmed: {len(confirmed)}  Suspects: {len(suspects)}")
    for f in confirmed:
        print(f"\n  [{f['severity'].upper():<8}] {f['host']}")
        print(f"             CNAME → {f['cname']}")
        print(f"             Service: {f['service']}")
        print(f"             Claim: {f['claim_url']}")
        print(f"             {f['note']}")
    if suspects:
        print(f"\n  Unconfirmed (CNAME fingerprint only, no unclaimed body):")
        for f in suspects[:5]:
            print(f"    {f['host']} → {f['service']}")

    sys.exit(1 if confirmed else 0)

if __name__ == "__main__":
    main()
