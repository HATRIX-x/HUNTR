#!/usr/bin/env python3
"""
subdomain-enum — passive + active subdomain enumeration for a target domain.

Sources (no API key required):
  • crt.sh         — certificate transparency logs
  • hackertarget   — passive DNS
  • alienvault OTX — passive DNS
  • rapiddns       — passive DNS
  • brute-force    — wordlist (--brute, uses built-in common list or --wordlist)

Output: deduplicated list of live subdomains with HTTP status + title.
Seeds a coverage.tsv section when --seed-coverage is passed.

Usage:
  subdomain-enum.py --domain acme.com [--brute] [--wordlist words.txt]
                    [--seed-coverage] [--json] [--out results.json]
  subdomain-enum.py --domain acme.com --resolve-only   # just resolve, no HTTP
Exit: 0.
"""
import sys, re, os, json, time, socket, ssl
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

HUNT_DIR = Path(os.environ.get("HUNT_DIR", "."))

# built-in common subdomain wordlist (300 most-seen in BB)
COMMON = """www api app admin dev staging test qa uat beta mail smtp ftp ssh vpn
portal dashboard login auth sso oauth id accounts account user users profile
mobile m cdn static assets img images media files upload uploads download downloads
docs doc api2 api-v2 v2 v3 internal intranet corp corporate office hr it
support help desk ticket helpdesk status monitor ops ops2 prod production
staging2 dev2 beta2 preview demo sandbox lab labs research
git gitlab github bitbucket svn jira confluence wiki
db database mysql postgres redis mongo memcache cache
s3 storage backup archive data reports analytics metrics
shop store ecommerce checkout cart pay payment billing invoice
blog news press media events webinar forum community
alerts notification push sms email smtp mx
security sec firewall waf proxy gateway edge
k8s kubernetes docker registry ci cd jenkins build deploy
remote vpn2 access owa exchange autodiscover outlook
legacy old v1 deprecated test2 stage preprod pre""".split()

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def flag(n): return n in sys.argv

def fetch_json(url, timeout=15):
    try:
        req = Request(url, headers={"User-Agent":"Mozilla/5.0","Accept":"application/json"})
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8","ignore"))
    except Exception:
        return None

def fetch_text(url, timeout=15):
    try:
        req = Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8","ignore")
    except Exception:
        return ""

def crtsh(domain):
    print(f"[subdomain-enum] crt.sh …", file=sys.stderr)
    data = fetch_json(f"https://crt.sh/?q=%.{domain}&output=json")
    if not data: return set()
    subs = set()
    for entry in data:
        name = entry.get("name_value","")
        for n in name.splitlines():
            n = n.strip().lstrip("*.")
            if n.endswith(f".{domain}") or n == domain:
                subs.add(n.lower())
    return subs

def hackertarget(domain):
    print(f"[subdomain-enum] hackertarget …", file=sys.stderr)
    txt = fetch_text(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    subs = set()
    for line in txt.splitlines():
        if "," in line:
            sub = line.split(",")[0].strip().lower()
            if sub.endswith(f".{domain}"):
                subs.add(sub)
    return subs

def alienvault(domain):
    print(f"[subdomain-enum] alienvault OTX …", file=sys.stderr)
    data = fetch_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    if not data: return set()
    subs = set()
    for rec in (data.get("passive_dns") or []):
        h = rec.get("hostname","").lower().strip()
        if h.endswith(f".{domain}") or h == domain:
            subs.add(h)
    return subs

def rapiddns(domain):
    print(f"[subdomain-enum] rapiddns …", file=sys.stderr)
    txt = fetch_text(f"https://rapiddns.io/subdomain/{domain}?full=1")
    subs = set()
    for m in re.finditer(r'([a-z0-9_\-]+\.)+' + re.escape(domain), txt, re.I):
        subs.add(m.group(0).lower())
    return subs

def brute_force(domain, wordlist=None):
    words = []
    if wordlist and Path(wordlist).exists():
        words = [w.strip() for w in Path(wordlist).read_text().splitlines() if w.strip()]
    else:
        words = COMMON
    print(f"[subdomain-enum] brute-forcing {len(words)} subdomains …", file=sys.stderr)
    found = set()
    def resolve(word):
        sub = f"{word}.{domain}"
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(sub)
            return sub
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(resolve, w): w for w in words}
        for f in as_completed(futs):
            r = f.result()
            if r: found.add(r)
    return found

def resolve_ip(host):
    try:
        socket.setdefaulttimeout(3)
        return socket.gethostbyname(host)
    except Exception:
        return None

def http_probe(host, timeout=8):
    """Return (status, title, redirect) for a host."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = Request(url, headers={"User-Agent":"Mozilla/5.0"})
            import urllib.request
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            with opener.open(req, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8","ignore")
                status = r.status
                m = re.search(r"<title[^>]*>([^<]{1,80})</title>", body, re.I)
                title = m.group(1).strip() if m else ""
                redir = str(r.url) if r.url != url else ""
                return status, title[:60], redir[:80]
        except Exception:
            continue
    return None, "", ""

def seed_coverage(subs_live, domain):
    cov = HUNT_DIR / "coverage.tsv"
    lines = cov.read_text().splitlines() if cov.exists() else []
    header = lines[0] if lines else "endpoint\tclass\tstatus\tdepth\tnotes"
    existing = {l.split("\t")[0] for l in lines[1:]}
    new_lines = []
    for s in subs_live:
        key = f"subdomain:{s['host']}"
        if key not in existing:
            note = f"HTTP {s.get('status','')} {s.get('title','')[:40]}"
            new_lines.append(f"{key}\tRecon\tTODO\tT0\t{note}")
            existing.add(key)
    if new_lines:
        cov.write_text(header + "\n" + "\n".join(lines[1:]) + "\n" + "\n".join(new_lines) + "\n")
        print(f"[subdomain-enum] seeded {len(new_lines)} cells → {cov}", file=sys.stderr)
    return len(new_lines)

def main():
    domain = arg("--domain")
    if not domain: print(__doc__); sys.exit(0)
    domain = domain.lower().strip().lstrip("*.")
    wordlist = arg("--wordlist")
    out_file = arg("--out")
    resolve_only = flag("--resolve-only")

    # passive sources
    subs = set()
    subs |= crtsh(domain)
    subs |= hackertarget(domain)
    subs |= alienvault(domain)
    subs |= rapiddns(domain)
    if flag("--brute"):
        subs |= brute_force(domain, wordlist)

    subs = sorted(subs)
    print(f"[subdomain-enum] {len(subs)} unique subdomains found, resolving …", file=sys.stderr)

    # resolve + probe
    results = []
    def probe(host):
        ip = resolve_ip(host)
        if not ip: return None
        if resolve_only:
            return {"host": host, "ip": ip}
        status, title, redir = http_probe(host)
        return {"host": host, "ip": ip, "status": status, "title": title, "redirect": redir}

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(probe, s): s for s in subs}
        for f in as_completed(futs):
            r = f.result()
            if r: results.append(r)

    # sort: live HTTPS first, then by status
    live = [r for r in results if r.get("status")]
    dead = [r for r in results if not r.get("status")]
    live.sort(key=lambda r: (r.get("status") or 999))

    out = {
        "domain": domain, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "total_found": len(subs), "live": len(live), "dead": len(dead),
        "results": live + dead,
    }
    if out_file: Path(out_file).write_text(json.dumps(out, indent=2))
    if flag("--seed-coverage") and live:
        seeded = seed_coverage(live, domain)
        out["seeded_cells"] = seeded

    if flag("--json"):
        print(json.dumps(out)); return

    print(f"\n══ Subdomains · {domain} ══════════════════════════")
    print(f"  Found: {len(subs)}  Live: {len(live)}  Dead/NXDOMAIN: {len(dead)}")
    if live:
        print(f"\n  Live subdomains:")
        for r in live[:60]:
            st = f"[{r['status']}]" if r.get("status") else "[???]"
            print(f"  {st:<6} {r['host']:<45} {r.get('title','')[:40]}")
        if len(live) > 60:
            print(f"  … +{len(live)-60} more (use --json or --out for full list)")

if __name__ == "__main__":
    main()
