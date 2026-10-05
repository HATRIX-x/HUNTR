#!/usr/bin/env python3
"""
hunt-run.py — the real, dashboard-driven hunt runner.

The server spawns this detached when you click "New Hunt". It runs REAL recon
(subfinder -> live-host probe -> endpoint crawl -> fingerprint) against the
target, writing live progress to <hunt_dir>/run.json the whole time. The
dashboard polls /api/hunt/status and renders that file — so what you see is real
output, not a scripted animation.

This is the recon spine. Active class-scanning (idor/ssrf/…) and LLM-guided
hypotheses are layered on after, each writing into the same run.json.

Usage:
  hunt-run.py --target acme.com [--program "Acme"] [--mode grey]
              [--scope-types web,api] [--hunt-dir /path/.hunt]
Env: HUNT_DIR overrides --hunt-dir (the server sets it).
"""
import sys, os, re, json, time, subprocess, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def safe(t):
    return re.sub(r"[^a-z0-9._-]+", "_", (t or "default").lower()) or "default"


def apex(host):
    h = re.sub(r"^\*\.", "", (host or "").strip().lower()).strip("/")
    h = re.sub(r"^https?://", "", h).split("/")[0]
    h = h.split(":")[0]                              # drop any :port before apex math
    parts = [p for p in h.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def _single_host(target):
    """A bare IP, localhost, or host:port target can't be subdomain-enumerated and has no public
    archive history — skip subfinder/gau/waybackurls for it (they'd waste minutes on nothing)."""
    h = re.sub(r"^https?://", "", (target or "").strip().lower()).split("/")[0]
    hostonly = h.split(":")[0]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostonly):      # IPv4
        return True
    if hostonly in ("localhost",) or hostonly.endswith(".local"):
        return True
    if ":" in h:                                            # explicit port ⇒ a specific host, not a domain to enumerate
        return True
    return False


TARGET = (arg("--target") or "").strip()
PROGRAM = arg("--program", "")
MODE = arg("--mode", "grey")
SCOPE_TYPES = [s for s in (arg("--scope-types", "web,api") or "").split(",") if s]
HUNT_DIR = Path(os.environ.get("HUNT_DIR") or arg("--hunt-dir")
                or (Path.home() / ".huntr" / "targets" / safe(TARGET) / ".hunt"))
HUNT_DIR.mkdir(parents=True, exist_ok=True)
RUN = HUNT_DIR / "run.json"

STATE = {
    "target": TARGET, "program": PROGRAM, "mode": MODE, "scope_types": SCOPE_TYPES,
    "status": "running", "stage": "Boot", "pct": 0,
    "started": time.time(), "updated": time.time(),
    "logs": [], "hosts": [], "endpoints": [], "findings": [], "leads": [],
    "chains": [], "invariants": [], "economics": {},
    "coverage": {"breadth": 0, "depth": 0, "verified": 0, "total": 0, "resolved": 0, "todo": 0},
    "stats": {"subs": 0, "live": 0, "endpoints": 0, "findings": 0, "leads": 0, "chains": 0},
}

TESTED = {}  # endpoint -> set(class) actually scanned, for the coverage ledger
NO_TOOL = {}  # endpoint -> set(class) applicable but with no installed tool (honest "can't test" state)
def mark_tested(ep, cls):
    TESTED.setdefault(ep, set()).add(cls)

SEVMAP = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i", "unknown": "i"}
SEVLABEL = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW", "i": "INFO"}

# tri-hybrid model routing. Each is an ordered fallback chain: llm_call tries them in
# order and falls through on any error (429 rate-limit included), so the engine always
# uses the strongest model currently available and degrades to Haiku (which answers even
# when the heavy models are rate-limited) rather than failing.
#   STRONG = Layer-3 judge (validate findings, kill false-positives, write repro/impact).
#   CHEAP  = Layer-2 directed loop (high-frequency cell selection) — Haiku by design.
MODEL_STRONG = ["claude-opus-4-8", "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-haiku-4-5"]
MODEL_CHEAP = ["claude-haiku-4-5"]


def llm_call(models, system, user, max_tokens=1600, timeout=100):
    """One Claude call via llm_auth (account OAuth or API key). `models` = try in order (fallback on error). Returns text or None."""
    try:
        import urllib.request
        sys.path.insert(0, str(HERE))
        from llm_auth import llm_headers
        hdrs, mode = llm_headers()
        if not hdrs:
            return None
        hdrs["content-type"] = "application/json"
        import urllib.error, time as _time
        for m in (models if isinstance(models, list) else [models]):
            body = json.dumps({"model": m, "max_tokens": max_tokens, "system": system,
                               "messages": [{"role": "user", "content": user}]}).encode()
            for attempt in range(3):   # retry the same model on 429 before falling through
                req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers=hdrs, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        data = json.loads(r.read())
                    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
                except urllib.error.HTTPError as e:
                    if e.code == 429 and attempt < 2:
                        _time.sleep(2 * (attempt + 1)); continue   # backoff: 2s, 4s
                    break   # non-retryable or exhausted → next model
                except Exception:
                    break   # next model
        return None
    except Exception:
        return None


def llm_json(models, system, user, max_tokens=1600, timeout=100):
    """llm_call + robustly extract a JSON object/array from the reply."""
    txt = llm_call(models, system, user, max_tokens, timeout)
    if not txt:
        return None
    # strip ```json fences, then try the whole thing before falling back to a span search
    t = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", txt.strip(), flags=re.I | re.M).strip()
    for cand in (t,):
        try:
            return json.loads(cand)
        except Exception:
            pass
    # balanced-bracket scan from the FIRST container bracket (so an array of objects isn't mistaken
    # for its first element), to its matching close (handles trailing prose)
    firsts = [(t.find(o), o, c) for o, c in (("{", "}"), ("[", "]")) if t.find(o) >= 0]
    for _, open_ch, close_ch in sorted(firsts):
        i = t.find(open_ch)
        depth = 0; instr = False; esc = False
        for j in range(i, len(t)):
            ch = t[j]
            if esc:
                esc = False; continue
            if ch == "\\" and instr:
                esc = True; continue
            if ch == '"':
                instr = not instr; continue
            if instr:
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[i:j + 1])
                    except Exception:
                        break
    return None


def tool_json(tool, args, timeout=240):
    out, err, rc = sh([sys.executable, str(HERE / tool)] + args, timeout=timeout)
    for line in reversed((out or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except Exception:
                pass
    return None


def add_finding(sev, title, detail, endpoint, cvss="", cls="", verdict="", det=None):
    sev = sev if sev in SEVLABEL else SEVMAP.get((sev or "i").lower(), "i")
    key = (title + "|" + (endpoint or "")).lower()
    if any((f["title"] + "|" + (f.get("endpoint") or "")).lower() == key for f in STATE["findings"]):
        return
    f = {
        "sev": sev, "label": SEVLABEL[sev], "title": title, "detail": detail or "",
        "cvss": cvss or "", "endpoint": endpoint or "", "cls": cls or "",
    }
    if verdict:                       # tool-level evidence — reaches the submit queue without the AI judge
        f["verdict"] = verdict
        # _det = "undroppable": the judge may enrich but must not drop it. Default on for a confirmed
        # verdict (near-certain tools like sqlmap/OAST), but callers can pass det=False for
        # higher-FP-rate tools (e.g. nuclei) so the judge can still veto a false positive.
        if det if det is not None else (verdict == "confirmed"):
            f["_det"] = True
    STATE["findings"].append(f)
    STATE["stats"]["findings"] = len(STATE["findings"])
    sevw = SEVLABEL[sev]
    log("warn" if sev in ("c", "h", "m") else "out", "⚑ " + sevw + "  " + title + (" · " + endpoint if endpoint else ""))


def flush():
    STATE["updated"] = time.time()
    tmp = RUN.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(STATE))
    tmp.replace(RUN)


def log(t, v):
    STATE["logs"].append({"t": t, "v": v})
    if len(STATE["logs"]) > 400:
        STATE["logs"] = STATE["logs"][-400:]
    flush()


def stage(name, pct):
    STATE["stage"] = name
    STATE["pct"] = pct
    flush()


def sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", "not-found", -1


def has(binname):
    from shutil import which
    return which(binname) is not None


def probe_host(host, timeout=8):
    """Directly probe a single host (https then http). Returns (status|None, title, scheme)."""
    import urllib.request, urllib.error
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(scheme + "://" + host, method="GET",
                                         headers={"User-Agent": "Mozilla/5.0 HUNTR"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "ignore")
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                return (getattr(r, "status", 200) or 200), (m.group(1).strip()[:60] if m else ""), scheme
        except urllib.error.HTTPError as e:
            return e.code, "", scheme
        except Exception:
            continue
    return None, "", "https"


def phase_scope():
    stage("Scope", 6)
    ap = apex(TARGET)
    allow = HUNT_DIR / "scope.allow"
    lines = set()
    if (allow).exists():
        lines = {l.strip() for l in allow.read_text().splitlines() if l.strip()}
    lines.add(TARGET)
    lines.add(ap)
    lines.add("*." + ap)
    allow.write_text("\n".join(sorted(lines)) + "\n")
    log("cmd", "$ scope-guard --init  (" + TARGET + ")")
    log("ok", "✓ scope locked · " + ap + " + subdomains · mode: " + MODE + "-box")


def phase_recon():
    ap = apex(TARGET)
    stage("Recon", 18)
    log("cmd", "$ subfinder -d " + ap + " -silent | httpx -silent -title -sc")
    hosts = []
    single = _single_host(TARGET)
    if single:
        # IP / localhost / host:port — no subdomains to find; go straight to the literal host
        log("out", "→ single-host target (" + apex(TARGET) + ") — skipping subdomain enumeration")
    # prefer the engine's own recon tool (handles subfinder+resolve+probe)
    tool = HERE / "subdomain-enum.py"
    if (not single) and tool.exists():
        out, err, _ = sh([sys.executable, str(tool), "--domain", ap, "--json"], timeout=300)
        try:
            d = json.loads(out.strip().splitlines()[-1])
            hosts = d.get("results", [])
            STATE["stats"]["subs"] = d.get("total_found", len(hosts))
            STATE["stats"]["live"] = d.get("live", 0)
        except Exception:
            log("warn", "→ recon parse issue: " + (err or out)[:120])
    elif (not single) and has("subfinder"):
        out, _, _ = sh(["subfinder", "-d", ap, "-silent"], timeout=180)
        subs = [s.strip() for s in out.splitlines() if s.strip()]
        STATE["stats"]["subs"] = len(subs)
        for s in subs[:60]:
            hosts.append({"host": s, "status": None})
    else:
        if not single:
            log("warn", "→ subfinder not installed — recon limited to the named host")
        hosts = [{"host": re.sub(r'^\*\.', '', TARGET).split('/')[0], "status": None}]

    # --- FIX #1: always include the literal target host, probed directly, never silently dropped
    lithost = re.sub(r'^\*\.', '', TARGET).split('/')[0].strip()
    if lithost and not any(h.get("host") == lithost for h in hosts):
        hosts.insert(0, {"host": lithost, "status": None})
    lit = next((h for h in hosts if h.get("host") == lithost), None)
    if lit is not None and not lit.get("status"):
        st, title, sch = probe_host(lithost)
        lit["status"] = st; lit["scheme"] = sch
        if title:
            lit["title"] = title
    if lit is not None and lit.get("status"):
        hosts = [lit] + [h for h in hosts if h is not lit]   # target first
        log("ok", "✓ target live · " + lithost + " [" + str(lit.get("status")) + "]")
    elif lit is not None:
        log("warn", "⚠ target " + lithost + " is not responding (unreachable) — "
            "hunting discovered subdomains instead; findings may not cover the intended host")
        STATE["stats"]["target_unreachable"] = True

    live = [h for h in hosts if h.get("status")]
    STATE["hosts"] = hosts[:200]
    STATE["stats"]["live"] = len(live) or STATE["stats"]["live"]
    flush()
    for h in (live[:25] or hosts[:25]):
        tag = (str(h.get("status")) + " " if h.get("status") else "") + (h.get("title") or "")
        log("out", "→ " + h.get("host", "?") + ("  [" + tag.strip() + "]" if tag.strip() else ""))
    log("ok", "✓ " + str(STATE["stats"]["subs"]) + " subdomains · " +
        str(len(live)) + " live")
    stage("Recon", 45)


def phase_surface():
    stage("Surface", 52)
    live = [h for h in STATE["hosts"] if h.get("status")]
    # --- FIX #2: crawl the literal target first, then live hosts; deeper crawl + historical URLs
    lithost = re.sub(r'^\*\.', '', TARGET).split('/')[0].strip()
    ordered = [h for h in STATE["hosts"] if h.get("host") == lithost] + \
              [h for h in live if h.get("host") != lithost]
    targets = (ordered or STATE["hosts"])[:4]
    eps = {}
    for h in targets:
        host = h.get("host")
        if not host:
            continue
        sch = h.get("scheme")
        if not sch:                                  # determine the working scheme per crawl target
            try: sch = probe_host(host)[2]
            except Exception: sch = "https"
        url = (sch or "https") + "://" + host        # honor http targets (localhost/dev/plain-http)
        # recall: robots.txt + sitemap.xml often reveal surface the crawler won't reach
        import urllib.request as _ur
        for rf in ("/robots.txt", "/sitemap.xml"):
            try:
                with _ur.urlopen(_ur.Request(url + rf, headers={"User-Agent": "Mozilla/5.0 HUNTR"}), timeout=8) as r:
                    txt = r.read(200000).decode("utf-8", "ignore")
                for m in re.findall(r"(?:Allow|Disallow|Sitemap):\s*(\S+)", txt) + re.findall(r"<loc>\s*([^<\s]+)", txt):
                    p = m.strip()
                    full = p if p.startswith("http") else (url + ("" if p.startswith("/") else "/") + p)
                    if full.startswith("http") and "*" not in full:
                        eps[full] = host
            except Exception:
                pass
        if has("katana"):
            log("cmd", "$ katana -u " + url + " -silent -d 2")
            out, _, _ = sh(["katana", "-u", url, "-silent", "-d", "2", "-c", "15",
                            "-jc", "-timeout", "10"], timeout=100)
            for ln in out.splitlines():
                ln = ln.strip()
                if ln.startswith("http"):
                    eps[ln] = host
        # historical-URL services only make sense for public hosts (localhost/IP have no archive)
        if not _single_host(host):
            if has("gau"):
                log("cmd", "$ gau " + host + "  (historical URLs)")
                out, _, _ = sh(["gau", "--threads", "5", "--subs", host], timeout=45)
                for ln in out.splitlines()[:400]:
                    ln = ln.strip()
                    if ln.startswith("http"):
                        eps[ln] = host
            if has("waybackurls"):
                out, _, _ = sh(["waybackurls", host], timeout=45)
                for ln in out.splitlines()[:400]:
                    ln = ln.strip()
                    if ln.startswith("http"):
                        eps[ln] = host
        if len(eps) > 1200:
            break
    # prefer parameterized URLs (the testable surface) when capping
    items = list(eps.items())
    items.sort(key=lambda kv: (0 if re.search(r"[?&][\w\[\]]+=", kv[0]) else 1, len(kv[0])))
    # collapse near-duplicates by (host, path, sorted param NAMES) — testing ReadNews.aspx?id=1 is the
    # same cell as ?id=2..99; keeping one representative per shape stops the budget draining on clones
    import urllib.parse as _upd
    seen_sig = set(); deduped = []
    for u, hh in items:
        try:
            pu = _upd.urlparse(u)
            sig = (pu.netloc, pu.path, tuple(sorted(k for k, _ in _upd.parse_qsl(pu.query))))
        except Exception:
            sig = (u,)
        if sig in seen_sig:
            continue
        seen_sig.add(sig); deduped.append((u, hh))
    endpoints = [{"url": u, "host": hh} for u, hh in deduped[:400]]
    STATE["endpoints"] = endpoints
    STATE["stats"]["endpoints"] = len(endpoints)
    flush()
    # a few representative endpoint lines in the feed
    for e in endpoints[:20]:
        log("out", "→ " + e["url"][:110])
    if not endpoints:
        log("warn", "→ no endpoints crawled (host may block crawlers or have no links)")
    else:
        log("ok", "✓ " + str(len(endpoints)) + " endpoints mapped across " +
            str(len(targets)) + " host(s)")
    stage("Surface", 82)


def phase_active():
    """Real class-scanning across the mapped surface (best-effort; each tool guarded)."""
    stage("Exploit", 60)
    live = [h for h in STATE["hosts"] if h.get("status")]
    live_entries = [(h["host"], h.get("scheme") or "https") for h in live if h.get("host")][:5]  # honor http-only hosts
    live_hosts = [h for h, _ in live_entries]
    all_hosts = [h["host"] for h in STATE["hosts"] if h.get("host")]
    eps = [e["url"] for e in STATE["endpoints"]]

    # 1) Subdomain takeover across every discovered host
    if all_hosts and (HERE / "takeover-check.py").exists():
        log("cmd", "$ takeover-check · " + str(len(all_hosts)) + " hosts")
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tf.write("\n".join(all_hosts)); tf.close()
        d = tool_json("takeover-check.py", ["--subs-file", tf.name, "--json"], timeout=180)
        try: os.unlink(tf.name)
        except Exception: pass
        for f in (d or {}).get("findings", []):
            if f.get("confirmed") or f.get("vulnerable"):
                add_finding("h", "Subdomain takeover — " + (f.get("service") or "dangling CNAME"),
                            f.get("detail") or f.get("cname") or "", f.get("host") or f.get("subdomain") or "",
                            cls="Subdomain takeover", verdict="confirmed")  # tool proved the dangling claim
    stage("Exploit", 68)

    # 2) nuclei on live hosts — misconfig / exposure / CVE
    if live_hosts and (HERE / "nuclei-run.py").exists():
        log("cmd", "$ nuclei -severity critical,high,medium · " + str(len(live_hosts)) + " hosts")
        args = ["--json", "--severity", "critical,high,medium"]
        for h, sch in live_entries:
            args += ["--target", sch + "://" + h]   # http-only hosts were silently skipped before
        args += ["--rate", "150"]
        d = tool_json("nuclei-run.py", args, timeout=240)
        for e in STATE["endpoints"]:
            mark_tested(e["url"], "misconfig")
        for h, sch in live_entries:
            mark_tested(sch + "://" + h, "misconfig")
        for f in (d or {}).get("findings", []):
            # a matched nuclei template is deterministic evidence → confirmed (so real exposures/CVEs
            # reach the submit queue instead of being demoted to needs-work by the economics brain)
            add_finding(f.get("severity", "i"), f.get("name", "nuclei match"),
                        (f.get("template") or "") + (("  ·  " + f["matcher"]) if f.get("matcher") else ""),
                        f.get("url", ""), cls="Misconfig/CVE", verdict="confirmed", det=False)  # judge may still veto an FP
        if not (d or {}).get("findings"):
            log("out", "→ nuclei: no critical/high/medium matches")
    stage("Exploit", 82)

    # per-endpoint class probes (cors/redirect/idor/authz/param/race) are now owned by
    # the adaptive coverage loop (phase_adaptive) so EVERY applicable cell gets covered.

    # LLM: prioritized hypotheses for what to test next (uses your linked Claude account)
    if (HERE / "hypo-gen.py").exists() and eps:
        log("cmd", "$ hypothesize — highest-ROI attack ideas not yet tested")
        ef = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        ff = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        ef.write(json.dumps([e["url"] for e in STATE["endpoints"]][:40])); ef.close()
        ff.write(json.dumps([{"title": f["title"], "endpoint": f.get("endpoint", "")} for f in STATE["findings"]])); ff.close()
        a = ["--endpoints-file", ef.name, "--findings-file", ff.name, "--json", "--max", "5"]
        if PROGRAM: a += ["--program", PROGRAM]
        a += ["--model", "claude-haiku-4-5"]
        d = tool_json("hypo-gen.py", a, timeout=90)
        for p in (ef.name, ff.name):
            try: os.unlink(p)
            except Exception: pass
        hyps = (d or {}).get("hypotheses", [])
        STATE["leads"] = [{"title": h.get("title", ""), "attack": h.get("attack_class", ""),
                           "endpoint": h.get("target_endpoint", ""), "why": h.get("why_likely", ""),
                           "cmd": h.get("huntr_command") or h.get("command") or ""} for h in hyps]
        STATE["stats"]["leads"] = len(STATE["leads"])
        if STATE["leads"]:
            log("ok", "✓ " + str(len(STATE["leads"])) + " prioritized leads generated (see Leads)")
        else:
            log("out", "→ no new leads" + (" ("+(d or {}).get("error","")[:60]+")" if (d or {}).get("error") else ""))
    flush()
    stage("Exploit", 88)


def _creds():
    cf = HUNT_DIR / "creds.json"
    if cf.exists():
        try:
            return json.loads(cf.read_text())
        except Exception:
            return {}
    return {}


def phase_authed():
    """Authenticated class-scans — only when NOT black-box and a session token was supplied."""
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    if MODE == "black" or not tok:
        if MODE != "black" and not tok:
            log("out", "→ no session token supplied — authenticated surface skipped (black-box recon only)")
        return
    tok_bare = re.sub(r"^Bearer\s+", "", tok, flags=re.I).strip()
    tok2 = (c.get("token2") or "").strip()
    stage("Authed", 72)
    log("ok", "✓ authenticated pass — testing with your session (" + MODE + "-box)" + (" + 2nd identity" if tok2 else ""))
    hosts_live = [h["host"] for h in STATE["hosts"] if h.get("status")]
    eps = [e["url"] for e in STATE["endpoints"]]
    api_eps = [u for u in eps if ("/api" in u.lower() or "/graphql" in u.lower())]
    base_url = ("https://" + hosts_live[0]) if hosts_live else ("https://" + apex(TARGET))

    # 1) JWT attacks on the supplied token (if it is a JWT)
    if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", tok_bare) and (HERE / "jwt-test.py").exists():
        log("cmd", "$ jwt-test — alg:none · weak secret · RS→HS confusion · kid traversal")
        d = tool_json("jwt-test.py", ["--token", tok_bare, "--url", base_url, "--json"], timeout=120)
        for f in (d or {}).get("findings", []):
            add_finding(f.get("severity", "h"), "JWT — " + (f.get("name") or f.get("type") or "weakness"),
                        f.get("detail") or f.get("description") or "", base_url, cls="JWT", verdict="confirmed")
    stage("Authed", 78)
    # authenticated per-endpoint classes (auth-bypass / param / idor) are run by the
    # adaptive coverage loop below, which has the token and covers every applicable cell.
    log("ok", "✓ session accepted — authenticated classes will run in the coverage loop")


def _stack():
    p = (PROGRAM + " " + TARGET).lower()
    s = ["saas", "api"]
    if any(k in p for k in ("bank", "pay", "fin", "wallet", "card", "trading", "ledger", "crypto")):
        s = ["fintech"] + s
    if "graphql" in " ".join(e["url"] for e in STATE["endpoints"]).lower():
        s.append("graphql")
    return ",".join(dict.fromkeys(s))


APPLICABLE = ["cors", "redirect", "jwt", "idor", "authz", "param", "sqli", "xss", "ssti", "ssrf", "misconfig", "race"]


def _cls_key(c):
    c = (c or "").lower()
    if "sqli" in c or "sql injection" in c: return "sqli"
    if "ssti" in c or "template inj" in c: return "ssti"
    if "ssrf" in c or "server-side request" in c: return "ssrf"
    if "command inj" in c or "cmdi" in c or "rce" in c or "code exec" in c: return "rce"
    if "xxe" in c: return "xxe"
    if "xss" in c: return "xss"
    if "idor" in c: return "idor"
    if "auth" in c: return "authz"
    if "jwt" in c: return "jwt"
    if "cors" in c: return "cors"
    if "redirect" in c: return "redirect"
    if "race" in c: return "race"
    if "param" in c: return "param"
    if "invariant" in c: return "authz"
    return "misconfig"


def build_coverage():
    """Write a real coverage.tsv (surface item × vuln-class cells) from what was actually scanned."""
    eps = [e["url"] for e in STATE["endpoints"]]
    if not eps:
        eps = ["https://" + h["host"] for h in STATE["hosts"] if h.get("host")]
    find_cls = {}
    for i, f in enumerate(STATE["findings"]):
        find_cls[(f.get("endpoint", ""), _cls_key(f.get("cls")))] = "F%02d" % (i + 1)
    lines = ["# columns: item | type | " + " | ".join(APPLICABLE) + " | notes",
             "# target: " + TARGET + "  (built by hunt-run.py)"]
    for ep in eps[:400]:
        appl = set(applicable_classes(ep)) | {"misconfig"}  # only count cells that actually apply
        cells = []
        for cls in APPLICABLE:
            if (ep, cls) in find_cls:
                cells.append("FINDING:" + find_cls[(ep, cls)] + "@ev#T3")
            elif cls in TESTED.get(ep, set()):
                cells.append("TESTED-tool@ev#T2")
            elif cls in NO_TOOL.get(ep, set()):
                cells.append("NOTOOL")   # applicable but no scanner installed — honest, not false "tested"
            elif cls in appl:
                cells.append("TODO")
            else:
                cells.append(".")   # not applicable to this endpoint → not counted
        lines.append(ep + "\tendpoint\t" + "\t".join(cells) + "\t")
    (HUNT_DIR / "coverage.tsv").write_text("\n".join(lines) + "\n")


STATEFUL_RE = r"(redeem|coupon|voucher|order|checkout|cart|transfer|claim|vote|invite|apply|withdraw|balance|credit|gift|refund|payout)"
RANK = {"ssti": 0, "sqli": 0, "idor": 1, "ssrf": 1, "authz": 2, "xss": 3, "race": 4, "jwt": 5, "param": 6, "cors": 7, "redirect": 8}


def applicable_classes(ep):
    low = ep.lower()
    cl = []
    has_param = bool(re.search(r"[?&][\w\[\]]+=", low))
    if "/api" in low or "/graphql" in low:
        cl += ["cors", "param"]
    if has_param:                       # injectable surface (works unauth)
        cl += ["param", "sqli", "xss", "ssti"]
    if re.search(r"[?&](url|uri|path|dest|callback|webhook|fetch|load|src|target|feed|host|domain|site|proxy|redirect|return|next|continue|image|img|file)=", low):
        cl.append("ssrf")
    if re.search(r"/\d{1,8}(?:/|\?|$)", ep) or re.search(r"[?&](id|uid|user|account|order|doc|file|key)=", low):
        cl.append("idor")
    if any(k in low for k in ("/admin", "/internal", "/debug", "/actuator", "/manage", "/private")):
        cl.append("authz")
    if re.search(r"(redirect|url|next|return|dest|continue|goto|u)=", low):
        cl.append("redirect")
    if re.search(STATEFUL_RE, low):
        cl.append("race")
    return list(dict.fromkeys(cl))


def scan_cell(ep, cls, tok, tok2):
    """Scan one (endpoint × class) cell. Tool-level evidence sets a deterministic verdict
    (so a confirmed bug never depends on the AI judge). Coverage integrity: a cell whose tool
    ERRORED/timed-out is NOT marked tested — it stays TODO so resume re-does it (no silent miss)."""
    ran = None   # None = no tool executed (missing/unknown class); True = ran OK; False = tool errored
    try:
        if cls == "cors" and (HERE / "cors-test.py").exists():
            d = tool_json("cors-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=40); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "CORS — " + (f.get("type") or "misconfig"), f.get("detail") or "", ep, cls="CORS", verdict="likely")
        elif cls == "redirect" and (HERE / "open-redirect.py").exists():
            import urllib.parse as _up
            qs = _up.urlparse(ep).query
            param = next((kv.split("=")[0] for kv in qs.split("&")
                          if kv.split("=")[0] in ("redirect", "url", "next", "return", "returnUrl", "redirect_uri", "dest", "continue", "goto", "u")), "redirect")
            d = tool_json("open-redirect.py", ["--url", ep, "--param", param, "--json"], timeout=50); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "Open redirect — " + param, f.get("payload") or "", ep, cls="Open redirect", verdict="confirmed")
        elif cls == "idor" and tok and (HERE / "idor-chain.py").exists():
            a = ["--base-url", ep, "--token", tok, "--json"] + (["--token2", tok2] if tok2 else [])
            d = tool_json("idor-chain.py", a, timeout=150); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "IDOR — " + (f.get("name") or "object reference"), f.get("detail") or "", ep, cls="IDOR", verdict="confirmed")
        elif cls == "authz" and tok and (HERE / "auth-bypass.py").exists():
            d = tool_json("auth-bypass.py", ["--url", ep, "--token", tok, "--json"], timeout=60); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Auth bypass — " + (f.get("technique") or f.get("name") or "access control"), f.get("detail") or "", ep, cls="Auth bypass", verdict="confirmed")
        elif cls == "param" and (HERE / "param-fuzz.py").exists():
            d = tool_json("param-fuzz.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=120); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "Hidden param — " + (f.get("param") or f.get("name") or "parameter"), f.get("detail") or "", ep, cls="Param/IDOR", verdict="likely")
        elif cls == "xss" and (HERE / "xss-test.py").exists():
            d = tool_json("xss-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=80); ran = d is not None
            for f in (d or {}).get("findings", []):
                v = "confirmed" if "verified" in (f.get("type", "").lower()) else "likely"
                add_finding(f.get("severity", "m"), (f.get("type") or "Reflected XSS") + " — " + (f.get("param") or "param"), f.get("detail") or f.get("payload") or "", ep, cls="XSS", verdict=v)
        elif cls == "sqli" and (HERE / "sqli-test.py").exists():
            d = tool_json("sqli-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=160); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "c"), "SQL injection — " + (f.get("param") or "parameter"), f.get("detail") or "", ep, cls="SQLi", verdict="confirmed")
        elif cls == "ssti" and (HERE / "ssti-test.py").exists():
            d = tool_json("ssti-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=70); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "c"), "Server-side template injection — " + (f.get("param") or "param"), f.get("detail") or "", ep, cls="SSTI", verdict="confirmed")
        elif cls == "ssrf" and (HERE / "ssrf-test.py").exists():
            d = tool_json("ssrf-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=60); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "SSRF — " + (f.get("param") or "server-side request"), f.get("detail") or "", ep, cls="SSRF", verdict=f.get("verdict", "likely"))
        elif cls == "race" and (HERE / "race-fire.py").exists():
            a = ["--url", ep, "--count", "20", "--json"] + (["--token", tok] if tok else [])
            d = tool_json("race-fire.py", a, timeout=90); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Race condition — " + (f.get("type") or "state divergence"), f.get("note") or "", ep, cls="Race", verdict="confirmed")
    except Exception:
        ran = False
    if ran is True:
        mark_tested(ep, cls)                 # a tool actually ran → the cell is genuinely covered
    elif ran is False:
        log("warn", "⚠ " + cls + " cell errored — left TODO (not counted as tested): " + ep[:70])
    else:
        # ran is None: no tool for this class is installed. Record it as NOT-APPLICABLE so the coverage
        # ledger neither claims false coverage nor loops on it forever (honest "no tool" state).
        NO_TOOL.setdefault(ep, set()).add(cls)
    return ran


def phase_adaptive(deadline, max_cells=120):
    """Coverage-to-100% loop: cover EVERY applicable (endpoint × class) cell, ranked by ROI and
    boosted by the LLM leads, until the ledger is drained or the budget/time is hit."""
    c = _creds(); tok = (c.get("session_token") or "").strip(); tok2 = (c.get("token2") or "").strip()
    authed_ok = (MODE != "black") and bool(tok)
    work = []
    for e in STATE["endpoints"]:
        ep = e["url"]
        for cls in applicable_classes(ep):
            if cls in TESTED.get(ep, set()):
                continue
            if cls in ("idor", "authz") and not authed_ok:
                continue  # these two genuinely need a session (two-identity comparison)
            work.append((RANK.get(cls, 9), ep, cls))
    # adaptive prioritization: cells whose endpoint matches an LLM lead go first
    leadeps = set((l.get("endpoint") or "").lower() for l in STATE.get("leads", []) if l.get("endpoint"))
    work.sort(key=lambda w: (0 if any(le and le in w[1].lower() for le in leadeps) else 1, w[0], w[1]))
    total = len(work)
    stage("Hunt", 40)
    log("ok", "↻ adaptive coverage loop — " + str(total) + " untested cells queued" +
        ("" if authed_ok else " (unauth: idor/authz skipped — no session)"))
    done = 0
    for rank, ep, cls in work[:max_cells]:
        if time.time() > deadline:
            log("warn", "⏱ budget reached — " + str(total - done) + " cells left TODO (resume to continue)")
            break
        log("cmd", "$ [" + cls + "] " + ep)
        scan_cell(ep, cls, tok, tok2)
        done += 1
        STATE["pct"] = min(86, 40 + int(done / max(1, min(total, max_cells)) * 46))
        STATE["stage"] = "Hunt " + str(done) + "/" + str(min(total, max_cells))
        flush()
    log("ok", "✓ adaptive loop · " + str(done) + "/" + str(total) + " cells scanned")
    stage("Hunt", 88)


def phase_ai_direct(deadline, max_rounds=3):
    """Tri-hybrid Layer 2 — AI-directed targeted testing. Haiku reads the ledger + surface + findings
    and picks the highest-ROI untested cells to run next, in rounds, until done or budget."""
    eps = [e["url"] for e in STATE["endpoints"]]
    if not eps:
        return
    c = _creds(); tok = (c.get("session_token") or "").strip(); tok2 = (c.get("token2") or "").strip()
    authed = (MODE != "black") and bool(tok)
    stage("AI-direct", 88)
    log("ok", "◆ AI (Haiku) directing targeted tests over the mapped surface…")
    for rnd in range(max_rounds):
        if time.time() > deadline:
            break
        untested = []
        for ep in eps:
            for cls in applicable_classes(ep):
                if cls in TESTED.get(ep, set()):
                    continue
                if cls in ("idor", "authz") and not authed:   # param-fuzz works unauth (consistent with phase_adaptive)
                    continue
                untested.append({"endpoint": ep, "class": cls})
        if not untested:
            break
        sys_p = ("You are a bug-bounty lead directing an automated scanner. You get the target's mapped endpoints, "
                 "the findings so far, and the UNTESTED (endpoint,class) cells. Pick the highest-ROI cells to test next "
                 "(max 12). Reply STRICT JSON: {\"tests\":[{\"endpoint\":\"..\",\"class\":\"sqli|xss|ssti|ssrf|cors|redirect|idor|authz|param|race\"}],"
                 "\"done\":false,\"why\":\"one short line\"}. Set done=true when nothing left is worth testing.")
        usr = json.dumps({"target": TARGET, "mode": MODE,
                          "findings": [{"title": f["title"], "endpoint": f.get("endpoint", ""), "cls": f.get("cls", "")} for f in STATE["findings"]],
                          "untested": untested[:60]})
        d = llm_json(MODEL_CHEAP, sys_p, usr, max_tokens=1200, timeout=70)
        if not isinstance(d, dict):
            d = {}
        tests = d.get("tests") or []
        if d and d.get("why"):
            log("cmd", "AI round " + str(rnd + 1) + ": " + str(d.get("why"))[:90])
        ran = 0
        for t in tests[:12]:
            if time.time() > deadline:
                break
            if not isinstance(t, dict):
                continue
            ep = t.get("endpoint", ""); cls = (t.get("class") or "").lower()
            if not ep or cls not in ("sqli", "xss", "ssti", "ssrf", "cors", "redirect", "idor", "authz", "param", "race"):
                continue   # allow the injection classes the prompt advertises (were silently dropped before)
            if cls in TESTED.get(ep, set()):
                continue
            if cls in ("idor", "authz") and not authed:
                continue
            log("cmd", "$ [AI→" + cls + "] " + ep)
            scan_cell(ep, cls, tok, tok2); ran += 1
        if (d or {}).get("done") or ran == 0:
            break
    stage("AI-direct", 90)
    log("ok", "✓ AI-directed pass complete")


def _find_sig(f):
    """Root-cause signature for a finding: same class + same endpoint (host+path) + same injected
    parameter name(s) = the SAME bug, however many tools reported it. Param names come from the URL
    query (reliable) — not the title, whose wording varies by tool."""
    cls = _cls_key(f.get("cls"))
    ep = f.get("endpoint", "") or ""
    try:
        import urllib.parse as up
        u = up.urlparse(ep); loc = (u.netloc + u.path).lower().rstrip("/")
        params = tuple(sorted(k.lower() for k, _ in up.parse_qsl(u.query)))
    except Exception:
        loc = ep.lower(); params = ()
    if not params:   # no query param (e.g. invariant/misconfig) → fall back to a title param if present
        m = re.search(r"[—:-]\s*([\w\[\]]+)\s*$", f.get("title", ""))
        params = (m.group(1).lower(),) if m else ()
    return (cls, loc, params)


def phase_dedup():
    """Collapse intra-hunt duplicates: one root-cause bug detected by several tools/vectors (reflected
    + verified + OAST XSS on one param, or three SSTI hits on one endpoint) becomes ONE finding, keeping
    the strongest evidence. Cuts operator noise and makes the economics/chain views reflect real bugs."""
    finds = STATE["findings"]
    if len(finds) < 2:
        return
    def _best_rank(f):   # lower = better: confirmed+undroppable, then severity, then more evidence
        v = 0 if f.get("_det") else (1 if f.get("verdict") == "confirmed" else 2 if f.get("verdict") == "likely" else 3)
        return (v, SEVRANK.get(f.get("sev", "i"), 9), -len(f.get("detail", "")))
    groups = {}
    for f in finds:
        groups.setdefault(_find_sig(f), []).append(f)
    merged, removed = [], 0
    for sig, grp in groups.items():
        if len(grp) == 1:
            merged.append(grp[0]); continue
        grp.sort(key=_best_rank)
        keeper = grp[0]
        others = grp[1:]
        keeper["also_detected"] = len(others)
        tools = ", ".join(sorted({(o.get("cls") or "").strip() for o in others if o.get("cls")}))[:120]
        if tools:
            keeper["detail"] = (keeper.get("detail", "") + " · also detected via: " + tools).strip(" ·")
        merged.append(keeper); removed += len(others)
    if removed:
        # preserve original ordering by first appearance
        order = {id(f): i for i, f in enumerate(finds)}
        merged.sort(key=lambda f: order.get(id(f), 0))
        STATE["findings"] = merged
        STATE["stats"]["findings"] = len(merged)
        log("ok", "⊚ dedup · merged " + str(removed) + " duplicate detection(s) → " + str(len(merged)) + " distinct bug(s)")
        flush()


def phase_oob(deadline):
    """Blind / out-of-band injection fuzzing via nuclei DAST + interactsh. Confirms SSRF and other
    blind classes (cmdi/SSTI/XXE/log4j) that produce NO reflected response — an OAST callback is the
    proof. OAST hits are deterministic → verdict=confirmed (never gated on the AI judge)."""
    if not has("nuclei"):
        return
    params = [e["url"] for e in STATE["endpoints"] if re.search(r"[?&][\w\[\]]+=", e.get("url", ""))]
    if not params:
        return
    remaining = int(deadline - time.time())
    if remaining < 60:                       # not enough budget to run an OOB pass meaningfully
        log("warn", "⏱ skipped OOB fuzzing — budget exhausted (" + str(remaining) + "s left)")
        return
    sl = max(60, min(remaining - 20, 240))   # OOB slice: leave headroom for judge/chain/economics
    stage("OOB-fuzz", 92)
    log("ok", "◆ blind/OOB fuzzing · nuclei DAST + interactsh · " + str(len(params)) + " param URL(s) · " + str(sl) + "s")
    try:
        pf = HUNT_DIR / "oob_urls.txt"
        pf.write_text("\n".join(params[:120]))
        d = tool_json("oob-fuzz.py", ["--targets-file", str(pf), "--budget-sec", str(sl), "--max-urls", "60"], timeout=sl + 30)
    except Exception:
        d = None
    if d is None:
        log("warn", "→ OOB fuzzing errored/timed out — no blind findings captured this pass")
        return
    n = 0
    for f in (d or {}).get("findings", []):
        add_finding(f.get("severity", "h"), f.get("title") or "Out-of-band injection",
                    f.get("detail") or "", f.get("endpoint") or "", cls=f.get("cls", "OOB"),
                    verdict=f.get("verdict", "confirmed"))
        n += 1
    log("ok" if n else "info", "✓ OOB fuzzing · " + str(d.get("urls", 0)) + " URL(s) fuzzed · " +
        str(n) + " blind finding(s) confirmed via OAST")
    flush()


def phase_ai_judge():
    """Tri-hybrid Layer 3 — strong-model validation. Sonnet (fallback Haiku) reads every finding's real
    evidence, KILLS false positives, and writes real repro + impact + remediation + chains."""
    if not STATE["findings"]:
        return
    stage("AI-judge", 95)
    log("ok", "◆ AI (Sonnet) validating findings + writing reports…")
    items = [{"i": i, "title": f["title"], "cls": f.get("cls", ""), "endpoint": f.get("endpoint", ""),
              "sev": f.get("sev", ""), "cvss": f.get("cvss", ""), "evidence": (f.get("detail") or "")[:600]}
             for i, f in enumerate(STATE["findings"])]
    sys_p = ("You are a senior bug-bounty validator. For each finding you get its class, endpoint, severity and the "
             "scanner's raw evidence. Judge HONESTLY — scanners produce false positives. Reply STRICT JSON: "
             "{\"judgments\":[{\"i\":<index>,\"verdict\":\"confirmed|likely|false_positive\",\"drop\":bool,"
             "\"repro\":\"numbered reproducible steps grounded ONLY in the evidence; empty if not demonstrable\","
             "\"impact\":\"concrete impact in 1-2 sentences\",\"remediation\":\"the fix\",\"cvss\":\"x.x\"}],"
             "\"chains\":[\"short multi-step chain across findings if any\"]}. Never invent evidence; if the evidence "
             "doesn't support the finding set verdict=false_positive and drop=true.")
    d = llm_json(MODEL_STRONG, sys_p, json.dumps({"target": TARGET, "findings": items}), max_tokens=3200, timeout=150)
    if not isinstance(d, dict):   # model may return a bare array / malformed JSON — don't crash the hunt
        log("warn", "→ AI judge unavailable (rate-limited/offline) — findings left as-is")
        stage("AI-judge", 98); return
    drop = set(); kept = 0; conf = 0
    for j in (d.get("judgments") or []):
        if not isinstance(j, dict):
            continue
        i = j.get("i")
        if not isinstance(i, int) or i < 0 or i >= len(STATE["findings"]):
            continue
        f = STATE["findings"][i]
        if j.get("drop") or j.get("verdict") == "false_positive":
            if f.get("_det"):   # tool-confirmed (e.g. sqlmap) — the judge enriches, it cannot drop it
                f["detail"] = (f.get("detail", "") + " · note: AI judge flagged for review; tool evidence stands").strip(" ·")
                kept += 1; conf += 1; continue
            drop.add(i); continue
        if j.get("repro"): f["steps"] = j["repro"]
        if j.get("remediation"): f["remediation"] = j["remediation"]
        if j.get("impact"): f["detail"] = (f.get("detail", "") + " · impact: " + j["impact"]).strip(" ·")
        if j.get("cvss"): f["cvss"] = str(j["cvss"]) or f.get("cvss", "")
        if not (f.get("_det") and j.get("verdict") != "confirmed"):   # never downgrade a deterministic confirmation
            f["verdict"] = j.get("verdict", "") or f.get("verdict", "")
        kept += 1; conf += 1 if f.get("verdict") == "confirmed" else 0
    if drop:
        STATE["findings"] = [f for k, f in enumerate(STATE["findings"]) if k not in drop]
        STATE["stats"]["findings"] = len(STATE["findings"])
    # NOTE: the judge's free-text chain hints are intentionally NOT written to STATE["chains"] —
    # that field holds structured chains owned by phase_chain (dashboard calls ch.steps). Keep them as a note.
    jc = [c for c in (d.get("chains") or []) if c]
    if jc:
        STATE["chain_hints"] = jc
    log("warn" if drop else "ok", "✓ AI judge: " + str(kept) + " kept (" + str(conf) + " confirmed) · " + str(len(drop)) + " false-positive(s) dropped")
    flush(); stage("AI-judge", 98)


# ══ Economics brain — EV-rank findings + hard dedup gate (spend submissions where the money is) ══
DEFAULT_BOUNTY = {"c": 4000, "h": 1500, "m": 500, "l": 150, "i": 0}
P_REAL = {"confirmed": 0.92, "likely": 0.6, "false_positive": 0.0}
P_ACCEPT = {"c": 0.85, "h": 0.8, "m": 0.7, "l": 0.55, "i": 0.2}
DUP_GATE = 80  # dup% at/above which a finding is held OFF the submit queue


def _bounty_model():
    """$ per severity, scaled up for high-value program domains (fintech/crypto/infra)."""
    p = (PROGRAM + " " + TARGET).lower()
    mult = 1.0
    if any(k in p for k in ("bank", "pay", "fin", "wallet", "crypto", "trading", "ledger", "exchange", "card")):
        mult = 2.5
    elif any(k in p for k in ("cloud", "infra", "identity", "auth", "admin", "enterprise")):
        mult = 1.6
    return {k: int(v * mult) for k, v in DEFAULT_BOUNTY.items()}, mult


def phase_economics():
    """Rank findings by expected value; hold likely duplicates before they reach the operator.
    EV = P(real) × P(accepted) × bounty$ × (1 − P(duplicate)). Does NOT reorder findings
    (chain↔finding links depend on index) — the dashboard ranks for display."""
    finds = STATE["findings"]
    if not finds:
        return
    stage("Economics", 98)
    bounty, mult = _bounty_model()
    # ── learning loop: calibrated priors from past operator-reported outcomes ──
    priors = {}; ptot = 0
    try:
        pf = Path(os.environ.get("HUNTR_HOME", str(Path.home() / ".huntr"))) / "corpus" / "priors.json"
        if pf.exists():
            pj = json.loads(pf.read_text()); priors = pj.get("buckets", {}); ptot = pj.get("total", 0)
    except Exception:
        priors = {}; ptot = 0
    stack0 = _stack().split(",")[0]

    def _blend(default, learned, n, k=5):
        if learned is None or not n:
            return default
        w = n / (n + k)
        return default * (1 - w) + learned * w

    applied = 0
    for f in finds:
        sev = f.get("sev", "i")
        cls = _cls_key(f.get("cls"))
        verdict = (f.get("verdict") or ("confirmed" if f.get("steps") else "likely")).lower()
        preal = P_REAL.get(verdict, 0.5)
        pacc = P_ACCEPT.get(sev, 0.3)
        if (f.get("cls") or "").lower() == "chain":
            pacc = min(0.95, pacc + 0.05)   # proven escalated impact lands better
        dup = f.get("dup")
        pdup = (dup / 100.0) if isinstance(dup, (int, float)) else 0.15
        b = bounty.get(sev, 0)
        # blend learned priors (per class|stack, else per class) weighted by sample count
        pb = priors.get("cs|" + cls + "|" + stack0) or priors.get("cls|" + cls)
        if pb and pb.get("n", 0) >= 3:
            pacc = _blend(pacc, pb.get("p_accept"), pb["n"])
            if not isinstance(dup, (int, float)) and pb.get("p_dup") is not None:
                pdup = _blend(0.15, pb.get("p_dup"), pb["n"])
            if pb.get("avg_bounty"):
                b = int(_blend(b, pb.get("avg_bounty"), pb["n"]))
            f["learned"] = pb["n"]; applied += 1
        ev = preal * pacc * b * (1 - pdup)
        if isinstance(dup, (int, float)) and dup >= DUP_GATE:
            reco = "hold-duplicate"
        elif verdict != "confirmed" or not (f.get("steps") or f.get("detail")):
            reco = "needs-work"
        else:
            reco = "submit"
        f["ev"] = int(ev); f["bounty_est"] = b; f["reco"] = reco
        f["ev_band"] = "high" if ev >= 1500 else "med" if ev >= 400 else "low"
    submit_now = [f for f in finds if f.get("reco") == "submit"]
    held = [f for f in finds if f.get("reco") == "hold-duplicate"]
    needs = [f for f in finds if f.get("reco") == "needs-work"]
    total_ev = sum(f.get("ev", 0) for f in submit_now)
    STATE["economics"] = {
        "bounty_model": bounty, "program_mult": mult, "pipeline_ev": total_ev,
        "submit_now": len(submit_now), "needs_work": len(needs), "held_duplicate": len(held),
        "learned": {"outcomes": ptot, "applied": applied},
        "top": sorted(([{"title": f["title"], "sev": f["sev"], "ev": f.get("ev", 0), "endpoint": f.get("endpoint", "")}
                        for f in submit_now]), key=lambda x: -x["ev"])[:5],
    }
    STATE["stats"]["pipeline_ev"] = total_ev
    log("ok", "$ economics · pipeline EV ~$" + format(total_ev, ",") + " · " + str(len(submit_now)) +
        " submit-ready · " + str(len(held)) + " held (likely dup) · " + str(len(needs)) + " need work")
    if ptot:
        log("out", "⟲ learning loop · EV calibrated from " + str(ptot) + " past outcome(s) · " + str(applied) + " finding(s) adjusted")
    flush()


# ══ Chain-to-Impact planner — the moat: reason isolated findings into max-impact chains ══
IMPACT_SEV = {"account-takeover": "c", "rce": "c", "full-db-read": "c", "cloud-role": "c", "db-read": "c",
              "pii-read": "h", "other-user-data": "h", "admin-access": "h", "cloud-metadata": "h",
              "token-forge": "h", "host-control": "h", "cross-origin-read": "m", "js-exec": "m", "oauth-code": "m"}
SEVRANK = {"c": 0, "h": 1, "m": 2, "l": 3, "i": 4}


def _short_ep(ep):
    try:
        import urllib.parse as up
        u = up.urlparse(ep); return ((u.netloc + (u.path or "")) or ep)[:46]
    except Exception:
        return (ep or "")[:46]


def _finding_edges(f, fi, start):
    """A validated finding → (proven base edge, unproven escalation edge) toward its natural max impact."""
    cls = _cls_key(f.get("cls")); s = _short_ep(f.get("endpoint", "") or TARGET)
    t = (str(f.get("cls", "")) + " " + str(f.get("title", ""))).lower()
    if "takeover" in t and "sub" in t:
        return [(start, "subdomain-takeover " + s, "host-control", "proven", "h", fi)]
    M = {
        "sqli":     [(start, "SQLi " + s, "db-read", "proven", "c", fi), ("db-read", "dump PII tables", "pii-read", "unproven", "h", -1)],
        "ssti":     [(start, "SSTI " + s, "rce", "proven", "c", fi)],
        "rce":      [(start, "command/code exec " + s, "rce", "proven", "c", fi)],
        "xxe":      [(start, "XXE " + s, "full-db-read", "proven", "c", fi), ("full-db-read", "SSRF via external entity", "cloud-metadata", "unproven", "h", -1)],
        "ssrf":     [(start, "SSRF " + s, "cloud-metadata", "proven", "h", fi), ("cloud-metadata", "IMDS creds → role", "cloud-role", "unproven", "c", -1)],
        "idor":     [(start, "IDOR " + s, "other-user-data", "proven", "h", fi), ("other-user-data", "read secret / reset token", "account-takeover", "unproven", "c", -1)],
        "authz":    [(start, "auth-bypass " + s, "admin-access", "proven", "h", fi), ("admin-access", "privileged action", "account-takeover", "unproven", "c", -1)],
        "xss":      [(start, "XSS " + s, "js-exec", "proven", "m", fi), ("js-exec", "steal session", "account-takeover", "unproven", "c", -1)],
        "redirect": [(start, "open-redirect " + s, "oauth-code", "unproven", "m", fi), ("oauth-code", "steal code → token", "account-takeover", "unproven", "c", -1)],
        "cors":     [(start, "CORS null+creds " + s, "cross-origin-read", "proven", "m", fi), ("cross-origin-read", "+XSS → session theft", "account-takeover", "unproven", "c", -1)],
        "jwt":      [(start, "JWT weakness " + s, "token-forge", "proven", "h", fi), ("token-forge", "forge admin token", "account-takeover", "unproven", "c", -1)],
    }
    return M.get(cls, [])


def _reach(edges, starts, allow):
    """Fixed-point reachability. Returns {node: path(list of edges)} using edges whose status ∈ allow."""
    seen = {n: [] for n in starts}; changed = True
    while changed:
        changed = False
        for e in edges:
            if e["status"] in allow and e["frm"] in seen and e["to"] not in seen:
                seen[e["to"]] = seen[e["frm"]] + [e]; changed = True
    return seen


def phase_chain():
    """Chain-to-Impact: capability graph from validated findings → proven multi-step chains +
    the single highest-leverage missing edge, reported at escalated impact. (The competitor moat.)"""
    stage("Chaining", 96)
    STATE["chains"] = []   # this phase OWNS the field: always leave it a list of structured chains (the dashboard calls .steps)
    finds = STATE["findings"]
    if not finds:
        STATE["stats"]["chains"] = 0; return
    authed = bool((_creds().get("session_token") or "").strip())
    start = "userA" if authed else "anon"
    starts = {"anon"} | ({"userA", "userB"} if authed else set())
    edges = []
    for fi, f in enumerate(finds):
        for (frm, prim, to, status, imp, link) in _finding_edges(f, fi, start):
            edges.append({"frm": frm, "prim": prim, "to": to, "status": status, "impact": imp, "fi": link})
    if not edges:
        STATE["stats"]["chains"] = 0; return
    try:  # persist edges for capability-graph.py audit
        rows = ["# frm\tprim\tto\tstatus\timpact"] + ["\t".join([e["frm"], e["prim"], e["to"], e["status"], e["impact"] or "-"]) for e in edges]
        (HUNT_DIR / "capabilities.tsv").write_text("\n".join(rows) + "\n")
    except Exception:
        pass

    proven = _reach(edges, starts, {"proven"})
    allr = _reach(edges, starts, {"proven", "unproven"})
    cand = []
    for node in [n for n in allr if n in IMPACT_SEV]:
        if node in proven and len(proven[node]) >= 2:
            cand.append({"node": node, "path": proven[node], "status": "proven"})
        else:
            path = allr[node]; missing = [e for e in path if e["status"] == "unproven"]
            if missing and len(missing) <= 2:
                cand.append({"node": node, "path": path, "status": "near-miss"})
    if not cand:
        STATE["chains"] = []; STATE["stats"]["chains"] = 0; flush(); return

    nears = [c for c in cand if c["status"] == "near-miss"]
    for ni, c in enumerate(nears):
        c["_ni"] = ni
    plan = {}
    if nears:
        items = [{"i": c["_ni"], "impact": c["node"],
                  "path": " → ".join([c["path"][0]["frm"]] + [e["prim"] + "→" + e["to"] for e in c["path"]]),
                  "missing": [e["prim"] + " (" + e["frm"] + "→" + e["to"] + ")" for e in c["path"] if e["status"] == "unproven"]} for c in nears]
        sysp = ("You are a senior exploit-chain strategist for AUTHORIZED bug-bounty testing. Each near-miss chain has a "
                "proven path so far and the UNPROVEN edge(s) needed to reach impact. Reply STRICT JSON: "
                "{\"plans\":[{\"i\":<index>,\"plausible\":true|false,\"prove\":\"ONE concrete non-destructive step the operator "
                "runs to confirm the missing edge\",\"cvss\":\"x.x\",\"impact\":\"one line\"}]}. plausible=false if the escalation "
                "does not realistically follow. The step must be read-only / safe — never a destructive write.")
        d = llm_json(MODEL_STRONG, sysp, json.dumps({"target": TARGET, "chains": items}), max_tokens=1600, timeout=140)
        if not isinstance(d, dict):
            d = {}
        for p in (d.get("plans") or []):
            try: plan[int(p.get("i"))] = p
            except Exception: pass

    chains = []
    for c in cand:
        pl = plan.get(c.get("_ni")) if c["status"] == "near-miss" else None
        if pl and pl.get("plausible") is False:
            continue
        node = c["node"]; sev = IMPACT_SEV.get(node, "m"); path = c["path"]
        steps = []
        for e in path:
            if e["status"] == "proven":
                steps.append({"st": "done", "t": e["prim"], "note": "confirmed", "fi": e.get("fi", -1)})
            else:
                steps.append({"st": "partial", "t": e["prim"], "note": ((pl.get("prove") if pl else "") or "prove this edge to complete the chain")[:160], "fi": -1})
        cvss = (pl.get("cvss") if pl else "") or ""
        chains.append({"sev": sev, "name": path[0]["frm"] + " → " + node.replace("-", " "),
                       "tier": "PROVEN CHAIN" if c["status"] == "proven" else "1 EDGE AWAY",
                       "status": c["status"], "impact": node, "cvss": cvss, "steps": steps})
        if c["status"] == "proven":
            pe = next((e for e in path if e.get("fi", -1) >= 0), None)
            ep = finds[pe["fi"]].get("endpoint", "") if pe else ""
            add_finding(sev, "Chain → " + node.replace("-", " ") + " (" + " → ".join(e["prim"] for e in path) + ")",
                        "Proven multi-step chain from " + path[0]["frm"] + " to " + node + ". Every edge is backed by a validated finding — report at this escalated impact.",
                        ep, cvss=cvss, cls="Chain")
    chains.sort(key=lambda c: (SEVRANK.get(c["sev"], 9), 0 if c["status"] == "proven" else 1))
    STATE["chains"] = chains; STATE["stats"]["chains"] = len(chains)
    nprov = sum(1 for c in chains if c["status"] == "proven")
    if chains:
        log("warn", "⛓ chain-to-impact · " + str(nprov) + " proven chain(s) · " + str(len(chains) - nprov) + " one edge from impact")
        for c in chains[:4]:
            log("out", "   [" + c["tier"] + "] " + c["name"] + (" · CVSS " + c["cvss"] if c["cvss"] else ""))
    flush()


def phase_methodology(deadline=None):
    """The /autohunt methodology: invariant oracles, race, capability-graph chaining, dedup, coverage ledger."""
    stage("Validate", 90)
    live = [h["host"] for h in STATE["hosts"] if h.get("status")]
    host = ("https://" + live[0]) if live else ("https://" + apex(TARGET))
    inv = HUNT_DIR / "invariants.tsv"
    caps = HUNT_DIR / "capabilities.tsv"
    c = _creds(); tok = (c.get("session_token") or "").strip()

    # corpus-suggested + mined invariants (logic oracles)
    if (HERE / "hunt-corpus.py").exists():
        log("cmd", "$ hunt-corpus --suggest --stack " + _stack())
        sh([sys.executable, str(HERE / "hunt-corpus.py"), "--suggest", "--stack", _stack(), "--host", host, "--emit", str(inv)], timeout=60)
    if (HERE / "invariant-mine.py").exists() and STATE["endpoints"]:
        ef = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        ef.write("\n".join(e["url"] for e in STATE["endpoints"])); ef.close()
        log("cmd", "$ invariant-mine — derive BOLA/BFLA/idempotency/value invariants")
        sh([sys.executable, str(HERE / "invariant-mine.py"), ef.name, "--host", host, "--out", str(inv), "--edges", str(caps)], timeout=90)
        try: os.unlink(ef.name)
        except Exception: pass
    if (HERE / "invariant-check.py").exists() and inv.exists():
        log("cmd", "$ invariant-check --run invariants.tsv  (logic oracles)")
        out, err, rc = sh([sys.executable, str(HERE / "invariant-check.py"), "--run", str(inv)], timeout=180)
        n = 0
        TYPE_TITLE = {"noaccess": "Broken object-level authz (BOLA/IDOR)", "deny": "Broken function-level authz (BFLA)",
                      "rejects": "Input contract / mass-assignment violation", "once": "Idempotency violation (action repeatable)"}
        for ln in (out or "").splitlines():
            # a REAL violation is a per-check verdict row (uppercase "VIOLATION" token + a ✗),
            # NOT the summary line "0 violation(s). All invariants held." (lowercase) or the header.
            if ("VIOLATION" in ln) and ("violation(s)" not in ln.lower()) and ("if 200" not in ln.lower()):
                parts = ln.split()
                inv_id = parts[0] if parts else ""
                inv_type = parts[1] if len(parts) > 1 else ""
                title = TYPE_TITLE.get(inv_type, "Logic/authz violation")
                n += 1
                add_finding("h", title + (" [" + inv_id + "]" if inv_id else ""), ln.strip()[:200], "", cls="Invariant", verdict="confirmed")  # a logic-oracle VIOLATION is deterministic
        STATE["invariants"] = [l.strip() for l in (out or "").splitlines() if l.strip() and "INFO" not in l][:40]
        log("warn" if n else "out", ("⚑ " + str(n) + " invariant violation(s) — broken authorization/logic") if n else "→ invariants held (no logic violations)")
    stage("Validate", 94)

    # capability graph → proven chains (deterministic, multi-step impact)
    if (HERE / "capability-graph.py").exists() and caps.exists():
        log("cmd", "$ capability-graph — reachable impact via proven edges")
        out, err, rc = sh([sys.executable, str(HERE / "capability-graph.py"), "--file", str(caps)], timeout=60)
        # these are free-text audit lines; the structured STATE["chains"] is owned by phase_chain (runs later).
        chains = [l.rstrip() for l in (out or "").splitlines() if ("->" in l or "→" in l) and len(l.strip()) > 3]
        STATE["chain_audit"] = chains[:20]
        if chains:
            log("warn", "⛓ " + str(len(chains)) + " proven chain path(s) — escalated impact")

    # dedup vs disclosed corpus (bounded: 20s per finding × N can overrun — stop at the budget)
    if (HERE / "dedup-check.py").exists():
        for f in STATE["findings"]:
            if deadline and time.time() > deadline:
                log("warn", "⏱ budget reached — dedup skipped for remaining findings")
                break
            d = tool_json("dedup-check.py", ["--class", _cls_key(f.get("cls")), "--endpoint", f.get("endpoint", ""),
                                             "--title", f.get("title", "")], timeout=20)
            if isinstance(d, dict):
                dp = d.get("dup_score", d.get("dup", d.get("duplicate_pct")))
                if dp is not None:
                    try: f["dup"] = int(dp)
                    except Exception: pass

    # build the coverage ledger + read the completeness report
    build_coverage()
    if (HERE / "hunt-status.py").exists():
        out, err, rc = sh([sys.executable, str(HERE / "hunt-status.py"), "--dir", str(HUNT_DIR)], timeout=40)
        for ln in (out or "").splitlines():
            m = re.search(r"breadth\s*:\s*(\d+)/(\d+)\s*cells\s*\((\d+)%\).*verified:\s*(\d+)%.*findings:\s*(\d+)", ln)
            if m:
                STATE["coverage"].update({"resolved": int(m.group(1)), "total": int(m.group(2)),
                                          "breadth": int(m.group(3)), "verified": int(m.group(4))})
            md = re.search(r"depth\s*:\s*(\d+)/(\d+)\s*cells.*\((\d+)%\)", ln)
            if md: STATE["coverage"]["depth"] = int(md.group(3))
            mt = re.search(r"remaining:\s*(\d+)\s*TODO", ln)
            if mt: STATE["coverage"]["todo"] = int(mt.group(1))
        cov = STATE["coverage"]
        log("ok", "✓ coverage ledger · breadth " + str(cov.get("breadth", 0)) + "% · depth " +
            str(cov.get("depth", 0)) + "% · " + str(cov.get("total", 0)) + " cells")
    flush()
    stage("Validate", 94)


def phase_fingerprint():
    stage("Fingerprint", 88)
    live = [h for h in STATE["hosts"] if h.get("status")]
    nowaf = [h for h in live if h.get("title") and "cloudflare" not in (h.get("title") or "").lower()]
    log("cmd", "$ fingerprint + flag interesting surface")
    flagged = 0
    for e in STATE["endpoints"]:
        u = e["url"].lower()
        if any(k in u for k in ("/api", "/admin", "/internal", "/graphql", "/debug", "/.git", "/actuator", "token=", "redirect=", "url=")):
            flagged += 1
    if flagged:
        log("warn", "→ " + str(flagged) + " interesting endpoints flagged (api/admin/internal/params) — worth active testing")
    log("ok", "✓ surface fingerprinted")


def main():
    if not TARGET:
        STATE["status"] = "error"; STATE["stage"] = "No target"; flush()
        print("no --target"); return
    os.environ["HUNT_DIR"] = str(HUNT_DIR)  # so every engine tool shells into this workspace
    try:
        (HUNT_DIR / "run.pid").write_text(str(os.getpid()))  # so the dashboard can pause/resume/stop
    except Exception:
        pass
    try:
        log("ok", "▸ hunt started · " + TARGET + " · " + ",".join(SCOPE_TYPES) + " · " + MODE + "-box")
        budget_sec = int(arg("--budget-sec", "1200") or 1200)
        deadline = time.time() + budget_sec
        phase_scope()
        phase_recon()
        phase_surface()
        phase_active()          # Layer 1 — deterministic sweep (recon + scan matrix + LLM leads)
        phase_authed()
        phase_adaptive(deadline)
        phase_ai_direct(deadline)   # Layer 2 — AI-directed targeted tests (Haiku)
        phase_oob(deadline)         # Blind/OOB fuzzing — nuclei DAST + interactsh (blind SSRF etc.)
        phase_dedup()               # collapse same-root-cause duplicates before judge/chain/economics
        phase_fingerprint()
        phase_methodology(deadline)  # coverage ledger + invariants + chains + dedup (dedup bounded by budget)
        phase_ai_judge()            # Layer 3 — strong-model validation + real repro/impact (Sonnet)
        phase_chain()               # Chain-to-Impact — reason findings into max-impact chains (the moat)
        phase_economics()           # Economics brain — EV-rank findings + hard dedup gate
        STATE["status"] = "done"
        stage("Done", 100)
        nf = len(STATE["findings"]); cov = STATE["coverage"]
        log("ok", "■ hunt finished · " + str(nf) + " finding" + ("" if nf == 1 else "s") +
            " · " + str(len(STATE["leads"])) + " leads · " + str(len(STATE["chains"])) + " chains · coverage " +
            str(cov.get("breadth", 0)) + "%")
    except Exception as e:
        STATE["status"] = "error"
        import traceback
        tb = traceback.format_exc()
        STATE["error_trace"] = tb[-1200:]            # persisted for diagnosis
        sys.stderr.write(tb)                          # also to run.log
        log("warn", "✗ runner error: " + str(e)[:200])
        flush()


if __name__ == "__main__":
    main()
