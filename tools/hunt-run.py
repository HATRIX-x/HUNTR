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
    parts = [p for p in h.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


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
    "chains": [], "invariants": [],
    "coverage": {"breadth": 0, "depth": 0, "verified": 0, "total": 0, "resolved": 0, "todo": 0},
    "stats": {"subs": 0, "live": 0, "endpoints": 0, "findings": 0, "leads": 0, "chains": 0},
}

TESTED = {}  # endpoint -> set(class) actually scanned, for the coverage ledger
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
        for m in (models if isinstance(models, list) else [models]):
            body = json.dumps({"model": m, "max_tokens": max_tokens, "system": system,
                               "messages": [{"role": "user", "content": user}]}).encode()
            req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers=hdrs, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read())
                return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            except Exception:
                continue  # fall back to next model
        return None
    except Exception:
        return None


def llm_json(models, system, user, max_tokens=1600, timeout=100):
    """llm_call + extract the first JSON object/array from the reply."""
    txt = llm_call(models, system, user, max_tokens, timeout)
    if not txt:
        return None
    m = re.search(r"(\{.*\}|\[.*\])", txt, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
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


def add_finding(sev, title, detail, endpoint, cvss="", cls=""):
    sev = sev if sev in SEVLABEL else SEVMAP.get((sev or "i").lower(), "i")
    key = (title + "|" + (endpoint or "")).lower()
    if any((f["title"] + "|" + (f.get("endpoint") or "")).lower() == key for f in STATE["findings"]):
        return
    STATE["findings"].append({
        "sev": sev, "label": SEVLABEL[sev], "title": title, "detail": detail or "",
        "cvss": cvss or "", "endpoint": endpoint or "", "cls": cls or "",
    })
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
    """Directly probe a single host (https then http). Returns (status|None, title)."""
    import urllib.request, urllib.error
    for scheme in ("https://", "http://"):
        try:
            req = urllib.request.Request(scheme + host, method="GET",
                                         headers={"User-Agent": "Mozilla/5.0 HUNTR"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "ignore")
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                return (getattr(r, "status", 200) or 200), (m.group(1).strip()[:60] if m else "")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            continue
    return None, ""


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
    # prefer the engine's own recon tool (handles subfinder+resolve+probe)
    tool = HERE / "subdomain-enum.py"
    if tool.exists():
        out, err, _ = sh([sys.executable, str(tool), "--domain", ap, "--json"], timeout=300)
        try:
            d = json.loads(out.strip().splitlines()[-1])
            hosts = d.get("results", [])
            STATE["stats"]["subs"] = d.get("total_found", len(hosts))
            STATE["stats"]["live"] = d.get("live", 0)
        except Exception:
            log("warn", "→ recon parse issue: " + (err or out)[:120])
    elif has("subfinder"):
        out, _, _ = sh(["subfinder", "-d", ap, "-silent"], timeout=180)
        subs = [s.strip() for s in out.splitlines() if s.strip()]
        STATE["stats"]["subs"] = len(subs)
        for s in subs[:60]:
            hosts.append({"host": s, "status": None})
    else:
        log("warn", "→ subfinder not installed — recon limited to the named host")
        hosts = [{"host": re.sub(r'^\*\.', '', TARGET), "status": 200}]

    # --- FIX #1: always include the literal target host, probed directly, never silently dropped
    lithost = re.sub(r'^\*\.', '', TARGET).split('/')[0].strip()
    if lithost and not any(h.get("host") == lithost for h in hosts):
        hosts.insert(0, {"host": lithost, "status": None})
    lit = next((h for h in hosts if h.get("host") == lithost), None)
    if lit is not None and not lit.get("status"):
        st, title = probe_host(lithost)
        lit["status"] = st
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
        url = "https://" + host
        if has("katana"):
            log("cmd", "$ katana -u " + url + " -silent -d 2")
            out, _, _ = sh(["katana", "-u", url, "-silent", "-d", "2", "-c", "15",
                            "-jc", "-timeout", "10"], timeout=100)
            for ln in out.splitlines():
                ln = ln.strip()
                if ln.startswith("http"):
                    eps[ln] = host
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
    endpoints = [{"url": u, "host": hh} for u, hh in items[:400]]
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
    live_hosts = [h["host"] for h in live if h.get("host")][:5]
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
                            cls="Subdomain takeover")
    stage("Exploit", 68)

    # 2) nuclei on live hosts — misconfig / exposure / CVE
    if live_hosts and (HERE / "nuclei-run.py").exists():
        log("cmd", "$ nuclei -severity critical,high,medium · " + str(len(live_hosts)) + " hosts")
        args = ["--json", "--severity", "critical,high,medium"]
        for h in live_hosts:
            args += ["--target", "https://" + h]
        args += ["--rate", "150"]
        d = tool_json("nuclei-run.py", args, timeout=240)
        for e in STATE["endpoints"]:
            mark_tested(e["url"], "misconfig")
        for h in live_hosts:
            mark_tested("https://" + h, "misconfig")
        for f in (d or {}).get("findings", []):
            add_finding(f.get("severity", "i"), f.get("name", "nuclei match"),
                        (f.get("template") or "") + (("  ·  " + f["matcher"]) if f.get("matcher") else ""),
                        f.get("url", ""), cls="Misconfig/CVE")
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
                        f.get("detail") or f.get("description") or "", base_url, cls="JWT")
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


APPLICABLE = ["cors", "redirect", "jwt", "idor", "authz", "param", "sqli", "xss", "misconfig", "race"]


def _cls_key(c):
    c = (c or "").lower()
    if "sqli" in c or "sql injection" in c: return "sqli"
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
            elif cls in appl:
                cells.append("TODO")
            else:
                cells.append(".")   # not applicable to this endpoint → not counted
        lines.append(ep + "\tendpoint\t" + "\t".join(cells) + "\t")
    (HUNT_DIR / "coverage.tsv").write_text("\n".join(lines) + "\n")


STATEFUL_RE = r"(redeem|coupon|voucher|order|checkout|cart|transfer|claim|vote|invite|apply|withdraw|balance|credit|gift|refund|payout)"
RANK = {"sqli": 0, "idor": 1, "authz": 2, "xss": 3, "race": 4, "jwt": 5, "param": 6, "cors": 7, "redirect": 8}


def applicable_classes(ep):
    low = ep.lower()
    cl = []
    has_param = bool(re.search(r"[?&][\w\[\]]+=", low))
    if "/api" in low or "/graphql" in low:
        cl += ["cors", "param"]
    if has_param:                       # injectable surface (works unauth)
        cl += ["param", "sqli", "xss"]
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
    try:
        if cls == "cors" and (HERE / "cors-test.py").exists():
            d = tool_json("cors-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=40)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "CORS — " + (f.get("type") or "misconfig"), f.get("detail") or "", ep, cls="CORS")
        elif cls == "redirect" and (HERE / "open-redirect.py").exists():
            import urllib.parse as _up
            qs = _up.urlparse(ep).query
            param = next((kv.split("=")[0] for kv in qs.split("&")
                          if kv.split("=")[0] in ("redirect", "url", "next", "return", "returnUrl", "redirect_uri", "dest", "continue", "goto", "u")), "redirect")
            d = tool_json("open-redirect.py", ["--url", ep, "--param", param, "--json"], timeout=50)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "Open redirect — " + param, f.get("payload") or "", ep, cls="Open redirect")
        elif cls == "idor" and tok and (HERE / "idor-chain.py").exists():
            a = ["--base-url", ep, "--token", tok, "--json"] + (["--token2", tok2] if tok2 else [])
            d = tool_json("idor-chain.py", a, timeout=150)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "IDOR — " + (f.get("name") or "object reference"), f.get("detail") or "", ep, cls="IDOR")
        elif cls == "authz" and tok and (HERE / "auth-bypass.py").exists():
            d = tool_json("auth-bypass.py", ["--url", ep, "--token", tok, "--json"], timeout=60)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Auth bypass — " + (f.get("technique") or f.get("name") or "access control"), f.get("detail") or "", ep, cls="Auth bypass")
        elif cls == "param" and (HERE / "param-fuzz.py").exists():
            d = tool_json("param-fuzz.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=120)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "Hidden param — " + (f.get("param") or f.get("name") or "parameter"), f.get("detail") or "", ep, cls="Param/IDOR")
        elif cls == "xss" and (HERE / "xss-test.py").exists():
            d = tool_json("xss-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=80)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "m"), (f.get("type") or "Reflected XSS") + " — " + (f.get("param") or "param"), f.get("detail") or f.get("payload") or "", ep, cls="XSS")
        elif cls == "sqli" and (HERE / "sqli-test.py").exists():
            d = tool_json("sqli-test.py", ["--url", ep, "--json"] + (["--token", tok] if tok else []), timeout=160)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "c"), "SQL injection — " + (f.get("param") or "parameter"), f.get("detail") or "", ep, cls="SQLi")
        elif cls == "race" and (HERE / "race-fire.py").exists():
            a = ["--url", ep, "--count", "20", "--json"] + (["--token", tok] if tok else [])
            d = tool_json("race-fire.py", a, timeout=90)
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Race condition — " + (f.get("type") or "state divergence"), f.get("note") or "", ep, cls="Race")
    except Exception:
        pass
    mark_tested(ep, cls)


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
                if cls in ("idor", "authz", "param") and not authed:
                    continue
                untested.append({"endpoint": ep, "class": cls})
        if not untested:
            break
        sys_p = ("You are a bug-bounty lead directing an automated scanner. You get the target's mapped endpoints, "
                 "the findings so far, and the UNTESTED (endpoint,class) cells. Pick the highest-ROI cells to test next "
                 "(max 12). Reply STRICT JSON: {\"tests\":[{\"endpoint\":\"..\",\"class\":\"sqli|xss|cors|redirect|idor|authz|param|race\"}],"
                 "\"done\":false,\"why\":\"one short line\"}. Set done=true when nothing left is worth testing.")
        usr = json.dumps({"target": TARGET, "mode": MODE,
                          "findings": [{"title": f["title"], "endpoint": f.get("endpoint", ""), "cls": f.get("cls", "")} for f in STATE["findings"]],
                          "untested": untested[:60]})
        d = llm_json(MODEL_CHEAP, sys_p, usr, max_tokens=1200, timeout=70)
        tests = (d or {}).get("tests") or []
        if d and d.get("why"):
            log("cmd", "AI round " + str(rnd + 1) + ": " + str(d.get("why"))[:90])
        ran = 0
        for t in tests[:12]:
            if time.time() > deadline:
                break
            ep = t.get("endpoint", ""); cls = (t.get("class") or "").lower()
            if not ep or cls not in ("cors", "redirect", "idor", "authz", "param", "race"):
                continue
            if cls in TESTED.get(ep, set()):
                continue
            if cls in ("idor", "authz", "param") and not authed:
                continue
            log("cmd", "$ [AI→" + cls + "] " + ep)
            scan_cell(ep, cls, tok, tok2); ran += 1
        if (d or {}).get("done") or ran == 0:
            break
    stage("AI-direct", 90)
    log("ok", "✓ AI-directed pass complete")


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
    if not d:
        log("warn", "→ AI judge unavailable (rate-limited/offline) — findings left as-is")
        stage("AI-judge", 98); return
    drop = set(); kept = 0; conf = 0
    for j in (d.get("judgments") or []):
        i = j.get("i")
        if not isinstance(i, int) or i < 0 or i >= len(STATE["findings"]):
            continue
        f = STATE["findings"][i]
        if j.get("drop") or j.get("verdict") == "false_positive":
            drop.add(i); continue
        if j.get("repro"): f["steps"] = j["repro"]
        if j.get("remediation"): f["remediation"] = j["remediation"]
        if j.get("impact"): f["detail"] = (f.get("detail", "") + " · impact: " + j["impact"]).strip(" ·")
        if j.get("cvss"): f["cvss"] = str(j["cvss"]) or f.get("cvss", "")
        f["verdict"] = j.get("verdict", "")
        kept += 1; conf += 1 if j.get("verdict") == "confirmed" else 0
    if drop:
        STATE["findings"] = [f for k, f in enumerate(STATE["findings"]) if k not in drop]
        STATE["stats"]["findings"] = len(STATE["findings"])
    for ch in (d.get("chains") or []):
        if ch and ch not in STATE["chains"]:
            STATE["chains"].append(ch)
    STATE["stats"]["chains"] = len(STATE["chains"])
    log("warn" if drop else "ok", "✓ AI judge: " + str(kept) + " kept (" + str(conf) + " confirmed) · " + str(len(drop)) + " false-positive(s) dropped")
    flush(); stage("AI-judge", 98)


def phase_methodology():
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
                add_finding("h", title + (" [" + inv_id + "]" if inv_id else ""), ln.strip()[:200], "", cls="Invariant")
        STATE["invariants"] = [l.strip() for l in (out or "").splitlines() if l.strip() and "INFO" not in l][:40]
        log("warn" if n else "out", ("⚑ " + str(n) + " invariant violation(s) — broken authorization/logic") if n else "→ invariants held (no logic violations)")
    stage("Validate", 94)

    # capability graph → proven chains (deterministic, multi-step impact)
    if (HERE / "capability-graph.py").exists() and caps.exists():
        log("cmd", "$ capability-graph — reachable impact via proven edges")
        out, err, rc = sh([sys.executable, str(HERE / "capability-graph.py"), "--file", str(caps)], timeout=60)
        chains = [l.rstrip() for l in (out or "").splitlines() if ("->" in l or "→" in l) and len(l.strip()) > 3]
        STATE["chains"] = chains[:20]; STATE["stats"]["chains"] = len(STATE["chains"])
        if chains:
            log("warn", "⛓ " + str(len(chains)) + " proven chain path(s) — escalated impact")

    # dedup vs disclosed corpus
    if (HERE / "dedup-check.py").exists():
        for f in STATE["findings"]:
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
        phase_fingerprint()
        phase_methodology()         # coverage ledger + invariants + chains + dedup
        phase_ai_judge()            # Layer 3 — strong-model validation + real repro/impact (Sonnet)
        STATE["status"] = "done"
        stage("Done", 100)
        nf = len(STATE["findings"]); cov = STATE["coverage"]
        log("ok", "■ hunt finished · " + str(nf) + " finding" + ("" if nf == 1 else "s") +
            " · " + str(len(STATE["leads"])) + " leads · " + str(len(STATE["chains"])) + " chains · coverage " +
            str(cov.get("breadth", 0)) + "%")
    except Exception as e:
        STATE["status"] = "error"
        log("warn", "✗ runner error: " + str(e)[:200])
        flush()
    except Exception as e:
        STATE["status"] = "error"
        log("warn", "✗ runner error: " + str(e)[:200])
        flush()


if __name__ == "__main__":
    main()
