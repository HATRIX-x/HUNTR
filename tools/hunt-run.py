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
import sys, os, re, json, time, subprocess, tempfile, threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import llm_client
except ImportError:      # llm_client sits next to this script
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import llm_client


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
    archive history — skip subfinder/gau/waybackurls for it (they'd waste minutes on nothing).
    HUNT_SINGLE=1 forces this for a strict exact-host scope (e.g. a program scoped to named hosts,
    not *.domain) so recon never wanders off-scope."""
    if os.environ.get("HUNT_SINGLE") == "1":
        return True
    h = re.sub(r"^https?://", "", (target or "").strip().lower()).split("/")[0]
    hostonly = h.split(":")[0]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostonly):      # IPv4
        return True
    if hostonly in ("localhost",) or hostonly.endswith(".local"):
        return True
    if ":" in h:                                            # explicit port ⇒ a specific host, not a domain to enumerate
        return True
    return False


RAW_TARGET = (arg("--target") or "").strip()
# a scope can list MULTIPLE assets ("a.com, *.b.com, rpc.c.net, github.com/org/repo"). Split them so each
# is hunted, instead of treating the whole comma-string as one (broken) hostname.
_assets = [a.strip().rstrip("/") for a in re.split(r"[,\s]+", RAW_TARGET) if a.strip()]
SOURCE_ASSETS = [a for a in _assets if re.search(r"(github\.com|gitlab\.com|bitbucket\.org)/\S+/\S+", a, re.I)]
WEB_ASSETS = [a for a in _assets if a not in SOURCE_ASSETS] or _assets
TARGET = (WEB_ASSETS[0] if WEB_ASSETS else (_assets[0] if _assets else "")).strip()  # primary (apex/naming)
PROGRAM = arg("--program", "")
MODE = arg("--mode", "grey")
# stealth: throttle + lower concurrency + propagate the program UA so loud scanners don't get IP-blocked
# on WAF-protected real targets. On by env HUNT_STEALTH=1 or --stealth.
STEALTH = os.environ.get("HUNT_STEALTH") == "1" or "--stealth" in sys.argv
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
    "chains": [], "invariants": [], "economics": {}, "memory_recall": [],
    "coverage": {"breadth": 0, "depth": 0, "verified": 0, "total": 0, "resolved": 0, "todo": 0},
    "stats": {"subs": 0, "live": 0, "endpoints": 0, "findings": 0, "leads": 0, "chains": 0},
}

TESTED = {}  # endpoint -> set(class) actually scanned, for the coverage ledger
NO_TOOL = {}  # endpoint -> set(class) applicable but with no installed tool (honest "can't test" state)
def mark_tested(ep, cls):
    TESTED.setdefault(ep, set()).add(cls)

SEVMAP = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i", "unknown": "i"}
SEVLABEL = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW", "i": "INFO"}

# Model routing — Claude via OAuth (llm_auth.py) or API key.
# Tool-use agentic loop requires Anthropic — falls back to NVIDIA JSON-action loop
# only when no Anthropic credential is available at all.
def _resolve_claude_available():
    """True if any Anthropic credential is present (API key or Claude Code OAuth)."""
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return True
    try:
        import importlib.util as _il
        _spec = _il.spec_from_file_location("llm_auth", str(HERE / "llm_auth.py"))
        _m = _il.module_from_spec(_spec); _spec.loader.exec_module(_m)
        _, mode = _m.llm_headers()
        return mode in ("api-key", "claude-account")
    except Exception:
        return False

_have_claude = _resolve_claude_available()
if _have_claude:
    MODEL_LEAD   = {"provider": "anthropic", "model": "claude-sonnet-4-6"}
    MODEL_STRONG = {"provider": "anthropic", "model": "claude-sonnet-4-6"}
    MODEL_CHEAP  = {"provider": "anthropic", "model": "claude-haiku-4-5-20251001"}
else:
    MODEL_LEAD   = {"provider": "nvidia", "model": "nvidia/nemotron-3-ultra-550b-a55b"}
    MODEL_STRONG = {"provider": "nvidia", "model": "nvidia/nemotron-3-ultra-550b-a55b"}
    MODEL_CHEAP  = {"provider": "nvidia", "model": "nvidia/nemotron-3.5-lightning-30b-a3b"}
if os.environ.get("HUNT_LLM") == "haiku" or "--llm-light" in sys.argv:
    MODEL_LEAD   = MODEL_CHEAP
    MODEL_STRONG = MODEL_CHEAP


# rate-limit state: set when the provider returns 429 (rate limit reached).
_RL = {"hit": False, "retry_after": 0}
_LLM_LAST_ERR = {"e": ""}
# multi-agent STATE lock: prevents concurrent agents from corrupting findings/leads
_STATE_LOCK = threading.Lock()


class RateLimitPause(Exception):
    pass


def check_pause():
    """Raise if the account rate limit has been reached, so main() can pause the hunt for resume."""
    if _RL["hit"]:
        raise RateLimitPause()


def llm_call(system, user, max_tokens=1600, timeout=100, _model=None):
    """One LLM call via llm_client. Returns text, or None. Sets _RL['hit'] on rate limit.

    Transient provider failures (503 overload, blips, dropped connections) are retried with
    backoff — a single hiccup must not terminate an agentic loop that is mid-reasoning.

    _model: optional dict with 'provider' and 'model' keys (MODEL_LEAD / MODEL_STRONG / MODEL_CHEAP).
    When omitted the llm_client env config is used (NVIDIA default or HUNT_LLM_PROVIDER override)."""
    m = _model or {}
    text, err = None, None
    for attempt in range(4):
        try:
            text, err = llm_client.call_llm(
                system, user, max_tokens=max_tokens, timeout=timeout,
                provider=m.get("provider"), model=m.get("model"),
            )
        except Exception as _e:
            text, err = None, str(_e)
        if text:
            return text
        if err:
            _LLM_LAST_ERR["e"] = err
        if err and "429" in err:
            if attempt < 3:
                # rate limited but the account may still serve — back off and retry rather than
                # burning an agentic round; only a 429 that survives every retry pauses the hunt.
                time.sleep(5.0 * (attempt + 1))
                continue
            _RL["hit"] = True
            return None
        if attempt < 3:
            # 5xx overload needs a real pause, not a courtesy one — the provider serves the
            # same 503 if you come back a second later. 3.5 → 7 → 14s rides out a busy window.
            time.sleep((3.5 * (2 ** attempt)) if re.search(r"\b5\d\d\b", err or "") else (1.5 * (attempt + 1)))
    return None


def llm_json(system, user, max_tokens=1600, timeout=100, _model=None):
    """llm_call + robustly extract a JSON object/array from the reply."""
    txt = llm_call(system, user, max_tokens, timeout, _model=_model)
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
    STATE["tested"] = {ep: sorted(cs) for ep, cs in TESTED.items()}   # persist coverage so a paused hunt resumes
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


def _asset_host(a):
    """(host, is_wildcard) from an asset string like '*.b.com', 'https://x/y', 'rpc.c.net'."""
    h = re.sub(r"^https?://", "", (a or "").strip()).split("/")[0].strip().lower()
    wild = h.startswith("*.")
    return re.sub(r"^\*\.", "", h), wild


def phase_scope():
    stage("Scope", 6)
    allow = HUNT_DIR / "scope.allow"
    lines = set()
    if allow.exists():
        lines = {l.strip() for l in allow.read_text().splitlines() if l.strip()}
    for a in WEB_ASSETS:                      # every in-scope web/api asset
        host, wild = _asset_host(a)
        if not host:
            continue
        lines.add(host)
        if wild:
            lines.add("*." + host)
    for a in SOURCE_ASSETS:                    # source repo hosts stay in scope too
        lines.add(_asset_host(a)[0])
    allow.write_text("\n".join(sorted(x for x in lines if x)) + "\n")
    log("cmd", "$ scope-guard --init  (" + str(len(WEB_ASSETS)) + " web + " + str(len(SOURCE_ASSETS)) + " source asset(s))")
    log("ok", "✓ scope locked · " + str(len([a for a in WEB_ASSETS if _asset_host(a)[1]])) + " wildcard + " +
        str(len([a for a in WEB_ASSETS if not _asset_host(a)[1]])) + " exact host(s) · mode: " + MODE + "-box")


def phase_recon():
    stage("Recon", 18)
    forced_single = os.environ.get("HUNT_SINGLE") == "1"
    hosts = []; seen = set(); subs_total = 0
    def add(host, status=None):
        host = (host or "").strip().lower().split("/")[0]
        if host and host not in seen:
            seen.add(host); hosts.append({"host": host, "status": status})
    log("cmd", "$ recon · " + str(len(WEB_ASSETS)) + " web asset(s)")
    for asset in WEB_ASSETS:
        host, wild = _asset_host(asset)
        if not host:
            continue
        ap = apex(host)
        do_enum = wild and not forced_single and not _single_host(host)
        if do_enum:
            tool = HERE / "subdomain-enum.py"
            if tool.exists():
                out, err, _ = sh([sys.executable, str(tool), "--domain", ap, "--json"], timeout=240)
                try:
                    d = json.loads(out.strip().splitlines()[-1])
                    for r in d.get("results", []):
                        add(r.get("host"), r.get("status"))
                    subs_total += d.get("total_found", 0)
                    log("out", "→ " + ap + ": " + str(d.get("total_found", 0)) + " subdomains")
                except Exception:
                    log("warn", "→ recon parse issue for " + ap)
            elif has("subfinder"):
                out, _, _ = sh(["subfinder", "-d", ap, "-silent"], timeout=150)
                for s in out.splitlines()[:60]:
                    if s.strip(): add(s.strip())
            add(host)   # the apex itself
        else:
            add(ap if wild else host)   # exact host (or apex of a wildcard in single-host mode)
            log("out", "→ " + (ap if wild else host) + " (exact host — no enumeration)")
    # probe every host that has no status yet (bounded)
    probed = 0
    for h in hosts:
        if h.get("status") is None and probed < 50:
            probed += 1
            try:
                st, title, sch = probe_host(h["host"]); h["status"] = st; h["scheme"] = sch
                if title: h["title"] = title
            except Exception:
                pass
    # STICK TO SCOPE: drop any discovered host that matches scope.deny (out-of-scope)
    try:
        import fnmatch
        denyf = HUNT_DIR / "scope.deny"
        deny_pats = [l.strip() for l in denyf.read_text().splitlines() if l.strip() and not l.startswith("#")] if denyf.exists() else []
        if deny_pats:
            before = len(hosts)
            hosts = [h for h in hosts if not any(fnmatch.fnmatch(h["host"], p) or h["host"] == p or h["host"].endswith("." + p.lstrip("*.")) for p in deny_pats)]
            dropped = before - len(hosts)
            if dropped:
                log("out", "→ scope: dropped " + str(dropped) + " out-of-scope host(s) per deny list")
    except Exception:
        pass
    live = [h for h in hosts if h.get("status")]
    # put the live user-provided hosts first so the crawler hits them
    asset_hosts = {_asset_host(a)[0] for a in WEB_ASSETS}
    hosts.sort(key=lambda h: (0 if h["host"] in asset_hosts and h.get("status") else 1 if h.get("status") else 2))
    STATE["hosts"] = hosts[:200]
    STATE["stats"]["subs"] = subs_total or len(hosts)
    STATE["stats"]["live"] = len(live)
    if SOURCE_ASSETS:
        STATE["source_assets"] = SOURCE_ASSETS
        log("warn", "◆ " + str(len(SOURCE_ASSETS)) + " source repo(s) in scope (GitHub) — source review is a separate pass, not run in this web/api hunt")
    if not live:
        log("warn", "⚠ no live hosts among the assets — check the targets are reachable")
    flush()
    for h in (live[:25] or hosts[:25]):
        tag = (str(h.get("status")) + " " if h.get("status") else "") + (h.get("title") or "")
        log("out", "→ " + h.get("host", "?") + ("  [" + tag.strip() + "]" if tag.strip() else ""))
    log("ok", "✓ " + str(len(hosts)) + " host(s) from " + str(len(WEB_ASSETS)) + " asset(s) · " + str(len(live)) + " live")
    stage("Recon", 45)


def _build_surface_graph(endpoints):
    """Build / incrementally update a graphify knowledge graph from the crawled surface.

    Writes into <HUNT_DIR>/graphify-out/. The graph is small (endpoints + JS + specs) so
    extraction is fast and uses zero LLM tokens (pure AST / structural pass). The result
    feeds _lead_digest() and the dashboard's surface-graph tab. Silently skips if graphify
    is not installed."""
    recon_dir = HUNT_DIR / "recon"
    try:
        recon_dir.mkdir(parents=True, exist_ok=True)
        # Write a plain endpoint list as a text file so graphify can ingest it
        ep_file = recon_dir / "endpoints.txt"
        ep_file.write_text("\n".join(e["url"] for e in endpoints) + "\n")
    except Exception:
        return
    try:
        out, err, rc = sh(
            ["graphify", str(recon_dir), "--no-viz", "--update",
             "--out", str(HUNT_DIR / "graphify-out")],
            timeout=60,
        )
        if rc == 0:
            log("ok", "◆ surface graph built · " + str(len(endpoints)) + " endpoints → graphify-out/")
        else:
            # graphify not installed or failed — non-fatal
            log("out", "→ surface graph skipped (" + (err.strip() or "graphify not found")[:80] + ")")
    except Exception as _e:
        log("out", "→ surface graph skipped (" + str(_e)[:80] + ")")


def phase_surface():
    stage("Surface", 52)
    live = [h for h in STATE["hosts"] if h.get("status")]
    # crawl the user's explicit asset hosts first, then other live hosts; deeper crawl + historical URLs
    asset_hosts = {_asset_host(a)[0] for a in WEB_ASSETS}
    primary = [h for h in live if h.get("host") in asset_hosts]
    others = [h for h in live if h.get("host") not in asset_hosts]
    cap = max(4, min(len(primary) + 2, 8))   # make room for all explicit assets
    targets = (primary + others or STATE["hosts"])[:cap]
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
            log("cmd", "$ katana -u " + url + " -silent -d 2" + (" (stealth -rl 15)" if STEALTH else ""))
            kcmd = ["katana", "-u", url, "-silent", "-d", "2", "-c", "5" if STEALTH else "15",
                    "-jc", "-timeout", "10"] + (["-rl", "15"] if STEALTH else [])
            out, _, _ = sh(kcmd, timeout=110)
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

    # Build a graphify knowledge graph of the recon surface so the LLM lead loop gets
    # graph-ranked context instead of a flat URL list. Non-blocking: failure is logged,
    # never crashes the hunt. Only runs if graphify is installed.
    _build_surface_graph(endpoints)

    stage("Surface", 82)


DISCOVER_SEEDS = [
    # API surface — the classes katana can never reach because they are unlinked or JSON-only
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v1/", "/api/v2/",
    "/api/users", "/api/user", "/api/admin", "/api/me", "/api/orders", "/api/account",
    "/api/accounts", "/api/auth", "/api/login", "/api/session", "/api/token", "/api/tokens",
    "/api/profile", "/api/config", "/api/settings", "/api/search", "/api/products",
    "/api/health", "/api/status", "/api/info", "/api/version", "/api/debug", "/api/keys",
    "/api/upload", "/api/files", "/api/export", "/api/import", "/api/graphql",
    # auth / account surfaces
    "/admin", "/admin/", "/administrator", "/dashboard", "/panel", "/manage", "/manager",
    "/console", "/login", "/signin", "/logout", "/register", "/signup", "/auth", "/oauth",
    "/oauth/authorize", "/oauth/token", "/sso", "/saml", "/account", "/profile", "/settings",
    "/user", "/users", "/me", "/forgot", "/reset", "/password", "/verify",
    # spec + schema discovery (unlocks every path in one shot)
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml", "/api-docs",
    "/api-docs.json", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/swagger-ui", "/swagger-ui.html", "/api-docs-ui", "/graphql", "/graphiql", "/playground",
    # framework debug + metadata (high-severity when exposed)
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings", "/debug",
    "/debug/vars", "/debug/pprof", "/_debug", "/metrics", "/prometheus", "/health",
    "/healthz", "/readyz", "/livez", "/status", "/info", "/version", "/env", "/.env",
    "/server-status", "/server-info", "/phpinfo.php", "/trace", "/config.json",
    "/.well-known/openid-configuration", "/.well-known/security.txt", "/sitemap.xml",
    "/robots.txt", "/manifest.json", "/asset-manifest.json", "/.git/config", "/.git/HEAD",
    "/wp-login.php", "/wp-json", "/xmlrpc.php", "/cgi-bin/", "/vendor/phpunit",
    "/elmah.axd", "/trace.axd", "/console/", "/debug/vars/",
]


def _disc_probe(url, timeout=8):
    """One stealth-friendly GET. Returns (status, body_len, content_type) or (None, 0, '').
    Routed through scope-guard's own matcher so active discovery is covered by the same
    request-layer scope enforcement as the scanner tools — never a self-exempt path."""
    import urllib.request, urllib.error
    try:
        import importlib.util as _dl
        global _SG
        try:
            _SG
        except NameError:
            _s = _dl.spec_from_file_location("_sg", str(HERE / "scope-guard.py"))
            _SG = _dl.module_from_spec(_s); _s.loader.exec_module(_SG)
        _h = _SG.host_of(url)
        _ok, _why = _SG.in_scope(_h, _SG.host_variants(url))
        if not _ok:
            return None, 0, ""
    except Exception:
        pass
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) HUNTR/1.0",
            "Accept": "*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(300000)
            return (getattr(r, "status", 200) or 200), len(body), (r.headers.get("Content-Type") or "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(300000)
        except Exception:
            body = b""
        return e.code, len(body), (e.headers.get("Content-Type") or "") if e.headers else ""
    except Exception:
        return None, 0, ""


def _disc_spec_paths(text):
    """Pull every path (and its params) out of an OpenAPI/Swagger doc, without a YAML dep."""
    import json as _js
    paths = {}
    try:
        doc = _js.loads(text)
    except Exception:
        for m in re.finditer(r'^\s{0,4}(/[\w\-./{}\[\]*]+):', text, re.M):   # YAML-ish fallback
            paths[m.group(1)] = {}
        return paths
    raw = (doc.get("paths") if isinstance(doc, dict) else None) or {}
    if not isinstance(raw, dict):
        return paths
    for p, ops in raw.items():
        params = set()
        try:
            ops = ops if isinstance(ops, dict) else {}
            for method, op in ops.items():
                if not isinstance(op, dict):
                    continue
                for prm in (op.get("parameters") or []):
                    if isinstance(prm, dict) and prm.get("name"):
                        params.add(str(prm["name"]))
                for name in ((op.get("requestBody") or {}).get("content", {}) or {}):
                    params.add(str(name).replace("application/", "").split("+")[0] or "body")
            for comp in ((doc.get("components") or {}).get("schemas") or {}).values():
                if isinstance(comp, dict):
                    params.update(str(k) for k in (comp.get("properties") or {}))
        except Exception:
            pass
        paths[p] = sorted(params)[:8]
    return paths


def phase_discover(deadline=None):
    """ACTIVE surface discovery. katana only follows *linked* HTML, and gau/wayback are skipped for
    single-host/local targets — so unlinked routes (/api/admin/*, /graphql, /swagger.json) are never
    seen and the scanners have nothing to test. Probe a curated high-value path set against in-scope
    live hosts, walk any OpenAPI/Swagger doc found, then BFS-expand directories. Soft-404 is handled
    by comparing each response against a random-path baseline so 'everything returns 200' targets
    don't flood the ledger with phantom endpoints."""
    import time as _t
    from concurrent.futures import ThreadPoolExecutor
    t_start = _t.time()
    # Discovery gets its OWN allocation instead of scraping what's left of the hunt budget. Left-over
    # budgeting backfired: recon burns the slack on a big target, so the seed sweep still ran while the
    # collection-ID pass (the highest-yield one — it finds /collection/{id} routes that no wordlist can)
    # was the first thing dropped. A few hundred cheap GETs are worth more than a stalled tail.
    alloc = 180
    if deadline is not None:
        span = max(0.0, deadline - _t.time())
        alloc = int(max(45.0, min(45.0 + 0.15 * span, 180.0)))
    disc_deadline = _t.time() + alloc

    def out_of_time(reserve=25):
        return _t.time() > disc_deadline - reserve

    live = [h for h in STATE["hosts"] if h.get("status") and h.get("host")]
    if not live:
        return
    bases = []
    for h in live[:4]:
        host, sch = h.get("host"), (h.get("scheme") or "")
        if not sch:
            try:
                sch = probe_host(host)[2] or "https"
            except Exception:
                sch = "https"
        bases.append((sch + "://" + host, host))
    if not bases:
        return
    stage("Discover", 84)
    log("cmd", "$ active discovery · %d curated paths × %d host(s)" % (len(DISCOVER_SEEDS), len(bases)))

    workers = 3 if STEALTH else 10
    existing = {e["url"] for e in STATE["endpoints"]}
    found = {}          # url -> host
    tested = set()
    gated = set((STATE.get("discovery") or {}).get("gated") or [])   # 401/403 routes: real surface, untestable

    def probe(base, host, path):
        u = path if path.startswith("http") else base.rstrip("/") + path
        if u in tested:
            return None
        tested.add(u)
        st, blen, ctype = _disc_probe(u)
        return (u, host, path, st, blen, ctype)

    def sweep(base, host, paths):
        got = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(lambda p: probe(base, host, p), paths):
                if res:
                    got.append(res)
        return got

    base_status = {}
    for base, host in bases:
        # soft-404 baseline: a random path tells us what "not found" looks like on this host
        rnd = "/hunt-%d-x" % int(_t.time() * 1000 % 100000)
        st, blen, _ = _disc_probe(base.rstrip("/") + rnd)
        base_status[base] = (st, blen)
        if out_of_time():
            log("warn", "→ discovery stopped early (budget) after baseline for " + host)
            break
        hits = sweep(base, host, DISCOVER_SEEDS)
        spec_hits = [h for h in hits if re.search(r"(swagger|openapi|api-docs)", h[2], re.I)]
        interesting = []
        for (u, hh, path, st, blen, ctype) in hits:
            if st is None:
                continue
            bst, blen0 = base_status[base]
            soft = (st == bst and abs(blen - blen0) <= 3)
            live_hit = st in (200, 201, 204, 301, 302, 307, 401, 403, 405, 500) and not soft
            if live_hit or (st == 200 and blen != blen0):
                interesting.append((u, hh, path, st, blen, ctype))
        for (u, hh, path, st, blen, ctype) in interesting:
            found[u] = hh
            if st in (401, 403):
                gated.add(u)
        unauth = [h for h in interesting if h[3] in (401, 403)]
        log("ok", "✓ " + host + " · " + str(len(interesting)) + " live path(s) of " +
            str(len(DISCOVER_SEEDS)) + " probed" +
            (" · " + str(len(unauth)) + " auth-gated (401/403)" if unauth else "") +
            (" · " + str(len(spec_hits)) + " spec doc(s)" if spec_hits else ""))

        # walk specs → every documented path, with its params, in one shot
        for (u, hh, path, st, blen, ctype) in spec_hits:
            if st != 200 or blen > 900000:
                continue
            try:
                import urllib.request as _ur
                with _ur.urlopen(_ur.Request(u, headers={"User-Agent": "Mozilla/5.0 HUNTR"}), timeout=10) as r:
                    txt = r.read(900000).decode("utf-8", "ignore")
            except Exception:
                continue
            for sp, sparams in _disc_spec_paths(txt).items():
                concrete = re.sub(r"\{[^}]+\}", "1", sp).rstrip("/") or "/"
                if "?" in concrete or sparams:
                    concrete += "?" + "&".join("%s=1" % p for p in sparams[:4])
                fu = base.rstrip("/") + concrete
                if fu not in tested:
                    found[fu] = hh
            log("ok", "→ spec walk · " + u.split("/")[-1] + " → " + str(len(_disc_spec_paths(txt))) + " path(s)")

    # Collection-ID probe — the highest-yield IDOR shape. A real API rarely exposes /api/orders at all;
    # it exposes /api/orders/1 and /api/orders/2 and nothing links to them. No wordlist finds those,
    # and they are exactly the routes the IDOR/BFLA testers need. Probe <collection>/1 and /2 for any
    # discovered or seeded path whose last segment names a collection, so we catch /api/orders/{id}
    # even when the collection root itself 404s.
    COLLECTIONS = ("users", "user", "accounts", "account", "orders", "order", "items", "item",
                   "products", "product", "invoices", "invoice", "tickets", "ticket", "customers",
                   "customer", "transactions", "transaction", "payments", "payment", "documents",
                   "document", "files", "file", "messages", "message", "sessions", "session",
                   "tokens", "token", "keys", "key", "webhooks", "webhook", "jobs", "job",
                   "reports", "report", "cards", "card", "refunds", "refund", "comments",
                   "comment", "posts", "post", "projects", "project", "orgs", "org", "teams",
                   "team", "roles", "role", "permissions", "permission", "clients", "client",
                   "subscriptions", "subscription", "plans", "plan", "coupons", "coupon",
                   "vouchers", "voucher", "wallets", "wallet", "ledgers", "ledger", "entries")
    COLL_RE = re.compile(r"/(" + "|".join(COLLECTIONS) + r")/?$", re.I)
    if not out_of_time(35):
        stems, seen_stem = [], set()
        # discovered routes first (they are real), then seeded collections as the fallback net
        ordered = list(found) + [b.rstrip("/") + p for b, _ in bases[:1] for p in DISCOVER_SEEDS]
        for u in ordered:
            pu = re.sub(r"[?#].*$", "", u)
            if COLL_RE.search(pu) and not re.search(r"/\d+/?$", pu) and pu not in seen_stem:
                seen_stem.add(pu)
                stems.append(pu)
        for base, host in bases:
            if not stems:
                break
            cand = []
            for st_ in stems[:60]:
                cand += [st_ + "/1", st_ + "/2"]
            extra = 0
            bst, blen0 = base_status.get(base, (404, 0))
            for (u, hh, path, st, blen, ctype) in sweep(base, host, cand):
                if st is None or (st == bst and abs(blen - blen0) <= 3):
                    continue
                if st in (200, 201, 204, 301, 302, 401, 403, 405, 500) and u not in found:
                    found[u] = hh
                    if st in (401, 403):
                        gated.add(u)
                    extra += 1
            if extra:
                log("ok", "→ collection-ID probe · +" + str(extra) +
                    " record route(s) (/collection/{id}) — IDOR/BFLA testable")

    # BFS-expand directories: /api found → probe /api/<common leaf>
    leaves = ["users", "admin", "me", "orders", "accounts", "config", "settings", "search",
              "products", "items", "health", "status", "v1", "v2", "graphql", "docs", "login",
              "tokens", "keys", "upload", "export", "flags", "debug", "internal",
              "users/list", "admin/users", "admin/settings", "admin/config", "admin/roles",
              "admin/permissions", "admin/audit", "admin/logs", "admin/stats"]
    dirs = {u for u in found if re.search(r"/(api|admin|v\d+|[a-z-]+)/?$", u, re.I) and
            not re.search(r"\.(js|css|png|jpg|json|html?)$", u, re.I)}
    if dirs and not out_of_time():
        bfs = []
        for d in list(dirs)[:12]:
            bfs += [d.rstrip("/") + "/" + lf for lf in leaves]
        extra = 0
        for base, host in bases:
            got = sweep(base, host, bfs)
            bst, blen0 = base_status.get(base, (404, 0))
            for (u, hh, path, st, blen, ctype) in got:
                if st is None or (st == bst and abs(blen - blen0) <= 3):
                    continue
                if st in (200, 201, 204, 301, 302, 401, 403, 405, 500) and u not in found:
                    found[u] = hh
                    if st in (401, 403):
                        gated.add(u)
                    extra += 1
        if extra:
            log("ok", "→ BFS expand · +" + str(extra) + " route(s) under " + str(len(dirs)) + " discovered dir(s)")

    # ffuf amplifier — only when a curated probe already proved the host serves real content,
    # so we never hammer a host that is refusing us.
    if has("ffuf") and not out_of_time(40):
        for base, host in bases[:2]:
            bst, blen0 = base_status.get(base, (404, 0))
            if bst is None or bst >= 500:
                continue
            wl = HUNT_DIR / "discover-wordlist.txt"
            wl.write_text("\n".join(sorted({p.lstrip("/") for p in DISCOVER_SEEDS
                                            if not p.endswith("/")})) + "\n")
            rl = 3 if STEALTH else 25
            log("cmd", "$ ffuf -u " + base + "/FUZZ -w discover-wordlist.txt -rate " + str(rl))
            out, _, _ = sh(["ffuf", "-u", base + "/FUZZ", "-w", str(wl), "-rate", str(rl),
                            "-t", "10" if not STEALTH else "4", "-timeout", "8", "-s",
                            "-mc", "200,204,301,302,307,401,403,405,500"], timeout=70)
            n = 0
            for ln in out.splitlines():
                if "::" not in ln or not ln.startswith("http"):
                    continue
                u = ln.split("::")[0].strip()
                if u not in found:
                    found[u] = host
                    n += 1
            if n:
                log("ok", "→ ffuf · +" + str(n) + " path(s)")

    new = [(u, h) for u, h in found.items() if u not in existing]
    # collapse to one representative per (host, path, param-name) shape — same rule phase_surface uses
    import urllib.parse as _upd
    seen_sig = set()
    for e in STATE["endpoints"]:
        try:
            pu = _upd.urlparse(e["url"])
            seen_sig.add((pu.netloc, pu.path, tuple(sorted(k for k, _ in _upd.parse_qsl(pu.query)))))
        except Exception:
            pass
    added = 0
    for u, h in new:
        try:
            pu = _upd.urlparse(u)
            sig = (pu.netloc, pu.path, tuple(sorted(k for k, _ in _upd.parse_qsl(pu.query))))
        except Exception:
            continue
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        STATE["endpoints"].append({"url": u, "host": h})
        added += 1
    STATE["stats"]["endpoints"] = len(STATE["endpoints"])
    STATE["discovery"] = {"gated": sorted(gated)}
    STATE["stats"]["auth_gated"] = len(gated)
    elapsed = int(_t.time() - t_start)
    log("ok", "✓ discovery · +" + str(added) + " endpoint(s) → " + str(len(STATE["endpoints"])) +
        " total surface · " + str(elapsed) + "s")
    for e in STATE["endpoints"][-min(12, added):]:
        log("out", "↳ " + e["url"][:110])
    flush()
    stage("Discover", 90)

def phase_spa_capture():
    """SPA surface discovery: katana only sees linked HTML, so a single-page app's REAL API (the XHR/
    fetch calls its JS fires at runtime, often POST with params) is invisible to the crawler. With a
    session, drive a real browser (browser-capture) to record those calls and fold them into the
    surface — so the scanners and the exploit-agent test the endpoints that actually matter."""
    if not (HERE / "browser-capture.py").exists():
        return
    c = _creds()
    cookie = (c.get("cookie") or "").strip()
    tok = (c.get("session_token") or "").strip()
    if MODE == "black":   # grey/white: capture the SPA's runtime API (auth used if a session is present)
        return
    lithost = re.sub(r'^\*\.', '', TARGET).split('/')[0].strip()
    sch = next((h.get("scheme") for h in STATE["hosts"] if h.get("host") == lithost and h.get("scheme")), None) or "https"
    url = sch + "://" + lithost + "/"
    ua = (c.get("ua") or "").strip()
    stage("SPA-capture", 84)
    log("ok", "◆ SPA capture · driving real browser to record the app's runtime API calls…")
    a = ["--url", url, "--cookie", cookie, "--hosts", apex(TARGET), "--secs", "16"]
    if ua:
        a += ["--ua", ua]
    d = tool_json("browser-capture.py", a, timeout=120)
    calls = (d or {}).get("calls", []) if isinstance(d, dict) else []
    if not calls:
        log("out", "→ SPA capture · no runtime API calls recorded" + ((" (" + str((d or {}).get("error", ""))[:60] + ")") if isinstance(d, dict) and d.get("error") else ""))
        return
    STATE["api_calls"] = calls          # the real endpoints+params, for the exploit-agent
    # fold any GET calls that carry params into the testable endpoint surface
    existing = {e["url"] for e in STATE["endpoints"]}
    added = 0
    for cl in calls:
        u = cl.get("url", "")
        if cl.get("method") == "GET" and re.search(r"[?&][\w\[\]]+=", u) and u not in existing:
            STATE["endpoints"].append({"url": u, "host": apex(TARGET)}); existing.add(u); added += 1
    STATE["stats"]["endpoints"] = len(STATE["endpoints"])
    methods = {}
    for cl in calls:
        methods[cl.get("method", "?")] = methods.get(cl.get("method", "?"), 0) + 1
    log("ok", "✓ SPA capture · " + str(len(calls)) + " runtime API call(s) [" +
        ", ".join(k + ":" + str(v) for k, v in methods.items()) + "] · " + str(added) + " GET added to surface · " +
        str(len(calls) - added) + " POST/other → exploit-agent")
    flush()


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
        args += ["--rate", "20" if STEALTH else "150"]   # stealth: throttle to stay under WAF/rate-limit
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
        # no --model override: hypothesis generation uses the configured engine (Nemotron 3 Ultra)
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
    """Write a real coverage.tsv (surface item × vuln-class cells) from what was actually scanned.

    The ledger only ever grades DISCOVERED endpoints, so a hunt that found 6 easy routes could report
    94% depth while the routes it never discovered were invisible. Report the discovery denominator
    alongside it (auth-gated routes are reachable but untestable without a session) so a high depth
    can no longer hide a thin surface."""
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
    gated = len((STATE.get("discovery") or {}).get("gated") or STATE.get("stats", {}).get("auth_gated") or [])
    lines.append("# surface %d endpoint(s) graded · %d auth-gated(401/403) route(s) discovered but "
                 "untestable without a session · depth here covers DISCOVERED surface only, so a high "
                 "depth is not evidence the whole target was mapped" % (len(eps[:400]), gated))
    (HUNT_DIR / "coverage.tsv").write_text("\n".join(lines) + "\n")


STATEFUL_RE = r"(redeem|coupon|voucher|order|checkout|cart|transfer|claim|vote|invite|apply|withdraw|balance|credit|gift|refund|payout)"
RANK = {"ssti": 0, "sqli": 0, "idor": 1, "ssrf": 1, "authz": 2, "xss": 3, "race": 4, "jwt": 5, "param": 6, "cors": 7, "redirect": 8}


STATIC_EXT = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|"
                        r"mp4|webm|mp3|wav|pdf|zip|gz|tar|wasm|json|xml|txt|md)(\?|$)", re.I)

def applicable_classes(ep):
    low = ep.lower()
    # static assets (JS/CSS/images/fonts/media) have no server-side logic — never injection-test them,
    # even with a cache-busting param like ?dpl=… . This stops the hunt wasting its budget on /_next/static.
    path = re.sub(r"\?.*$", "", low)
    if STATIC_EXT.search(low) or "/_next/static/" in low or "/static/chunks/" in low or "/assets/" in path:
        return []
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


def _lead_fetch(url, method="GET", body=None, headers=None, timeout=10):
    """Scope-gated request for the LLM-led loop. Returns a COMPACT result — status, redirect, title,
    a small text snippet and any error signal — because the model has to re-read every round: a full
    body would blow the context window and actually make the agent dumber, not better informed."""
    import urllib.request, urllib.error
    import json as _js
    if not url.startswith("http"):
        return {"ok": False, "err": "url must be absolute"}
    try:
        global _SG
        try:
            _SG
        except NameError:
            import importlib.util as _dl
            _s = _dl.spec_from_file_location("_sg", str(HERE / "scope-guard.py"))
            _SG = _dl.module_from_spec(_s); _s.loader.exec_module(_SG)
        _h = _SG.host_of(url)
        _ok, _why = _SG.in_scope(_h, _SG.host_variants(url))
        if not _ok:
            return {"ok": False, "scope": "DENY", "err": "OUT OF SCOPE: " + str(_why)}
    except Exception as _e:
        return {"ok": False, "err": "scope-check failed: " + str(_e)[:80]}
    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) HUNTR/1.0", "Accept": "*/*"}
    for k, v in (headers or {}).items():
        if str(k).lower() not in ("host", "content-length"):
            hdrs[str(k)] = str(v)
    data = None
    if body is not None:
        data = (body if isinstance(body, bytes) else str(body).encode("utf-8", "ignore"))
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs,
                                     method=(method or "GET").upper())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(160000)
            st = getattr(r, "status", 200) or 200
            redir = r.geturl() if r.geturl() != url else ""
            ctype = r.headers.get("Content-Type") or ""
            rh = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(160000)
        except Exception:
            raw = b""
        st, redir, ctype = e.code, "", (e.headers.get("Content-Type") or "") if e.headers else ""
        rh = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
    except Exception as e:
        return {"ok": False, "url": url, "method": method, "err": str(e)[:140]}
    txt = raw.decode("utf-8", "ignore") if isinstance(raw, bytes) else str(raw)
    r = {"ok": True, "method": (method or "GET").upper(), "url": url, "status": st, "len": len(raw)}
    if redir:
        r["redirect"] = redir
    if ctype:
        r["ctype"] = ctype.split(";")[0]
    for k in ("location", "server", "x-powered-by", "set-cookie", "access-control-allow-origin",
              "www-authenticate", "content-security-policy"):
        if k in rh:
            r["hdr:" + k] = str(rh[k])[:220]
    m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
    if m:
        r["title"] = m.group(1).strip()[:120]
    if "json" in ctype or txt.lstrip()[:1] in "{[":
        try:
            j = _js.loads(txt)
            r["json_keys"] = (sorted(j.keys())[:24] if isinstance(j, dict)
                              else ("[%d items]" % len(j)))
            r["json_preview"] = _js.dumps(j)[:500]
        except Exception:
            pass
    else:
        snippet = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", txt)
        snippet = re.sub(r"(?s)<[^>]+>", " ", snippet)
        snippet = re.sub(r"\s+", " ", snippet).strip()
        if snippet:
            r["snippet"] = snippet[:520]
    sig = re.search(r"(traceback|exception|stack trace|SQLSTATE|syntax error|ORA-\d|"
                    r"column .* not found|doesn't exist|debug|is not permitted|unauthorized|"
                    r"forbidden|denied|{{\d+}}|<script>alert)", txt, re.I)
    if sig:
        r["signal"] = sig.group(0)[:60]
    return r


def _note_gated(url, status, step=None):
    """A 401/403 is not a finding — it is proof the route exists behind auth.

    Record it so the session/coverage layers (and the operator) know there is something
    worth a token here, instead of the probe evaporating into the log."""
    if status not in (401, 403) or not url:
        return False
    d = STATE.setdefault("discovery", {})
    gated = d.setdefault("gated", [])
    if url in gated:
        return False
    gated.append(url)
    d["gated"] = sorted(set(gated))
    STATE.setdefault("stats", {})["auth_gated"] = len(d["gated"])
    STATE.setdefault("leads", [])
    if not any(l.get("endpoint") == url for l in STATE["leads"]):
        STATE["leads"].append({
            "lead": ("route exists behind auth (" + str(status) + ") — reachable but untestable "
                     "without a session; supply a token/cookie or run an authenticated pass"),
            "endpoint": url, "step": step, "source": "probe"})
        STATE["leads"] = STATE["leads"][-60:]
    return True


_SKILL_CAT = None


def _skill_catalog():
    """Index every local Claude skill once per process: frontmatter description, report_count and
    section map. Whole file is held so section extraction is pure string work — 135 skills, one read.

    Covers ALL skills, not just hunt-*: chain-builder / bb-local-toolkit / report-writing /
    never-submit carry judgement the loop is otherwise blind to."""
    global _SKILL_CAT
    if _SKILL_CAT is not None:
        return _SKILL_CAT
    root = Path.home() / ".claude" / "skills"
    cat = []
    if root.is_dir():
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            f = d / "SKILL.md"
            if not f.exists():
                cand = sorted(x for x in d.glob("*.md") if x.name != "README.md")
                if not cand:
                    continue
                f = cand[0]
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            if not text.strip():
                continue
            fm = ""
            m = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
            if m:
                fm = m.group(1)
            desc = ""
            dm = re.search(r"^description:\s*(.+)$", fm or text[:1500], re.M)
            if dm:
                desc = " ".join(dm.group(1).split())
            rc = 0
            rm = re.search(r"report_count:\s*(\d+)", fm)
            if rm:
                rc = int(rm.group(1))
            secs = [(mm.group(1).strip(), mm.start())
                    for mm in re.finditer(r"^#{2,3}\s+(.+)$", text, re.M)]
            cat.append({"name": d.name, "desc": desc[:420], "rc": rc, "secs": secs, "text": text})
    _SKILL_CAT = cat
    return cat


def _skill_pick(state, topn=3, budget=460):
    """Retrieve the skill sections most relevant to what this round is actually looking at.

    Relevance = overlap with the live attack surface (untested classes, endpoint paths, gated
    routes, finding classes, stack) + a report_count prior — not a hardcoded skill list."""
    cat = _skill_catalog()
    if not cat:
        return []
    tok = set()
    for g in (state.get("untested_cells") or []):
        tok.update(re.findall(r"[a-z]{4,}", str(g.get("ep", "")).lower()))
        tok.update(re.findall(r"[a-z]{4,}", str(g.get("untested", "")).lower()))
    for f in (state.get("findings") or []):
        tok.update(re.findall(r"[a-z]{4,}", str(f.get("cls", "")).lower()))
    for u in (state.get("endpoints") or []):
        tok.update(re.findall(r"[a-z]{4,}", str(u).lower()))
    for g in (state.get("discovered_gated_routes") or []):
        tok.update(re.findall(r"[a-z]{4,}", str(g).lower()))
    tok.update(re.findall(r"[a-z]{4,}", (state.get("target") or "").lower()))
    if not tok:
        return []
    scored = []
    for s_ in cat:
        name = s_["name"].lower()
        hay = name + " " + s_["desc"].lower()
        sc = sum(1 for t in tok if t in hay)
        for cls in ("idor", "sqli", "xss", "ssrf", "ssti", "cors", "authz", "redirect",
                    "race", "oauth", "jwt", "csrf", "lfi", "xxe", "upload", "ssrf"):
            if cls in tok and cls in name:
                sc += 3
        sc += min(s_["rc"], 40) / 20.0
        if sc > 0:
            scored.append((sc, s_))
    scored.sort(key=lambda x: -x[0])
    out = []
    for sc, s_ in scored[:topn]:
        # deepest matching section: prefer a heading that names what we are looking at
        best = None; best_n = -1
        for i, (h, _off) in enumerate(s_["secs"]):
            hl = h.lower()
            n = sum(1 for t in tok if t in hl)
            # prefer the actionable sections (methodology / step / test) over overview or
            # FEEDER / "what unlocks next" — the loop needs the how, not the why
            if any(k in hl for k in ("methodolog", "step-by-step", "step ", "testing",
                                     "test ", "exploit", "technique", "how to", "checklist")):
                n += 1.5
            if any(k in hl for k in ("feeder", "unlocks", "crown jewel", "what ", "reference")):
                n -= 1.5
            if n > best_n:
                best_n, best = n, i
        if best is None:
            body = " ".join(s_["text"].split())[:budget]
            heading = ""
        else:
            h, off = s_["secs"][best]
            nxt = s_["secs"][best + 1][1] if best + 1 < len(s_["secs"]) else len(s_["text"])
            body = " ".join(s_["text"][off:nxt].split())[:budget]
            heading = h
        out.append({"skill": s_["name"], "heading": heading, "gist": body})
    return out


def _graphify_surface_digest():
    """Query the target's graphify knowledge graph (if built) and return a compact,
    high-signal surface summary. Returns None when no graph exists — caller falls back
    to the flat digest.

    The graph is built by phase_discover / phase_surface writing raw recon into
    <HUNT_DIR>/recon/ and then calling `graphify` on it. When present it gives us:
      - the 8 highest-betweenness endpoints (most connected → widest attack surface)
      - untested cells ranked by graph centrality instead of raw order
      - cross-endpoint relationships the flat list can't express
    """
    graph_json = HUNT_DIR / "graphify-out" / "graph.json"
    if not graph_json.exists():
        return None
    try:
        import json as _json
        g = _json.loads(graph_json.read_text())
        nodes = g.get("nodes", [])
        # score by degree — proxy for betweenness when we don't want to recompute it
        ep_nodes = [n for n in nodes if n.get("type") == "endpoint" or
                    (n.get("source_location", "").startswith("http"))]
        ep_nodes.sort(key=lambda n: n.get("degree", 0), reverse=True)
        top_eps = [{"url": n.get("id", ""), "degree": n.get("degree", 0),
                    "community": n.get("community_name", n.get("community", ""))}
                   for n in ep_nodes[:12]]
        # surface edges that cross community boundaries — these are the attack paths
        cross_edges = [e for e in g.get("edges", [])
                       if e.get("source_community") != e.get("target_community")][:8]
        return {"graph_endpoints": top_eps, "cross_community_edges": cross_edges,
                "total_graph_nodes": len(nodes)}
    except Exception:
        return None


def _lead_digest(max_eps=34, max_res=14):
    """Compact view of hunt state for the LLM — enough to decide the next move, small enough to
    repeat every round without exhausting the context.

    When a graphify surface graph exists for this target, the endpoint list is replaced with a
    graph-ranked view (highest-betweenness endpoints first, cross-community edges highlighted).
    This cuts context by ~60% on large surfaces while surfacing the most attack-relevant paths."""
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    eps = [e["url"] for e in STATE["endpoints"][:max_eps]]
    tested = sum(len(v) for v in TESTED.values())
    gaps = []
    for ep in STATE["endpoints"]:
        gaps.append({"ep": ep["url"], "untested": sorted(set(applicable_classes(ep["url"])) - TESTED.get(ep["url"], set()))})
        if len(gaps) >= 16:
            break
    res = list(STATE.get("lead_results", []))[-max_res:]

    # Try to enrich with the graphify surface graph — replaces raw endpoint list if available
    graph_ctx = _graphify_surface_digest()
    if graph_ctx:
        # Reorder gaps to prioritise high-degree graph endpoints
        top_urls = {e["url"] for e in graph_ctx.get("graph_endpoints", [])}
        gaps_top = [g for g in gaps if g["ep"] in top_urls]
        gaps_rest = [g for g in gaps if g["ep"] not in top_urls]
        gaps = (gaps_top + gaps_rest)[:16]
        eps_out = [e["url"] for e in graph_ctx["graph_endpoints"]]
    else:
        eps_out = eps

    digest = {
        "target": TARGET, "mode": MODE,
        "session": bool(tok) if MODE != "black" else None,
        "endpoints": eps_out,
        "endpoint_count": len(STATE["endpoints"]),
        "tested_cells": tested,
        "findings": [{"sev": f.get("sev"), "title": f.get("title"), "cls": f.get("cls"),
                      "endpoint": f.get("endpoint"), "verdict": f.get("verdict"),
                      "_det": f.get("_det", False)}
                     for f in STATE["findings"][:16]],
        "leads": (STATE.get("leads") or [])[-8:],
        "untested_cells": gaps,
        "recent_results": res,
        "discovered_gated_routes": (STATE.get("discovery") or {}).get("gated", [])[:12],
        "past_situations": STATE.get("memory_recall", [])[:5],
        "playbook": _skill_pick({"untested_cells": gaps, "findings": STATE["findings"][:8],
                                 "endpoints": eps_out, "discovered_gated_routes":
                                     (STATE.get("discovery") or {}).get("gated", [])[:8],
                                 "target": TARGET}),
    }
    if graph_ctx:
        digest["graph_surface"] = graph_ctx   # extra signal: cross-community edges
    return digest


def phase_memory_recall():
    """Long-term memory — recall analogous situations from every past hunt BEFORE the LLM leads.

    The corpus/invariants tell the loop what to ASSERT; memory tells it 'this exact response shape
    paid $8k on target Y, here is the technique that worked'. Retrieval is local (character n-gram
    + token cosine weighted by reward) — no cloud, no keys. This is the one piece of the knowledge
    layer that was never wired into the production path (only hunt-agent/hunt-swarm called it)."""
    mem = HERE / "hunt-memory.py"
    if not mem.exists() or not STATE["endpoints"]:
        return
    paths = []
    for e in STATE["endpoints"][:40]:
        paths.append(_upd_path(str(e)))
    gated = (STATE.get("discovery") or {}).get("gated", [])[:10]
    q = " ".join([x for x in ([PROGRAM, TARGET] + paths + gated) if x])
    q = q[:900]
    if len(q) < 24:
        return
    try:
        out, err, rc = sh([sys.executable, str(mem), "--recall", "--text", q,
                           "--stack", (_stack().split(",")[0] or "generic"), "--k", "5"], timeout=45)
    except Exception:
        return
    if rc != 0 or not out.strip():
        log("out", "→ memory recall · " + (err.strip() or "no analogous past situation")[:120])
        return
    hits = []
    # recall prints "  [cos] kind/cls · program" then the situation on the next indented line
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*\[([0-9.]+)\]\s+(\S+?)\s*·\s*(\S+)", ln)
        if not m:
            continue
        txt = ""
        if i + 1 < len(lines):
            txt = lines[i + 1].strip()
        # recall prints "<kind>/<cls> · <program>" — split them, don't mislabel program as cls
        w = m.group(2).split("/", 1)
        hits.append({"cos": float(m.group(1)), "kind": w[0], "cls": w[-1],
                     "program": m.group(3), "text": txt[:260]})
    hits.sort(key=lambda h: -h.get("cos", 0))
    STATE["memory_recall"] = hits[:5]
    if hits:
        log("ok", "◆ memory · " + str(len(hits[:5])) + " analogous past situation(s) recalled — " +
            str(hits[0]["kind"]) + "/" + str(hits[0]["cls"]) + " · " + str(hits[0].get("program", "")) +
            " @cos " + str(hits[0]["cos"]))
        for h in hits[:3]:
            log("out", "   ⤷ [" + str(h["cos"]) + "] " + str(h["cls"]) + " · " + str(h["text"])[:120])
    else:
        log("out", "→ memory recall · no analogous past situation — this looks new")
    flush()


def _start_background_scanners():
    """Improvement #4 — fire nuclei + subfinder in background threads before the agent loop.

    Results land in HUNT_DIR/nuclei_bg.txt and HUNT_DIR/subs_bg.txt.
    Claude can read them any time with bash("cat ~/.huntr/targets/.../nuclei_bg.txt").
    This means heavy scanners run in parallel with Claude's reasoning — not after."""
    domain = apex(TARGET)

    def _nuclei():
        if not has("nuclei"):
            return
        out_f = str(HUNT_DIR / "nuclei_bg.txt")
        hosts = [e["url"] for e in STATE.get("endpoints", [])[:20]] or ["https://" + domain]
        input_f = str(HUNT_DIR / "nuclei_targets.txt")
        Path(input_f).write_text("\n".join(hosts) + "\n")
        sh(["nuclei", "-l", input_f, "-severity", "critical,high,medium",
            "-silent", "-timeout", "8", "-o", out_f], timeout=300)

    def _subfinder():
        if not has("subfinder"):
            return
        sh(["subfinder", "-d", domain, "-silent",
            "-o", str(HUNT_DIR / "subs_bg.txt")], timeout=120)

    def _gau():
        if not has("gau"):
            return
        out, _, _ = sh(["gau", "--subs", domain], timeout=90)
        if out:
            (HUNT_DIR / "gau_bg.txt").write_text(out)

    for fn in (_nuclei, _subfinder, _gau):
        threading.Thread(target=fn, daemon=True).start()
    log("ok", "◉ background: nuclei + subfinder + gau started (results in HUNT_DIR/)")


def _query_hunt_corpus():
    """Improvement #3 — pull past technique wins for this tech stack from hunt-corpus.

    Returns a compact string Claude gets in its initial context:
    'On Next.js+Supabase targets: found anon key in JS chunks, enumerated tables via
    error oracle, admin edge function returned 405 on GET → test POST.'
    Returns '' when corpus tool unavailable or no relevant history."""
    cor = HERE / "hunt-corpus.py"
    if not cor.exists():
        return ""
    stack = _stack()
    host = "https://" + apex(TARGET)
    try:
        out, _, rc = sh(
            [sys.executable, str(cor), "--recall", "--stack", stack,
             "--host", host, "--limit", "8", "--json"],
            timeout=30,
        )
        if not out:
            return ""
        data = json.loads(out.strip().splitlines()[-1])
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            return ""
        lines = []
        for it in items[:8]:
            tech = it.get("technique") or it.get("title") or ""
            paid = it.get("paid") or it.get("bounty") or ""
            ep   = it.get("endpoint") or it.get("url") or ""
            if tech:
                lines.append(f"- {tech}" + (f" [{ep}]" if ep else "") + (f" → {paid}" if paid else ""))
        return "\n".join(lines)
    except Exception:
        return ""


def _auto_chain_trigger():
    """Improvement #5 — after a new finding is recorded, auto-run chain-builder.

    Fires in a daemon thread so it doesn't block the agent loop.
    Results are appended to STATE['leads'] so the agent sees them in the next round."""
    cb = HERE / "chain-builder.py"
    if not cb.exists() or len(STATE["findings"]) < 2:
        return
    def _run():
        try:
            f_arg = json.dumps(STATE["findings"][-10:])
            tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            tmp.write(f_arg); tmp.close()
            out, _, rc = sh(
                [sys.executable, str(cb), "--findings", tmp.name, "--json"],
                timeout=60,
            )
            try: os.unlink(tmp.name)
            except Exception: pass
            if not out:
                return
            for line in out.strip().splitlines():
                if not line.startswith("{"):
                    continue
                ch = json.loads(line)
                chain_desc = ch.get("chain") or ch.get("title") or ""
                if chain_desc:
                    with _STATE_LOCK:
                        STATE.setdefault("leads", []).append({
                            "lead": "AUTO-CHAIN: " + chain_desc[:300],
                            "endpoint": ch.get("endpoint", ""),
                            "source": "chain-builder",
                        })
                        STATE["leads"] = STATE["leads"][-60:]
                    log("ok", "⛓ auto-chain: " + chain_desc[:120])
        except Exception:
            pass
    threading.Thread(target=_run, daemon=True).start()


def _save_conversation_checkpoint(messages):
    """Improvement #7 — persist the tool-use conversation to disk.

    Saved to HUNT_DIR/lead_conversation.json on every tool round.
    On resume, prior leads and lead_log are already in STATE (loaded from run.json),
    and the agent's initial digest includes them — so context carries over even after
    the process is killed and restarted."""
    try:
        ckpt = HUNT_DIR / "lead_conversation.json"
        # keep only last 40 messages to avoid huge files
        trimmed = messages[-40:] if len(messages) > 40 else messages
        ckpt.write_text(json.dumps(trimmed, default=str, ensure_ascii=False))
    except Exception:
        pass


def _graphify_clusters(n=2):
    """Improvement #2 — split endpoints into n clusters using graphify communities.

    Returns list of endpoint-URL lists, one per cluster. Falls back to
    round-robin split when no graph is available."""
    graph_json = HUNT_DIR / "graphify-out" / "graph.json"
    eps = [e["url"] for e in STATE.get("endpoints", [])]
    if not eps:
        return [eps]
    if not graph_json.exists():
        # round-robin fallback
        clusters = [[] for _ in range(n)]
        for i, u in enumerate(eps):
            clusters[i % n].append(u)
        return [c for c in clusters if c]
    try:
        g = json.loads(graph_json.read_text())
        nodes = {nd["id"]: nd for nd in g.get("nodes", [])}
        # group nodes by community
        from collections import defaultdict
        by_comm = defaultdict(list)
        for nd in g.get("nodes", []):
            comm = nd.get("community", 0)
            url  = nd.get("label", "") or nd.get("id", "")
            if url.startswith("http") and url in eps:
                by_comm[comm].append(url)
        # merge small communities into n buckets by size
        sorted_comms = sorted(by_comm.values(), key=len, reverse=True)
        clusters = [[] for _ in range(n)]
        for i, comm_eps in enumerate(sorted_comms):
            clusters[i % n].extend(comm_eps)
        # anything not in graph: append to smallest cluster
        covered = set(u for c in clusters for u in c)
        leftovers = [u for u in eps if u not in covered]
        for i, u in enumerate(leftovers):
            clusters[i % n].append(u)
        return [c for c in clusters if c]
    except Exception:
        clusters = [[] for _ in range(n)]
        for i, u in enumerate(eps):
            clusters[i % n].append(u)
        return [c for c in clusters if c]


def _hunt_tools(authed):
    """Tool definitions for the agentic lead loop. Claude gets a real shell + HTTP + scanner."""
    return [
        {
            "name": "bash",
            "description": (
                "Run any shell command and get stdout+stderr. Use this for everything: "
                "curl, python3, subfinder, httpx, katana, waybackurls, gau, nuclei, nmap, "
                "grep, awk, jq, dnsx, ffuf, sqlmap, dalfox. "
                "The scope guard is your responsibility — do not probe hosts outside the scope list. "
                "Truncated at 12KB. Use pipes and head/tail to control output size."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "timeout":  {"type": "integer", "description": "Timeout seconds (default 45, max 180)"}
                },
                "required": ["command"]
            }
        },
        {
            "name": "http_request",
            "description": (
                "Make one HTTP request to the target (scope-guarded). "
                "Returns status, headers, and body excerpt. "
                "Use bash+curl for multi-request loops or custom payloads instead."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url":     {"type": "string"},
                    "method":  {"type": "string", "enum": ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"], "default": "GET"},
                    "headers": {"type": "object", "description": "Extra request headers"},
                    "body":    {"type": "string", "description": "Request body (POST/PUT/PATCH)"}
                },
                "required": ["url"]
            }
        },
        {
            "name": "scan_endpoint",
            "description": (
                "Run a deterministic scanner (nuclei / sqlmap / dalfox / custom) against one endpoint "
                "for a specific vulnerability class. Returns tool-grade findings with proof. "
                "Use AFTER you have a hypothesis — scanner evidence upgrades a lead to a confirmed finding."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "cls": {
                        "type": "string",
                        "description": "sqli|xss|ssti|ssrf|cors|redirect|idor|authz|param|race|lfi|rce"
                    },
                    "extra_args": {"type": "string", "description": "Extra flags passed verbatim to the scanner"}
                },
                "required": ["url", "cls"]
            }
        },
        {
            "name": "record_finding",
            "description": (
                "Record a confirmed vulnerability. Call ONLY when you have OBSERVED evidence "
                "(response body, status code, reflected payload, tool output). "
                "Do NOT call this to log a hypothesis — use bash/http_request to confirm first. "
                "401/403 alone is NOT a finding."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "title":        {"type": "string"},
                    "severity":     {"type": "string", "enum": ["critical","high","medium","low","info"]},
                    "cls":          {"type": "string", "description": "sqli|xss|idor|ssrf|rce|ato|cors|ssti|lfi|redirect|logic|info"},
                    "url":          {"type": "string"},
                    "evidence":     {"type": "string", "description": "Exact observed evidence: status, body excerpt, payload, tool output"},
                    "reproduction": {"type": "string", "description": "Step-by-step reproduction (numbered)"},
                    "cvss":         {"type": "string", "description": "CVSS score if known"}
                },
                "required": ["title","severity","cls","url","evidence","reproduction"]
            }
        },
        {
            "name": "done",
            "description": "Signal that the hunt is complete for this surface. Call when you have exhausted meaningful attack surface or found everything worth reporting.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "What you found and why you're stopping"}
                },
                "required": ["summary"]
            }
        }
    ]


def _make_tool_executor(tok, tok2, authed, step_counter):
    """Return a closure that executes hunt tool calls and updates STATE."""

    def executor(name, inp):
        step = step_counter[0]
        step_counter[0] += 1

        if name == "bash":
            cmd = str(inp.get("command", "")).strip()
            if not cmd:
                return "ERROR: empty command"
            timeout = min(int(inp.get("timeout", 45)), 180)
            log("cmd", "$ " + cmd[:120])
            out, err, rc = sh(["bash", "-c", cmd], timeout=timeout)
            combined = (out + err).strip()
            # improvement #6: large outputs summarized by Haiku before Sonnet sees them
            if len(combined) > 3500:
                combined = llm_client.summarize_if_large(combined, threshold=3500, label="bash:" + cmd[:40])
            flush()
            return combined or f"(exit {rc}, no output)"

        elif name == "http_request":
            url = str(inp.get("url", "")).strip()
            if not url:
                return '{"error":"missing url"}'
            res = _lead_fetch(url, method=str(inp.get("method","GET")),
                              body=inp.get("body"), headers=inp.get("headers") or {})
            # register newly discovered endpoints (lock for multi-agent safety)
            if res.get("ok") and res.get("status") not in (404, None):
                u = res.get("url") or url
                with _STATE_LOCK:
                    if u and not any(u == e["url"] for e in STATE["endpoints"]):
                        from urllib.parse import urlparse as _up
                        STATE["endpoints"].append({"url": u, "host": _up(u).netloc})
                        STATE["stats"]["endpoints"] = len(STATE["endpoints"])
                _note_gated(u, res.get("status"), step)
            log("cmd", "$ " + inp.get("method","GET").upper() + " " + url[:90] +
                " → " + str(res.get("status") or res.get("err",""))[:60])
            flush()
            return json.dumps(res, default=str)[:8000]

        elif name == "scan_endpoint":
            url = str(inp.get("url","")).strip()
            cls = str(inp.get("cls","")).lower().strip()
            if not url or not cls:
                return '{"error":"need url and cls"}'
            if cls in ("idor","authz") and not authed:
                return '{"error":"idor/authz need an authenticated session — supply a token/cookie"}'
            log("cmd", "$ scan_cell [" + cls + "] " + url[:90])
            before = len(STATE["findings"])
            try:
                scan_cell(url, cls, tok, tok2)
            except Exception as _e:
                return json.dumps({"error": str(_e)[:200]})
            newf = STATE["findings"][before:]
            flush()
            return json.dumps({
                "ok": True, "scanned": url, "cls": cls,
                "new_findings": [{"title": f.get("title"), "sev": f.get("sev"),
                                  "cls": f.get("cls"), "verdict": f.get("verdict")} for f in newf]
            })

        elif name == "record_finding":
            title = str(inp.get("title","")).strip()
            evidence = str(inp.get("evidence","")).strip()
            url = str(inp.get("url","")).strip()
            if not title or not evidence or not url:
                return '{"error":"title, evidence, and url are required"}'
            if len(evidence) < 20:
                return '{"error":"evidence too thin — describe exactly what you observed"}'
            sev_map = {"critical":"c","high":"h","medium":"m","low":"l","info":"i"}
            sev = sev_map.get(str(inp.get("severity","medium")).lower(), "m")
            with _STATE_LOCK:
                add_finding(sev, title, evidence, url,
                            cvss=str(inp.get("cvss","")),
                            cls=str(inp.get("cls","")),
                            verdict="agent", det=False)
                for f in STATE["findings"]:
                    if f.get("title") == title and not f.get("steps"):
                        f["steps"] = str(inp.get("reproduction",""))[:1000]
            log("ok", "★ finding recorded: [" + sev.upper() + "] " + title[:100])
            flush()
            # improvement #5: auto-trigger chain-builder in background
            _auto_chain_trigger()
            return json.dumps({"ok": True, "recorded": title,
                               "note": "chain-builder running in background; check leads for chain opportunities"})

        elif name == "done":
            summary = str(inp.get("summary","")).strip()
            log("ok", "✓ agent done: " + summary[:200])
            STATE.setdefault("lead_results",[]).append({"action":"done","summary":summary[:400]})
            flush()
            return "__DONE__"

        return json.dumps({"error": f"unknown tool: {name}"})

    return executor


def phase_llm_lead(deadline, share=0.70, max_steps=120):
    """THE AGENT LOOP — Claude leads the hunt with REAL tool access.

    Architecture: multi-turn Anthropic tool-use conversation (same as Claude Code).
    Claude gets bash, http_request, scan_endpoint, record_finding, done.
    Every tool call executes synchronously and feeds raw output back into the next
    message — no JSON-action dispatch layer, no subprocess boundary, no pre-digested
    snapshots. Claude reads JS, follows redirects, enumerates Supabase tables, chains
    from recon to exploitation, all in one continuous reasoning thread.

    Falls back to legacy JSON-action loop if OAuth/API key unavailable (NVIDIA path)."""
    if not STATE["endpoints"]:
        log("warn", "→ LLM-led loop skipped: no mapped surface")
        return
    if deadline is None:
        return

    span = max(0.0, deadline - time.time())
    lead_budget = max(30.0, min(span * share, span - 30))
    lead_deadline = time.time() + lead_budget

    c = _creds()
    tok  = (c.get("session_token") or "").strip()
    tok2 = (c.get("token2") or "").strip()
    authed = (MODE != "black") and bool(tok)

    STATE.setdefault("lead_results", [])
    STATE.setdefault("leads", [])
    stage("LLM-led", 86)

    # improvement #4: start background scanners immediately
    _start_background_scanners()

    _use_tool_loop = (MODEL_LEAD.get("provider") == "anthropic")

    if not _use_tool_loop:
        _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps)
    else:
        n_eps = len(STATE.get("endpoints", []))
        # improvement #2: dual-agent for larger surfaces (≥8 endpoints)
        if n_eps >= 8:
            clusters = _graphify_clusters(n=2)
            if len(clusters) >= 2:
                steps_each = max(40, max_steps // 2)
                log("ok", f"◆ dual-agent mode · {len(clusters[0])} + {len(clusters[1])} endpoints")
                # stagger start by 12s to avoid concurrent OAuth rate-limit burst
                def _run_deep():
                    time.sleep(12)
                    _phase_llm_lead_tool_use(
                        lead_deadline, tok, tok2, authed, steps_each,
                        surface_filter=set(clusters[1]), agent_label="DEEP")
                t = threading.Thread(target=_run_deep, daemon=True)
                t.start()
                _phase_llm_lead_tool_use(
                    lead_deadline, tok, tok2, authed, steps_each,
                    surface_filter=set(clusters[0]), agent_label="BROAD")
                t.join(timeout=max(0, lead_deadline - time.time()))
            else:
                _phase_llm_lead_tool_use(lead_deadline, tok, tok2, authed, max_steps)
        else:
            _phase_llm_lead_tool_use(lead_deadline, tok, tok2, authed, max_steps)

    log("ok", "✓ LLM-led · " + str(len(STATE.get("lead_log",[]))) + " action(s) · " +
        str(len(STATE["findings"])) + " finding(s) so far")
    flush()
    stage("LLM-led", 94)


def _phase_llm_lead_tool_use(lead_deadline, tok, tok2, authed, max_steps,
                              surface_filter=None, agent_label=""):
    """Real tool-use agentic loop — Claude has bash, http, scanner, finding tools.

    surface_filter: optional URL list this agent owns (improvement #2 multi-agent mode).
    agent_label: short label e.g. 'BROAD' or 'DEEP' for logging."""
    label = f"[{agent_label}] " if agent_label else ""
    log("ok", f"◆ {label}tool-use agent · bash + HTTP + scanner + corpus memory")

    # improvement #3: seed corpus memory before the loop
    corpus_context = _query_hunt_corpus()

    # improvement #7: inject prior leads from previous sessions
    prior_leads = STATE.get("leads", [])[-20:]
    prior_lead_text = ""
    if prior_leads:
        prior_lead_text = "\n\n## Leads from Prior Session\n" + "\n".join(
            f"- {l.get('lead','')} [{l.get('endpoint','')}]" for l in prior_leads
        )

    digest = _lead_digest()
    if surface_filter:
        digest["endpoints"] = [e for e in digest.get("endpoints", [])
                               if e.get("url") in surface_filter]
        digest["untested_cells"] = [c for c in digest.get("untested_cells", [])
                                    if c.get("ep") in surface_filter]

    scope_summary = ", ".join(sorted(set(
        e.get("host", "") for e in STATE["endpoints"]
    )))[:400]
    creds_hint = (
        "\nAuthenticated: YES (session token available). Use it in Authorization/Cookie headers."
        if tok else
        "\nAuthenticated: NO — black-box mode. Focus on unauthenticated surface."
    )
    surface_note = (
        f"\nYour surface slice: {len(surface_filter)} endpoints (multi-agent mode — stay on your slice)."
        if surface_filter else ""
    )

    sys_p = (
        f"You are an elite bug bounty hunter. Target: {TARGET}\n"
        f"In-scope hosts: {scope_summary}{creds_hint}{surface_note}\n\n"
        "You have a real shell via bash. Use it like a terminal:\n"
        "  curl, python3, subfinder, httpx, katana, nuclei, sqlmap, dalfox, ffuf, jq, gau, waybackurls\n"
        "  Read JS chunks for API keys, Supabase URLs, payment flows, admin routes\n"
        "  Enumerate tables via Supabase error oracle; test JWTs (alg:none, weak secret)\n"
        f"  Background scanners already running — check: bash('cat {HUNT_DIR}/nuclei_bg.txt')\n\n"
        "METHODOLOGY:\n"
        "1. JS analysis first — grep _next/static/chunks for keys, fetch() calls, auth patterns\n"
        "2. Enumerate: subdomains, hidden routes, edge functions, GraphQL introspection\n"
        "3. Attack: hypothesis → bash/http_request → verify → scan_endpoint → record_finding\n"
        "4. Chain: CORS+XSS=ATO, IDOR+info=data breach, open-redirect+OAuth=token hijack\n"
        "5. record_finding ONLY with OBSERVED evidence (response body, tool output, scanner proof)\n\n"
        "Skill playbook and past wins on similar targets are below — apply matching technique FIRST."
    )

    skill_data = _skill_pick({
        "untested_cells": digest.get("untested_cells", []),
        "findings": STATE["findings"][:8],
        "endpoints": [e["url"] for e in STATE["endpoints"][:20]],
        "target": TARGET,
    })
    playbook_text = ""
    if skill_data:
        playbook_text = "\n\n## Skill Playbook\n" + "\n---\n".join(
            f"### {s['skill']} — {s['heading']}\n{s['gist']}" for s in skill_data
        )
    corpus_text = ("\n\n## Past Wins on Similar Targets\n" + corpus_context) if corpus_context else ""

    initial_user = (
        "## Hunt State\n" +
        json.dumps(digest, default=str, indent=2)[:5000] +
        corpus_text +
        playbook_text +
        prior_lead_text +
        "\n\nBegin the hunt. Map surface → identify targets → attack → record findings."
    )

    step_counter = [0]
    messages_snapshot = [[]]

    executor = _make_tool_executor(tok, tok2, authed, step_counter)

    def on_tool_call(name, inp, result):
        step = step_counter[0]
        with _STATE_LOCK:
            STATE["stage"] = f"{label}agent·{name}·{step}"
            STATE["pct"] = min(93, 86 + int(step / max(1, max_steps) * 7))
            STATE.setdefault("lead_log", []).append({
                "step": step, "act": name,
                "ok": not str(result).startswith("ERROR") and not str(result).startswith('{"error"'),
                "detail": str(result)[:100],
                "agent": agent_label or "main",
            })
            STATE["lead_log"] = STATE["lead_log"][-120:]
        # improvement #7: checkpoint conversation every 10 tool calls
        if step % 10 == 0:
            _save_conversation_checkpoint(messages_snapshot[0])
        if time.time() > lead_deadline:
            raise TimeoutError("lead budget exceeded")

    tools = _hunt_tools(authed)

    try:
        final_text, tool_log, err = llm_client.call_llm_with_tools(
            system=sys_p,
            initial_user=initial_user,
            tools=tools,
            tool_executor=executor,
            model=MODEL_LEAD.get("model", "claude-sonnet-4-6"),
            max_tokens=4096,
            timeout=120,
            on_tool_call=on_tool_call,
            max_tool_rounds=max_steps,
        )
    except TimeoutError:
        log("warn", f"⏱ {label}tool-use agent budget reached")
        return
    except Exception as _e:
        log("warn", f"→ {label}tool-use agent error: " + str(_e)[:200])
        return

    if err and not tool_log:
        log("warn", f"→ {label}tool-use agent failed: " + str(err)[:200] +
            " — falling back to JSON-action loop")
        if not agent_label:  # only fallback on the main agent, not sub-agents
            _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps)
        return

    if err:
        log("warn", f"→ {label}agent ended: " + str(err)[:120])

    with _STATE_LOCK:
        STATE["lead_results"].append({
            "action": "tool_loop_complete",
            "agent": agent_label or "main",
            "tool_calls": len(tool_log),
            "findings_added": sum(1 for t in tool_log if t["name"] == "record_finding"),
        })


def _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps):
    """Legacy JSON-action dispatch loop — used for NVIDIA/non-Anthropic providers."""
    log("ok", "◆ LLM-led loop (JSON mode) · max " + str(max_steps) + " steps")
    tried = set()
    for _r in STATE.get("lead_results", []):
        if isinstance(_r.get("k"), list):
            tried.add(tuple(_r["k"]))
    stale = 0
    transport = 0

    sys_p = (
        "You are the LEAD BUG BOUNTER on target " + str(TARGET) + ". Reply STRICT JSON only.\n"
        'Actions: {"action":"probe","path":"/path"} | '
        '{"action":"request","method":"GET","url":"…","headers":{},"body":"…"} | '
        '{"action":"test","endpoint":"…","class":"sqli|xss|ssti|ssrf|cors|redirect|idor|authz"} | '
        '{"action":"remember","lead":"…","endpoint":"…"} | '
        '{"action":"finding","severity":"c|h|m|l","title":"…","cls":"…","endpoint":"…","detail":"…","steps":"…"} | '
        '{"action":"done","summary":"…"}\n'
        "Only report findings you OBSERVED. 401/403 is a lead, not a vuln."
    )

    for step in range(max_steps):
        if time.time() > lead_deadline:
            log("warn", "⏱ LLM-led loop budget reached at step " + str(step))
            break
        check_pause()
        STATE["stage"] = "LLM-led " + str(step + 1)
        STATE["pct"] = min(94, 86 + int(step / max(1, max_steps) * 8))
        flush()
        state = _lead_digest()
        usr = json.dumps(state, default=str)
        plan = llm_json(sys_p, usr, max_tokens=1500, timeout=90, _model=MODEL_LEAD)
        if plan is None:
            transport += 1
            log("warn", "→ LLM-led round " + str(step) + " no reply [" +
                str(_LLM_LAST_ERR.get("e"))[:120] + "] — " + str(transport) + "/6")
            if transport >= 6:
                break
            time.sleep(min(30, 5 * transport))
            continue
        transport = 0
        if not isinstance(plan, dict):
            stale += 1
            if stale >= 3:
                break
            continue
        stale = 0
        act = (plan.get("action") or "").lower().strip()
        if act in ("done", "stop"):
            log("ok", "✓ agent stopped: " + str(plan.get("summary",""))[:150])
            STATE["lead_results"].append({"step":step,"action":"done","summary":str(plan.get("summary",""))[:200]})
            break
        res = None
        cur_key = None

        if act == "probe":
            path = str(plan.get("path") or plan.get("url") or "/").strip()
            if not path.startswith("http"):
                path = "http://" + TARGET.split("/")[0] + "/" + path.lstrip("/")
            key = ("probe", path)
            if key in tried:
                res = {"ok": False, "err": "already tried"}
            else:
                tried.add(key); cur_key = key
                res = _lead_fetch(path)
                if isinstance(res, dict): res["k"] = list(key)
                if res.get("ok") and res.get("status") not in (404, None):
                    u = res.get("url")
                    if u and not any(u == e["url"] for e in STATE["endpoints"]):
                        from urllib.parse import urlparse as _up
                        STATE["endpoints"].append({"url": u, "host": _up(u).netloc})
                        STATE["stats"]["endpoints"] = len(STATE["endpoints"])
                    _note_gated(u or path, res.get("status"), step)
                log("cmd", "$ probe " + path + " → " + str(res.get("status") or res.get("err",""))[:80])

        elif act == "request":
            url = str(plan.get("url") or "").strip()
            if not url:
                res = {"ok": False, "err": "missing url"}
            else:
                key = ("req", str(plan.get("method","GET")).upper(), url, str(plan.get("body") or "")[:80])
                if key in tried:
                    res = {"ok": False, "err": "already sent"}
                else:
                    tried.add(key); cur_key = key
                    res = _lead_fetch(url, method=str(plan.get("method","GET")),
                                      body=plan.get("body"), headers=plan.get("headers") or {})
                    if res.get("ok"):
                        ep = str(plan.get("endpoint") or url).split("?")[0]
                        if ep and not any(ep == e["url"] for e in STATE["endpoints"]):
                            from urllib.parse import urlparse as _up
                            STATE["endpoints"].append({"url": ep, "host": _up(ep).netloc})
                            STATE["stats"]["endpoints"] = len(STATE["endpoints"])
                        _note_gated(res.get("url") or url, res.get("status"), step)
                    log("cmd", "$ " + str(plan.get("method","GET")).upper() + " " + url[:80] +
                        " → " + str(res.get("status") or res.get("err",""))[:60])

        elif act == "test":
            ep = str(plan.get("endpoint") or "").strip()
            cls = str(plan.get("class") or "").lower().strip()
            if not ep or not cls:
                res = {"ok": False, "err": "test needs endpoint and class"}
            else:
                key = ("test", ep, cls)
                if key in tried:
                    res = {"ok": False, "err": "already tested"}
                else:
                    tried.add(key); cur_key = key
                    if cls in ("idor","authz") and not authed:
                        res = {"ok": False, "err": "needs session"}
                    else:
                        log("cmd", "$ scan_cell [" + cls + "] " + ep[:80])
                        before = len(STATE["findings"])
                        try:
                            scan_cell(ep, cls, tok, tok2)
                        except Exception as _e:
                            res = {"ok": False, "err": str(_e)[:100]}
                        else:
                            newf = STATE["findings"][before:]
                            res = {"ok": True, "scanned": ep, "cls": cls,
                                   "new_findings": [{"title": f.get("title"), "sev": f.get("sev")} for f in newf]}

        elif act == "remember":
            lead = str(plan.get("lead") or "").strip()
            if lead:
                STATE["leads"].append({"lead": lead, "endpoint": str(plan.get("endpoint") or ""), "step": step})
                STATE["leads"] = STATE["leads"][-60:]
                res = {"ok": True, "recorded": lead[:160]}
            else:
                res = {"ok": False, "err": "missing lead text"}

        elif act == "finding":
            title = str(plan.get("title") or "").strip()
            detail = str(plan.get("detail") or plan.get("evidence") or "").strip()
            endpoint = str(plan.get("endpoint") or plan.get("url") or "").strip()
            if not title or len(detail) < 20 or not endpoint:
                res = {"ok": False, "err": "missing title/evidence/endpoint"}
            else:
                sev = str(plan.get("severity") or plan.get("sev") or "m")
                add_finding(sev, title, detail, endpoint, cls=str(plan.get("cls") or ""), verdict="", det=False)
                res = {"ok": True, "accepted": title[:160]}
        else:
            res = {"ok": False, "err": "unknown action '" + str(act) + "'"}

        if res is not None:
            res["step"] = step
            if "k" not in res and cur_key is not None:
                res["k"] = list(cur_key)
            STATE["lead_results"].append(res)
            STATE["lead_results"] = STATE["lead_results"][-40:]
            STATE.setdefault("lead_log", []).append({
                "step": step, "act": act, "ok": res.get("ok"),
                "detail": str(res.get("status") or res.get("err") or res.get("note") or "")[:100]})
            STATE["lead_log"] = STATE["lead_log"][-80:]
            flush()


def phase_adaptive(deadline, max_cells=200):
    """Coverage-to-100% loop: cover EVERY applicable (endpoint × class) cell, ranked by ROI and
    boosted by the LLM leads, until the ledger is drained or the budget/time is hit. Classes are
    INTERLEAVED so a budget cap doesn't spend everything on one class (sqli/ssti) and starve the rest."""
    c = _creds(); tok = (c.get("session_token") or "").strip(); tok2 = (c.get("token2") or "").strip()
    authed_ok = (MODE != "black") and bool(tok)
    leadeps = set((l.get("endpoint") or "").lower() for l in STATE.get("leads", []) if l.get("endpoint"))
    from collections import defaultdict
    bycls = defaultdict(list)
    for e in STATE["endpoints"]:
        ep = e["url"]
        for cls in applicable_classes(ep):
            if cls in TESTED.get(ep, set()):
                continue
            if cls in ("idor", "authz") and not authed_ok:
                continue  # these two genuinely need a session (two-identity comparison)
            bycls[cls].append(ep)
    # order each class's endpoints: LLM-lead matches first
    for cls in bycls:
        bycls[cls].sort(key=lambda ep: 0 if any(le and le in ep.lower() for le in leadeps) else 1)
    # round-robin across classes (by ROI rank) so every class gets coverage within the cap
    work = []
    order = sorted(bycls.keys(), key=lambda c: RANK.get(c, 9))
    while any(bycls[c] for c in order):
        for cls in order:
            if bycls[cls]:
                work.append((RANK.get(cls, 9), bycls[cls].pop(0), cls))
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
        d = llm_json(sys_p, usr, max_tokens=1200, timeout=70, _model=MODEL_CHEAP)
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


def phase_api_test(deadline):
    """SPA-first testing: run api-test on the REAL API calls captured at runtime (phase_spa_capture) —
    POST + body params, auth-aware — for injection + IDOR. This is the surface that actually matters on
    a modern app, which katana-crawling never reaches."""
    calls = STATE.get("api_calls") or []
    if not calls or not (HERE / "api-test.py").exists():
        return
    c = _creds()
    cookie = (c.get("cookie") or "").strip(); tok = (c.get("session_token") or "").strip(); ua = (c.get("ua") or "").strip()
    delay = "0.5" if STEALTH else "0"
    stage("API-test", 86)
    # dedup by (method, path, sorted param names) so we test each distinct call once
    seen, uniq = set(), []
    for cl in calls:
        pu = re.sub(r"\?.*$", "", cl.get("path", ""))
        pk = tuple(sorted(re.findall(r"(\w+)=", (cl.get("url", "") + "&" + (cl.get("req_body") or "")))))
        key = (cl.get("method"), pu, pk)
        if key in seen:
            continue
        seen.add(key); uniq.append(cl)
    log("ok", "◆ API-test · " + str(len(uniq)) + " distinct runtime call(s) · injection + IDOR" + (" · stealth" if STEALTH else ""))
    n = 0
    for cl in uniq[:30]:
        if time.time() > deadline:
            log("warn", "⏱ budget reached — API-test stopped"); break
        a = ["--url", cl.get("url", ""), "--method", cl.get("method", "GET"), "--ua", ua or "Mozilla/5.0 HUNTR", "--delay", delay]
        if cl.get("req_body"): a += ["--data", cl["req_body"]]
        if cookie: a += ["--cookie", cookie]
        if tok: a += ["--token", tok]
        d = tool_json("api-test.py", a, timeout=90)
        for f in (d or {}).get("findings", []):
            add_finding(f.get("severity", "h"), f.get("title") or (f.get("cls", "API") + " issue"),
                        f.get("detail") or "", f.get("endpoint") or cl.get("url", ""),
                        cls=f.get("cls", "API"), verdict=f.get("verdict", "likely"),
                        det=(f.get("verdict") == "confirmed"))
            n += 1
    log("ok" if n else "out", "✓ API-test · " + str(n) + " finding(s) on the runtime API surface")
    flush()


def phase_exploit_agent(deadline):
    """Depth layer: an LLM-driven, AUTHENTICATED exploitation agent (exploit-agent.py) that drives a live
    session in a loop to prove the high-value access-control bugs that live behind login — IDOR/BOLA,
    BFLA, privilege escalation, business-logic. Runs only with a session (token or a real-Chrome CDP
    port); skipped for pure black-box recon. Agent findings are LLM-adjudicated → verdict as returned
    (not deterministic), so the judge/economics still weigh them."""
    if not (HERE / "exploit-agent.py").exists():
        return
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    tok2 = (c.get("token2") or "").strip()
    cdp = str(c.get("cdp_port") or "").strip()
    cookie = (c.get("cookie") or "").strip()
    ua = (c.get("ua") or "").strip()
    if MODE == "black" or not (tok or cdp or cookie):
        return
    remaining = int(deadline - time.time())
    if remaining < 90:
        log("warn", "⏱ skipped exploit-agent — budget too low (" + str(remaining) + "s)")
        return
    sl = max(90, min(remaining - 30, 300))
    live = [h["host"] for h in STATE["hosts"] if h.get("status")]
    sch = next((h.get("scheme") for h in STATE["hosts"] if h.get("status") and h.get("scheme")), "https")
    base = (sch + "://" + live[0]) if live else (sch + "://" + apex(TARGET))
    obj = "prove broken access control on the authenticated surface: cross-account IDOR/BOLA, BFLA on privileged routes, privilege escalation, and multi-step business-logic abuse"
    stage("Exploit-agent", 90)
    sess_kind = "real-Chrome CDP" if cdp else ("cookie" if cookie else "token") + (" ×2 identities" if tok2 else "")
    log("ok", "◆ exploit-agent · LLM-driven authenticated session · " + sess_kind + " · " + str(sl) + "s")
    a = ["--target", base, "--objective", obj, "--budget-sec", str(sl), "--max-steps", "18", "--json"]
    if cdp:
        a += ["--cdp-port", cdp]
    if tok:
        a += ["--token", tok]
    if tok2:
        a += ["--token2", tok2]
    if cookie:
        a += ["--cookie", cookie]
    if ua:
        a += ["--ua", ua]
    if STATE.get("api_calls"):   # feed the SPA's real runtime endpoints+params to the agent
        try:
            sf = HUNT_DIR / "api_surface.json"
            sf.write_text(json.dumps({"calls": STATE["api_calls"]}))
            a += ["--surface-file", str(sf)]
        except Exception:
            pass
    d = tool_json("exploit-agent.py", a, timeout=sl + 40)
    if not isinstance(d, dict):
        log("warn", "→ exploit-agent produced no result (session/LLM unavailable)")
        return
    n = 0
    for f in d.get("findings", []):
        if not isinstance(f, dict):
            continue
        add_finding(f.get("severity", "h"), f.get("title") or "Broken access control",
                    f.get("detail") or "", f.get("endpoint") or base, cls=f.get("cls", "authz"),
                    verdict=f.get("verdict", "likely"), det=False)   # LLM-adjudicated → judge can still weigh
        n += 1
    log("ok" if n else "out", "✓ exploit-agent · " + str(d.get("steps", 0)) + " step(s) · " + str(n) + " access-control finding(s)")
    flush()


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
             "\"impact\":\"concrete impact in 1-2 sentences\",\"remediation\":\"the fix\",\"cvss\":\"x.x\","
             "\"reason\":\"ONLY when drop=true: the concrete disproof — quote or name the specific piece of "
             "evidence that contradicts the finding (e.g. payload HTML-escaped in the response body, endpoint only "
             "302-redirects so nothing is ever rendered or queried). Empty when you keep it.\"}],"
             "\"chains\":[\"short multi-step chain across findings if any\"]}. Never invent evidence; if the evidence "
             "doesn't support the finding set verdict=false_positive, drop=true, and say WHY in \"reason\".")
    d = llm_json(sys_p, json.dumps({"target": TARGET, "findings": items}), max_tokens=3200, timeout=150, _model=MODEL_STRONG)
    if not isinstance(d, dict):   # model may return a bare array / malformed JSON — don't crash the hunt
        log("warn", "→ AI judge unavailable (rate-limited/offline) — findings left as-is")
        stage("AI-judge", 98); return
    drop = set(); kept = 0; conf = 0; reasons = {}
    for j in (d.get("judgments") or []):
        if not isinstance(j, dict):
            continue
        i = j.get("i")
        if not isinstance(i, int) or i < 0 or i >= len(STATE["findings"]):
            continue
        f = STATE["findings"][i]
        if j.get("drop") or j.get("verdict") == "false_positive":
            reason = str(j.get("reason") or "").strip()
            if f.get("_det") and len(reason) < 40:
                # tool-confirmed and the judge offered no concrete disproof — a bare "false_positive"
                # call must not silently discard sqlmap/OAST-grade evidence.
                f["detail"] = (f.get("detail", "") +
                               " · note: AI judge flagged for review without a concrete disproof; "
                               "tool evidence stands").strip(" ·")
                f["judge_disputed"] = True
                kept += 1; conf += 1; continue
            # quarantine instead of delete — dropped findings stay auditable (and recoverable) on disk
            STATE.setdefault("dropped", []).append({
                "title": f.get("title", ""), "cls": f.get("cls", ""), "sev": f.get("sev", ""),
                "endpoint": f.get("endpoint", ""), "verdict": f.get("verdict", ""),
                "reason": reason or "(no reason given)", "det": bool(f.get("_det")),
                "evidence": (f.get("detail") or "")[:400],
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})
            STATE["dropped"] = STATE["dropped"][-120:]
            reasons[i] = reason or "(no reason given)"
            drop.add(i); continue
        if j.get("repro"):
            r = j["repro"]
            # Nemotron hands back a list; the dashboard calls f.steps.trim()/split('\n'),
            # so a raw array would throw TypeError in the report view
            f["steps"] = "\n".join(str(x) for x in r) if isinstance(r, (list, tuple)) else str(r)
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
    log("warn" if drop else "ok", "✓ AI judge: " + str(kept) + " kept (" + str(conf) + " confirmed) · " +
        str(len(drop)) + " false-positive(s) quarantined → STATE[dropped]")
    for k in sorted(drop):   # leave a visible trail — an operator should be able to see what was rejected and why
        _f = STATE["findings"][k] if k < len(STATE["findings"]) else {}
        log("out", "  ✗ rejected: " + str(_f.get("title"))[:70] + " — " + str(reasons.get(k, ""))[:140])
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
        d = llm_json(sysp, json.dumps({"target": TARGET, "chains": items}), max_tokens=1600, timeout=140, _model=MODEL_STRONG)
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


def load_resume():
    """Reload prior run.json so a paused hunt continues where it left off (findings, mapped surface,
    captured API, and the coverage already done). Returns True if there's a usable mapped surface."""
    try:
        prior = json.loads(RUN.read_text())
    except Exception:
        return False
    for k in ("findings", "endpoints", "hosts", "leads", "chains", "api_calls", "economics", "coverage", "invariants", "logs"):
        if k in prior:
            STATE[k] = prior[k]
    for ep, cs in (prior.get("tested") or {}).items():
        TESTED[ep] = set(cs)
    STATE["stats"]["findings"] = len(STATE["findings"])
    return bool(prior.get("endpoints"))


# finding class → an invariant type invariant-check can actually EXECUTE next run.
# Anything unmapped lands as `technique`, which invariant-check only lists (it executes
# deny/noaccess/rejects/allow/once) — useful as a hypothesis, but not as an oracle.
TYPE_FOR_CLS = (
    ("idor", "noaccess"), ("bola", "noaccess"), ("broken object", "noaccess"),
    ("object-level", "noaccess"), ("auth bypass", "deny"), ("authz", "deny"),
    ("bfla", "deny"), ("broken function", "deny"), ("function-level", "deny"),
    ("privilege", "deny"), ("mass assignment", "rejects"), ("param/idor", "rejects"),
    ("race", "once"), ("idempot", "once"),
)


def phase_learn():
    """Close the learning loop — promote this hunt's confirmed, submit-worthy findings into learned
    rules so the next hunt on a similar stack starts from real outcomes instead of static priors.

    This is what keeps the corpus from going stale: skills seed the first prior, the engine's own
    confirmed findings keep refining it. Idempotent (hunt-corpus --learn dedups on type|fam|url)."""
    picks = [f for f in STATE["findings"]
             if f.get("reco") == "submit" and (f.get("verdict") or "").lower() == "confirmed"]
    cor = HERE / "hunt-corpus.py"
    if not picks or not cor.exists():
        return
    stack = (_stack().split(",")[0] or "generic")
    n = 0
    for f in picks:
        cls = (f.get("cls") or "").lower()
        itype = "technique"
        for k, v in TYPE_FOR_CLS:
            if k in cls:
                itype = v
                break
        ep = f.get("endpoint") or ""
        path = _upd_path(ep)
        fam = re.sub(r"[^a-z0-9]+", "", cls)[:24] or "misc"
        note = (("confirmed " + (f.get("cls") or "issue") + " — " + str(f.get("title") or "")[:90] +
                 " · retest this first on comparable endpoints of the same shape")[:220])
        try:
            out, err, rc = sh([sys.executable, str(cor), "--learn", "--type", itype,
                               "--fam", fam, "--stack", stack, "--note", note, "--url", path], timeout=30)
        except Exception:
            continue
        # rc==0 on a dedup skip too — count only rows that were actually written
        if rc == 0 and "already present" not in out and "skipped" not in out:
            n += 1
    # memory store — the SITUATION (response shape, error string, endpoint pattern) so hunt N+1
    # can recall it. corpus rules assert invariants; memory recalls technique that already worked.
    mem = HERE / "hunt-memory.py"
    if mem.exists():
        for f in picks:
            parts = [str(f.get("title") or ""), _upd_path(str(f.get("endpoint") or "")),
                     str(f.get("detail") or "")[:400]]
            txt = " ".join(x for x in parts if x).strip()
            if len(txt) < 40:
                continue
            try:
                out, err, rc = sh([sys.executable, str(mem), "--add", "--kind", "finding",
                                   "--cls", str(_cls_key(f.get("cls"))), "--stack", stack,
                                   "--program", str(PROGRAM or TARGET), "--reward",
                                   str(f.get("bounty_est") or 0), "--text", txt], timeout=30)
            except Exception:
                continue
            if rc == 0 and "already stored" not in out and "skipped" not in out:
                n += 1
    if n:
        STATE["stats"]["learned"] = (STATE["stats"].get("learned") or 0) + n
        log("ok", "✓ learning loop · " + str(n) + " new rule(s)/situation(s) → corpus (stack=" +
            stack + " · " + str(len(picks)) + " confirmed finding(s) seen, rest already known)")
        flush()


def _upd_path(url):
    """Endpoint → path used as the corpus hint, so a learned rule says WHERE it paid."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
    except Exception:
        return str(url or "")



def main():
    if not TARGET:
        STATE["status"] = "error"; STATE["stage"] = "No target"; flush()
        print("no --target"); return
    os.environ["HUNT_DIR"] = str(HUNT_DIR)  # so every engine tool shells into this workspace
    RESUME = "--resume" in sys.argv
    try:
        (HUNT_DIR / "run.pid").write_text(str(os.getpid()))  # so the dashboard can pause/resume/stop
    except Exception:
        pass
    try:
        resumed = load_resume() if RESUME else False
        budget_sec = int(arg("--budget-sec", "2700") or 2700)  # default 45 min (was 20)
        deadline = time.time() + budget_sec
        if resumed:
            _RL["hit"] = False   # clear the pause flag — the operator says the limit has reset
            STATE["status"] = "running"; STATE.pop("paused_reason", None)
            log("ok", "▸ RESUMING · " + TARGET + " · reusing " + str(len(STATE["endpoints"])) +
                " endpoints · " + str(len(STATE["findings"])) + " finding(s) so far · " +
                str(sum(len(v) for v in TESTED.values())) + " cell(s) already done")
        else:
            log("ok", "▸ hunt started · " + TARGET + " · " + ",".join(SCOPE_TYPES) + " · " + MODE + "-box")
        # setup + surface mapping — skipped on resume (already mapped)
        if not resumed:
            phase_scope()
            phase_recon()
            phase_surface()
            phase_discover(deadline)  # ACTIVE discovery — unlinked paths + spec walk + BFS (katana can't see these)
            phase_spa_capture()     # SPA runtime API discovery (real browser) — folds XHR/fetch into the surface
            phase_memory_recall()    # long-term memory — analogous past situations, before the LLM leads
            # the LLM leads FIRST — it decides what to touch before any deterministic sweep runs, so the
            # engine's actions follow the model's hypotheses rather than the model annotating a fixed grid.
            phase_active()          # Layer 1 — deterministic sweep first; LLM gets real scan evidence
            phase_authed()
            phase_llm_lead(deadline)  # LLM-led loop AFTER scan: reasons over what the scanner found AND missed
        else:
            log("out", "→ resume: skipping recon/surface (reusing mapped surface); continuing the hunt")
        # hunt phases — a pause checkpoint before each LLM-heavy one so a rate limit halts cleanly
        check_pause(); phase_adaptive(deadline)
        check_pause(); phase_api_test(deadline)      # SPA-first — test captured runtime API for injection/IDOR
        check_pause(); phase_ai_direct(deadline)     # Layer 2 — AI-directed (Haiku)
        check_pause(); phase_exploit_agent(deadline) # Depth — LLM-driven authenticated exploitation
        check_pause(); phase_oob(deadline)           # Blind/OOB fuzzing — nuclei DAST + interactsh
        phase_dedup()
        phase_fingerprint()
        check_pause(); phase_methodology(deadline)
        check_pause(); phase_ai_judge()              # Layer 3 — strong-model validation
        check_pause(); phase_chain()                 # Chain-to-Impact
        phase_economics()                            # Economics brain
        phase_learn()                                # close the loop → learned rules for the NEXT hunt
        STATE["status"] = "done"
        stage("Done", 100)
        nf = len(STATE["findings"]); cov = STATE["coverage"]
        log("ok", "■ hunt finished · " + str(nf) + " finding" + ("" if nf == 1 else "s") +
            " · " + str(len(STATE["leads"])) + " leads · " + str(len(STATE["chains"])) + " chains · coverage " +
            str(cov.get("breadth", 0)) + "%")
    except RateLimitPause:
        STATE["status"] = "paused"; STATE["paused_reason"] = "rate-limit"
        ra = _RL.get("retry_after", 0)
        log("warn", "⏸ PAUSED — account rate limit reached" + (" (retry ~" + str(ra) + "s)" if ra else "") +
            " · findings + coverage saved · click Resume when the limit resets")
        flush()
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
