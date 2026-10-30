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

# hunt-brain: self-learning module — imported lazily to avoid startup cost
_BRAIN = None
def _brain():
    global _BRAIN
    if _BRAIN is None:
        try:
            import importlib.util as _ilu
            _spec = _ilu.spec_from_file_location("hunt_brain", str(HERE / "hunt-brain.py"))
            _BRAIN = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_BRAIN)
        except Exception:
            _BRAIN = type("NoBrain", (), {
                "record_winning_path": lambda *a, **k: None,
                "record_hit": lambda *a, **k: None,
                "write_hunt_note": lambda *a, **k: None,
                "read_hunt_notes": lambda *a, **k: [],
                "record_fp": lambda *a, **k: None,
                "get_fp_filters": lambda *a, **k: [],
                "get_technique_priority": lambda *a, **k: [],
                "get_winning_paths": lambda *a, **k: [],
                "record_tool_use": lambda *a, **k: None,
                "log_hunt": lambda *a, **k: None,
            })()
    return _BRAIN


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def safe(t):
    s = re.sub(r"[^a-z0-9._-]+", "_", (t or "default").lower()).strip("_") or "default"
    # Bound the workspace dir name: a pasted program page (thousands of chars) as the "target" made
    # mkdir() raise "File name too long" and crash. Cap length and append a short hash of the full
    # input so distinct long inputs stay unique. Keep in sync with huntr-server.py:safe.
    #
    # This fallback only fires when NEITHER $HUNT_DIR NOR --hunt-dir was given (the dashboard always
    # sets $HUNT_DIR explicitly, so this path is dead there) — i.e. a direct/manual CLI invocation.
    # Still: reuse an already-existing workspace slug as-is instead of re-hashing it — re-hashing the
    # SLUG TEXT (not the original target) lands on a different hash and silently points at a brand
    # new, empty workspace. See [[otto-resume-rehash-bug]].
    if len(s) > 80:
        if (Path.home() / ".huntr" / "targets" / s).exists():
            return s
        import hashlib
        s = s[:72] + "_" + hashlib.sha1((t or "").encode("utf-8", "ignore")).hexdigest()[:8]
    return s


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
WEB_ASSETS = [a for a in _assets if a not in SOURCE_ASSETS]  # never fall back to source repos as web targets
TARGET = (WEB_ASSETS[0] if WEB_ASSETS else (_assets[0] if _assets else "")).strip()  # primary (apex/naming)
PROGRAM = arg("--program", "")
MODE = arg("--mode", "grey")
# stealth: throttle + lower concurrency + propagate the program UA so loud scanners don't get IP-blocked
# on WAF-protected real targets. On by env HUNT_STEALTH=1 or --stealth.
STEALTH = os.environ.get("HUNT_STEALTH") == "1" or "--stealth" in sys.argv
# Deterministic-only mode: skip every LLM phase and run the 0-token scanners +
# oracles + triage to completion. Fast, offline, needs no account — and makes the
# autonomous loop reproducibly verifiable (CI/benchmark) independent of LLM quota.
NO_LLM = os.environ.get("HUNT_NO_LLM") == "1" or "--no-llm" in sys.argv
# Full-agentic rewrite (operator directive, 2026-10-25): phases listed here run as one real
# `claude -p` agent (see _run_phase_agent) instead of the legacy scripted phase_*() pipeline. Staged,
# reversible per-phase migration — a phase name's absence here means it still runs the old scripted
# path, so this can be dialed back by editing the env var alone, no code revert needed.
HUNT_AGENTIC_PHASES = set(s.strip() for s in (os.environ.get("HUNT_AGENTIC_PHASES") or "").split(",") if s.strip())
SCOPE_TYPES = [s for s in (arg("--scope-types", "web,api") or "").split(",") if s]
HUNT_DIR = Path(os.environ.get("HUNT_DIR") or arg("--hunt-dir")
                or (Path.home() / ".huntr" / "targets" / safe(TARGET) / ".hunt"))
HUNT_DIR.mkdir(parents=True, exist_ok=True)
RUN = HUNT_DIR / "run.json"

STATE = {
    "target": TARGET, "scope": RAW_TARGET, "program": PROGRAM, "mode": MODE, "scope_types": SCOPE_TYPES,
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
    # Reachable from the dual-agent BROAD+DEEP threads (both call the scan_endpoint tool, which runs
    # scan_cell -> mark_tested) concurrently with the single-threaded coverage sweep's own calls, and
    # with flush()'s TESTED.items() read — a bare dict mutation here could corrupt TESTED or raise
    # "dictionary changed size during iteration" in flush(). _STATE_LOCK is defined further down in
    # this module but resolved at call time, so the forward reference is fine.
    with _STATE_LOCK:
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
# HARD POLICY (operator choice, 2026-10-09; REVERTED 2026-10-22 after a same-day round-trip): hunt
# ONLY on Anthropic — Opus 4.8 (strong) + Sonnet 4.6 (lead/cheap). No Groq, no NVIDIA, no Haiku for
# the hunt tiers. Env-overridable via HUNT_MODEL_STRONG/_MID/_CHEAP.
#
# Earlier the same day these were bumped to opus-5-5/sonnet-5-5 on the theory that a newer model
# reasons better. It does, but under this account's CLI-subscription auth (see cli-mode-identity-leak
# memory — raw OAuth API calls 429, so every call goes through `claude -p`, which carries Claude
# Code's own real identity/safety-reasoning underneath whatever persona the hunt prompt asks for),
# the newer 5.x generation's sharper injection/autonomous-action caution makes it refuse that persona
# far more often. Live-tested side by side, 10 trials each, same exact prompt: sonnet-4-6 10/10,
# opus-4-8 10/10, sonnet-5-5 ~75% (1 refusal in an early batch of 4). A model that reasons 10% better
# but runs 25%+ less often is a net loss for an unattended loop with no human present to vouch for
# the request each time — reliability beats marginal quality here. Revert to 4.6/4.8.
_M_STRONG = os.environ.get("HUNT_MODEL_STRONG", "claude-opus-4-8")
_M_MID    = os.environ.get("HUNT_MODEL_MID", "claude-sonnet-4-6")
_M_CHEAP  = os.environ.get("HUNT_MODEL_CHEAP", "claude-sonnet-4-6")
MODEL_LEAD   = {"provider": "anthropic", "model": _M_MID}
MODEL_STRONG = {"provider": "anthropic", "model": _M_STRONG}
MODEL_CHEAP  = {"provider": "anthropic", "model": _M_CHEAP}
if os.environ.get("HUNT_LLM") == "haiku" or "--llm-light" in sys.argv:
    MODEL_LEAD = MODEL_STRONG = MODEL_CHEAP   # light mode → all tiers on the cheap (Sonnet) model
# Report drafting is prose-shaping over evidence the hunt already proved — not new reasoning about
# the target — so it's carved out of the "no Haiku" policy above (operator choice, 2026-10-15):
# Haiku 5.5 is fast/cheap and, held to the same report STRUCTURE contract as report-draft.py, matches
# the stronger tiers on this specific job. Independent of HUNT_LLM/--llm-light.
MODEL_REPORT = {"provider": "anthropic", "model": os.environ.get("HUNT_MODEL_REPORT", "claude-haiku-5-5")}


# rate-limit state: set when the provider returns 429 (rate limit reached).
_RL = {"hit": False, "retry_after": 0, "cost_cap": False}
_LLM_LAST_ERR = {"e": ""}
# A 429 pauses the hunt (see RateLimitPause) because the account may still serve later. An AUTH/CREDIT
# failure (subscription logged out, bad API key, no credit) never resolves on its own and is NOT a 429,
# so it fell through llm_call's retries and just returned None forever — every LLM-dependent phase
# (triage, chaining, reports) silently no-oped for the rest of the budget window with zero indication
# anywhere. This does not pause the hunt (deterministic-only operation is a legitimate, intentional mode
# — see NO_LLM), it only makes the degradation VISIBLE, same as session_alert/circuit_open.
_LLM_AUTH_RE = re.compile(r"/login|invalid api key|credit balance|out of credit|\bquota\b|"
                          r"no api key for|\b401\b|unauthorized", re.I)
_llm_auth_fail_streak = [0]
# multi-agent STATE lock: prevents concurrent agents from corrupting findings/leads.
# RLock (not Lock): add_finding()/mark_tested() acquire it internally (see below), and
# record_finding's tool handler ALSO wraps its own add_finding() call in it — a plain Lock would
# deadlock the same thread trying to re-enter its own held lock; RLock allows that safely.
_STATE_LOCK = threading.RLock()


class RateLimitPause(Exception):
    pass


def check_pause():
    """Raise if the account rate limit has been reached, so main() can pause the hunt for resume."""
    if _RL["hit"]:
        raise RateLimitPause()


# Same prose the CLI prints for a hit 5-hour session limit (see llm_client.call_llm's docstring for
# the live example: "You've hit your session limit · resets 5:10pm"). _run_phase_agent's claude-cli
# subprocess is a separate, raw subprocess.run call (not routed through llm_client/llm_call), so it
# never passed through that detection — it just logged "produced nothing" and returned False, letting
# main() cascade straight through every remaining agentic phase on a dead account with status "done"
# at the end. This regex is intentionally the same wording list as llm_client's.
_CLI_LIMIT_RE = re.compile(
    r"hit your session limit|hit your limit|usage limit|rate limit|please run /login|"
    r"invalid api key|credit balance is too low|out of credit|\bquota\b", re.I)
_CLI_RESET_RE = re.compile(r"resets?\s+(\d{1,2}:\d{2}\s*[ap]m)\s*(?:\(([^)]+)\))?", re.I)


def _parse_cli_reset(text):
    """Best-effort epoch seconds for a "resets 5:10pm (America/New_York)"-style notice. Returns None
    if unparseable — callers must fall back to an operator-facing message + manual Resume either way."""
    m = _CLI_RESET_RE.search(text or "")
    if not m:
        return None
    try:
        import datetime
        tzname = (m.group(2) or "").strip()
        tz = None
        if tzname:
            try:
                from zoneinfo import ZoneInfo
                tz = ZoneInfo(tzname)
            except Exception:
                tz = None
        now = datetime.datetime.now(tz) if tz else datetime.datetime.now()
        clock = re.sub(r"\s+", "", m.group(1)).upper()   # "5:10pm" -> "5:10PM"
        t = datetime.datetime.strptime(clock, "%I:%M%p")
        target = now.replace(hour=t.hour, minute=t.minute, second=0, microsecond=0)
        if target <= now:
            target += datetime.timedelta(days=1)   # the time already passed today — it means tomorrow
        return target.timestamp()
    except Exception:
        return None


# $/1M tokens (input, output) — current Anthropic API rates, only meaningful when a raw API key
# is in play. Under the subscription (HUNT_LLM_VIA_CLI=1) there is no per-call billing at all, so
# llm_client._LAST_USAGE comes back {} and _record_llm_cost() correctly adds nothing but a call count.
_MODEL_PRICE = {
    "claude-opus-5-5": (5.00, 25.00), "claude-sonnet-5-5": (3.00, 15.00),
    "claude-haiku-5-5": (1.00, 5.00), "claude-sonnet-5": (3.00, 15.00),
    # older generations kept so a hunt resumed/override-pinned to them still prices correctly
    "claude-opus-4-8": (5.00, 25.00), "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00), "claude-sonnet-4-5": (3.00, 15.00),
}


def _record_llm_cost():
    """Pull the usage from the call llm_client just made (if any) into STATE, so the dashboard's
    cost meter reflects real spend under an API key, or an honest call-count under the subscription."""
    try:
        u = llm_client._LAST_USAGE or {}
    except Exception:
        u = {}
    STATE["llm_calls"] = STATE.get("llm_calls", 0) + 1
    itok, otok = u.get("input_tokens", 0), u.get("output_tokens", 0)
    if itok or otok:
        price = _MODEL_PRICE.get(u.get("model"), (3.00, 15.00))
        STATE["llm_input_tokens"] = STATE.get("llm_input_tokens", 0) + itok
        STATE["llm_output_tokens"] = STATE.get("llm_output_tokens", 0) + otok
        STATE["cost_usd"] = round(STATE.get("cost_usd", 0.0) +
                                   itok / 1e6 * price[0] + otok / 1e6 * price[1], 4)
    # Only a TIME budget (budget_sec) was ever enforced — nothing stopped runaway spend if a phase
    # misbehaved and looped on LLM calls within that window. An operator-set $ cap reuses the exact
    # same pause mechanism as a provider rate limit (check_pause() is already threaded through every
    # LLM-heavy phase), so it takes effect at the same granularity with no new call sites needed.
    cap = STATE.get("cost_cap_usd")
    if cap and STATE.get("cost_usd", 0.0) >= cap and not _RL["hit"]:
        _RL["hit"] = True
        _RL["cost_cap"] = True


def llm_call(system, user, max_tokens=1600, timeout=100, _model=None):
    """One LLM call via llm_client. Returns text, or None. Sets _RL['hit'] on rate limit.

    Transient provider failures (503 overload, blips, dropped connections) are retried with
    backoff — a single hiccup must not terminate an agentic loop that is mid-reasoning.

    _model: optional dict with 'provider' and 'model' keys (MODEL_LEAD / MODEL_STRONG / MODEL_CHEAP).
    When omitted the llm_client env config is used (NVIDIA default or HUNT_LLM_PROVIDER override)."""
    if NO_LLM:
        return None   # deterministic-only run: every LLM call fast-returns; phases degrade gracefully
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
        _record_llm_cost()
        if text:
            _llm_auth_fail_streak[0] = 0
            STATE.pop("llm_alert", None)
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
    if _LLM_LAST_ERR.get("e") and _LLM_AUTH_RE.search(_LLM_LAST_ERR["e"]):
        _llm_auth_fail_streak[0] += 1
        if _llm_auth_fail_streak[0] >= 2:
            msg = ("the engine's own AI credentials look dead (" + _LLM_LAST_ERR["e"][:150] + ") — "
                   "every LLM-dependent phase (triage, chaining, report drafting) has been silently "
                   "degrading to no-op. Re-authenticate (claude login, or check the API key) — "
                   "the hunt keeps running deterministic-only in the meantime.")
            was_set = STATE.get("llm_alert") is not None
            STATE["llm_alert"] = {"ts": time.time(), "error": _LLM_LAST_ERR["e"][:200], "msg": msg}
            if not was_set:   # log/flush once on the rising edge, not on every failed call after that
                log("warn", "⚠ LLM ALERT — " + msg)
    return None


def _extract_json_from_text(t):
    """Balanced-bracket, string-aware scan for the first JSON object/array in text, from its
    opening bracket to its own matching close — NOT a greedy regex span to the last bracket
    anywhere in the text, which breaks the moment trailing prose after the real JSON contains any
    stray brace (a URL path param like /api/users/ID_PLACEHOLDER in a summary is enough).
    Shared by llm_json() and _call_llm_threaded() — same bug class, same fix, one place to get it
    right. See agent_core._extract_json_object's docstring for the live incident that found this."""
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


def llm_json(system, user, max_tokens=1600, timeout=100, _model=None):
    """llm_call + robustly extract a JSON object/array from the reply."""
    txt = llm_call(system, user, max_tokens, timeout, _model=_model)
    if not txt:
        return None
    # strip ```json fences, then try the whole thing before falling back to a span search
    t = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", txt.strip(), flags=re.I | re.M).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    return _extract_json_from_text(t)


_LAST_TOOL_ERR = None  # set by tool_json() on failure; scan_cell()'s single "cell errored"
                       # log line reads this, so the ONE existing diagnostic point gets a real
                       # reason (timeout / binary-missing / nonzero-exit / parse-error /
                       # no-json-output) instead of every failure looking identical.

def tool_json(tool, args, timeout=240):
    global _LAST_TOOL_ERR
    _LAST_TOOL_ERR = None
    out, err, rc = sh([sys.executable, str(HERE / tool)] + args, timeout=timeout)
    for line in reversed((out or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except Exception as e:
                _LAST_TOOL_ERR = "parse-error: " + str(e)[:100]
                return None
    if err in ("timeout", "not-found") or err.startswith("exec-error"):
        _LAST_TOOL_ERR = err
    elif rc != 0:
        _LAST_TOOL_ERR = "nonzero-exit(" + str(rc) + "): " + (err or out or "").strip()[:150]
    else:
        _LAST_TOOL_ERR = "no-json-output"
    return None


_FP = None
def _fp_rules():
    global _FP
    if _FP is None:
        import importlib.util as _il
        _s = _il.spec_from_file_location("fp_rules", str(HERE / "fp_rules.py"))
        _FP = _il.module_from_spec(_s); _s.loader.exec_module(_FP)
    return _FP


# ORDER MATTERS: more-specific keys first, because matching is substring-based and e.g. "sqli" is a
# substring of "nosqli" and "ssti" of "blind ssti". List the specific class before its superstring.
_ORACLE_KEYS = (("nosql", "nosqli"), ("prototype pollution", "prototype-pollution"),
                ("prototype-pollution", "prototype-pollution"), ("web cache deception", "web-cache-deception"),
                ("web-cache-deception", "web-cache-deception"), ("mass assignment", "mass-assignment"),
                ("mass-assignment", "mass-assignment"), ("deserial", "deserialization"),
                ("websocket", "websocket"), ("cswsh", "websocket"), ("request smuggl", "request-smuggling"),
                ("saml", "saml"), ("xsw", "saml"), ("dns rebind", "dns-rebinding"), ("dns-rebind", "dns-rebinding"),
                ("file upload", "file-upload"), ("file-upload", "file-upload"), ("zip slip", "file-upload"),
                ("blind ssti", "blind-ssti"), ("open redirect", "redirect"),
                ("response splitting", "crlf"), ("host header", "host-header"), ("host-header", "host-header"),
                ("cache poison", "cache-poison"), ("cache-poison", "cache-poison"), ("command injection", "cmdi"),
                ("cmdi", "cmdi"), ("remote code", "rce"), ("access control", "authz"), ("auth bypass", "authz"),
                ("sql injection", "sqli"), ("sqli", "sqli"), ("ssti", "ssti"), ("xss", "xss"), ("cors", "cors"),
                ("ldap", "ldap"), ("xpath", "xpath"), ("csp", "csp"), ("oauth", "oauth"), ("oidc", "oauth"),
                ("lfi", "lfi"), ("traversal", "lfi"), ("ssrf", "ssrf"), ("idor", "idor"), ("bola", "idor"),
                ("authz", "authz"), ("jwt", "jwt"), ("graphql", "graphql"), ("redirect", "redirect"),
                ("crlf", "crlf"), ("clickjack", "clickjack"), ("csrf", "csrf"), ("xsrf", "csrf"),
                ("rce", "rce"), ("xxe", "xxe"))

def _oracle_key(cls, title):
    hay = ((cls or "") + " " + (title or "")).lower()
    for lab, k in _ORACLE_KEYS:
        if lab in hay:
            return k
    return None


_SG = None
def _in_scope(url):
    """Is url's host actually in scope.allow (and not scope.deny)?

    CRITICAL (2026-10-21): verify-finding.py and every standalone scanner tool in tools/ (ssrf-test,
    mass-assign, sqli-test, jwt-test, auth-bypass, cors-test, idor-chain, takeover-check, oob-fuzz,
    ...) make RAW, UNGATED HTTP requests via urllib/sockets directly — NONE of them check scope
    themselves. scope-guard.py's own docstring says "EVERY outbound test request must go through
    this wrapper... blast radius [is] a mechanical guarantee" — but that guarantee only holds for
    code paths that remember to call it first. _disc_probe()/_lead_fetch() already did. _det_oracle()
    and scan_cell() — the two chokepoints through which literally every deterministic proof and
    every scanner-tool dispatch flows — did NOT, until this fix. Caught live: a hunt recorded 7
    "confirmed" findings against www.databricks.com and login.databricks.com, NEITHER of which was
    in scope.allow (only the bare apex + two specific subdomains were) — real, unauthorized requests
    had already been sent to hosts the operator never approved before this was found. Single shared
    helper so every current and future call site gets the same enforcement, instead of each one
    needing to remember to inline scope-guard's host_of/in_scope calls correctly on its own."""
    global _SG
    try:
        if _SG is None:
            import importlib.util as _dl
            _s = _dl.spec_from_file_location("_sg", str(HERE / "scope-guard.py"))
            _SG = _dl.module_from_spec(_s); _s.loader.exec_module(_SG)
        h = _SG.host_of(url)
        return _SG.in_scope(h, _SG.host_variants(url))
    except Exception as e:
        return False, "scope-check failed: " + str(e)[:80]


def _det_oracle(cls, title, endpoint, detail=""):
    """0-TOKEN deterministic proof at record time (pure HTTP, no LLM) — so proof survives a later
    rate-limit pause. Returns (verified, method, evidence) or (None, '', '') when not applicable."""
    key = _oracle_key(cls, title)
    if not key or not str(endpoint or "").startswith("http"):
        return None, "", ""
    _ok, _why = _in_scope(endpoint)
    if not _ok:
        log("err", "⛔ _det_oracle refused OUT-OF-SCOPE endpoint (no request sent): " +
            str(endpoint)[:120] + " — " + str(_why))
        return None, "", ""
    import urllib.parse as _up
    args = ["--url", endpoint, "--cls", key, "--json"]
    try:
        qs = _up.urlparse(endpoint).query
        p = _up.parse_qs(qs)
        if p:
            args += ["--param", next(iter(p))]
    except Exception:
        pass
    if detail:
        args += ["--detail", str(detail)[:400]]
    try:
        r = subprocess.run([sys.executable, str(HERE / "verify-finding.py")] + args,
                           capture_output=True, text=True, timeout=40)
        d = json.loads((r.stdout or "").strip().splitlines()[-1])
        return d.get("verified"), str(d.get("method", ""))[:60], str(d.get("evidence", ""))[:300]
    except Exception:
        return None, "", ""

# Classes that are near-universally out-of-scope (security-header / UI hygiene). Recorded as a single
# informational note per host, never submit-routed. CoinTR and most programs exclude these explicitly.
HYGIENE_CLASSES = {"csp", "clickjack", "clickjacking", "hsts", "x-frame-options", "referrer-policy", "permissions-policy"}

def add_finding(sev, title, detail, endpoint, cvss="", cls="", verdict="", det=None, proof=None, source=""):
    sev = sev if sev in SEVLABEL else SEVMAP.get((sev or "i").lower(), "i")
    # deterministic FP guard: public-by-design identifiers (NEXT_PUBLIC_*, reCAPTCHA site key,
    # Sentry public DSN, Stripe pk_, analytics ids, …) can NEVER be high/medium. Born as info.
    try:
        _dg, _why = _fp_rules().should_downgrade(title, detail, cls)
        if _dg and sev in ("c", "h", "m", "l"):
            sev = "i"
            detail = ((detail or "") + " · [auto-info: " + _why + "]").strip(" ·")
            if verdict in ("confirmed", "likely"):
                verdict = "needs_review"
    except Exception:
        pass
    # CORS alone is informational — needs XSS/ATO/SSRF chain to be submittable
    if (cls or "").lower() == "cors":
        existing_classes = {f.get("cls", "").lower() for f in STATE.get("findings", [])}
        if not existing_classes.intersection({"xss", "ssrf", "ato", "rce", "sqli"}):
            sev = "i"
            if not title.lower().startswith("note:"):
                title = "Note: " + title
    # Security-header / hygiene classes (CSP, clickjacking, missing headers) are explicitly out of
    # scope on nearly every bounty program (CoinTR lists CSP/X-Frame/HSTS as "NOT accepted") and a
    # single site-wide policy re-fires on every crawled URL — 315 identical "confirmed" CSP findings
    # on one hunt. Born as info, collapsed to ONE per host, verdict cleared so the oracle stamp below
    # cannot re-confirm them and they never reach the submit queue. See [[huntr-no-false-positives]].
    if (cls or "").lower() in HYGIENE_CLASSES:
        import urllib.parse as _upf
        sev = "i"; verdict = "info"; det = False; proof = None
        _host = _upf.urlparse(endpoint or "").netloc or (endpoint or "")
        for _ef in STATE.get("findings", []):
            if (_ef.get("cls", "").lower() == (cls or "").lower()
                    and (_upf.urlparse(_ef.get("endpoint", "")).netloc or _ef.get("endpoint", "")) == _host):
                return
        if not title.lower().startswith("note:"):
            title = "Note: " + title
    key = (title + "|" + (endpoint or "")).lower()
    # Fast-path, UNLOCKED check: correct and sufficient in the overwhelmingly common single-threaded
    # case, and lets the common case skip the (sometimes slow — _det_oracle below can make a live
    # HTTP probe) rest of this function before even building `f`. The dual-agent BROAD+DEEP threads
    # (both reachable via the scan_endpoint tool -> scan_cell -> add_finding) can both pass this
    # check for the same finding at once — that race is closed by the SECOND, authoritative check
    # under _STATE_LOCK right before the actual append, below. Never hold the lock across the oracle
    # probe itself — that would serialize the two agents' network calls and defeat the whole point of
    # running them in parallel.
    if any((f["title"] + "|" + (f.get("endpoint") or "")).lower() == key for f in STATE["findings"]):
        return
    f = {
        "sev": sev, "label": SEVLABEL[sev], "title": title, "detail": detail or "",
        "cvss": cvss or "", "endpoint": endpoint or "", "cls": cls or "",
    }
    if source:                        # provenance (e.g. "nuclei") — the novelty gate uses it to tell n-days apart
        f["source"] = source
    if verdict:                       # tool-level evidence — reaches the submit queue without the AI judge
        f["verdict"] = verdict
        # _det = "undroppable": the judge may enrich but must not drop it. Default on for a confirmed
        # verdict (near-certain tools like sqlmap/OAST), but callers can pass det=False for
        # higher-FP-rate tools (e.g. nuclei) so the judge can still veto a false positive.
        if det if det is not None else (verdict == "confirmed"):
            f["_det"] = True
    # a caller that already ran the deterministic oracle (scan_cell) passes its result straight through,
    # so the finding carries authoritative proof without the stamp re-running the oracle.
    if isinstance(proof, dict) and proof.get("proven") is True:
        f["proof"] = {"proven": True, "method": str(proof.get("method", ""))[:60], "evidence": str(proof.get("evidence", ""))[:300]}
        f["_det"] = True
    # ── 0-token deterministic proof stamp (survives a later rate-limit pause) ──
    if not f.get("proof") and f.get("verdict") != "confirmed" and (cls or "").lower() not in HYGIENE_CLASSES \
            and os.environ.get("HUNTR_DET_PROOF", "1") != "0":
        try:
            ov, om, oe = _det_oracle(cls, title, endpoint, detail)
            if ov is True:
                f["verdict"] = "confirmed"; f["_det"] = True
                f["proof"] = {"proven": True, "method": "oracle:" + om, "evidence": oe}
                log("ok", "✓ deterministic proof · " + (cls or title)[:40] + " · " + om)
            elif ov is False and not f.get("verdict"):
                f["proof"] = {"proven": False, "method": "oracle:" + om, "evidence": oe}
        except Exception:
            pass
    # One-click reproduction: a deterministic command a triager pastes to reproduce,
    # plus the exact signal to look for. The trust layer — a finding verifiable in 30s.
    try:
        import proof_repro as _pr
        _rp = _pr.repro_for(f)
        if _rp:
            f["repro"] = _rp
    except Exception:
        pass
    with _STATE_LOCK:
        # authoritative re-check — see the comment on the fast-path check above
        if any((e["title"] + "|" + (e.get("endpoint") or "")).lower() == key for e in STATE["findings"]):
            return
        STATE["findings"].append(f)
        STATE["stats"]["findings"] = len(STATE["findings"])
    sevw = SEVLABEL[sev]
    log("warn" if sev in ("c", "h", "m") else "out", "⚑ " + sevw + "  " + title + (" · " + endpoint if endpoint else ""))


_FLUSH_LOCK = threading.Lock()

def flush():
    with _FLUSH_LOCK:
        STATE["updated"] = time.time()
        # mark_tested() mutates TESTED under _STATE_LOCK from any of the dual-agent threads or the
        # main sweep — snapshot it under the same lock, or a concurrent setdefault() adding a new key
        # mid-iteration raises "dictionary changed size during iteration" here.
        with _STATE_LOCK:
            STATE["tested"] = {ep: sorted(cs) for ep, cs in TESTED.items()}
        tmp = RUN.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(STATE))
        tmp.replace(RUN)
    _check_session_health()
    _check_circuit_breakers()


_CB_THRESHOLD = 5   # keep in sync with scope-guard.py:CB_THRESHOLD
_cb_last_check = [0.0]
_CB_CHECK_COOLDOWN = 5   # this only reads small local files (no network) — a light debounce is
                         # enough to keep flush()'s hot path from doing a directory listing every call


def _check_circuit_breakers():
    """scope-guard opens a per-host circuit breaker after 5 consecutive 403/429/timeouts and DENIES
    every further request to that host — logged only to audit.jsonl, with zero visibility anywhere
    else. A multi-hour autonomous hunt could silently stop testing a whole host for the rest of the
    budget window while the dashboard keeps showing 'running' as if nothing happened. This surfaces
    any currently-open breaker into STATE so the dashboard can show it, exactly like session_alert."""
    now = time.time()
    if now - _cb_last_check[0] < _CB_CHECK_COOLDOWN:
        return
    _cb_last_check[0] = now
    cbdir = HUNT_DIR / "cb"
    if not cbdir.exists():
        STATE.pop("circuit_open", None)
        return
    open_hosts = []
    try:
        for p in cbdir.iterdir():
            try:
                n = int(p.read_text().strip())
            except Exception:
                continue
            if n >= _CB_THRESHOLD:
                open_hosts.append(p.name)
    except Exception:
        return
    if open_hosts:
        STATE["circuit_open"] = sorted(open_hosts)
    else:
        STATE.pop("circuit_open", None)


_SESSION_CHECK_COOLDOWN = 600   # at most one LIVE probe per 10 minutes, not per flush() call
_session_last_check = [0.0]
_session_bad_streak = [0]
_pausing_for_creds = [False]   # reentrancy guard — _pause_for_creds's own flush() re-enters
                                # _check_session_health, which must not probe/pause a 2nd time


def _session_probe_url():
    host = (TARGET or "").split(",")[0].strip()
    if "://" in host:
        import urllib.parse as _up
        p = _up.urlparse(host)
        return f"{p.scheme}://{p.hostname or host}/"
    return "https://" + host.split("/")[0] + "/"


def _self_pause(reason, msg):
    """Self-pause the hunt for a problem that needs the operator's attention — generalized
    2026-10-23 from the original creds-only version after a live incident showed the SAME silent-
    degradation class applies beyond just sessions (see _pause_for_cdp's docstring). Grey/white-box
    hunting that silently degrades (no session, dead session, or — the live case — a dead CDP
    connection leaving an SPA's real API surface completely undiscovered) defeats the hunt's
    purpose with nothing forcing the operator to notice.

    Uses the EXACT same mechanism the operator's own Pause button already uses (self-SIGSTOP, not
    the RateLimitPause-exception path) — deliberately NOT the exception/process-exit/--resume-
    relaunch route, because relaunching re-enters main() with resumed=True, which skips every phase
    gated `if not resumed:` — including the exact phase that hit the problem. That would mean
    fixing the problem and resuming would never actually trigger the pass it paused to wait for.
    SIGSTOP instead freezes this exact process at this exact line; the operator's Resume action (or
    an API endpoint auto-resuming once the fix is saved) sends SIGCONT, and execution falls right
    back out of this function, in the same call stack, about to retry with live data — no relaunch,
    no skipped phase, no re-run of completed work either.

    reason: the paused_reason value the UI keys off (e.g. "creds-required", "cdp-required")."""
    with _STATE_LOCK:
        STATE["status"] = "paused"
        STATE["paused_reason"] = reason
        STATE["creds_alert"] = {"ts": time.time(), "msg": msg}   # one shared alert field for the UI
        STATE.setdefault("logs", []).append({"t": "err", "v": "⏸ PAUSED — " + msg})
        if len(STATE["logs"]) > 400:
            STATE["logs"] = STATE["logs"][-400:]
    flush()
    try:
        import signal as _sig
        os.kill(os.getpid(), _sig.SIGSTOP)
    except Exception:
        pass
    # execution resumes HERE once SIGCONT arrives — same process, same call stack, nothing re-run.
    with _STATE_LOCK:
        if STATE.get("paused_reason") == reason:
            STATE["status"] = "running"
            STATE.pop("paused_reason", None)
            STATE.pop("creds_alert", None)
            STATE.setdefault("logs", []).append({"t": "ok", "v": "▷ hunt resumed"})
    flush()


def _pause_for_creds(msg):
    """Self-pause for a missing/dead session — operator directive 2026-10-23: "if it lacks creds
    the hunt pauses and a pop-up appears... to make sure everything works perfectly in grey box and
    white box hunting." See _check_session_health's docstring for the exact silent-degradation
    incident this exists to actually stop, not just make visible."""
    _self_pause("creds-required", msg)


def _pause_for_cdp(msg):
    """Self-pause when CDP (the mechanism that discovers an SPA's REAL API surface — see
    phase_spa_capture) is configured but unreachable. CAUGHT LIVE 2026-10-23: a grey-box hunt
    against a Vue.js SPA finished with 0 findings while a months-long manual engagement against the
    SAME target had 50+ confirmed critical bugs (IDOR, auth bypass, ATO chains) living entirely
    under /system/v1/* — a path space the hunt's own endpoint list had ZERO entries for. Root cause:
    the operator's CDP session (port configured in creds, alive at hunt start — _auto_cdp only
    checks liveness ONCE, at start) died sometime before phase_spa_capture actually ran. Both
    js-api-harvest.py and browser-capture.py correctly reported "Connection refused" — this was
    never a silent code bug — but NOTHING escalated that into anything the operator would ever see:
    just two log lines that get rotated out of the 400-entry buffer by the rest of the hunt. The
    hunt then spent its entire budget thoroughly testing a surface that was structurally incapable
    of containing the real bugs, with no indication anything had gone wrong. Same fix class as
    _pause_for_creds — just for the OTHER thing that silently guts a grey/white-box hunt's value."""
    _self_pause("cdp-required", msg)


def _check_session_health():
    """Without this, an expired/revoked token or cookie causes NO error, NO exception, NO status
    change — the hunt just keeps running every authenticated scan unauthenticated for hours, and
    the operator only finds out when they notice 0 authed findings long after the fact (exactly
    the bug reported: laptop slept, session died, hunt kept 'running' with dead creds and nothing
    flagged it). Debounced to one live probe per _SESSION_CHECK_COOLDOWN (flush() can fire many
    times a second — this must not), and requires 2 consecutive bad readings before alerting, so
    a single transient 500/WAF hiccup doesn't false-alarm. Does NOT call log()/flush() itself —
    both already re-enter flush(), so mutate STATE directly and let the NEXT flush() persist it."""
    if MODE == "black":
        return
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    cookie = (c.get("cookie") or "").strip()
    ah_raw = (c.get("auth_header") or "").strip()
    if not (tok or cookie or ah_raw):
        return
    now = time.time()
    if now - _session_last_check[0] < _SESSION_CHECK_COOLDOWN:
        return
    _session_last_check[0] = now
    tool = HERE / "creds-test.py"
    if not tool.exists():
        return
    args = [sys.executable, str(tool), "--url", _session_probe_url(), "--json"]
    if tok:
        args += ["--authorization", tok]
    if cookie:
        args += ["--cookie", cookie]
    for ln in ah_raw.replace("\\n", "\n").splitlines():
        if ":" in ln:
            args += ["--auth-header", ln.strip()]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=35, env=os.environ)
        lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
        res = json.loads(lines[-1]) if lines else {}
    except Exception:
        return
    verdict = res.get("verdict")
    if verdict not in ("jwt-expired", "authed-looks-logged-out"):
        _session_bad_streak[0] = 0
        STATE.pop("session_alert", None)
        return
    _session_bad_streak[0] += 1
    if _session_bad_streak[0] < 2:
        return
    msg = ("Session token looks EXPIRED (its own JWT exp claim has already passed)"
           if verdict == "jwt-expired" else
           "Authenticated probe now looks logged-out on 2 consecutive checks — session may have "
           "been revoked or expired")
    STATE["session_alert"] = {"ts": now, "verdict": verdict, "msg": msg, "probe_url": res.get("url")}
    STATE["logs"].append({"t": "err", "v": "⚠ SESSION ALERT — " + msg + ". Update credentials to keep hunting authenticated."})
    if len(STATE["logs"]) > 400:
        STATE["logs"] = STATE["logs"][-400:]
    # ESCALATE 2026-10-23: a banner alone was easy to miss — "the operator only finds out when they
    # notice 0 authed findings long after the fact" was the exact bug this function already existed
    # to fix, but it only ever made the degradation VISIBLE, never actually stopped it. Self-pause
    # (reentrancy-guarded: _pause_for_creds's own flush() call re-enters this function, which would
    # otherwise probe/append-log a second time before the first SIGSTOP even lands).
    if not _pausing_for_creds[0]:
        _pausing_for_creds[0] = True
        try:
            _pause_for_creds(msg + ". Update credentials to resume authenticated hunting.")
        finally:
            _pausing_for_creds[0] = False
            _session_bad_streak[0] = 0  # fresh read after resume, whatever the operator did


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
    except Exception as e:
        # previously uncaught here — any other OSError/PermissionError/etc. would propagate
        # and kill the whole hunt-run.py process instead of just failing this one tool call.
        return "", "exec-error: " + str(e)[:150], -1


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


def phase_program_intel():
    """STRATUM 0 — Pre-hunt intelligence: run BEFORE any probe is sent.

    Flying blind costs bounties. This phase ingests everything PUBLIC about the program
    so the engine attacks with context, not randomly:

    1. Known disclosures (H1 hacktivity via disclosed-index.py) — dedup corpus seeded with
       what's already been reported; the engine skips re-finding it and focuses on the gaps.
    2. GitHub org full scan (github-recon.py) — trufflehog + gitleaks + CI/CD misconfig on
       the entire org's public repos. A single leaked .env → instant critical, zero probes.
    3. Shodan host intelligence (requires SHODAN_API_KEY) — exposed services, open ports,
       TLS certificates, banners. Finds the attack surface the web scanner never sees.
    4. Wayback Machine deleted endpoints — URLs the app removed from its SPA but forgot to
       restrict on the backend. "The endpoint exists but isn't linked" is a real pattern.
    5. Reward table parsing — extract bounty amounts from the scope data so attack-planner.py
       can rank attack cells by actual dollar value on THIS program, not generic severity.

    All results feed STATE["program_intel"] which attack-planner.py and phase_plan consume."""
    STATE["program_intel"] = {}
    prog = (PROGRAM or apex(TARGET) or TARGET).strip()
    prog_handle = re.sub(r"[^a-z0-9\-]", "", prog.lower().replace(".", "-"))

    # ── 1. Known disclosures ─────────────────────────────────────────────────────────────────
    if (HERE / "disclosed-index.py").exists():
        log("cmd", "$ disclosed-index — H1 hacktivity for " + prog_handle)
        out_d, _, rc = sh([sys.executable, str(HERE / "disclosed-index.py"),
                           "--program", prog, "--handle", prog_handle, "--limit", "100", "--json"],
                          timeout=40)
        try:
            dd = json.loads(out_d.strip().splitlines()[-1]) if out_d.strip() else {}
            known = dd.get("added", 0) or dd.get("count", 0)
            STATE["program_intel"]["disclosures"] = dd.get("reports", [])[:50]
            if known:
                log("ok", "✓ disclosures · " + str(known) + " known finding(s) indexed → dedup corpus")
            else:
                log("out", "→ disclosures · no public reports found for " + prog_handle)
        except Exception:
            pass

    # ── 2. GitHub org deep scan ───────────────────────────────────────────────────────────────
    # github-recon.py supersedes the basic _github_dork() added earlier — it clones repos
    # and runs trufflehog/gitleaks for real secret extraction, not just API filename matching.
    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if gh_token and (HERE / "github-recon.py").exists():
        log("cmd", "$ github-recon — org secrets + staging hosts + CI/CD misconfig")
        gr_args = ["--org", prog_handle, "--token", gh_token, "--json"]
        grd, _, _ = sh([sys.executable, str(HERE / "github-recon.py")] + gr_args, timeout=180)
        try:
            grd_j = json.loads(grd.strip().splitlines()[-1]) if grd.strip() else {}
            for f in grd_j.get("findings", []):
                add_finding(f.get("severity", "c"), "GitHub — " + (f.get("name") or f.get("type", "secret")),
                            f.get("detail") or f.get("description") or "", f.get("url") or f.get("file") or "",
                            cls="Secret/credential leak", verdict="confirmed")
            STATE["program_intel"]["github"] = grd_j
            if grd_j.get("findings"):
                log("ok", "✓ github-recon · " + str(len(grd_j["findings"])) + " finding(s)")
        except Exception:
            pass

    # ── 3. Shodan host intelligence ───────────────────────────────────────────────────────────
    shodan_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if shodan_key:
        import urllib.request as _shur, urllib.parse as _shup
        lithost = re.sub(r"^\*\.", "", TARGET).split("/")[0].strip()
        domain = ".".join(lithost.split(".")[-2:])
        url = ("https://api.shodan.io/shodan/host/search?key=" + _shup.quote(shodan_key) +
               "&query=" + _shup.quote("hostname:" + domain) + "&facets=port,country&minify=true")
        try:
            req = _shur.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with _shur.urlopen(req, timeout=15) as r:
                sd = json.loads(r.read().decode("utf-8", "ignore"))
            hosts_found = sd.get("total", 0)
            STATE["program_intel"]["shodan"] = sd
            # surface exposed non-standard ports as leads
            for match in (sd.get("matches") or [])[:20]:
                port = match.get("port")
                ip = match.get("ip_str")
                product = match.get("product") or ""
                banner = (match.get("data") or "")[:120]
                if port and port not in (80, 443):
                    add_finding("m", f"Shodan — non-standard port exposed: {ip}:{port} {product}",
                                banner, f"http://{ip}:{port}/", cls="Misconfig/CVE", verdict="likely")
            log("ok" if hosts_found else "out",
                f"{'✓' if hosts_found else '→'} shodan · {hosts_found} host(s) on {domain}")
        except Exception as _se:
            log("out", "→ shodan · " + str(_se)[:80])

    # ── 4. Wayback Machine deleted endpoints ─────────────────────────────────────────────────
    import urllib.request as _wbur
    lithost = re.sub(r"^\*\.", "", TARGET).split("/")[0].strip()
    domain = ".".join(lithost.split(".")[-2:])
    wb_url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json"
              f"&fl=original&collapse=urlkey&limit=500&filter=statuscode:200")
    try:
        req = _wbur.Request(wb_url, headers={"User-Agent": "Mozilla/5.0"})
        with _wbur.urlopen(req, timeout=20) as r:
            wb_data = json.loads(r.read().decode("utf-8", "ignore"))
        archived_urls = [row[0] for row in wb_data[1:] if row] if len(wb_data) > 1 else []
        # inject archived URLs as endpoint candidates for the surface phase
        existing_urls = {e["url"] for e in STATE.get("endpoints", [])}
        new_from_wb = 0
        for au in archived_urls[:300]:
            if au not in existing_urls and _in_scope(au)[0]:
                STATE.setdefault("endpoints", []).append({"url": au, "method": "GET",
                                                          "source": "wayback", "status": None})
                existing_urls.add(au)
                new_from_wb += 1
        STATE["program_intel"]["wayback_count"] = len(archived_urls)
        if new_from_wb:
            log("ok", f"✓ wayback · {len(archived_urls)} archived URL(s) · {new_from_wb} new endpoint(s) injected")
        else:
            log("out", f"→ wayback · {len(archived_urls)} archived URL(s) (all known or out-of-scope)")
    except Exception as _we:
        log("out", "→ wayback · " + str(_we)[:80])

    # ── 5. Reward table parsing ───────────────────────────────────────────────────────────────
    # Read the scope file for bounty amounts so attack-planner.py can rank by dollar value.
    scope_f = HUNT_DIR / "scope.md"
    scope_j = HUNT_DIR / "scope.json"
    reward_table = {}
    for sf in (scope_j, scope_f):
        if not sf.exists():
            continue
        try:
            raw = sf.read_text(errors="ignore")
            # JSON: look for "rewards", "bounties", "bounty" keys
            if sf.suffix == ".json":
                sd = json.loads(raw)
                for key in ("rewards", "bounties", "bounty", "reward_table"):
                    if isinstance(sd.get(key), dict):
                        reward_table.update(sd[key])
            else:
                # Markdown: parse rows like "| Critical | $5,000 - $10,000 |"
                for m in re.finditer(r"\|\s*(Critical|High|Medium|Low|Informational)\s*\|.*?\$([\d,]+)", raw, re.I):
                    sev = m.group(1).lower()[:1]
                    amt = int(re.sub(r"[,.]", "", m.group(2)))
                    reward_table[sev] = amt
        except Exception:
            pass
    if reward_table:
        STATE["program_intel"]["reward_table"] = reward_table
        log("ok", "✓ reward table · " + str(reward_table))

    flush()


def phase_auth_deep():
    """Deep authentication & session security testing — beyond JWT and basic IDOR.

    phase_authed establishes a session and does JWT attacks + BOLA/BFLA diffing.
    This phase goes deeper on the authentication/session layer itself:

    1. OAuth/OIDC flows (oauth-probe.py) — state param missing → CSRF, redirect_uri lax
       matching, implicit flow (token in URL fragment), PKCE downgrade, scope escalation.
    2. Password-reset flow — host-header injection in reset email, token reuse, timing-based
       username enumeration. "Forgot password" endpoints are the most-overlooked high-severity
       class because they're boring to click through manually.
    3. Session security — auth-session.py checks for JWT expiry problems, fixation, infinite
       sessions (no exp claim).
    4. MFA/OTP — rate limit on the OTP endpoint, backup code entropy.

    All findings added to STATE["findings"] with verdict="confirmed" where the oracle proves it."""
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    if MODE == "black" or (not tok and not c.get("cookie")):
        return
    hosts_live = [h["host"] for h in STATE["hosts"] if h.get("status")]
    base_url = ("https://" + hosts_live[0]) if hosts_live else ("https://" + apex(TARGET))
    eps = [e["url"] for e in STATE["endpoints"]]

    # ── 1. OAuth/OIDC audit ──────────────────────────────────────────────────────────────────
    oauth_eps = [e["url"] for e in STATE["endpoints"] if re.search(r"(/oauth|/authorize|/connect/|/openid|/oidc|/sso)", e.get("url", ""), re.I)]
    if not oauth_eps:
        # Guess common paths — but verify each returns a real OAuth-like response (not 404/redirect
        # to a marketing page) before handing it to oauth-probe. A guessed URL that returns 404 or
        # a plain HTML marketing page is not an OAuth endpoint and would false-positive every check.
        import urllib.request as _gur, urllib.error as _gue
        for _candidate in [base_url + "/oauth/authorize", base_url + "/api/oauth/authorize"]:
            try:
                _ok2, _ = _in_scope(_candidate)
                if not _ok2:
                    continue
                _gr = _gur.urlopen(_gur.Request(_candidate, headers={"User-Agent": "Mozilla/5.0"}), timeout=5)
                _gbody = _gr.read(512).decode("utf-8", "replace").lower()
                # A real OAuth /authorize returns JSON error, a login-redirect, or an OAuth error page,
                # NOT a generic marketing/404 page. Exclude obvious non-OAuth responses.
                if any(tok in _gbody for tok in ("not found", "404", "page not found", "error", "invalid_client", "client_id", "redirect_uri")):
                    if "invalid_client" in _gbody or "client_id" in _gbody or "redirect_uri" in _gbody:
                        oauth_eps.append(_candidate)  # looks like a real OAuth error → genuine endpoint
                    # else: generic 404/marketing page → skip
            except _gue.HTTPError as _ghe:
                if _ghe.code in (400, 401, 302, 303):  # 400/401 = real OAuth server rejecting bad req
                    _gbody = (_ghe.read(256) or b"").decode("utf-8", "replace").lower()
                    if any(tok in _gbody for tok in ("invalid_client", "client_id", "redirect_uri", "error", "oauth")):
                        oauth_eps.append(_candidate)
            except Exception:
                pass
    if (HERE / "oauth-probe.py").exists() and oauth_eps:
        for oa_ep in oauth_eps[:3]:
            log("cmd", "$ oauth-probe — state/CSRF · redirect_uri · implicit · PKCE · scope · " + oa_ep)
            op_args = ["--auth-url", oa_ep, "--json"]
            od = tool_json("oauth-probe.py", op_args, timeout=60)
            for f in (od or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "OAuth — " + (f.get("name") or f.get("type") or "misconfiguration"),
                            f.get("detail") or f.get("description") or "", oa_ep, cls="oauth", verdict="confirmed", det=True)
            if (od or {}).get("findings"):
                log("ok", "✓ oauth-probe · " + str(len(od["findings"])) + " finding(s) · " + oa_ep)
            mark_tested(oa_ep, "oauth")

    # ── 2. Password-reset host-header injection ────────────────────────────────────────────────
    # Finding the reset endpoint and checking if the server uses the Host header to build the
    # reset link. If it does, an attacker can redirect the reset email to their domain.
    reset_eps = [e["url"] for e in STATE["endpoints"] if re.search(r"(reset|forgot|recover|password)", e.get("url", ""), re.I)]
    if not reset_eps:
        reset_eps = [base_url + "/api/password/reset", base_url + "/forgot-password",
                     base_url + "/api/auth/forgot", base_url + "/auth/password/reset"]
    import urllib.request as _rur, urllib.error as _rue
    _ah = _auth_headers()
    for rst_ep in reset_eps[:4]:
        _ok, _ = _in_scope(rst_ep)
        if not _ok:
            continue
        try:
            evil_host = "evil.huntr-test.com"
            req_h = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json",
                     "Host": evil_host, "X-Forwarded-Host": evil_host, "X-Host": evil_host}
            for k, v in _ah.items():
                req_h[k] = v
            # POST with a dummy email — we're probing the reset SEND endpoint, not clicking the link
            payload = json.dumps({"email": "security-test@huntr-probe.local"}).encode()
            req = _rur.Request(rst_ep, data=payload, headers=req_h, method="POST")
            with _rur.urlopen(req, timeout=8) as r:
                status = r.status
                body = r.read(2048).decode("utf-8", "ignore")
                # If the reset link in the email would contain our evil host, the email server
                # would confirm it — we can only detect it via a DNS callback. Log as "likely".
                if status in (200, 202, 204):
                    add_finding("h", "Password-reset host-header injection (likely)",
                                f"POST {rst_ep} with Host: {evil_host} returned {status}. "
                                "If the reset link is built from the Host header, the token may be redirected to the attacker's domain. "
                                "Verify by checking the reset email — does it contain evil.huntr-test.com?",
                                rst_ep, cls="host-header", verdict="likely")
                    mark_tested(rst_ep, "host-header")
                    break
        except (_rue.HTTPError, _rue.URLError, Exception):
            pass

    # ── 3. Session security check (JWT expiry / infinite sessions) ────────────────────────────
    tok_bare = re.sub(r"^Bearer\s+", "", tok, flags=re.I).strip() if tok else ""
    if tok_bare and re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", tok_bare):
        try:
            import base64 as _b64
            payload_part = tok_bare.split(".")[1]
            pad = "=" * (4 - len(payload_part) % 4)
            claims = json.loads(_b64.urlsafe_b64decode(payload_part + pad).decode("utf-8", "ignore"))
            exp = claims.get("exp")
            iat = claims.get("iat")
            if exp is None:
                add_finding("m", "JWT with no expiry (infinite session)",
                            "The supplied JWT has no 'exp' claim — it never expires. "
                            "A stolen token grants permanent access with no rotation path.",
                            base_url, cls="jwt", verdict="confirmed", det=True)
            elif exp > 0 and (exp - time.time()) > 30 * 86400:
                days = int((exp - time.time()) / 86400)
                add_finding("l", f"JWT with excessive expiry ({days} days)",
                            f"Token expires in {days} days. Long-lived tokens increase window of compromise.",
                            base_url, cls="jwt", verdict="confirmed", det=True)
        except Exception:
            pass

    # ── 4. OTP rate-limit probe ────────────────────────────────────────────────────────────────
    # Match only in the URL path (not the query string) and only as true path segments
    # (preceded by / or start) so "2fa" inside a UUID like "62fa…" doesn't match.
    def _is_otp_ep(url):
        from urllib.parse import urlparse as _up
        path = _up(url).path or ""
        return bool(re.search(r"(?:^|/)(otp|mfa|2fa|verify-otp|totp|authenticat)(?:[/_?-]|$)", path, re.I))
    otp_eps = [e["url"] for e in STATE["endpoints"] if _is_otp_ep(e.get("url", ""))]
    for otp_ep in otp_eps[:2]:
        _ok, _ = _in_scope(otp_ep)
        if not _ok:
            continue
        try:
            # Fire 6 rapid OTP guesses and check if ANY returns a non-rate-limit response
            codes_tried = 0
            rl_hit = False
            for test_code in ["000000", "111111", "123456", "999999", "000001", "000002"]:
                req_h = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
                if tok and not tok.startswith("session-identity"):
                    req_h["Authorization"] = tok if tok.startswith("Bearer ") else "Bearer " + tok
                payload = json.dumps({"code": test_code, "otp": test_code, "token": test_code}).encode()
                req = _rur.Request(otp_ep, data=payload, headers=req_h, method="POST")
                try:
                    with _rur.urlopen(req, timeout=5) as r:
                        if r.status == 429:
                            rl_hit = True; break
                        codes_tried += 1
                except _rue.HTTPError as he:
                    if he.code == 429:
                        rl_hit = True; break
                    codes_tried += 1
                except Exception:
                    break
            if codes_tried >= 5 and not rl_hit:
                add_finding("h", "MFA/OTP — no rate limit on verification endpoint",
                            f"POST {otp_ep} accepted {codes_tried} rapid OTP guesses without a 429 response. "
                            "Brute-force 6-digit TOTP is trivial without rate limiting.",
                            otp_ep, cls="authz", verdict="confirmed", det=True)
                mark_tested(otp_ep, "authz")
        except Exception:
            pass

    flush()


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
    # source repo hosts are NOT added to the web crawl allow list — they are handled separately
    allow.write_text("\n".join(sorted(x for x in lines if x)) + "\n")
    log("cmd", "$ scope-guard --init  (" + str(len(WEB_ASSETS)) + " web + " + str(len(SOURCE_ASSETS)) + " source asset(s))")
    log("ok", "✓ scope locked · " + str(len([a for a in WEB_ASSETS if _asset_host(a)[1]])) + " wildcard + " +
        str(len([a for a in WEB_ASSETS if not _asset_host(a)[1]])) + " exact host(s) · mode: " + MODE + "-box")


def _cloud_recon():
    """Probe common S3 bucket name variants for the target brand (unauthenticated data leaks).

    A single publicly readable S3 bucket is routinely a critical/high finding and takes <10s to
    check. We probe /<brand>/, /<brand>-dev/, /<brand>-backup/ etc. with a single HTTP GET;
    the XML ListBucketResult response is unambiguous proof. Does NOT enumerate bucket contents —
    just confirms existence + public access.  Non-fatal: any network error silently skips."""
    import urllib.request as _ur
    import urllib.error as _ue
    # derive the root brand name — "acme" from "acme.example.com"
    root = re.sub(r"^\*\.", "", TARGET).split("/")[0].strip()
    root_parts = root.split(".")
    brand = root_parts[-2] if len(root_parts) >= 2 else root_parts[0]
    brand = re.sub(r"[^a-z0-9]", "", brand.lower())
    if not brand or len(brand) < 3:
        return
    variants = [brand, brand + "-dev", brand + "-staging", brand + "-test",
                brand + "-backup", brand + "-data", brand + "-assets",
                brand + "-static", brand + "-media", brand + "-prod",
                brand + "-files", brand + "-uploads", brand + "-public"]
    found = 0
    for v in variants:
        # S3 virtual-hosted style
        s3_url = f"https://{v}.s3.amazonaws.com/"
        try:
            req = _ur.Request(s3_url, headers={"User-Agent": "Mozilla/5.0"})
            with _ur.urlopen(req, timeout=5) as r:
                body = r.read(4096).decode("utf-8", "ignore")
                if "ListBucketResult" in body or "<Contents>" in body:
                    add_finding("c", "Open S3 bucket — publicly readable",
                                f"s3://{v} lists objects unauthenticated at {s3_url}",
                                s3_url, cls="Misconfigured cloud storage", verdict="confirmed")
                    found += 1
        except (_ue.HTTPError, _ue.URLError, Exception):
            pass
    if found:
        log("ok", f"✓ cloud recon · {found} open S3 bucket(s) — CRITICAL finding(s) added")
    else:
        log("out", f"→ cloud recon · no open S3 buckets found for {brand} variants")


def _github_dork():
    """Search GitHub for credential files in the target org's public repos.

    Requires GITHUB_TOKEN env var. Finds .env files, DB_PASSWORD, AWS keys etc. A leaked
    secret in a public repo is an instant critical finding. Silently skips if no token."""
    import urllib.request as _ur
    import urllib.parse as _up
    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not gh_token:
        return   # silent skip — GITHUB_TOKEN is optional
    # derive org from PROGRAM or apex of TARGET
    org_raw = (PROGRAM or apex(TARGET) or TARGET).split(".")[0].lower()
    org = re.sub(r"[^a-z0-9\-]", "", org_raw)
    if not org or len(org) < 3:
        return
    dork_queries = [
        f"org:{org} filename:.env",
        f"org:{org} AWS_SECRET_ACCESS_KEY",
        f"org:{org} DB_PASSWORD",
        f"org:{org} secret_key language:Python",
        f"org:{org} api_key language:YAML",
    ]
    headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "huntr/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    found = 0
    for q in dork_queries:
        url = "https://api.github.com/search/code?q=" + _up.quote(q) + "&per_page=5"
        try:
            req = _ur.Request(url, headers=headers)
            with _ur.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
                for item in (data.get("items") or [])[:3]:
                    file_url = item.get("html_url") or item.get("url") or ""
                    repo = item.get("repository", {}).get("full_name") or ""
                    add_finding("c", "GitHub secret exposure — " + (item.get("name") or "credentials"),
                                f"Query: {q}\nRepo: {repo}\nFile: {file_url}\n"
                                "Public repo contains credential file — rotate immediately.",
                                file_url, cls="Secret/credential leak", verdict="confirmed")
                    found += 1
        except Exception:
            pass
    if found:
        log("ok", f"✓ github dork · {found} secret file(s) in {org}'s public repos — CRITICAL")
    else:
        log("out", f"→ github dork · no exposed secrets in {org}'s public repos")


def phase_recon():
    """Delegates to tools/recon.py — the resumable, failure-classifying recon
    primitive (also what /autopilot drives). Replaces the old inline version
    of this logic, which duplicated recon.py's job with silent
    `except Exception: pass`/`continue` at every failure point and no
    checkpointing — a crash here used to mean starting the whole phase over.

    recon.py checkpoints its own state to <HUNT_DIR>/recon-state.json, so a
    crash of hunt-run.py itself (not just this phase) also resumes cleanly:
    the next phase_recon() call re-runs recon.py against the same state file
    and it skips every asset already resolved.
    """
    stage("Recon", 18)
    if not WEB_ASSETS and SOURCE_ASSETS:
        log("warn", "⚠ scope contains only source repos — web/API hunt skipped. Use a source-review hunt type for GitHub targets.")
        log("out", "  repos: " + ", ".join(SOURCE_ASSETS[:5]))
        STATE["hosts"] = []; STATE["stats"]["subs"] = 0; STATE["stats"]["live"] = 0
        STATE["source_assets"] = SOURCE_ASSETS
        flush(); stage("Recon", 45); return

    recon_tool = HERE / "recon.py"
    state_file = HUNT_DIR / "recon-state.json"
    log("cmd", "$ recon.py · " + str(len(WEB_ASSETS)) + " web asset(s)")

    cmd = [sys.executable, str(recon_tool), "--assets", ",".join(WEB_ASSETS), "--state", str(state_file)]
    if os.environ.get("HUNT_SINGLE") == "1":
        cmd.append("--single-host")
    if os.environ.get("HUNT_NO_BRUTE") == "1":
        cmd.append("--no-brute")
    denyf = HUNT_DIR / "scope.deny"
    if denyf.exists():
        cmd += ["--deny-file", str(denyf)]

    hosts, result, attempts = [], None, 0
    # recon.py reports work still pending via unprobed_remaining instead of silently
    # finishing early — loop it until that hits 0 or we've clearly stopped making
    # progress (bounded retries, not an infinite loop on a genuinely stuck host).
    while attempts < 6:
        attempts += 1
        out, err, rc = sh(cmd, timeout=400)
        try:
            result = json.loads(out.strip().splitlines()[-1])
        except Exception as e:
            log("warn", "→ recon.py produced no parseable result (attempt " + str(attempts) + "): " + str(e)[:120])
            if err:
                log("warn", "  stderr: " + err.strip()[-300:])
            break
        for e in result.get("errors", []):
            # surface classified failures instead of swallowing them — exactly the thing
            # the old inline version never did
            tag = e.get("asset") or e.get("host") or "?"
            log("warn", "→ recon: " + tag + " — " + e.get("kind", "error") + (" (" + e.get("step", "") + ")" if e.get("step") else ""))
        for w in result.get("warnings", []):
            log("warn", "→ recon: " + str(w.get("detail") or w.get("kind") or w))
        if not result.get("unprobed_remaining"):
            break
        log("out", "→ recon: " + str(result["unprobed_remaining"]) + " host(s) still unprobed, continuing…")

    if result:
        hosts = result.get("hosts", [])
    hosts = hosts[:200]
    live = [h for h in hosts if h.get("status")]
    asset_hosts = {_asset_host(a)[0] for a in WEB_ASSETS}
    hosts.sort(key=lambda h: (0 if h["host"] in asset_hosts and h.get("status") else 1 if h.get("status") else 2))

    STATE["hosts"] = hosts
    STATE["stats"]["subs"] = result.get("total_count", len(hosts)) if result else len(hosts)
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

    # ── Cloud asset discovery ────────────────────────────────────────────────────────────────
    # Probe S3 bucket variants derived from the target brand name (unauthenticated data leaks).
    # A single open bucket with PII/keys is routinely a critical/high finding — worth the 10-20
    # fast HEAD probes even when the main recon found nothing interesting.
    _cloud_recon()

    # ── GitHub secret dorking ─────────────────────────────────────────────────────────────────
    # Only if GITHUB_TOKEN is set. Search public repos for credential files (.env, config.yml,
    # etc.) belonging to the target's GitHub org — leaked API keys, DB passwords, cloud creds.
    _github_dork()


def _merge_into_global_graph():
    """Merge this hunt's final exploit-chain graph into a persistent, cross-hunt knowledge graph
    (~/.huntr/global-graph/graph.json) — operator directive 2026-10-23 ("what other features can we
    add"). A per-hunt graph only knows this ONE target; a graph that accumulates across every hunt
    this operator has run can answer questions a single hunt never could: "has this exact WAF/CDN
    fingerprint shown this bypass before, on a different target?", "which tech-stack signature most
    often correlates with which vuln class?" — patterns hunt-brain.py's flat similarity search can
    miss because it has no structured relationship model, just text-similarity recall.

    Deterministic (`graphify merge-graphs`), 0 LLM tokens, fast — safe to run synchronously at hunt
    end. Silently skips if this hunt produced no graph or graphify is unavailable."""
    this_graph = HUNT_DIR / "graphify-out" / "graph.json"
    if not this_graph.exists():
        return
    try:
        global_dir = Path.home() / ".huntr" / "global-graph"
        global_dir.mkdir(parents=True, exist_ok=True)
        global_graph = global_dir / "graph.json"
        if global_graph.exists():
            out, err, rc = sh(["graphify", "merge-graphs", str(global_graph), str(this_graph),
                               "--out", str(global_graph)], timeout=120)
        else:
            import shutil as _shu5
            _shu5.copy(str(this_graph), str(global_graph))
            rc = 0
        if rc == 0:
            log("ok", "◆ merged into cross-hunt knowledge graph · " + str(global_graph))
        else:
            log("out", "→ cross-hunt graph merge skipped (" + (err or "").strip()[:80] + ")")
    except Exception as e:
        log("out", "→ cross-hunt graph merge skipped (" + str(e)[:80] + ")")

    stage("Recon", 45)


def _build_surface_graph(endpoints, deep=False, update=False, blocking=False):
    """Build / update a graphify knowledge graph of the target's surface — Claude-driven, not just
    structural. Writes into <HUNT_DIR>/graphify-out/.

    REBUILT 2026-10-23 (operator: "connect the graph to claude to make claude smarter, stronger, use
    less tokens... what other features can we add"). The bare `graphify <dir> --update` subprocess
    call only does fast structural/AST extraction (free, no LLM) — it can pull URL path structure but
    can't understand that a sentence describing an IDOR means "this finding ENABLES cross-user data
    read" or that two endpoints share a trust boundary. Semantic extraction needs either GEMINI_API_KEY
    (not set here) or a host agent doing the reasoning — and we already have a proven mechanism for
    that: invoke `claude -p "/graphify <dir>"` so a REAL Claude Code session (not a bare completion)
    runs the actual graphify SKILL, which dispatches its own subagents to extract entities/relationships
    from prose with its own reasoning. Live-verified 2026-10-23 against a tiny test corpus: a sentence
    merely mentioning "potential IDOR" produced a standalone `IDOR Vulnerability on /api/orders/{id}`
    node, and the extraction found a genuine cross-community edge linking it to an admin role-check —
    relationships no bare structural pass could find. Falls back to the bare binary (structural-only,
    still useful) if the `claude` CLI is unavailable. Runs in a background thread — Claude-driven
    extraction takes real minutes, must never block the hunt pipeline.

    deep=True also writes findings.md with explicit REQUIRES/ENABLES framing per confirmed finding —
    this is what turns `graphify path "unauthenticated" "admin-panel"` into a genuine multi-hop
    exploit-chain query instead of a structural URL-adjacency guess (same pattern arXiv 2610.20902
    describes: encode pre/post-conditions as edges, query the chain instead of re-reasoning over every
    finding from scratch). Call deep=True AFTER findings exist (post-hunt), not during initial recon.

    update=True passes --update to the skill invocation for an incremental re-extract (this graph
    already exists from an earlier deep=False pre-hunt call) instead of a fresh build.

    blocking=True waits for the build instead of firing a daemon thread. Only use this for the
    LAST build of a hunt (after phase_hard_triage's final pass, right before the process exits) —
    a daemon thread started this close to process exit can be killed mid-build the moment main()
    returns, silently losing the one graph build that actually has confirmed findings to encode."""
    recon_dir = HUNT_DIR / "recon"
    try:
        recon_dir.mkdir(parents=True, exist_ok=True)
        ep_file = recon_dir / "endpoints.txt"
        ep_file.write_text("\n".join(e["url"] for e in endpoints) + "\n")

        # POISONING DEFENSE (GraphRAG-under-fire: arXiv 2501.14050 — a hostile target can plant
        # misleading content in crawled responses specifically to manipulate graph-based agent
        # reasoning). Tag provenance so Claude's extraction — and later readers of the graph —
        # know which nodes come from untrusted target-controlled data vs. HUNTR's own analysis.
        (recon_dir / "PROVENANCE.md").write_text(
            "# Provenance — trust level of each file in this corpus\n\n"
            "- endpoints.txt: crawled directly from the TARGET. Untrusted data — a URL path or "
            "parameter name is whatever the target server chose to serve, not a verified fact.\n"
            "- biz-logic.md (if present): HUNTR's own pattern-matched analysis of the crawled "
            "surface — moderate trust, still derived from target-controlled input.\n"
            "- findings.md (if present): HUNTR's own CONFIRMED findings, each independently proven "
            "by a deterministic oracle (real HTTP request + real response check) before being "
            "recorded — high trust, this is HUNTR's verified output, not raw target content.\n"
        )

        biz = STATE.get("biz_logic") or {}
        if biz:
            lines = ["# Business Logic Model\n"]
            if biz.get("entities"):
                lines.append("## Entities\n" + "\n".join("- " + str(e) for e in biz["entities"][:30]) + "\n")
            if biz.get("roles"):
                lines.append("## Roles\n" + "\n".join("- " + str(r) for r in biz["roles"][:15]) + "\n")
            if biz.get("flows"):
                lines.append("## Flows\n" + "\n".join("- " + str(f) for f in biz["flows"][:20]) + "\n")
            if biz.get("value_endpoints"):
                lines.append("## Value-flow endpoints (money/credits/quota — race-condition targets)\n" +
                             "\n".join("- " + str(u) for u in biz["value_endpoints"][:20]) + "\n")
            if biz.get("admin_endpoints"):
                lines.append("## Admin/privileged endpoints (BFLA targets)\n" +
                             "\n".join("- " + str(u) for u in biz["admin_endpoints"][:20]) + "\n")
            if biz.get("trust_boundaries"):
                lines.append("## Trust boundaries — what the app trusts WITHOUT verifying\n" +
                             "\n".join("- " + str(t.get("signal", "")) + ": " + str(t.get("example_url", ""))
                                      for t in biz["trust_boundaries"][:15]) + "\n")
            if len(lines) > 1:
                (recon_dir / "biz-logic.md").write_text("\n".join(lines))

        if deep:
            findings = [f for f in STATE.get("findings", [])
                       if f.get("verdict") in ("confirmed", "likely", "true_positive")
                       and not f.get("noise")]
            if findings:
                lines = ["# Confirmed Findings — Exploit Chain Model\n",
                         "Each finding states what it REQUIRES (precondition) and what it ENABLES "
                         "(postcondition). Use this to find multi-step attack chains: a chain exists "
                         "when one finding's ENABLES satisfies another's REQUIRES.\n"]
                for f in findings[:40]:
                    cls_l = str(f.get("cls", "")).lower()
                    requires = ("an authenticated session" if cls_l in ("idor", "authz", "race", "bola")
                               else "no authentication (reachable pre-auth)")
                    lines.append("## " + str(f.get("title", "")))
                    lines.append("- Endpoint: " + str(f.get("endpoint", "")))
                    lines.append("- Class: " + str(f.get("cls", "")))
                    lines.append("- Severity: " + str(f.get("sev", "")))
                    lines.append("- Requires: " + requires)
                    lines.append("- Enables: " + str(f.get("detail", ""))[:300])
                    if f.get("impact_evidence"):
                        lines.append("- Proven impact (independently escalated): " + str(f["impact_evidence"])[:300])
                    lines.append("")
                (recon_dir / "findings.md").write_text("\n".join(lines))
    except Exception:
        return

    def _run():
        cli = None
        try:
            import shutil as _shu3
            cli = _shu3.which("claude") or os.path.expanduser("~/.local/bin/claude")
        except Exception:
            pass
        if cli and os.path.exists(cli):
            try:
                cmd_txt = "/graphify recon" + (" --update" if update else "")
                r = subprocess.run(
                    [cli, "-p", cmd_txt,
                     "--model", MODEL_LEAD.get("model") or "claude-sonnet-4-6",
                     "--add-dir", str(HUNT_DIR),
                     "--permission-mode", "bypassPermissions",
                     "--allowedTools", "Bash", "Read", "Write",
                     "--disallowedTools", "WebFetch", "WebSearch",
                     "--no-session-persistence"],
                    cwd=str(HUNT_DIR), capture_output=True, text=True, timeout=600,
                    env=dict(os.environ))
                if (HUNT_DIR / "graphify-out" / "graph.json").exists():
                    log("ok", "◆ surface graph built (Claude-driven semantic extraction" +
                        (", deep/exploit-chain" if deep else "") + ") · " +
                        str(len(endpoints)) + " endpoints → graphify-out/")
                    return
            except Exception:
                pass
        # Fallback: bare binary, structural-only (still useful, just thinner — no semantic
        # relationships from biz-logic.md/findings.md, since that needs a reasoning pass).
        out, err, rc = sh(["graphify", str(recon_dir), "--no-viz", "--update",
                           "--out", str(HUNT_DIR / "graphify-out")], timeout=60)
        if rc == 0:
            log("ok", "◆ surface graph built (structural only — claude CLI unavailable) · " +
                str(len(endpoints)) + " endpoints → graphify-out/")
        else:
            log("out", "→ surface graph skipped (" + (err.strip() or "graphify not found")[:80] + ")")

    if blocking:
        _run()
    else:
        threading.Thread(target=_run, daemon=True).start()


def phase_surface():
    """Delegates to tools/surface.py — same resumable, failure-classifying
    contract as phase_recon()/recon.py. Replaces the old inline crawl, which
    had ~8 `except Exception: pass` sites (robots/sitemap fetch, katana, gau,
    waybackurls each swallowed independently) and no checkpointing: a crash
    mid-crawl used to mean re-crawling every host from scratch.
    """
    stage("Surface", 52)
    live = [h for h in STATE["hosts"] if h.get("status")]
    # crawl the user's explicit asset hosts first, then other live hosts
    asset_hosts = {_asset_host(a)[0] for a in WEB_ASSETS}
    primary = [h for h in live if h.get("host") in asset_hosts]
    others = [h for h in live if h.get("host") not in asset_hosts]
    cap = max(4, min(len(primary) + 2, 8))   # make room for all explicit assets
    targets = (primary + others or STATE["hosts"])[:cap]
    if not targets:
        STATE["endpoints"] = []; STATE["stats"]["endpoints"] = 0
        flush(); stage("Surface", 82); return

    surface_tool = HERE / "surface.py"
    state_file = HUNT_DIR / "surface-state.json"
    targets_json = json.dumps([{"host": h.get("host"), "scheme": h.get("scheme")} for h in targets])
    log("cmd", "$ surface.py · " + str(len(targets)) + " host(s)")

    cmd = [sys.executable, str(surface_tool), "--hosts", targets_json,
           "--state", str(state_file), "--max-hosts", str(len(targets))]
    if STEALTH:
        cmd.append("--stealth")
    if os.environ.get("HUNT_SINGLE") == "1":
        cmd.append("--single-host")

    endpoints, result, attempts = [], None, 0
    while attempts < 4:
        attempts += 1
        out, err, rc = sh(cmd, timeout=600)
        try:
            result = json.loads(out.strip().splitlines()[-1])
        except Exception as e:
            log("warn", "→ surface.py produced no parseable result (attempt " + str(attempts) + "): " + str(e)[:120])
            if err:
                log("warn", "  stderr: " + err.strip()[-300:])
            break
        for e in result.get("errors", []):
            tag = e.get("host") or "?"
            log("warn", "→ surface: " + tag + " — " + e.get("kind", "error") + (" (" + e.get("step", "") + ")" if e.get("step") else ""))
        for w in result.get("warnings", []):
            log("warn", "→ surface: " + str(w.get("detail") or w.get("kind") or w))
        if not result.get("hosts_remaining"):
            break
        log("out", "→ surface: " + str(len(result["hosts_remaining"])) + " host(s) still uncrawled, continuing…")

    if result:
        endpoints = result.get("endpoints", [])
    # HTML-decode URLs: katana scrapes hrefs from raw HTML where & is encoded as &amp;
    # Storing "?foo=1&amp;bar=2" instead of "?foo=1&bar=2" causes every authz/param scan
    # cell to fail with "errored (unknown)" because the server never sees a valid query string.
    import html as _html
    for _ep in endpoints:
        if "&amp;" in _ep.get("url", ""):
            _ep["url"] = _html.unescape(_ep["url"])
    STATE["endpoints"] = endpoints
    STATE["stats"]["endpoints"] = len(endpoints)
    flush()
    for e in endpoints[:20]:
        log("out", "→ " + e["url"][:110])
    if not endpoints:
        log("warn", "→ no endpoints crawled (host may block crawlers or have no links)")
    else:
        log("ok", "✓ " + str(len(endpoints)) + " endpoints mapped across " +
            str((result or {}).get("hosts_crawled", len(targets))) + " host(s)")

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
            out, err, rc = sh(["ffuf", "-u", base + "/FUZZ", "-w", str(wl), "-rate", str(rl),
                            "-t", "10" if not STEALTH else "4", "-timeout", "8", "-s",
                            "-mc", "200,204,301,302,307,401,403,405,500"], timeout=70)
            if err in ("timeout", "not-found") or (rc not in (0, None) and not out):
                # PREVIOUSLY: err/rc discarded entirely — ffuf timing out silently looked identical
                # to ffuf running fine and finding nothing, so a budget-starved target quietly got
                # zero amplifier coverage with no sign anything went wrong.
                log("warn", "→ ffuf " + host + ": " + (err or ("exit " + str(rc))) + " — no amplifier coverage this host")
                continue
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
        import html as _html
        u = _html.unescape(u) if "&amp;" in u else u
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

def phase_mobile():
    """Mobile scope (scope_types includes 'mobile'): mine the APK's backend surface — hosts, API paths,
    WS endpoints, hardcoded secrets — and fold the IN-SCOPE ones into the hunt. The mobile backend is
    usually hosts/endpoints the web app never exposes. APK path from creds.json['apk'] or --apk; the
    file is only read (unzip/strings), never run. Secrets are reported (public-by-design tagged info)."""
    if "mobile" not in [s.lower() for s in SCOPE_TYPES]:
        return
    if not (HERE / "apk-recon.py").exists():
        return
    apk = (_creds().get("apk") or "").strip() or arg("--apk")
    if not apk or not Path(apk).exists():
        log("out", "→ mobile in scope but no APK supplied (set creds.apk or --apk) — skipping mobile recon")
        return
    stage("Mobile", 30)
    log("cmd", "$ apk-recon — extracting backend surface from the APK")
    ap = apex(TARGET)
    d = tool_json("apk-recon.py", ["--apk", apk, "--host-filter", ap, "--json"], timeout=300)
    if not isinstance(d, dict):
        log("warn", "→ apk-recon produced no result — " + (_LAST_TOOL_ERR or "unknown")); return
    existing = {e["url"] for e in STATE["endpoints"]}
    added = 0
    base = "https://" + ap
    for u in (d.get("urls") or []):
        host = re.sub(r"^https?://", "", u).split("/")[0]
        if ap in host and u not in existing:
            STATE["endpoints"].append({"url": u, "host": ap, "src": "apk"}); existing.add(u); added += 1
    for p in (d.get("api_paths") or []):
        u = base + p
        if u not in existing:
            STATE["endpoints"].append({"url": u, "host": ap, "src": "apk"}); existing.add(u); added += 1
    STATE["stats"]["endpoints"] = len(STATE["endpoints"])
    # non-public hardcoded secrets → findings (public-by-design tagged ones are info via fp_rules)
    real_secrets = [s for s in (d.get("secrets") or []) if not s.get("public_by_design")]
    for s in real_secrets[:30]:
        add_finding("m", "Hardcoded secret in APK — " + s.get("type", "secret"),
                    "Value (truncated): " + str(s.get("value", "")) + " — verify it grants privileged access before rating",
                    "apk://" + os.path.basename(apk), cls="secret-leak", verdict="likely")
    STATE["mobile"] = {"package": d.get("package"), "hosts": d.get("hosts", []),
                       "api_paths": len(d.get("api_paths") or []), "secrets": len(real_secrets)}
    log("ok", "✓ APK recon · pkg " + str(d.get("package")) + " · " + str(len(d.get("hosts") or [])) +
        " host(s) · " + str(added) + " endpoint(s) → surface · " + str(len(real_secrets)) + " non-public secret(s)")
    flush()


def phase_spa_capture():
    """SPA surface discovery: katana only sees linked HTML, so a single-page app's REAL API (the XHR/
    fetch calls its JS fires at runtime, often POST with params) is invisible to the crawler. With a
    session, drive a real browser (browser-capture) to record those calls and fold them into the
    surface — so the scanners and the exploit-agent test the endpoints that actually matter."""
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

    # CAUGHT LIVE 2026-10-23: a grey-box hunt against a Vue.js SPA finished with 0 findings while a
    # months-long manual engagement against the SAME target had 50+ confirmed critical bugs (IDOR,
    # auth bypass, full ATO chains) living entirely under /system/v1/* — a path space this hunt's
    # endpoint list had ZERO entries for. Root cause: the CDP port in creds was alive when the hunt
    # STARTED (_auto_cdp only checks liveness once, then moves on) but had died by the time THIS
    # phase actually ran — js-api-harvest.py and browser-capture.py both correctly reported
    # "Connection refused", but that was two log lines in a 400-entry ring buffer the rest of the
    # hunt rotated out before the operator ever saw them. Check liveness HERE, right before use, not
    # just once at hunt start — and if it's dead, try to self-heal via _auto_cdp() (same persistent
    # profile dir, so a relaunch recovers the actual logged-in session) before accepting degraded
    # coverage silently.
    cdp = str(c.get("cdp_port") or "").strip()
    if cdp and not _cdp_alive(int(cdp)):
        log("warn", "⚠ CDP port " + cdp + " configured but unreachable — the SPA's real API surface "
            "cannot be captured without it. Attempting to re-attach…")
        _auto_cdp()
        c = _creds()
        cdp = str(c.get("cdp_port") or "").strip()
        if cdp and _cdp_alive(int(cdp)):
            log("ok", "✓ CDP recovered on port " + cdp)
        else:
            _pause_for_cdp(
                "CDP session is unreachable and could not be auto-recovered — this hunt is grey/white-box "
                "but cannot capture the app's real runtime API surface (the SPA's own XHR/fetch calls and "
                "JS-bundle-declared routes). Every scanner will only see the shallow, generic surface. "
                "Re-attach a live Chrome with --remote-debugging-port (or update the CDP port) to fix this "
                "before resuming, or resume anyway to accept a black-box-equivalent surface for this app.")
            c = _creds()
            cdp = str(c.get("cdp_port") or "").strip()
            if cdp and _cdp_alive(int(cdp)):
                log("ok", "✓ CDP attached after resume · " + cdp)
            else:
                log("warn", "→ resumed without a live CDP session — SPA capture will cover the "
                    "unauthenticated/public surface only")
    # the operator may have also refreshed cookie/token/UA in the same modal while fixing CDP —
    # re-read everything from creds.json now, not just the cdp_port this block has been tracking.
    cookie = (c.get("cookie") or "").strip()
    tok = (c.get("session_token") or "").strip()
    ua = (c.get("ua") or "").strip()

    # INJECT the operator's own session into the CDP-attached browser — operator directive
    # 2026-10-23: "HUNTR must take the session I provided... not need to login manually... like
    # claude does." Live-tested root cause: a CDP-attached Chrome (fresh-launched OR an existing one
    # whose stored profile session had simply expired) is NOT automatically logged in just because
    # HUNTR is attached to it — js-api-harvest.py/browser-capture.py both only ever read whatever
    # session already happens to be in that browser; nothing ever pushed the operator's own cookie
    # INTO it. addCookies() goes through CDP's Network.setCookie, so it works for HttpOnly cookies
    # too (document.cookie injection wouldn't). Live-verified end to end against the real target this
    # fixed: cookie injected → navigated straight to an authenticated dashboard route (no login wall)
    # → the very next browser-capture.py run (previously 0 calls every time) recorded real
    # /system/v1/user* traffic — exactly the endpoint family every one of this target's 50+ known
    # critical bugs lives under. 0-cost when it's a no-op (CDP down, or already logged in and the
    # cookie values are identical) — just best-effort, never blocks the rest of the phase on failure.
    if cdp and cookie and (HERE / "cdp-login-session.py").exists():
        try:
            lr = tool_json("cdp-login-session.py", ["--cdp-port", cdp, "--url", url, "--cookie", cookie], timeout=35)
            if lr and lr.get("ok"):
                if lr.get("looks_logged_in"):
                    log("ok", "✓ CDP session injected · landed on " + str(lr.get("final_url", ""))[:90])
                else:
                    log("warn", "→ CDP session injected but still looks logged-out — " +
                        str(lr.get("evidence", ""))[:120])
        except Exception:
            pass

    # ── STATIC bundle harvest (CDP) — the real fix for SPA blindness ──────────────────────────────
    # katana sees only linked HTML and the passive XHR capture below records only what the app FIRES on
    # a bare load (near-nothing on a server-rendered SPA). The API the app DECLARES lives as path
    # literals in its JS bundles; js-api-harvest fetches every loaded bundle in-page over the live CDP
    # session and extracts them. On CoinTR this turned 0 → 530 real /v1 endpoints. Runs whenever a debug
    # Chrome is attached (creds.cdp_port); folds every harvested path into the testable surface.
    if cdp and (HERE / "js-api-harvest.py").exists():
        log("cmd", "$ js-api-harvest — mining API paths from the SPA's JS bundles (CDP :" + cdp + ")")
        hd = tool_json("js-api-harvest.py", ["--cdp-port", cdp, "--origin", sch + "://" + lithost, "--json"], timeout=120)
        hpaths = (hd or {}).get("paths", []) if isinstance(hd, dict) else []
        if hpaths:
            existing = {e["url"] for e in STATE["endpoints"]}
            added = 0
            for p in hpaths:
                u = sch + "://" + lithost + p
                if u not in existing:
                    STATE["endpoints"].append({"url": u, "host": apex(TARGET), "src": "js-bundle"})
                    existing.add(u); added += 1
            # WebSocket endpoints found in the bundles (trading/quotes streams) → add for CSWSH testing
            wsadded = 0
            for w in ((hd or {}).get("ws", []) or []):
                u = w if w.startswith("ws") else (sch + "://" + lithost + w)
                if u not in existing:
                    STATE["endpoints"].append({"url": u, "host": apex(TARGET), "src": "js-bundle", "ws": True})
                    existing.add(u); wsadded += 1
            STATE["stats"]["endpoints"] = len(STATE["endpoints"])
            STATE["api_paths"] = hpaths
            log("ok", "✓ JS-bundle harvest · " + str((hd or {}).get("scripts", 0)) + " bundles · " +
                str(len(hpaths)) + " API paths · " + str(added) + " new → surface" +
                (" · " + str(wsadded) + " ws endpoint(s)" if wsadded else ""))
            flush()
        else:
            # PREVIOUSLY: when hd was None (tool crashed/timed out), `(hd or {}).get("error","")` always
            # evaluated to "" — a real tool failure logged identically to "ran fine, found nothing".
            if hd is None:
                log("warn", "→ JS-bundle harvest failed — " + (_LAST_TOOL_ERR or "unknown") + " (surface may be missing real API paths)")
            else:
                log("out", "→ JS-bundle harvest · no API paths found" +
                    ((" (" + str(hd.get("error", ""))[:60] + ")") if hd.get("error") else ""))

    if not (HERE / "browser-capture.py").exists():
        return
    log("ok", "◆ SPA capture · driving real browser to record the app's runtime API calls…")
    spa_secs = 16
    a = ["--url", url, "--cookie", cookie, "--hosts", apex(TARGET), "--secs", str(spa_secs)]
    if ua:
        a += ["--ua", ua]
    # BUG FIX (2026-10-21): this previously only ever passed --cookie. A session that's a bearer
    # token (creds.session_token) or a custom program auth header (creds.auth_header — neither
    # cookie nor Bearer, e.g. Files.com's X-FilesAPI-Auth) got silently dropped: browser-capture.py
    # had nowhere to put them, so the capture ran fully unauthenticated with no error — it "succeeded"
    # and recorded only the public surface. --cdp-port (same port js-api-harvest.py already uses
    # earlier in this same phase) is the real fix: it attaches to the operator's already-logged-in
    # debug Chrome instead of a fresh incognito one, inheriting the whole real session — cookies,
    # localStorage, everything — the only way to ever cover a localStorage-JWT SPA. --header carries
    # a bearer/custom-header session on a fresh (non-CDP) browser too.
    if cdp:
        a += ["--cdp-port", cdp]
    if tok and tok != "session-identity":
        a += ["--header", "Authorization: Bearer " + tok]
    for hk, hv in _auth_headers().items():
        a += ["--header", hk + ": " + hv]
    if MODE != "black" and not cookie and not cdp and not tok and not _auth_headers():
        log("warn", "⚠ SPA capture has no cookie/cdp-port/token/auth-header — capturing the "
            "UNAUTHENTICATED surface only (no session was available to attach)")
    # BUG FIX (2026-10-21): browser-capture.py's own inner `node` subprocess is given timeout=
    # SECS+120 (136s here) to cover a 30s networkidle wait + the SECS dwell + up to 4 nav-link
    # selectors × 3 elements × ~4.5s each (click+wait) — on a JS/analytics-heavy real site
    # (continuous polling/beacons routinely keep "networkidle" from ever firing, burning its full
    # 30s) this realistically runs close to or past that full budget. The OUTER call here only gave
    # it timeout=120 — strictly LESS than the inner tool's own self-granted 136s — so this was
    # structurally guaranteed to sometimes time out even when browser-capture.py was working exactly
    # as designed, not actually hung. Give the outer call real headroom above the inner budget.
    d = tool_json("browser-capture.py", a, timeout=spa_secs + 120 + 30)
    calls = (d or {}).get("calls", []) if isinstance(d, dict) else []
    if not calls:
        # same fix as the JS-bundle harvest above: distinguish "tool crashed/timed out" from
        # "tool ran fine, genuinely recorded nothing" — they used to look identical.
        if d is None:
            log("warn", "→ SPA capture failed — " + (_LAST_TOOL_ERR or "unknown") + " (runtime API calls not captured)")
        else:
            log("out", "→ SPA capture · no runtime API calls recorded" + ((" (" + str(d.get("error", ""))[:60] + ")") if d.get("error") else ""))
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
    _am = (d or {}).get("auth_mode", "?")
    log("ok", "✓ SPA capture · " + str(len(calls)) + " runtime API call(s) [" +
        ", ".join(k + ":" + str(v) for k, v in methods.items()) + "] · " + str(added) + " GET added to surface · " +
        str(len(calls) - added) + " POST/other → exploit-agent · auth=" + _am)
    if MODE != "black" and _am == "none":
        log("warn", "⚠ SPA capture ran fully UNAUTHENTICATED — the recorded calls are the public surface "
            "only, not the real logged-in app")
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
                        f.get("url", ""), cls="Misconfig/CVE", verdict="confirmed", det=False,  # judge may still veto an FP
                        source="nuclei")  # scanner provenance → novelty gate flags these as n-days, not zero-days
        if not (d or {}).get("findings"):
            log("out", "→ nuclei: no critical/high/medium matches")
    stage("Exploit", 82)

    # 3) clickjacking — a PAGE-level header check (X-Frame-Options / CSP frame-ancestors), so probe it
    # ONCE per live host root via the 0-token oracle rather than per-endpoint (same answer per host).
    for h, sch in live_entries:
        root = sch + "://" + h + "/"
        for _hcls, _hsev, _hlabel in (("clickjack", "l", "Clickjacking"),):
            try:
                ov, om, oe = _det_oracle(_hcls, _hcls, root)
                if ov is True:
                    add_finding(_hsev, _hlabel + (" — " + om if om else ""), oe, root, cls=_hcls, verdict="confirmed",
                                proof={"proven": True, "method": om, "evidence": oe})
                if ov in (True, False):
                    mark_tested(root, _hcls)
            except Exception:
                pass

    # per-endpoint class probes (cors/redirect/idor/authz/param/race) are now owned by
    # the adaptive coverage loop (phase_adaptive) so EVERY applicable cell gets covered.

    # 4) GraphQL deep schema mapping — fire graphql-map.py on every /graphql endpoint
    # to extract the full schema, detect batch-query rate-limit bypass, admin mutations,
    # and IDOR-candidate fields. Runs in phase_active (deterministic — no LLM token cost).
    graphql_eps = [e["url"] for e in STATE["endpoints"]
                   if re.search(r"/graphql|/gql\b", e.get("url", ""), re.I)]
    if graphql_eps and (HERE / "graphql-map.py").exists():
        gql_tok = (_creds().get("session_token") or "").strip()
        for gql_ep in graphql_eps[:4]:
            log("cmd", "$ graphql-map — schema · batch · IDOR · admin · " + gql_ep)
            gql_args = ["--url", gql_ep, "--json"]
            if gql_tok:
                gql_args += ["--token", gql_tok]
            gd = tool_json("graphql-map.py", gql_args, timeout=120)
            for f in (gd or {}).get("findings", []):
                add_finding(f.get("severity", "m"), "GraphQL — " + (f.get("name") or f.get("type", "weakness")),
                            f.get("detail") or f.get("description") or "", gql_ep, cls="graphql",
                            verdict="confirmed", det=True)
            # inject new operation endpoints so the adaptive sweep covers them
            import urllib.parse as _gqlparse
            for op in (gd or {}).get("operations", []):
                op_url = gql_ep + "?op=" + _gqlparse.quote(str(op.get("name", "")))
                if op_url not in {e["url"] for e in STATE["endpoints"]}:
                    STATE["endpoints"].append({"url": op_url, "method": "POST",
                                               "cls_hint": op.get("cls", "graphql"),
                                               "source": "graphql-map"})
            if (gd or {}).get("operations"):
                log("ok", "✓ graphql-map · " + str(len(gd.get("operations", []))) +
                    " operation(s) · " + str(len(gd.get("findings", []))) + " finding(s) · " + gql_ep)
        flush()
    stage("Exploit", 84)

    # 5) WebSocket depth — ws-probe.py on every ws:// / wss:// and /socket endpoint
    # Tests CSWSH (cross-site WebSocket hijacking), missing auth, message injection/IDOR.
    ws_eps = [e["url"] for e in STATE["endpoints"]
              if re.search(r"(/ws\b|/websocket|/socket|/stomp|/hub|/cable|/sockjs)", e.get("url", ""), re.I)
              or e.get("url", "").lower().startswith(("ws://", "wss://"))]
    if ws_eps and (HERE / "ws-probe.py").exists():
        gql_tok = (_creds().get("session_token") or "").strip()
        for ws_ep in ws_eps[:6]:
            log("cmd", "$ ws-probe — CSWSH · missing auth · origin reflection · " + ws_ep)
            ws_args = ["--url", ws_ep, "--json"]
            if gql_tok:
                ws_args += ["--token", gql_tok]
            wd = tool_json("ws-probe.py", ws_args, timeout=30)
            for f in (wd or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "WebSocket — " + (f.get("name") or f.get("type", "vulnerability")),
                            f.get("detail") or f.get("description") or "", ws_ep, cls="websocket",
                            verdict="confirmed", det=True)
            mark_tested(ws_ep, "websocket")
        if ws_eps:
            log("ok" if any(f.get("cls") == "websocket" for f in STATE["findings"]) else "out",
                "✓ ws-probe · " + str(len(ws_eps[:6])) + " endpoint(s) tested")
        flush()

    # 6) Targeted SSRF probe — ssrf-probe.py on endpoints with URL parameters
    # More thorough than ssrf-test.py: tests cloud metadata + internal service sweep + protocol bypass
    ssrf_param_eps = [e["url"] for e in STATE["endpoints"]
                      if re.search(r"[?&](url|uri|path|dest|callback|webhook|fetch|load|src|target|feed|host|domain|site|proxy|redirect|return|next|image|img)=", e.get("url", ""), re.I)]
    if ssrf_param_eps and (HERE / "ssrf-probe.py").exists():
        gql_tok = (_creds().get("session_token") or "").strip()
        for ssrf_ep in ssrf_param_eps[:10]:
            _ok, _ = _in_scope(ssrf_ep)
            if not _ok:
                continue
            # extract the param name from the URL
            m_param = re.search(r"[?&](url|uri|path|dest|callback|webhook|fetch|load|src|target|feed|host|domain|site|proxy|redirect|return|next|image|img)=", ssrf_ep, re.I)
            param_name = m_param.group(1) if m_param else "url"
            sp_args = ["--url", ssrf_ep, "--param", param_name, "--json"]
            if gql_tok:
                sp_args += ["--token", gql_tok]
            sd = tool_json("ssrf-probe.py", sp_args, timeout=45)
            for f in (sd or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "SSRF — " + (f.get("name") or f.get("type", "server-side request forgery")),
                            f.get("detail") or f.get("description") or "", ssrf_ep, cls="ssrf",
                            verdict="confirmed", det=True)
            mark_tested(ssrf_ep, "ssrf")
        flush()

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
            d = json.loads(cf.read_text())
        except Exception:
            return {}
        if d.get("cookie"):
            try:
                import huntrlib as _hl
                d["cookie"] = _hl.normalize_cookie(d["cookie"])
            except Exception:
                pass
        return d
    return {}


def _auth_headers():
    """Parse creds.auth_header (one or many 'Name: value' lines) into a {name: value} dict — a custom
    program auth header like Files.com's X-FilesAPI-Auth, which is neither a Bearer token nor a cookie."""
    raw = (_creds().get("auth_header") or "")
    out = {}
    for ln in str(raw).replace("\\n", "\n").splitlines():
        ln = ln.strip()
        if ln and ":" in ln:
            k, v = ln.split(":", 1)
            if k.strip() and v.strip():
                out[k.strip()] = v.strip()
    return out


def phase_authed():
    """Authenticated class-scans — when NOT black-box and we have (or can auto-obtain) a session."""
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    ah = _auth_headers()          # custom program auth header (e.g. X-FilesAPI-Auth)
    ah_cookie = (c.get("cookie") or "").strip()
    # A custom auth header (or a session cookie) is a valid session too — proceed even without a bearer
    # token. HUNT_AUTH_HEADERS/identities.json are already exported in main(), so the coverage-loop
    # scanners carry the header on every authed request.
    if MODE != "black" and not tok and (ah or ah_cookie):
        tok = "session-identity"  # sentinel so the authed loop proceeds; scanners read the header from env
    # AUTO-AUTH: no token supplied, but creds/signup available → let the auth agent get a session itself.
    if MODE != "black" and not tok and (c.get("username") or c.get("auto_signup")) and (HERE / "agent-auth.py").exists():
        log("cmd", "$ agent-auth — establishing a session autonomously")
        flush()
        payload = {"target": TARGET, "signup": bool(c.get("auto_signup")),
                   "creds": {"username": c.get("username", ""), "password": c.get("password", "")},
                   "login_url": c.get("login_url", "")}
        try:
            r = subprocess.run([sys.executable, str(HERE / "agent-auth.py")], input=json.dumps(payload),
                               capture_output=True, text=True, timeout=180, env=dict(os.environ, HUNT_DIR=str(HUNT_DIR)))
            ad = json.loads((r.stdout or "").strip().splitlines()[-1])
            if ad.get("ok") and ad.get("authenticated"):
                log("ok", "✓ auto-auth succeeded — authenticated surface unlocked")
                # the agent saved identity 'session' to identities.json; exec-http picks it up automatically
                tok = "session-identity"  # sentinel so the authed loop proceeds
            else:
                log("warn", "→ auto-auth did not establish a session: " + str(ad.get("evidence", ""))[:120])
        except Exception as _e:
            log("warn", "→ auto-auth skipped: " + str(_e)[:100])
    if MODE == "black":
        return
    if not tok:
        # Grey/white-box hunting with NO session at all defeats half the hunt's purpose (auth-bypass/
        # IDOR/authz-matrix/race-critical/exploit-agent all need one) — this used to be a single log
        # line easy to miss in a wall of recon output, and the hunt would run its FULL budget testing
        # only the unauthenticated surface with nothing forcing the operator to notice. Pause and wait
        # instead (operator directive 2026-10-23).
        _pause_for_creds(
            "Grey/white-box hunt has no session — supply a session token, cookie, or auth header "
            "(or switch this hunt to Black box if that's intentional) to test the authenticated surface.")
        # Woke up (SIGCONT) — re-read creds fresh; _creds() hits disk every call, so /api/hunt/creds
        # having written new ones while paused is picked up here with no relaunch needed.
        c = _creds()
        tok = (c.get("session_token") or "").strip()
        ah = _auth_headers()
        ah_cookie = (c.get("cookie") or "").strip()
        if not tok and (ah or ah_cookie):
            tok = "session-identity"
        if not tok:
            # Operator resumed without actually adding a session — respect that as a deliberate
            # choice to proceed black-box-style rather than re-pausing in a loop.
            log("out", "→ resumed with no session still supplied — continuing black-box recon only")
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

    # ── Multi-account auto-setup ──────────────────────────────────────────────────────────────
    # IDOR/BOLA (cross-account access control) requires TWO real accounts. Without a second token
    # we can only test "does this endpoint require auth" — not "does account A see account B's data".
    # If tok2 is not already set and auto_signup is enabled (or the app allows free registration),
    # mint a second identity autonomously and save it as token2 / "session2" in creds.json.
    if not tok2 and c.get("auto_signup") and (HERE / "agent-auth.py").exists():
        log("cmd", "$ agent-auth (2nd account) — auto-registering attacker identity for IDOR testing")
        flush()
        _victim_payload = json.dumps({
            "target": TARGET, "signup": True,
            "creds": {"username": "", "password": ""},
            "login_url": c.get("login_url", ""),
            "identity": "session2",
        })
        try:
            import subprocess as _sp2
            ar2 = _sp2.run([sys.executable, str(HERE / "agent-auth.py")], input=_victim_payload,
                           capture_output=True, text=True, timeout=180,
                           env=dict(os.environ, HUNT_DIR=str(HUNT_DIR)))
            ad2 = json.loads((ar2.stdout or "").strip().splitlines()[-1]) if ar2.stdout.strip() else {}
            if ad2.get("authenticated"):
                # Read the session2 identity from identities.json and persist as token2 in creds.json
                ids_f = HUNT_DIR / "identities.json"
                if ids_f.exists():
                    ids = json.loads(ids_f.read_text())
                    sess2 = ids.get("session2", {})
                    tok2_val = sess2.get("authorization") or sess2.get("cookie") or ""
                    if tok2_val:
                        cf = HUNT_DIR / "creds.json"
                        cdata = json.loads(cf.read_text()) if cf.exists() else {}
                        cdata["token2"] = tok2_val
                        fd = os.open(str(cf), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        try:
                            os.write(fd, json.dumps(cdata).encode())
                        finally:
                            os.close(fd)
                        tok2 = tok2_val
                        log("ok", "✓ 2nd account registered — tok2 saved · full IDOR/BOLA testing now active")
            else:
                log("out", "→ 2nd account: auto-signup not available or blocked: " + str(ad2.get("evidence", ""))[:80])
        except Exception as _ae:
            log("warn", "→ 2nd account setup skipped: " + str(_ae)[:100])

    # first-class access-control agent: cross-identity IDOR/BOLA diffing (the highest-bounty class).
    if "--no-authtest" not in sys.argv and (HERE / "agent-authtest.py").exists() and STATE.get("endpoints"):
        import subprocess as _sp
        log("cmd", "$ agent-authtest — IDOR/BOLA cross-identity diffing" + (" (2 identities)" if tok2 else " (authed vs anon)"))
        flush()
        payload = {"session_token": tok}
        if tok2:
            payload["session2_token"] = tok2
        try:
            _sp.run([sys.executable, str(HERE / "agent-authtest.py")], input=json.dumps(payload),
                    capture_output=True, text=True, timeout=300, env=dict(os.environ, HUNT_DIR=str(HUNT_DIR)))
            _reload_findings()
            log("ok", "✓ access-control agent done · " + str(len(STATE["findings"])) + " finding(s) total")
        except Exception as _e:
            log("warn", "→ authtest agent skipped: " + str(_e)[:120])


def phase_biz_logic_map():
    """Map the application's business model BEFORE attacking it — the biggest gap in naive scanners.

    Top-tier hunters don't fire probes randomly; they first understand:
      - Entities: core domain objects (User, Workspace, Order, Payment, Subscription, Token...)
      - Role hierarchy: what privilege levels exist and what each one is allowed to do
      - State machines: multi-step flows worth attacking (checkout, invite, password-reset, etc.)
      - Value flows: where money / credits / quota are debited or credited (primary race targets)
      - Trust boundaries: what the app trusts implicitly (user-supplied IDs, self-signed JWTs)

    The model is stored in STATE["biz_logic"] and consumed by:
      - phase_plan:          adds entity-aware IDOR/BOLA flows + state-machine attacks to the plan
      - phase_race_critical: extends STATEFUL_RE with discovered value-flow endpoint paths
      - phase_authz_matrix:  uses the role hierarchy to build a systematic test matrix

    Skipped in NO_LLM mode (pure deterministic run) or when the surface hasn't been mapped yet."""
    if NO_LLM or not STATE.get("endpoints"):
        return
    biz_tool = HERE / "biz-logic-map.py"
    if not biz_tool.exists():
        return
    stage("Plan", 34)
    log("cmd", "$ biz-logic-map — entity model · role hierarchy · state machines · value flows")
    ep_sample = [e["url"] for e in STATE["endpoints"][:80]]
    spa_flows = STATE.get("spa_flows") or STATE.get("discovery", {}).get("api_calls", [])
    d = tool_json("biz-logic-map.py", [
        "--endpoints-json", json.dumps(ep_sample),
        "--flows-json", json.dumps((spa_flows or [])[:30]),
        "--program", str(PROGRAM or TARGET),
        "--json"
    ], timeout=150)
    if not isinstance(d, dict) or not d.get("entities"):
        log("out", "→ biz-logic-map: no model produced" + ((" (" + _LAST_TOOL_ERR + ")") if _LAST_TOOL_ERR else ""))
        return
    STATE["biz_logic"] = d
    entities = d.get("entities", [])
    flows_biz = d.get("flows", [])
    value_eps = d.get("value_endpoints", [])
    # Extend STATEFUL_RE with value-flow endpoint path fragments the LLM identified —
    # so phase_race_critical and applicable_classes both pick them up automatically.
    if value_eps:
        import urllib.parse as _bizparse
        frags = "|".join(
            re.escape(_bizparse.urlparse(u).path.rstrip("/").rsplit("/", 1)[-1])
            for u in value_eps[:30] if u and "/" in u
        )
        if frags:
            global STATEFUL_RE
            STATEFUL_RE = STATEFUL_RE.rstrip(")") + "|" + frags + ")"
    log("ok", "✓ biz-logic · " + str(len(entities)) + " entit" + ("y" if len(entities) == 1 else "ies") +
        " · " + str(len(flows_biz)) + " flow(s) · " + str(len(value_eps)) + " value endpoint(s)")
    flush()


def phase_race_critical():
    """Dedicated race-condition sweep on value-flow endpoints BEFORE the generic adaptive loop.

    Race conditions on payment/credit/limit/coupon operations are the highest EV-per-hour
    finding class in bug bounty — routinely $5–15k bounties found in 30 minutes. The adaptive
    sweep treats `race` the same as any other class (one cell at a time). This phase fires
    20-thread concurrent bursts SPECIFICALLY against every endpoint whose URL matches
    STATEFUL_RE (now expanded by phase_biz_logic_map with the target's own value-flow paths).

    If token2 is available, we also test a cross-account race: attacker fires a request AS
    the victim's object (token2 victim, token attacker) to catch cross-tenant balance races."""
    race_tool = HERE / "race-fire.py"
    if not race_tool.exists():
        return
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    if not tok and not (c.get("cookie") or "").strip():
        return   # unauthenticated — race conditions on value flows require a session
    tok2 = (c.get("token2") or "").strip()
    stateful_eps = [e["url"] for e in STATE["endpoints"] if re.search(STATEFUL_RE, e.get("url", ""), re.I)]
    if not stateful_eps:
        return
    log("cmd", "$ race-fire (critical) — " + str(len(stateful_eps)) + " value-flow endpoint(s) · 25 threads each")
    stage("Plan", 42)
    raced_count = 0
    for ep in stateful_eps[:20]:
        # infer method from endpoint (POST for mutation-ish paths, GET otherwise)
        _meth = "POST" if re.search(r"(redeem|checkout|purchase|pay|charge|transfer|subscribe|grant|allocat|claim|convert|merge|revoke)", ep.lower()) else "GET"
        _args = ["--url", ep, "--method", _meth, "--count", "25", "--json"]
        _ah = _auth_headers()
        if tok and not tok.startswith("session-identity"):
            _args += ["--token", tok]
        elif (c.get("cookie") or "").strip():
            _args += ["--cookie", (c.get("cookie") or "").strip()]
        for k, v in _ah.items():
            _args += ["--header", f"{k}: {v}"]
        rd = tool_json("race-fire.py", _args, timeout=45)
        raced_count += 1
        for f in (rd or {}).get("findings", []):
            add_finding(f.get("severity", "h"), "Race condition — " + (f.get("name") or f.get("type", "duplicate operation")),
                        f.get("detail") or f.get("description") or "", ep, cls="race", verdict="confirmed", det=True)
        # cross-account race: if tok2 exists, try victim's endpoint with attacker's token
        if tok2 and (rd or {}).get("findings"):
            _args2 = [a for a in _args if a not in (tok, "--token")]
            _args2 += ["--token", tok2, "--cross-token", tok]
            rd2 = tool_json("race-fire.py", _args2, timeout=45)
            for f in (rd2 or {}).get("findings", []):
                add_finding("c", "Cross-account race condition — " + (f.get("name") or "balance manipulation"),
                            f.get("detail") or "", ep, cls="race", verdict="confirmed", det=True)
        mark_tested(ep, "race")
    if raced_count:
        log("ok", "✓ race-critical · " + str(raced_count) + " endpoint(s) raced · " +
            str(len([f for f in STATE["findings"] if f.get("cls") == "race"])) + " finding(s)")

    # ── Business logic fuzzing — price/quantity/limit manipulation ────────────────────────────
    # logic-fuzz.py sends the original request then mutates each field: qty=-1, price=0,
    # amount=2^31, role="admin". Any field the server accepts that shouldn't be accepted is a bug.
    # Run it on value-flow endpoints (checkout, purchase, subscribe) after the race sweep.
    if (HERE / "logic-fuzz.py").exists():
        mutation_eps = [ep for ep in stateful_eps if re.search(
            r"(checkout|purchase|order|cart|pay|charge|subscribe|credit|coupon|redeem|invoice|price)", ep.lower())][:8]
        for ep in mutation_eps:
            _meth = "POST"
            _lf_args = ["--url", ep, "--method", _meth, "--data", "{}", "--json"]
            if tok and not tok.startswith("session-identity"):
                _lf_args += ["--token", tok]
            elif (c.get("cookie") or "").strip():
                _lf_args += ["--token", (c.get("cookie") or "").strip()]
            for k, v in _auth_headers().items():
                _lf_args += ["--header", f"{k}: {v}"]
            lfrd = tool_json("logic-fuzz.py", _lf_args, timeout=45)
            for f in (lfrd or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Business logic — " + (f.get("name") or f.get("type") or "unexpected field accepted"),
                            f.get("detail") or f.get("description") or "", ep, cls="mass-assignment", verdict="likely")
        if mutation_eps:
            log("out", "→ logic-fuzz · " + str(len(mutation_eps)) + " value endpoint(s) fuzzed")
    flush()


def phase_authz_matrix():
    """Systematic authorization matrix: every available identity × high-value endpoints.

    Complements agent-authtest (which does LLM-driven IDOR/BOLA diffing) with two things it
    doesn't do:

    1. BFLA (Broken Function-Level Authorization): test EVERY admin/management/privileged
       endpoint with a REGULAR user token. Can a normal user call /api/admin/*, /manage/*,
       /debug/*, /actuator/*, /internal/*? This is a pure HTTP sweep — no LLM needed.

    2. Role boundary sweep: if phase_biz_logic_map identified roles, probe each role's
       exclusive endpoints with a lower-privilege token. Even without biz_logic, the pattern
       match on /admin|/internal|/manage|/staff|/superuser covers the most common cases.

    Findings are added as `authz` class with `verdict=confirmed` when a ≥200 response with
    meaningful content is returned to a token that should be denied."""
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    if not tok and not (c.get("cookie") or "").strip():
        return
    eps = [e["url"] for e in STATE["endpoints"]]
    if not eps:
        return
    # Admin / management / privileged endpoints
    priv_eps = [u for u in eps if re.search(r"(/admin|/internal|/debug|/actuator|/manage|/staff|/superuser|/sudo|/root|/privilege|/system)", u.lower())]
    # Also add role-specific endpoints from the biz_logic model
    biz = STATE.get("biz_logic") or {}
    for ep in (biz.get("admin_endpoints") or []):
        if ep not in priv_eps:
            priv_eps.append(ep)
    if not priv_eps:
        return
    log("cmd", "$ authz-matrix — " + str(len(priv_eps)) + " privileged endpoint(s) · regular-user probe")
    import urllib.request as _amur
    import urllib.error as _amue
    _ah = _auth_headers()
    _ck = (c.get("cookie") or "").strip()
    found = 0
    for ep in priv_eps[:40]:
        _ok, _why = _in_scope(ep)
        if not _ok:
            continue
        try:
            req_h = {"User-Agent": "Mozilla/5.0"}
            if tok and not tok.startswith("session-identity"):
                req_h["Authorization"] = tok if tok.startswith("Bearer ") else "Bearer " + tok
            elif _ck:
                req_h["Cookie"] = _ck
            for k, v in _ah.items():
                req_h[k] = v
            req = _amur.Request(ep, headers=req_h)
            with _amur.urlopen(req, timeout=8) as r:
                status = r.status
                body = r.read(2048).decode("utf-8", "ignore")
                # Flag if: 200 OK with non-trivial body that isn't a login redirect or generic 404
                if status == 200 and len(body) > 200 and not re.search(r"(login|sign.?in|not found|404|forbidden|unauthorized)", body.lower()):
                    add_finding("h", "BFLA — privileged endpoint accessible to regular user",
                                f"GET {ep} returned HTTP 200 ({len(body)}B) with a regular session.\n"
                                "Expected: 403/404 or redirect to login.",
                                ep, cls="authz", verdict="confirmed", det=True)
                    found += 1
                    mark_tested(ep, "authz")
        except (_amue.HTTPError, _amue.URLError, Exception):
            mark_tested(ep, "authz")   # 403/404 = correctly blocked, still counts as tested
    if found:
        log("ok", "✓ authz-matrix · " + str(found) + " BFLA finding(s) — privileged endpoints accessible")
    else:
        log("ok", "✓ authz-matrix · " + str(len(priv_eps)) + " privileged endpoint(s) probed · all blocked (correct)")

    # ── Mass-assignment sweep on write endpoints ──────────────────────────────────────────────
    # mass-assign.py probes sensitive field injection on PUT/PATCH endpoints: role, isAdmin,
    # password, email, active, tenantId, balance — the fields the endpoint was never meant to
    # accept. Run it on every write endpoint found in the surface.
    if (HERE / "mass-assign.py").exists():
        write_eps = [e for e in STATE["endpoints"] if e.get("method", "GET").upper() in ("PUT", "PATCH") or
                     re.search(r"/(update|edit|modify|profile|settings|account|user)", e.get("url", ""), re.I)][:15]
        for we in write_eps:
            _ok2, _ = _in_scope(we["url"] if isinstance(we, dict) else we)
            if not _ok2:
                continue
            ep_url = we["url"] if isinstance(we, dict) else we
            _meth = we.get("method", "PUT").upper() if isinstance(we, dict) else "PUT"
            ma_args = ["--url", ep_url, "--method", _meth, "--json"]
            if tok and not tok.startswith("session-identity"):
                ma_args += ["--token", tok]
            elif _ck:
                ma_args += ["--token", _ck]
            for k, v in _ah.items():
                ma_args += ["--header", f"{k}: {v}"]
            mad = tool_json("mass-assign.py", ma_args, timeout=40)
            for f in (mad or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Mass assignment — " + (f.get("name") or f.get("impact") or "sensitive field accepted"),
                            f.get("detail") or f.get("description") or "", ep_url, cls="mass-assignment",
                            verdict="confirmed" if f.get("confirmed") else "likely", det=bool(f.get("confirmed")))
            mark_tested(ep_url, "mass-assignment")
        if write_eps:
            log("out", "→ mass-assign · " + str(len(write_eps)) + " write endpoint(s) probed")
    flush()


def _stack():
    p = (PROGRAM + " " + TARGET).lower()
    s = ["saas", "api"]
    if any(k in p for k in ("bank", "pay", "fin", "wallet", "card", "trading", "ledger", "crypto")):
        s = ["fintech"] + s
    if "graphql" in " ".join(e["url"] for e in STATE["endpoints"]).lower():
        s.append("graphql")
    return ",".join(dict.fromkeys(s))


APPLICABLE = ["cors", "redirect", "jwt", "idor", "authz", "param", "sqli", "xss", "ssti", "ssrf", "misconfig",
              "race", "nosqli", "crlf", "lfi", "host-header", "clickjack", "cmdi",
              "prototype-pollution", "web-cache-deception", "mass-assignment", "ldap", "xpath",
              "csp", "oauth", "file-upload", "deserialization", "websocket", "graphql"]


def _cls_key(c):
    c = (c or "").lower()
    if "nosql" in c: return "nosqli"   # MUST precede sqli: "sqli" is a substring of "nosqli"
    if "sqli" in c or "sql injection" in c: return "sqli"
    if "prototype pollution" in c or "prototype-pollution" in c or "proto pollution" in c: return "prototype-pollution"
    if "web cache deception" in c or "web-cache-deception" in c or "cache deception" in c: return "web-cache-deception"
    if "mass assignment" in c or "mass-assignment" in c or "overposting" in c or "autobind" in c: return "mass-assignment"
    if "ldap" in c: return "ldap"
    if "xpath" in c: return "xpath"
    if "deserial" in c or "deserialis" in c: return "deserialization"
    if "websocket" in c or "cswsh" in c: return "websocket"
    if "request smuggl" in c or "request-smuggl" in c or "desync" in c: return "request-smuggling"
    if "saml" in c or "xsw" in c or "signature wrap" in c: return "saml"
    if "dns rebind" in c or "dns-rebind" in c or "rebinding" in c: return "dns-rebinding"
    if "file upload" in c or "file-upload" in c or "zip slip" in c or "zip-slip" in c: return "file-upload"
    if "csp" in c or "content security policy" in c or "content-security-policy" in c: return "csp"
    if "oauth" in c or "oidc" in c or "openid" in c: return "oauth"
    if "blind ssti" in c: return "blind-ssti"
    if "ssti" in c or "template inj" in c: return "ssti"
    if "ssrf" in c or "server-side request" in c: return "ssrf"
    if "command inj" in c or "cmdi" in c: return "cmdi"
    if "rce" in c or "remote code" in c or "code exec" in c: return "rce"
    if "xxe" in c: return "xxe"
    if "lfi" in c or "traversal" in c or "path traversal" in c or "file read" in c or "file disclosure" in c: return "lfi"
    if "clickjack" in c: return "clickjack"
    if "crlf" in c or "response splitting" in c or "header injection" in c: return "crlf"
    if "host header" in c or "host-header" in c: return "host-header"
    if "cache poison" in c or "cache-poison" in c: return "cache-poison"
    if "csrf" in c or "xsrf" in c: return "csrf"
    if "graphql" in c or "gql" in c: return "graphql"
    if "secret" in c or "credential" in c or "source leak" in c or "source-leak" in c: return "secret"
    if "xss" in c: return "xss"
    if "idor" in c or "bola" in c: return "idor"
    if "auth" in c: return "authz"
    if "access control" in c: return "authz"
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


STATEFUL_RE = r"(redeem|coupon|voucher|order|checkout|cart|transfer|claim|vote|invite|apply|withdraw|balance|credit|gift|refund|payout|purchase|payment|pay|charge|subscribe|subscription|upgrade|downgrade|renew|limit|quota|consume|unlock|activate|deactivate|bulk|batch|exchange|convert|merge|split|allocat|assign|grant|revoke)"
RANK = {"ssti": 0, "sqli": 0, "idor": 1, "ssrf": 1, "mass-assignment": 1, "authz": 2, "xss": 3, "nosqli": 3,
        "lfi": 3, "ldap": 3, "xpath": 3, "prototype-pollution": 3, "oauth": 2, "file-upload": 3, "race": 4,
        "jwt": 5, "param": 6, "crlf": 6, "host-header": 6, "web-cache-deception": 7, "cors": 7, "redirect": 8,
        "clickjack": 9, "csp": 9, "websocket": 6, "deserialization": 5, "cmdi": 9, "graphql": 2}

# classes with NO dedicated scanner tool — probed by the deterministic oracle in scan_cell.
# Fast (0-token, instant): nosqli/crlf/lfi/host-header/clickjack. OOB (needs a callback: interactsh for
# real targets, or the local collaborator for reachable/localhost targets): cmdi. These are slower
# (~20s each) so applicable_classes gates cmdi to command-ish params to keep the cell count sane.
_ORACLE_CELL = {"nosqli": ("h", "NoSQL injection"), "crlf": ("m", "CRLF / header injection"),
                "lfi": ("h", "Local file inclusion / path traversal"),
                "host-header": ("m", "Host-header injection"), "clickjack": ("l", "Clickjacking"),
                "cmdi": ("c", "OS command injection"),
                # extended classes — all probed by the deterministic oracle in verify-finding.py
                "prototype-pollution": ("h", "Server-side prototype pollution"),
                "web-cache-deception": ("m", "Web cache deception"),
                "mass-assignment": ("h", "Mass assignment / overposting"),
                "ldap": ("h", "LDAP injection"), "xpath": ("h", "XPath injection"),
                "csp": ("l", "Weak Content-Security-Policy"),
                "oauth": ("h", "OAuth redirect_uri hijack"),
                "file-upload": ("h", "File-upload path traversal (zip-slip)"),
                "deserialization": ("c", "Insecure deserialization"),
                "websocket": ("m", "Cross-site WebSocket hijacking"),
                "graphql": ("m", "GraphQL introspection / batching"),
                "authz": ("h", "Broken access control / auth bypass")}


STATIC_EXT = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|"
                        r"mp4|webm|mp3|wav|pdf|zip|gz|tar|wasm|json|xml|txt|md)(\?|$)", re.I)

def applicable_classes(ep):
    low = ep.lower()
    # static assets (JS/CSS/images/fonts/media) have no server-side logic — never injection-test them,
    # even with a cache-busting param like ?dpl=… . This stops the hunt wasting its budget on /_next/static.
    path = re.sub(r"\?.*$", "", low)
    # match the extension on the PATH only — a filename in a query value (?file=readme.txt, the classic
    # LFI/traversal param) must NOT get the endpoint skipped as if it were a static asset.
    if STATIC_EXT.search(path) or "/_next/static/" in low or "/static/chunks/" in low or "/assets/" in path:
        return []
    cl = []
    has_param = bool(re.search(r"[?&][\w\[\]]+=", low))
    if "/api" in low or "/graphql" in low:
        cl += ["cors", "param"]
    if "/graphql" in low or "/gql" in low or low.rstrip("/").endswith("/graphql"):
        cl.append("graphql")
    if has_param:                       # injectable surface (works unauth)
        cl += ["param", "sqli", "xss", "ssti", "nosqli", "crlf", "lfi"]  # oracle-probed classes are 0-token
    # host-header injection: only on link/token-generating flows (keeps the cell count sane on big targets)
    if re.search(r"(reset|confirm|verify|password|forgot|invite|recover|activ|magic|token|email)", path):
        cl.append("host-header")
    if re.search(r"[?&](url|uri|path|dest|callback|webhook|fetch|load|src|target|feed|host|domain|site|proxy|redirect|return|next|continue|image|img|file)=", low):
        cl.append("ssrf")
    # OS command injection: gate to command-ish params (host/ip/cmd/ping/exec/…) — the OAST probe is slow,
    # so don't fire it on every param, only where a shell sink is plausible.
    if re.search(r"[?&](host|ip|cmd|command|exec|ping|dns|domain|addr|target|lookup|query|q|name|data|file|path)=", low):
        cl.append("cmdi")
    # LDAP / XPath injection: param endpoints whose param name suggests a directory/document lookup
    if re.search(r"[?&](user|username|uid|login|cn|dn|account|member|group)=", low):
        cl.append("ldap")
    if re.search(r"[?&](q|query|search|xpath|doc|node|path|find|filter)=", low):
        cl.append("xpath")
    # OAuth redirect_uri hijack: authorize-style endpoints
    if ("oauth" in low or "/authorize" in low or "/connect/" in low or "openid" in low) and re.search(r"[?&](redirect_uri|redirect|callback|return_uri|reply_url)=", low):
        cl.append("oauth")
    # API JSON surfaces → prototype pollution + mass assignment (POST/PUT body probes)
    if "/api" in low or "/graphql" in low or re.search(r"(merge|config|settings|profile|user|account|object|import|save|update)", path):
        cl += ["prototype-pollution", "mass-assignment"]
    # web cache deception: private/dynamic page endpoints (no param needed)
    if re.search(r"(profile|account|dashboard|settings|wallet|billing|/me\b|private|inbox|orders?)", path):
        cl.append("web-cache-deception")
    # weak CSP: HTML page endpoints (no param, not an API) — oracle returns a finding ONLY for an
    # exploitable unsafe-inline/wildcard script-src; mere absence is info (verified=None), so no FP spam.
    if not has_param and "/api" not in low and "/graphql" not in low:
        cl.append("csp")
    # file-upload path traversal: upload-ish endpoints
    if re.search(r"(upload|/files?\b|import|attach|avatar|photo|media|document)", path):
        cl.append("file-upload")
    # insecure deserialization: endpoints that smell like object/state loaders (OAST probe — gate narrowly)
    if re.search(r"(deser|unserialize|object|pickle|yaml|/load\b|restore|session|viewstate|__VIEWSTATE)", path):
        cl.append("deserialization")
    if re.search(r"/\d{1,8}(?:/|\?|$)", ep) or re.search(r"[?&](id|uid|user|account|order|doc|file|key)=", low):
        cl.append("idor")
    if any(k in low for k in ("/admin", "/internal", "/debug", "/actuator", "/manage", "/private")):
        cl.append("authz")
    if re.search(r"(redirect|url|next|return|dest|continue|goto|u)=", low):
        cl.append("redirect")
    # cross-site WebSocket hijacking: ws-ish endpoints
    if re.search(r"(/ws\b|/websocket|/socket|/stomp|/hub|/cable|/sockjs)", path) or low.startswith(("ws://", "wss://")):
        cl.append("websocket")
    # webhook IDOR / event-stream hijack: can the caller register to receive another user's events?
    if re.search(r"(/webhook|/hooks?|/callback|/notify|/event|/subscribe|/push|/notification)", path):
        cl += ["idor", "authz", "ssrf"]   # ssrf because the server fetches the registered URL
    if re.search(STATEFUL_RE, low):
        cl.append("race")
    return list(dict.fromkeys(cl))


def scan_cell(ep, cls, tok, tok2, method="GET"):
    """Scan one (endpoint × class) cell. Tool-level evidence sets a deterministic verdict
    (so a confirmed bug never depends on the AI judge). Coverage integrity: a cell whose tool
    ERRORED/timed-out is NOT marked tested — it stays TODO so resume re-does it (no silent miss).
    `method` comes from the attack plan: a POST/PUT/PATCH endpoint (the whole upex/SPA API) is tested
    through its JSON BODY — param-fuzz/idor-chain/auth-bypass get --method+--data so body params
    (orderId/userId/amount/role) are actually fuzzed, not just the empty query string."""
    # CRITICAL (2026-10-21): this is the single dispatch chokepoint to every standalone scanner tool
    # (cors-test, open-redirect, idor-chain, auth-bypass, param-fuzz, ssti-test, sqli-test, ssrf-test,
    # race-fire, ...) — NONE of which check scope themselves (see _in_scope()'s docstring). `ep` is
    # trusted to already be in-scope because it came from STATE["endpoints"], but that trust was
    # misplaced: caught live, an out-of-scope host made it all the way into "confirmed" findings.
    # Out-of-scope is permanent, not transient — treat it the same as "no tool for this class" (never
    # re-queued, never counted as tested) rather than leaving it as an endless TODO.
    _ok, _why = _in_scope(ep)
    if not _ok:
        log("err", "⛔ scan_cell refused OUT-OF-SCOPE endpoint (no request sent): " + str(ep)[:120] + " — " + str(_why))
        NO_TOOL.setdefault(ep, set()).add(cls)
        return None
    _write = method.upper() in ("POST", "PUT", "PATCH")
    _mt = ["--method", method.upper(), "--data", "{}"] if _write else []
    # "session-identity" is a sentinel used for header/cookie auth (no bearer token). Scanners must NOT
    # receive it as a --token value (it would become a bogus `Bearer session-identity`); they read the
    # real auth from HUNT_AUTH_HEADERS/identities.json. `tok` stays truthy so authed branches still run;
    # `tokv` is the real bearer value (empty under the sentinel) used wherever a token VALUE is passed.
    tokv = "" if tok == "session-identity" else tok
    ran = None   # None = no tool executed (missing/unknown class); True = ran OK; False = tool errored
    global _LAST_TOOL_ERR
    _LAST_TOOL_ERR = None
    try:
        if cls == "cors" and (HERE / "cors-test.py").exists():
            d = tool_json("cors-test.py", ["--url", ep, "--json"] + (["--token", tokv] if tokv else []), timeout=40); ran = d is not None
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
        elif cls == "idor" and tokv and (HERE / "idor-chain.py").exists():
            # idor-chain diffs identity A vs B by BEARER token — it needs a real token value, so it is
            # skipped under header/cookie auth (tokv==""); param-fuzz + agent-authtest cover IDOR there.
            a = ["--base-url", ep, "--token", tokv, "--json"] + _mt + (["--token2", tok2] if tok2 else [])
            d = tool_json("idor-chain.py", a, timeout=150); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "IDOR — " + (f.get("name") or "object reference"), f.get("detail") or "", ep, cls="IDOR", verdict="confirmed")
        elif cls == "authz" and (HERE / "auth-bypass.py").exists():
            # tokv is the real Bearer value; empty under cookie/header auth — auth-bypass.py reads
            # HUNT_AUTH_HEADERS from the env for cookie/custom-header sessions, so no --token needed.
            d = tool_json("auth-bypass.py", ["--url", ep, "--json"] + (["--token", tokv] if tokv else []) + _mt, timeout=60); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "h"), "Auth bypass — " + (f.get("technique") or f.get("name") or "access control"), f.get("detail") or "", ep, cls="Auth bypass", verdict="confirmed")
        elif cls == "param" and (HERE / "param-fuzz.py").exists():
            d = tool_json("param-fuzz.py", ["--url", ep, "--json"] + _mt + (["--token", tokv] if tokv else []), timeout=120); ran = d is not None
            for f in (d or {}).get("findings", []):
                # A merely-discovered hidden param/endpoint is NOT a finding — it is a LEAD (surface, not
                # a vuln: does fuzzing it yield IDOR/injection/authz?). Keep it OUT of the findings list
                # entirely so it never becomes info-noise; record it as a lead for the next round instead.
                # Only a PROVEN-impact sub-finding (param-fuzz's idor_candidate) becomes a real finding.
                _ptype = (f.get("type") or "").lower()
                if _ptype in ("hidden_param", "hidden_endpoint", "discovered_param", "discovered_endpoint") \
                        or (f.get("severity") or "").lower() in ("info", "i", ""):
                    # reachable from both dual-agent threads via scan_endpoint -> scan_cell; see
                    # [[add-finding-race-2026-10-18]] — same unlocked check-then-append shape.
                    with _STATE_LOCK:
                        STATE.setdefault("leads", [])
                        _lep = ep + "#" + (f.get("param") or "")
                        if not any(l.get("endpoint") == _lep for l in STATE["leads"]):
                            STATE["leads"].append({
                                "title": "Hidden param lead — " + (f.get("param") or "parameter"),
                                "attack": "param/idor", "endpoint": _lep,
                                "why": f.get("detail") or f.get("deviation") or "discovered; fuzz for IDOR/injection"})
                            STATE["leads"] = STATE["leads"][-60:]
                    continue
                add_finding(f.get("severity", "h"), "IDOR candidate — " + (f.get("param") or f.get("name") or "parameter"),
                            f.get("detail") or "", ep, cls="Param/IDOR", verdict="likely")
        elif cls == "xss" and (HERE / "xss-test.py").exists():
            d = tool_json("xss-test.py", ["--url", ep, "--json"] + (["--token", tokv] if tokv else []), timeout=80); ran = d is not None
            for f in (d or {}).get("findings", []):
                v = "confirmed" if "verified" in (f.get("type", "").lower()) else "likely"
                add_finding(f.get("severity", "m"), (f.get("type") or "Reflected XSS") + " — " + (f.get("param") or "param"), f.get("detail") or f.get("payload") or "", ep, cls="XSS", verdict=v)
        elif cls == "sqli" and (HERE / "sqli-test.py").exists():
            d = tool_json("sqli-test.py", ["--url", ep, "--json"] + (["--token", tokv] if tokv else []), timeout=160); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "c"), "SQL injection — " + (f.get("param") or "parameter"), f.get("detail") or "", ep, cls="SQLi", verdict="confirmed")
        elif cls == "ssti" and (HERE / "ssti-test.py").exists():
            d = tool_json("ssti-test.py", ["--url", ep, "--json"] + (["--token", tokv] if tokv else []), timeout=70); ran = d is not None
            for f in (d or {}).get("findings", []):
                add_finding(f.get("severity", "c"), "Server-side template injection — " + (f.get("param") or "param"), f.get("detail") or "", ep, cls="SSTI", verdict="confirmed")
        elif cls == "ssrf" and (HERE / "ssrf-test.py").exists():
            d = tool_json("ssrf-test.py", ["--url", ep, "--json"] + (["--token", tokv] if tokv else []), timeout=60); ran = d is not None
            got = False
            for f in (d or {}).get("findings", []):
                got = True
                add_finding(f.get("severity", "h"), "SSRF — " + (f.get("param") or "server-side request"), f.get("detail") or "", ep, cls="SSRF", verdict=f.get("verdict", "likely"))
            if not got:
                # ssrf-test can't see BLIND ssrf (no reflection). The oracle stands up a callback listener
                # (local collaborator / interactsh) and proves it on a real outbound request.
                ov, om, oe = _det_oracle("ssrf", "ssrf", ep)
                if ov is True:
                    add_finding("h", "SSRF (blind) — " + om, oe, ep, cls="ssrf", verdict="confirmed",
                                proof={"proven": True, "method": om, "evidence": oe})
                if ov in (True, False):
                    ran = True
        elif cls == "race" and (HERE / "race-fire.py").exists():
            a = ["--url", ep, "--count", "20", "--json"] + (["--token", tokv] if tokv else [])
            d = tool_json("race-fire.py", a, timeout=90); ran = d is not None
            for f in (d or {}).get("findings", []):
                # A race is NEVER auto-confirmed. race-fire's signals (duplicate_id/toctou/non_idempotent/
                # balance_diverge) are HEURISTICS over parallel responses — proving an actual race needs a
                # manual state-effect check (did a balance really double-spend? was a 2nd resource really
                # created?), which a response-diff cannot establish. So every race finding is a LEAD
                # (verdict=likely → never auto-submitted); the human verifies the state effect and writes the
                # PoC. balance_diverge/duplicate_creation are the strongest and ride higher severity as leads.
                _rtype = (f.get("type") or "state divergence")
                if _rtype == "non_idempotent":
                    add_finding("i", "Race lead — non-idempotent endpoint", f.get("note") or "", ep, cls="Race", verdict="likely")
                else:
                    _rsev = {"balance_diverge": "h", "duplicate_creation": "h"}.get(_rtype, "m")
                    add_finding(_rsev, "Race lead — " + _rtype, f.get("note") or "", ep, cls="Race",
                                verdict="likely", det=False)
        elif cls in _ORACLE_CELL:
            # No dedicated scanner tool for these classes — the deterministic oracle (verify-finding.py)
            # IS the probe: it injects the class-specific payload, reads the response, and returns a hard
            # verified true/false. 0-token, so it runs in the fast sweep without touching the rate limit.
            ov, om, oe = _det_oracle(cls, cls, ep)
            # ov is True (finding confirmed), False (no vuln, oracle ran), or None (oracle not applicable
            # / verify-finding had no handler for this cls). None must stay None so the cell lands in
            # NO_TOOL instead of being logged as "errored" — `None in (True, False)` evaluates to the
            # Python bool False (via __eq__), which makes `ran is False` true and triggers a misleading
            # "errored (unknown)" warning for every oracle-not-applicable cell.
            ran = True if ov is True else (False if ov is False else None)
            if ov is True:
                sev, lab = _ORACLE_CELL[cls]
                add_finding(sev, lab + (" — " + om if om else ""), oe, ep, cls=cls, verdict="confirmed",
                            proof={"proven": True, "method": om, "evidence": oe})
    except Exception as _e:
        ran = False
        # a bare Python exception in the scan_cell branch itself (parsing/add_finding/etc.) —
        # distinct from a tool subprocess failure, so tag it even when tool_json never ran.
        _LAST_TOOL_ERR = _LAST_TOOL_ERR or ("python-exception: " + str(_e)[:150])
    if ran is True:
        mark_tested(ep, cls)                 # a tool actually ran → the cell is genuinely covered
    elif ran is False:
        log("warn", "⚠ " + cls + " cell errored (" + (_LAST_TOOL_ERR or "unknown") +
            ") — left TODO (not counted as tested): " + ep[:70])
    else:
        # ran is None: no tool for this class is installed. Record it as NOT-APPLICABLE so the coverage
        # ledger neither claims false coverage nor loops on it forever (honest "no tool" state).
        NO_TOOL.setdefault(ep, set()).add(cls)
    # brain: record attempt outcome for hit-rate matrix (True case handled in record_finding)
    if ran is True:
        try:
            _brain().record_hit(_stack(), cls, False)
        except Exception:
            pass
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
    worth a token here, instead of the probe evaporating into the log. Called directly from the
    http_request tool, reachable from both dual-agent threads at once — see
    [[add-finding-race-2026-10-18]]; both check-then-mutate sequences below need the same lock."""
    if status not in (401, 403) or not url:
        return False
    with _STATE_LOCK:
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
      - the 12 highest-degree endpoints (most connected → widest attack surface) to
        replace the flat endpoint list with (fewer, better-chosen URLs = fewer tokens)
      - untested cells ranked by graph centrality instead of raw order

    Deliberately does NOT also dump cross-community edges or the full node list into the
    digest (it used to — that duplicated graph_endpoints verbatim inside the same JSON
    blob every single round). Claude's briefs (_phase_claude_code_hunt, phase_recon_agent)
    are told the graph FILES exist and how to query them on demand (`graphify path A B`,
    `graphify explain X`, or just `jq`/`grep` graphify-out/graph.json directly) — pulling
    exactly the relationship it's curious about costs far fewer tokens than pre-loading a
    guess at which 8 edges might matter into every single turn whether needed or not."""
    graph_json = HUNT_DIR / "graphify-out" / "graph.json"
    if not graph_json.exists():
        return None
    try:
        import json as _json
        g = _json.loads(graph_json.read_text())
        nodes = g.get("nodes", []) or []
        links = g.get("links", g.get("edges", [])) or []   # real graphify output uses "links"
        by_id = {n.get("id"): n for n in nodes if n.get("id")}
        # degree from the link list (no per-node "degree" field in the real format)
        deg = {}
        for l in links:
            for k in (l.get("source"), l.get("target")):
                if k:
                    deg[k] = deg.get(k, 0) + 1
        top = sorted(deg.items(), key=lambda x: -x[1])[:12]
        key_entities = [{"entity": (by_id.get(i, {}).get("label") or i), "degree": d,
                         "theme": by_id.get(i, {}).get("community_name", "")} for i, d in top]
        comm = {}
        for n in nodes:
            cn = n.get("community_name")
            if cn:
                comm[cn] = comm.get(cn, 0) + 1
        # communities ARE the attack themes graphify extracted (e.g. "IDOR Cross-Tenant Access")
        themes = [{"theme": t, "entities": c} for t, c in sorted(comm.items(), key=lambda x: -x[1])[:12]]
        chains = [{"from": (by_id.get(l.get("source"), {}).get("label") or l.get("source")),
                   "to": (by_id.get(l.get("target"), {}).get("label") or l.get("target")),
                   "rel": l.get("relation", "")}
                  for l in links
                  if re.search(r"enabl|requir|exploit|escalat|bypass|lead|priv", (l.get("relation") or ""), re.I)][:10]
        clusters = [h.get("label", "") for h in (g.get("hyperedges") or []) if h.get("label")][:8]
        return {"attack_themes": themes, "key_entities": key_entities, "chain_edges": chains,
                "clusters": clusters, "graph_endpoints": [], "total_graph_nodes": len(nodes),
                "total_graph_edges": len(links),
                "query_hint": "graphify-out/graph.json exists — `jq '.nodes'/'.links'` it, or `graphify "
                               "path \"A\" \"B\"` for a relationship / `graphify explain \"X\"` for a node's "
                               "neighbors. Pull only what you need instead of re-reading the whole surface."}
    except Exception:
        return None


def _surface_brief(inline=60):
    """Token-cheap surface block for the agentic briefs. Instead of dumping the entire endpoint list
    into every brief (the active-hunt brief alone used to inline ~250 URLs / 6KB every call), this
    gives the agent: the knowledge-graph digest (attack themes, most-connected entities, exploit-chain
    edges) when the graph is built, a short inline endpoint shortlist, and pointers to the FULL
    endpoint list (./endpoints.txt) and graph (graphify-out/graph.json) it can read on demand with its
    own Bash/Read tools. Build-once-query-often: the graph is reused across every phase that calls this
    rather than each phase re-dumping the surface."""
    eps = [e["url"] for e in STATE.get("endpoints", []) if e.get("url")]
    try:
        (HUNT_DIR / "endpoints.txt").write_text("\n".join(eps))
    except Exception:
        pass
    parts = []
    g = _graphify_surface_digest()
    if g and (g.get("attack_themes") or g.get("key_entities")):
        parts.append(
            "## Attack-surface knowledge graph (BUILT — reason over this, query it instead of re-reading everything)\n"
            + json.dumps({"attack_themes": g.get("attack_themes"), "key_entities": g.get("key_entities"),
                          "chain_edges": g.get("chain_edges"), "clusters": g.get("clusters")},
                         default=str)[:2600]
            + "\n" + g.get("query_hint", "") + "\n")
    parts.append(
        f"## Endpoints — shortlist of {min(inline, len(eps))} (FULL {len(eps)} in ./endpoints.txt; read it for breadth)\n"
        + json.dumps(eps[:inline], default=str)[:2600] + "\n")
    return "\n".join(parts) + "\n"


def _plan_priors():
    """Cross-hunt priors for the Plan phase (0-token, deterministic): which vuln CLASSES historically
    pay on THIS stack (hunt-brain hit-rates) and which attack THEMES recur across every past hunt (the
    global knowledge graph ~/.huntr/global-graph). Lets the plan prioritise the high-value surface
    first instead of exploring blind. Returns "" when there's no cross-hunt history yet."""
    parts = []
    try:
        p = ((PROGRAM or "") + " " + (TARGET or "")).lower()
        stack = ["fintech"] if any(k in p for k in ("bank", "pay", "fin", "wallet", "card", "trading", "ledger", "crypto")) else []
        stack += ["saas", "api"]
        if any("graphql" in (e.get("url", "") or "").lower() for e in STATE.get("endpoints", [])):
            stack.append("graphql")
        stack = ",".join(dict.fromkeys(stack))
        out, err, rc = sh([sys.executable, str(HERE / "hunt-brain.py"), "--get-priorities", "--stack", stack], timeout=20)
        pri = json.loads(out) if out else []
        top = [{"cls": x.get("cls"), "hit_rate": x.get("rate"), "n": x.get("attempts")}
               for x in pri[:8] if x.get("attempts", 0) >= 5]
        if top:
            parts.append("### Vuln classes that historically pay on this stack (" + stack + ")\n" + json.dumps(top)[:800])
    except Exception:
        pass
    try:
        gg = Path.home() / ".huntr" / "global-graph" / "graph.json"
        if gg.exists():
            g = json.loads(gg.read_text())
            from collections import Counter
            c = Counter(n.get("community_name") for n in (g.get("nodes") or []) if n.get("community_name"))
            themes = [t for t, _ in c.most_common(12)]
            if themes:
                parts.append("### Attack themes that recur across past hunts (prioritise surface matching these)\n" + json.dumps(themes)[:800])
    except Exception:
        pass
    if not parts:
        return ""
    return ("## Priors from past hunts — use these to PRIORITISE, not to limit (still test what the surface warrants)\n"
            + "\n".join(parts) + "\n\n")


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
        eps_out = [e["url"] for e in graph_ctx.get("graph_endpoints", [])] or eps
    else:
        eps_out = eps

    # "smarter than a loop" #1: structured ledger state as the agent's PRIMARY memory, not something
    # it has to re-derive from its own scrollback. coverage_pct/brain_priority are computed fresh from
    # the ledger/brain every round — they survive a context compaction perfectly (conversation history
    # doesn't), and they're the same bandit signal phase_adaptive's deterministic dispatch now uses, so
    # the LLM-led loop and the deterministic loop are reading the same ground truth, not two opinions.
    total_cells = sum(len(applicable_classes(e["url"])) for e in STATE["endpoints"])
    coverage_pct = round(100.0 * tested / total_cells, 1) if total_cells else 0.0
    brain_priority = []
    try:
        brain_priority = [{"cls": p["cls"], "hit_rate": p["rate"], "n": p["attempts"]}
                          for p in _brain().get_technique_priority(_stack())[:6]]
    except Exception:
        pass

    digest = {
        "target": TARGET, "mode": MODE,
        "session": bool(tok) if MODE != "black" else None,
        "endpoints": eps_out,
        "endpoint_count": len(STATE["endpoints"]),
        "tested_cells": tested,
        "coverage_pct": coverage_pct,          # ledger ground truth, not a guess from memory
        "brain_priority": brain_priority,       # this stack's actual historical hit-rates — lead with these
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


def phase_recon_agent(budget_sec=600):
    """Agentic recon ENRICHMENT, not a replacement for recon.py/surface.py. Those stay exactly as
    they are — fast, cheap, checkpointed, resumable, and don't need judgment (running subfinder is
    not a decision). What a fixed script sequence can't do is notice "this is a GraphQL endpoint,
    check introspection" or "this JS references an internal admin panel, go find it" and act on it.
    This phase runs AFTER the deterministic pipeline has a baseline, hands Claude that baseline, and
    lets it decide what ADDITIONAL targeted exploration is worth doing — same real-Claude-Code
    mechanism as _phase_claude_code_hunt (real task, real Bash/Read/Write, no fictional persona),
    proven reliable on sonnet-4-6/opus-4-8 (see claude-code-native-vs-json-loop memory). Bounded to a
    modest fixed budget (default 10min) since this is enrichment, not the main event — the attack
    phase gets the real budget.

    Unlike _phase_claude_code_hunt, this does NOT force exec-http.py/deny curl: recon tools
    (subfinder/httpx/katana/gau/whatweb/dnsx) take a domain and operate within it by construction,
    the same trust level the existing deterministic recon.py/surface.py already run at (no scope-guard
    wrapper either). The brief still states the scope boundary explicitly and recommends exec-http.py
    for any one-off URL probe (gets evidence capture for free), but it's guidance, not a hard gate —
    appropriate for discovery, not exploitation."""
    if not STATE.get("hosts") and not STATE.get("endpoints"):
        log("out", "→ recon-agent skipped: no baseline surface to build on yet")
        return
    cli = None
    try:
        import shutil as _shu2
        cli = _shu2.which("claude") or os.path.expanduser("~/.local/bin/claude")
    except Exception:
        pass
    if not cli or not os.path.exists(cli):
        return

    stage("Recon-agent", 48)
    hosts = STATE.get("hosts", [])[:40]
    endpoints = STATE.get("endpoints", [])[:60]
    prog_intel = STATE.get("program_intel") or {}
    mobile = STATE.get("mobile") or {}
    scope_summary = ", ".join(sorted(set(h.get("host", "") for h in STATE.get("hosts", []))))[:400] or TARGET

    brief = (
        "# Recon Enrichment Task\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\n"
        f"In-scope hosts: {scope_summary}\n\n"
        f"Deterministic recon already ran and found {len(hosts)} host(s), {len(endpoints)} endpoint(s). "
        "Your job is NOT to redo that — it's to look at what's already here and decide what ADDITIONAL "
        "targeted exploration is worth doing, the way you would if you were driving this by hand and "
        "noticed something interesting partway through.\n\n"
        f"## Baseline already found\n"
        f"Hosts: {json.dumps(hosts, default=str)[:2000]}\n"
        f"Sample endpoints: {json.dumps(endpoints, default=str)[:3000]}\n"
        + (f"Program intel: {json.dumps(prog_intel, default=str)[:1000]}\n" if prog_intel else "")
        + (f"Mobile findings: {json.dumps(mobile, default=str)[:800]}\n" if mobile else "")
        + "\n## What to look for\n"
        "- A GraphQL endpoint → check introspection (`graphql-map.py` exists in " + str(HERE) + "/ if useful)\n"
        "- Signs of a mobile backend → look for versioned/internal API routes\n"
        "- JS referencing an internal tool, admin panel, or hidden route → try to find it\n"
        "- A tech stack with known default paths (Next.js /_next, Supabase /rest/v1, WordPress /wp-json) "
        "→ probe them\n"
        "- Anything in subfinder/gau/wayback history that looks more interesting than what's in the "
        "baseline list\n\n"
        "## Tools\n"
        "You have real Bash access. subfinder/httpx/katana/gau/whatweb/dnsx are installed if you want "
        "another enumeration pass on a specific lead. For any single URL you want to check, "
        f"`python3 {HERE}/exec-http.py --url <url> [--method GET|POST]` from this directory is scope-"
        "guarded and auto-captures evidence — prefer it over raw curl when you're probing a specific "
        "endpoint, but this phase is discovery, not exploitation, so it's a recommendation, not a rule.\n"
        + (("A graph of the surface crawled so far exists at " + str(HUNT_DIR / "graphify-out" / "graph.json") +
            " — `graphify path \"A\" \"B\"` / `graphify explain \"X\"` or grep/jq it directly if it's "
            "faster than re-deriving a relationship by eye.\n") if (HUNT_DIR / "graphify-out" / "graph.json").exists() else "")
        + "\n"
        f"Stay on: {scope_summary}. Write anything new you find to {HUNT_DIR}/agent-recon.json as a single "
        'JSON object: {"endpoints":[{"url":...,"host":...,"note":...}], "hosts":[{"host":...}], '
        '"tech_notes":"...", "secrets":["..."]}.\n\n'
        "Begin now: review what's known, pick the 2-4 most promising leads, investigate them for real, "
        "and write what you find. Stop once you've covered them or you're repeating yourself."
    )

    env = dict(os.environ)
    cdir = os.environ.get("HUNT_CLAUDE_CLI_DIR") or (
        os.path.dirname(os.environ["HUNT_CLAUDE_CREDS"]) if os.environ.get("HUNT_CLAUDE_CREDS") else "")
    if cdir:
        env["CLAUDE_CONFIG_DIR"] = os.path.expanduser(cdir)
    model = MODEL_LEAD.get("model") or "claude-sonnet-4-6"
    log("ok", "◆ recon-agent · model=" + model + " · budget=" + str(budget_sec) + "s")
    cmd = [cli, "-p", brief,
           "--model", model,
           "--add-dir", str(HUNT_DIR),
           "--permission-mode", "bypassPermissions",
           "--allowedTools", "Bash", "Read", "Write",
           "--no-session-persistence"]
    try:
        r = subprocess.run(cmd, cwd=str(HUNT_DIR), capture_output=True, text=True,
                           timeout=budget_sec, env=env)
        summary = (r.stdout or r.stderr or "").strip()
    except subprocess.TimeoutExpired:
        summary = ""
        log("warn", "⏱ recon-agent hit its time budget — reading whatever it found so far")
    except Exception as e:
        log("warn", "→ recon-agent failed to launch: " + str(e)[:200])
        return

    rpath = HUNT_DIR / "agent-recon.json"
    if not rpath.exists():
        log("out", "→ recon-agent found nothing new · " + summary[:160].replace("\n", " "))
        return
    try:
        rd = json.loads(rpath.read_text(errors="ignore"))
    except Exception as e:
        log("warn", "→ recon-agent wrote unparseable agent-recon.json: " + str(e)[:120])
        return

    added_eps = added_hosts = 0
    existing_urls = {e["url"] for e in STATE["endpoints"]}
    for e in rd.get("endpoints", []) or []:
        u = str(e.get("url", "")).strip()
        if not u or u in existing_urls:
            continue
        STATE["endpoints"].append({"url": u, "host": str(e.get("host") or "")})
        existing_urls.add(u)
        added_eps += 1
    existing_hosts = {h.get("host") for h in STATE.get("hosts", [])}
    for h in rd.get("hosts", []) or []:
        hn = str(h.get("host", "")).strip()
        if not hn or hn in existing_hosts:
            continue
        STATE.setdefault("hosts", []).append({"host": hn})
        existing_hosts.add(hn)
        added_hosts += 1
    if rd.get("secrets"):
        STATE.setdefault("js_secrets", []).extend(
            {"source": "recon-agent", "value": str(s)[:200]} for s in rd["secrets"][:20])
    if rd.get("tech_notes"):
        STATE["recon_agent_notes"] = str(rd["tech_notes"])[:1500]
    STATE["stats"]["endpoints"] = len(STATE["endpoints"])
    log("ok", "✓ recon-agent · +" + str(added_eps) + " endpoint(s) · +" + str(added_hosts) +
        " host(s) · " + summary[:150].replace("\n", " "))
    flush()
    stage("Recon-agent", 50)


def _run_phase_agent(phase_name, stage_label, stage_pct, brief, budget_sec, result_file, merge_fn, model=None):
    """Generic full-agentic phase runner (operator directive, 2026-10-25: "only agents for each phase,
    no scripted scanners or any scripted things"). One real `claude -p` call — Claude-Code-native, real
    Bash/Read/Write, no fictional persona — replaces a scripted phase's judgment entirely with the
    model's own. Same proven invocation shape as phase_recon_agent/_phase_claude_code_hunt above
    (reliability data in those functions' own comments: sonnet-4-6/opus-4-8 100% across tested trials,
    sonnet-5-5 ~75% — the model pin below must not drift to a 5.x default).

    There is deliberately no scope-guard/oracle/verification code backing this call — the brief is the
    only thing telling the agent what's in/out of scope, and the agent's own judgment is the only thing
    deciding whether a finding is real. This is the explicit, confirmed tradeoff of the full-agentic
    rewrite, not an oversight.

    result_file: a JSONL file (one JSON object per line) the brief tells the agent to append to AS IT
    WORKS, so a budget timeout mid-phase still yields partial, usable results — the same resilience
    pattern as _phase_claude_code_hunt's agent-findings.jsonl. merge_fn(lines) is the only phase-
    specific piece besides the brief text; it should reuse existing STATE-shape helpers (e.g.
    add_finding()) rather than inventing a new dict shape, so every other phase and the dashboard keep
    working unmodified."""
    check_pause()
    stage(stage_label, stage_pct)
    import shutil as _shu
    cli = _shu.which("claude") or os.path.expanduser("~/.local/bin/claude")
    if not cli or not os.path.exists(cli):
        log("warn", "→ " + phase_name + " skipped — claude CLI not found")
        return False
    model = model or MODEL_LEAD.get("model") or "claude-sonnet-4-6"
    log("ok", "◆ " + phase_name + " · model=" + model + " · budget=" + str(int(budget_sec)) + "s")
    cmd = [cli, "-p", brief,
           "--model", model,
           "--add-dir", str(HUNT_DIR),
           "--permission-mode", "bypassPermissions",
           "--allowedTools", "Bash", "Read", "Write",
           "--no-session-persistence"]
    env = dict(os.environ)
    cdir = os.environ.get("HUNT_CLAUDE_CLI_DIR") or (
        os.path.dirname(os.environ["HUNT_CLAUDE_CREDS"]) if os.environ.get("HUNT_CLAUDE_CREDS") else "")
    if cdir:
        env["CLAUDE_CONFIG_DIR"] = os.path.expanduser(cdir)
    try:
        r = subprocess.run(cmd, cwd=str(HUNT_DIR), capture_output=True, text=True,
                           timeout=budget_sec, env=env)
        summary = (r.stdout or r.stderr or "").strip()
    except subprocess.TimeoutExpired as e:
        summary = ((e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
        log("warn", "⏱ " + phase_name + " hit its budget — reading whatever it wrote so far")
    except Exception as e:
        log("warn", "→ " + phase_name + " failed to launch: " + str(e)[:200])
        return False

    # This subprocess is raw `claude -p`, not routed through llm_client/llm_call — the account's
    # 5-hour session limit (or a dead/auth-less CLI) prints its notice to stdout/stderr here and
    # would otherwise just look like "produced nothing", letting main() cascade through every
    # remaining agentic phase the same way and finish "done" with a silently thin result (the
    # exact incident this fix exists for — see the migration note above _run_phase_agent). Detect
    # it here and pause the whole hunt via the SAME mechanism a provider 429 already uses, instead
    # of limping through the rest of the pipeline on a dead account.
    # Same length guard as llm_client.call_llm's own detection of this exact prose: a genuine limit/
    # auth notice IS the whole CLI output (short), whereas a real agent response that happens to
    # mention "rate limit" early on (e.g. "no rate limit on the login endpoint" as a finding) can be
    # long — only a short, limit-shaped output is treated as the notice, never a substring match
    # inside real agent prose.
    if len(summary) < 400 and _CLI_LIMIT_RE.search(summary):
        reset_epoch = _parse_cli_reset(summary[:400])
        with _STATE_LOCK:
            _RL["hit"] = True
            if reset_epoch:
                _RL["retry_after"] = max(0, int(reset_epoch - time.time()))
                STATE["rate_limit_reset"] = reset_epoch
            STATE["rate_limit_notice"] = summary[:200]
        log("warn", "⏸ " + phase_name + " hit the account limit — pausing the hunt · " +
            summary[:160].replace("\n", " "))
        raise RateLimitPause()

    if not result_file.exists():
        log("out", "→ " + phase_name + " produced nothing · " + summary[:160].replace("\n", " "))
        return False
    lines = []
    for line in result_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            lines.append(json.loads(line))
        except Exception:
            continue
    if not lines:
        refused = bool(re.search(r"i won'?t|safety classifier|prompt.?injection|i can'?t (proceed|continue|help)",
                                  summary[:400], re.I))
        log("warn" if refused else "out",
            ("→ refused — " if refused else "→ ") + phase_name + " wrote no usable result lines · " +
            summary[:160].replace("\n", " "))
        return False
    with _STATE_LOCK:
        merge_fn(lines)
    flush()
    log("ok", "✓ " + phase_name + " · " + str(len(lines)) + " result line(s)")
    return True


def _phase_recon_surface_agent(deadline=None):
    """PILOT of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 2:
    Recon + Surface Mapping. Replaces phase_recon()/phase_mobile()/phase_surface()/phase_recon_agent()
    entirely with one real Claude Code agent that decides its own enumeration strategy. subfinder/httpx/
    katana/gau/dnsx/whatweb are installed and available via the agent's own Bash tool, same as a human
    hunter would use them by hand — these are third-party binaries, not HUNTR's own scripted judgment,
    so giving the agent access to them doesn't contradict "no scripted things" (see the framing
    principle in the plan).

    Flag-gated: only called from main() when "recon_surface" is in HUNT_AGENTIC_PHASES — the legacy
    scripted phases remain the default, reverted by removing the env var alone, no code revert needed.
    Lowest-risk pilot: worst case is an incomplete endpoint list, never a corrupted finding or a
    destructive write."""
    budget = 1200.0
    if deadline:
        budget = max(120.0, min(budget, deadline - time.time()))
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET
    denyf = HUNT_DIR / "scope.deny"
    deny_text = denyf.read_text(errors="ignore")[:800] if denyf.exists() else "(none written)"
    brief = (
        "# Recon + Surface Mapping — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n\n"
        f"## In-scope (never test outside this)\n{scope_summary}\n"
        f"## Explicitly OUT OF SCOPE — never send a request here\n{deny_text}\n"
        "There is no technical enforcement behind this. You are the only thing stopping an "
        "out-of-scope request. Treat the deny list as a hard operational boundary, not a suggestion.\n\n"
        "## Your job\n"
        "Map this target's real attack surface the way a human recon specialist would: find live "
        "subdomains/hosts, then crawl/enumerate real endpoints on each (including any mobile-app "
        "backend API if an APK/mobile asset is in scope). You have real Bash access — subfinder, dnsx, "
        "httpx, katana, gau, whatweb are installed if useful; use them, curl, or anything else you "
        "judge is the right tool, and read/interpret the raw output yourself. There is no scripted "
        "parser behind you — your own judgment decides what counts as a real, live host or endpoint "
        "worth recording, not a hardcoded status-code rule.\n\n"
        f"## Output — append as you go, not all at the end\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-surface.jsonl as you discover things "
        "(create it if missing; if you run out of time partway through, whatever is already written "
        "is kept). Two line shapes:\n"
        '  {"type":"host","host":"sub.target.com"}\n'
        '  {"type":"endpoint","url":"https://sub.target.com/api/x","host":"sub.target.com","note":"optional"}\n\n'
        "Begin now: enumerate, crawl, and record what's real. Stop once you've covered the surface or "
        "you're repeating yourself."
    )

    def _merge(lines):
        existing_hosts = {h.get("host") for h in STATE.get("hosts", [])}
        existing_urls = {e.get("url") for e in STATE.get("endpoints", [])}
        added_h = added_e = 0
        for r in lines:
            t = r.get("type")
            if t == "host":
                hn = str(r.get("host", "")).strip()
                if hn and hn not in existing_hosts:
                    STATE.setdefault("hosts", []).append({"host": hn})
                    existing_hosts.add(hn); added_h += 1
            elif t == "endpoint":
                u = str(r.get("url", "")).strip()
                if u and u not in existing_urls:
                    STATE["endpoints"].append({"url": u, "host": str(r.get("host") or "")})
                    existing_urls.add(u); added_e += 1
        STATE["stats"]["subs"] = STATE["stats"]["live"] = len(STATE.get("hosts", []))
        STATE["stats"]["endpoints"] = len(STATE["endpoints"])
        log("out", "→ recon+surface agent · +" + str(added_h) + " host(s) · +" + str(added_e) + " endpoint(s)")

    ok = _run_phase_agent("recon+surface agent", "Recon+Surface (agentic)", 50, brief, budget,
                           HUNT_DIR / "agent-surface.jsonl", _merge)
    if not ok:
        log("warn", "→ agentic recon+surface produced nothing — hunt will have little/no surface this run")
    stage("Recon+Surface (agentic)", 52)


def _phase_auth_spa_agent(deadline=None):
    """Stage 2 of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 3:
    Authenticated Session + SPA Capture. Replaces phase_spa_capture()/phase_authed()/phase_auth_deep()
    entirely: one real Claude Code agent establishes/verifies the authenticated session, drives the app
    through a real browser to capture its runtime API surface, and tests auth-adjacent vuln classes
    (JWT, OAuth/OIDC, session handling, password-reset flows) using its own judgment — no jwt-test.py,
    oauth-probe.py, cdp-login-session.py, or browser-capture.py called as a tool.

    Skipped in black-box mode (MODE=="black") — same gate phase_authed/phase_spa_capture already use;
    there is no session to establish or use. _auto_cdp() (launching a debuggable Chrome, operational
    plumbing not detection judgment — kept unchanged per the plan) still runs beforehand so a CDP port
    is available if the agent wants to drive a real browser.

    Flag-gated: only called from main() when "auth_spa" is in HUNT_AGENTIC_PHASES."""
    if MODE == "black":
        log("out", "→ auth+SPA agent skipped — black-box hunt, no session to establish")
        return
    _auto_cdp()
    c = _creds()
    budget = 1500.0
    if deadline:
        budget = max(180.0, min(budget, deadline - time.time()))
    cookie = (c.get("cookie") or "").strip()
    tok = (c.get("session_token") or "").strip()
    ua = (c.get("ua") or "").strip()
    cdp = str(c.get("cdp_port") or "").strip()
    username = (c.get("username") or "").strip()
    login_url = (c.get("login_url") or "").strip()
    ah = _auth_headers()
    lithost = re.sub(r'^\*\.', '', TARGET).split('/')[0].strip()
    sch = next((h.get("scheme") for h in STATE.get("hosts", []) if h.get("host") == lithost and h.get("scheme")), None) or "https"
    url = sch + "://" + lithost + "/"
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET

    creds_block = []
    if cookie:
        creds_block.append(f"Cookie header to use: {cookie[:600]}")
    if tok:
        creds_block.append(f"Session/bearer token: {tok[:300]}")
    if ah:
        creds_block.append(f"Custom auth header(s): {json.dumps(ah)[:300]}")
    if username:
        login_how = login_url or "the app's own login flow"
        creds_block.append(f"Login credentials: username={username!r}, password=(in {HUNT_DIR}/creds.json "
                            f"as 'password') — log in via {login_how} if no cookie/token above already works.")
    if cdp and _cdp_alive(int(cdp)):
        creds_block.append(
            f"A debuggable Chrome is live on CDP port {cdp}. To drive the REAL authenticated browser "
            "(preferred over a fresh headless context — inherits whatever real session is already there, "
            "and lets you inject the cookie above via CDP's Network.setCookie which also works for "
            "HttpOnly cookies): write and run a short Playwright script yourself, e.g.\n"
            "```python\n"
            "from playwright.sync_api import sync_playwright\n"
            "with sync_playwright() as p:\n"
            f"    browser = p.chromium.connect_over_cdp('http://127.0.0.1:{cdp}')\n"
            "    contexts = browser.contexts\n"
            "    # a real (non-incognito) Chrome attached over CDP often reports zero contexts here —\n"
            "    # opening a page first and reading ITS context is what actually gets you the real,\n"
            "    # already-logged-in profile instead of a blank one\n"
            "    ctx = contexts[0] if contexts else browser.new_page().context\n"
            "    if cookie_string:\n"
            "        ctx.add_cookies([{'name': n, 'value': v, 'url': target_url}\n"
            "                         for n, v in (kv.split('=', 1) for kv in cookie_string.split('; ') if '=' in kv)])\n"
            "    page = ctx.new_page()\n"
            "    page.on('request', lambda req: ...)   # record XHR/fetch calls as you navigate\n"
            "    page.goto(target_url)\n"
            "```\n"
            "Navigate through the app's real UI (log in if not already, click through its main sections/"
            "flows) and record every XHR/fetch request you observe — that's the SPA's real API, usually "
            "invisible to a plain crawler.")
    else:
        creds_block.append("No live CDP browser available — use exec-http.py / curl with the cookie/token "
                            "above instead of a real browser for this hunt.")
    if ua:
        creds_block.append(f"User-Agent to send: {ua[:200]}")

    brief = (
        "# Authenticated Session + SPA Capture — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\nMain URL: {url}\n\n"
        f"## In-scope (never test outside this)\n{scope_summary}\n"
        "There is no technical enforcement behind this. You are the only thing stopping an "
        "out-of-scope request.\n\n"
        "## Credentials / session\n" + "\n".join("- " + b for b in creds_block) + "\n\n"
        "## Your job (two parts)\n"
        "1. **Capture the real authenticated API surface.** Establish or confirm a working session, "
        "then drive the app through real usage (not just the login page) to see what it actually calls — "
        "record every distinct endpoint.\n"
        "2. **Test auth-adjacent vulnerability classes with real requests**, using your own judgment on "
        "what's actually confirmed, not a hardcoded checklist: JWT weaknesses (alg:none, weak/guessable "
        "secret, missing signature verification, RS/HS confusion) but ONLY after confirming the endpoint "
        "actually enforces the JWT at all (send a garbage token first — if it's accepted anyway, the "
        "endpoint doesn't validate JWTs and none of this applies); OAuth/OIDC flow issues (open redirect "
        "via redirect_uri, state/PKCE missing, authorization code reuse); session handling (fixation, no "
        "invalidation on logout, predictable tokens); password-reset flow issues (host-header injection "
        "into reset links, no rate limit, token not single-use). Never upgrade a guess into a finding — "
        "verify from the actual response.\n\n"
        f"## Output — append as you go, not all at the end\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-auth-spa.jsonl (create it if missing; "
        "partial results from a timeout are kept). Two line shapes:\n"
        '  {"type":"endpoint","url":"https://.../api/x","host":"...","note":"optional"}\n'
        '  {"type":"finding","title":"...","severity":"critical|high|medium|low|info","cls":"jwt|oauth|'
        'session|authz|...","endpoint":"...","evidence":"what you actually observed","reproduction":'
        '"numbered steps"}\n\n'
        "Begin now: get authenticated, capture real traffic, then test what you found. Stop once you've "
        "covered the meaningful surface or you're repeating yourself."
    )

    def _merge(lines):
        existing_urls = {e.get("url") for e in STATE.get("endpoints", [])}
        added_e = added_f = 0
        for r in lines:
            t = r.get("type")
            if t == "endpoint":
                u = str(r.get("url", "")).strip()
                if u and u not in existing_urls:
                    STATE["endpoints"].append({"url": u, "host": str(r.get("host") or "")})
                    existing_urls.add(u); added_e += 1
            elif t == "finding":
                title = str(r.get("title", "")).strip()
                evidence = str(r.get("evidence", "")).strip()
                endpoint = str(r.get("endpoint", "")).strip()
                if not title or not endpoint or len(evidence) < 20:
                    continue
                sev_map = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i"}
                sev = sev_map.get(str(r.get("severity", "medium")).lower(), "m")
                add_finding(sev, title, evidence, endpoint, cls=str(r.get("cls", "")),
                            verdict="agent", det=False)
                for sf in STATE["findings"]:
                    if sf.get("title") == title and not sf.get("steps"):
                        sf["steps"] = str(r.get("reproduction", ""))[:1000]
                added_f += 1
        STATE["stats"]["endpoints"] = len(STATE["endpoints"])
        STATE["stats"]["findings"] = len(STATE["findings"])
        log("out", "→ auth+SPA agent · +" + str(added_e) + " endpoint(s) · +" + str(added_f) + " finding(s)")

    ok = _run_phase_agent("auth+SPA agent", "Auth+SPA (agentic)", 84, brief, budget,
                           HUNT_DIR / "agent-auth-spa.jsonl", _merge)
    if not ok:
        log("warn", "→ agentic auth+SPA produced nothing — hunt may proceed with an unauthenticated-only surface")
    stage("Auth+SPA (agentic)", 86)


def _phase_intel_agent(deadline=None):
    """Stage 3 of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 1:
    Setup + Program Intel. Replaces phase_program_intel() entirely: one real Claude Code agent
    gathers public OSINT about the program (known disclosures, leaked secrets, exposed infra,
    forgotten-but-still-live endpoints, bounty/reward info) and decides for itself what's worth
    recording, instead of five hardcoded API-call steps.

    phase_source_audit() (the separate code-review path for source-only scope) is NOT folded in here
    — it already reads files and reasons with no regex/hardcoded patterns ("No regex. No hardcoded
    patterns. The LLM hunts." — its own docstring), so it already satisfies the full-agentic intent
    and converting it adds no value; left on the legacy path. phase_scope() also stays — it's plain
    file I/O (writing scope.allow/deny from the CLI args), not judgment.

    Flag-gated: only called from main() when "intel" is in HUNT_AGENTIC_PHASES. Low risk — this phase
    is informational context for later phases plus the occasional leaked-secret finding, never a
    destructive action."""
    budget = 600.0
    if deadline:
        budget = max(90.0, min(budget, deadline - time.time()))
    prog = (PROGRAM or apex(TARGET) or TARGET).strip()
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET
    gh_token_note = ("A GITHUB_TOKEN is set in this environment if you want to use the gh CLI or git "
                      "for a GitHub org scan." if os.environ.get("GITHUB_TOKEN", "").strip() else
                      "No GITHUB_TOKEN is set — a GitHub scan is still possible against public repos "
                      "without one, just rate-limited.")
    shodan_note = ("A SHODAN_API_KEY is set if you want host/port intelligence from Shodan's API."
                   if os.environ.get("SHODAN_API_KEY", "").strip() else
                   "No SHODAN_API_KEY is set — skip Shodan.")

    brief = (
        "# Program Intel — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {prog}\n\n"
        f"## In-scope\n{scope_summary}\n\n"
        "## Your job\n"
        "Gather public intelligence about this program BEFORE any active probing happens, the way a "
        "researcher would before starting a real engagement. You have real Bash access — use curl, "
        "gh, git, whois, or anything else you judge useful; read and interpret the raw output yourself, "
        "there's no scripted parser behind you. Look for:\n"
        "- Already-disclosed reports (HackerOne/Bugcrowd/Intigriti public hacktivity for this program) "
        "— so the hunt doesn't waste time re-finding what's already known.\n"
        f"- {gh_token_note} A leaked secret/key/credential in a public repo is an instant, serious "
        "finding — look for .env files, hardcoded API keys, CI/CD misconfig.\n"
        f"- {shodan_note}\n"
        "- Wayback Machine / archive.org history for this domain — URLs the app used to link to but "
        "removed from its SPA; they often still work on the backend even though nothing links to them "
        "anymore. (`curl 'https://web.archive.org/cdx/search/cdx?url=*.<domain>/*&output=json&"
        "collapse=urlkey&limit=500&filter=statuscode:200'`)\n"
        f"- Any bounty/reward amounts in {HUNT_DIR}/scope.md or scope.json, if present, so later "
        "phases know what severity actually pays here.\n\n"
        f"## Output — append as you go\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-intel.jsonl (create it if missing). Three "
        "line shapes:\n"
        '  {"type":"note","key":"disclosures|github|shodan|wayback|rewards","value":...} — any free-form '
        "JSON you want later phases to see\n"
        '  {"type":"endpoint","url":"https://.../old-path","host":"...","note":"found via wayback, '
        'verify it still responds"}\n'
        '  {"type":"finding","title":"...","severity":"critical|high|medium|low|info","cls":"secret|'
        'misconfig|...","endpoint":"...","evidence":"...","reproduction":"..."} — only for something '
        "genuinely confirmed (e.g. a real leaked secret you can show), not a guess\n\n"
        "Begin now. This is reconnaissance, not exploitation — stay read-only, don't send anything "
        "destructive. Stop once you've covered the obvious OSINT surface or you're repeating yourself."
    )

    def _merge(lines):
        intel = STATE.setdefault("program_intel", {})
        existing_urls = {e.get("url") for e in STATE.get("endpoints", [])}
        added_e = added_f = added_n = 0
        for r in lines:
            t = r.get("type")
            if t == "note":
                k = str(r.get("key", "")).strip()
                if k:
                    intel[k] = r.get("value")
                    added_n += 1
            elif t == "endpoint":
                u = str(r.get("url", "")).strip()
                if u and u not in existing_urls and _in_scope(u)[0]:
                    STATE["endpoints"].append({"url": u, "host": str(r.get("host") or ""),
                                                "source": "intel-agent"})
                    existing_urls.add(u); added_e += 1
            elif t == "finding":
                title = str(r.get("title", "")).strip()
                evidence = str(r.get("evidence", "")).strip()
                endpoint = str(r.get("endpoint", "")).strip()
                if not title or not endpoint or len(evidence) < 20:
                    continue
                sev_map = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i"}
                sev = sev_map.get(str(r.get("severity", "medium")).lower(), "m")
                add_finding(sev, title, evidence, endpoint, cls=str(r.get("cls", "")),
                            verdict="agent", det=False)
                added_f += 1
        log("out", "→ intel agent · " + str(added_n) + " note(s) · +" + str(added_e) +
            " endpoint(s) · +" + str(added_f) + " finding(s)")

    ok = _run_phase_agent("intel agent", "Intel (agentic)", 10, brief, budget,
                           HUNT_DIR / "agent-intel.jsonl", _merge)
    if not ok:
        STATE.setdefault("program_intel", {})
        log("out", "→ agentic intel produced nothing — proceeding without pre-hunt OSINT context")
    flush()


def _phase_plan_agent(deadline=None):
    """Stage 4 of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 4:
    Business-Logic Modeling + Attack Planning. Replaces phase_biz_logic_map()/phase_authz_matrix()/
    phase_plan() entirely: one real Claude Code agent reads the known surface, builds its own mental
    model of the app's entities/roles/value-flows, probes for the most common authorization-boundary
    bug (a regular token reaching an admin/internal endpoint) using its own judgment, and ranks what's
    worth testing next — instead of a hardcoded entity-extraction prompt + a fixed admin-path regex +
    a separate ranking script.

    COMPATIBILITY note: STATE["plan"]["targets"] (a list of {"endpoint","cls"} cells) is still
    produced in the exact shape the legacy phase_plan() always wrote, since the legacy scanner path
    (phase_adaptive/scan_cell) can still consume it when "active_hunt" is NOT in HUNT_AGENTIC_PHASES.
    When Phase 5 IS agentic (_phase_active_hunt_agent), it reads these as ranked suggestions, not a
    hard dispatch table — so this phase's merge_fn still applies the same applicable_classes() filter
    scan_cell()'s own callers rely on, dropping a cls that doesn't actually fit the endpoint (e.g.
    sqli on a static asset) regardless of which path consumes it downstream.

    Flag-gated: only called from main() when "plan" is in HUNT_AGENTIC_PHASES."""
    if NO_LLM or not STATE.get("endpoints"):
        return
    budget = 900.0
    if deadline:
        budget = max(120.0, min(budget, deadline - time.time()))
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    has_session = bool(tok or (c.get("cookie") or "").strip())
    ep_sample = [e["url"] for e in STATE["endpoints"][:150]]
    prog_intel = STATE.get("program_intel") or {}
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET

    brief = (
        "# Business-Logic Modeling + Attack Planning — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n\n"
        f"## In-scope\n{scope_summary}\n"
        "There is no technical enforcement behind this. You are the only thing stopping an "
        "out-of-scope request.\n\n"
        + _surface_brief(90)
        + (f"## Reward table\n{json.dumps(prog_intel['reward_table'])[:400]}\n\n" if prog_intel.get("reward_table") else "")
        + _plan_priors()
        + "## Your job (three parts)\n"
        "1. **Model the app** the way a researcher would before attacking it: what are the core "
        "entities (User, Order, Payment, Tenant...)? What role levels exist (anonymous/user/admin/"
        "internal-service)? What multi-step flows matter (checkout, invite, password-reset, signup)? "
        "Which endpoints touch money/credits/quota (the highest-value race-condition targets)?\n"
        + (
            "2. **Probe for broken authorization** using your own judgment, not a fixed checklist: try "
            "the regular authenticated session above against anything that looks admin/internal/"
            "privileged (paths containing admin, internal, manage, staff, actuator, system, debug, "
            "sudo, root), AND consider header-based trust bypasses (an internal service-to-service "
            "header like `service-name`, `x-internal`, `x-forwarded-for` that a gateway might forward "
            "from an external caller without stripping it) — this exact pattern has been a real "
            "critical bug on this family of app before. Confirm from the actual response (real data "
            "returned, not just a 200 with an empty body) before calling it a finding.\n"
            if has_session else
            "2. (No session available — skip the live authorization probe, model the role hierarchy "
            "from endpoint naming/structure alone.)\n"
        )
        + "3. **Rank what's worth testing next.** For each endpoint you think deserves active vulnerability "
        "testing, propose the endpoint plus which vuln classes actually make sense for it given what it "
        "does (e.g. a POST endpoint with a user-supplied ID → idor/authz; a search box → sqli/xss; a "
        "redirect param → redirect/ssrf) — don't propose a class that makes no sense for the endpoint's "
        "role (no injection classes on a static JS file). Valid class names: cors, redirect, idor, "
        "authz, param, xss, sqli, ssti, ssrf, race, graphql, host-header, oauth, prototype-pollution, "
        "mass-assignment, web-cache-deception, csp, cmdi, ldap, xpath, nosqli, crlf, lfi.\n\n"
        f"## Output — append as you go\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-plan.jsonl (create it if missing). "
        "Four line shapes:\n"
        '  {"type":"model","key":"entities|flows|value_endpoints","value":[...]}\n'
        '  {"type":"target","endpoint":"https://.../api/x","cls":"idor"} — one line per endpoint×class '
        "you think is worth testing\n"
        '  {"type":"flow","name":"...","steps":["..."]} — a multi-step attack worth trying (e.g. '
        "password-reset-then-reuse, invite-then-escalate)\n"
        '  {"type":"finding","title":"...","severity":"critical|high|medium|low|info","cls":"authz",'
        '"endpoint":"...","evidence":"...","reproduction":"..."} — only for a genuinely confirmed '
        "authorization bypass, not a guess\n\n"
        "Begin now: model the app, probe authorization if you have a session, then rank what's worth "
        "testing. Stop once you've covered the meaningful surface or you're repeating yourself."
    )

    def _merge(lines):
        biz = STATE.setdefault("biz_logic", {})
        _ren = {"open-redirect": "redirect", "auth-bypass": "authz"}
        targets, flows = [], []
        added_f = 0
        dropped = 0
        for r in lines:
            t = r.get("type")
            if t == "model":
                k = str(r.get("key", "")).strip()
                if k in ("entities", "flows", "value_endpoints"):
                    biz[k] = r.get("value") or []
            elif t == "target":
                ep = str(r.get("endpoint", "")).strip()
                cls = _ren.get(r.get("cls"), r.get("cls"))
                if ep and cls and cls in applicable_classes(ep):
                    targets.append({"endpoint": ep, "cls": cls})
                else:
                    dropped += 1
            elif t == "flow":
                name = str(r.get("name", "")).strip()
                if name:
                    flows.append({"name": name, "steps": r.get("steps") or []})
            elif t == "finding":
                title = str(r.get("title", "")).strip()
                evidence = str(r.get("evidence", "")).strip()
                endpoint = str(r.get("endpoint", "")).strip()
                if not title or not endpoint or len(evidence) < 20:
                    continue
                sev_map = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i"}
                sev = sev_map.get(str(r.get("severity", "medium")).lower(), "m")
                add_finding(sev, title, evidence, endpoint, cls=str(r.get("cls", "authz")),
                            verdict="agent", det=False)
                added_f += 1
        if targets or flows:
            STATE["plan"] = {"targets": targets, "flows": flows}
            STATE["flows"] = flows
            STATE["stats"]["plan_cells"] = len(targets)
            STATE["stats"]["flows"] = len(flows)
        if dropped:
            log("warn", "→ plan agent proposed " + str(dropped) + " cell(s) whose class doesn't fit the endpoint — dropped")
        log("out", "→ plan agent · " + str(len(biz.get('entities', []))) + " entit(y/ies) · " +
            str(len(targets)) + " ranked cell(s) · " + str(len(flows)) + " flow(s) · +" + str(added_f) + " finding(s)")

    ok = _run_phase_agent("plan agent", "Plan (agentic)", 38, brief, budget,
                           HUNT_DIR / "agent-plan.jsonl", _merge)
    if not ok:
        log("out", "→ agentic plan produced nothing — Phase 5 will fall back to the static class matrix")
    flush()


def _phase_active_hunt_agent(deadline=None):
    """Stage 5 of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 5:
    Core Vulnerability-Hunting Loop (largest budget share). Replaces phase_active()/
    phase_race_critical()/phase_adaptive()+scan_cell()/phase_llm_lead()/phase_ai_direct()/
    phase_api_test()/phase_exploit_agent()/phase_oob() entirely: one real Claude Code agent reasons
    continuously over the known surface, decides what to test and in what order, fires real HTTP
    requests itself (curl / exec-http.py via its own Bash tool), and chains a real finding to
    concrete impact — instead of a 0-token endpoint×class sweep dispatching into ~10 separate
    scanner scripts, a bespoke tool-use loop, a second Haiku-driven pass, and a subprocess
    exploitation agent all running as separate layers.

    Third-party CLI binaries encode no HUNTR judgment and stay available via Bash, same framing as
    _phase_recon_surface_agent: nuclei, sqlmap, ffuf, interactsh-client are installed. The agent
    reads/interprets their raw output itself — there is no scripted parser or verdict behind it.

    This is converted LAST among finding-producers (per the plan's migration order), specifically so
    _phase_verify_agent (already converted, see its docstring) is already independently validated and
    sits downstream as a backstop for whatever false positives this phase's own judgment produces.

    Flag-gated: only called from main() when "active_hunt" is in HUNT_AGENTIC_PHASES."""
    if NO_LLM or not STATE.get("endpoints"):
        return
    budget = 5400.0
    if deadline:
        budget = max(600.0, min(budget, deadline - time.time()))
    c = _creds()
    tok = (c.get("session_token") or "").strip()
    tok2 = (c.get("token2") or "").strip()
    has_session = bool(tok or (c.get("cookie") or "").strip())
    ep_sample = [e["url"] for e in STATE["endpoints"][:250]]
    plan = STATE.get("plan") or {}
    plan_targets = (plan.get("targets") or [])[:80]
    flows = (plan.get("flows") or STATE.get("flows") or [])[:20]
    api_calls = [{"method": c2.get("method"), "url": c2.get("url")} for c2 in (STATE.get("api_calls") or [])[:40]]
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET
    denyf = HUNT_DIR / "scope.deny"
    deny_text = denyf.read_text(errors="ignore")[:800] if denyf.exists() else "(none written)"
    scope_block = (
        f"## In-scope (never test outside this)\n{scope_summary}\n"
        f"## Explicitly OUT OF SCOPE — never send a request here\n{deny_text}\n"
        "There is no technical enforcement behind this. You are the only thing stopping an "
        "out-of-scope request.\n"
    )

    brief = (
        "# Core Vulnerability-Hunting Loop — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n\n"
        f"{scope_block}\n"
        + _surface_brief(80)
        + (f"## Ranked plan cells from an earlier phase (endpoint + vuln class worth testing)\n"
           f"{json.dumps(plan_targets, default=str)[:4000]}\n\n" if plan_targets else "")
        + (f"## Multi-step flows worth attacking end-to-end\n{json.dumps(flows, default=str)[:2000]}\n\n"
           if flows else "")
        + (f"## Real runtime API calls the app itself made (SPA capture) — test these FIRST, they're "
           f"confirmed-real, unlike a crawled URL that might 404\n{json.dumps(api_calls, default=str)[:3000]}\n\n"
           if api_calls else "")
        + ("## You have an authenticated session"
           + (" AND a second account (token2 in ./.hunt/creds.json) for cross-account IDOR/race testing"
              if tok2 else "") + ".\n\n" if has_session else
           "## No authenticated session — test what's reachable unauthenticated only.\n\n")
        + "## Your job\n"
        "This is the real hunting loop — the budget share is intentionally the largest of any phase. "
        "Reason the way a human bug bounty hunter would: read real responses, form a hypothesis, test "
        "it, and if it's real, chain it to actual impact. There is no scripted scanner behind you "
        "deciding what's a bug — your judgment is the only verification this phase has (a separate "
        "skeptical verify pass runs after you, so don't worry about being the final word, but DO back "
        "every claim with a concrete observed response, not a guess).\n\n"
        "1. **Full coverage, not a sample.** Work through the known endpoints (and the ranked plan "
        "cells / flows / runtime API calls above, which deserve priority) deciding for each one which "
        "vuln classes actually make sense given what it does — don't test sqli on a static asset or "
        "idor on an endpoint with no object id. Valid classes: cors, redirect, idor, authz, param, "
        "xss, sqli, ssti, ssrf, race, graphql, host-header, oauth, prototype-pollution, "
        "mass-assignment, web-cache-deception, csp, cmdi, ldap, xpath, nosqli, crlf, lfi. Fire real "
        f"requests via `python3 {HERE}/exec-http.py --url <url> [--method ...] [--data ...]` (auto-"
        "captures evidence) or curl directly — either is fine, you decide.\n\n"
        "2. **Race conditions** on stateful/value-flow endpoints (payment, credit, coupon, limit, "
        "redeem, transfer): fire concurrent requests yourself — a short Python script with a "
        "ThreadPoolExecutor, or `ffuf -c` style bursts — and check for a double-spend/over-redeem "
        "effect across the responses. If you have a second account, also test the cross-account case "
        "(account A's token racing against account B's object).\n\n"
        "3. **Blind/OOB injection** (SSRF, blind cmdi, SSTI, XXE, log4shell-style): `interactsh-client` "
        "is installed — start it yourself to get a real callback domain, inject that domain into "
        "candidate sinks, and only call it confirmed if you actually observe a callback in the "
        "interactsh output. A blocked/odd response alone is never proof for this class.\n\n"
        "4. **Deep authenticated exploitation.** Once something looks real (IDOR/BOLA/BFLA, privilege "
        "escalation, business-logic abuse), don't stop at one probe — go deeper the way a human "
        "pentester chains access: read data you shouldn't, modify something that shouldn't be yours, "
        "escalate role — and capture the exact request/response that proves it.\n\n"
        "5. **nuclei is installed** — run it yourself against the live hosts if you think it's worth "
        "the time (`nuclei -u <host> -severity critical,high,medium`), but READ every hit yourself "
        "before trusting it; nuclei's own template matches are frequently wrong and you are the judge, "
        "not the template.\n\n"
        "6. **Hard-won false-positive lessons, re-taught in prose since no code enforces them "
        "anymore:**\n"
        "   - A marker/pattern matching ANYWHERE in a response (an echoed error, a wrapper field) is "
        "not the same as it appearing as a NEW, attacker-controlled effect.\n"
        "   - Same response SIZE is not proof of identical content — read the actual bodies.\n"
        "   - A blocked/crashed exploitation attempt is not confirmed RCE/SSTI just because it looks "
        "unusual.\n"
        "   - For IDOR/authz: confirm the SAME request without proper authorization is actually "
        "denied (a real negative-case baseline) before calling it proven.\n"
        "   - Security-header/CSP/clickjacking/missing-header classes are informational at most, "
        "never Critical/High/Medium.\n\n"
        f"## Output — append as you go, not all at the end\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-hunt.jsonl (create it if missing):\n"
        '  {"type":"finding","sev":"critical|high|medium|low|info","title":"...","detail":"what you '
        'observed, concretely","endpoint":"https://.../api/x","cls":"idor","verdict":"confirmed|'
        'likely","evidence":"the exact proof \\u2014 request/response or callback"}\n\n'
        f"{scope_block}\n"
        "Begin now: work through the surface, test for real, and write a finding line the moment you "
        "confirm or strongly suspect one. Stop once you've covered the meaningful surface, you're "
        "repeating yourself, or you run out of budget."
    )

    def _merge(lines):
        n = 0
        for r in lines:
            if r.get("type") != "finding":
                continue
            title = str(r.get("title", "")).strip()
            endpoint = str(r.get("endpoint", "")).strip()
            detail = str(r.get("detail") or r.get("evidence") or "").strip()
            if not title or not endpoint or len(detail) < 10:
                continue
            sev = str(r.get("sev", "medium")).strip().lower()
            verdict = str(r.get("verdict", "likely")).strip()
            if verdict not in ("confirmed", "likely"):
                verdict = "likely"
            proof = None
            evidence = str(r.get("evidence", ""))[:300]
            if verdict == "confirmed" and evidence:
                proof = {"proven": True, "method": "phase5-agent", "evidence": evidence}
            add_finding(sev, title, detail, endpoint, cls=str(r.get("cls", "")),
                        verdict=verdict, det=(verdict == "confirmed"), proof=proof,
                        source="phase5-agent")
            n += 1
        log("out", "→ active-hunt agent · +" + str(n) + " finding(s)")

    ok = _run_phase_agent("active-hunt agent", "Hunt (agentic)", 75, brief, budget,
                           HUNT_DIR / "agent-hunt.jsonl", _merge)
    if not ok:
        log("warn", "→ agentic active-hunt produced nothing — this run will have little/no new findings")
    stage("Hunt (agentic)", 90)
    flush()


def _phase_verify_agent(deadline=None):
    """Stage 5 of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 6:
    Verify + Triage + Dedup. Replaces phase_dedup()/phase_verify()/phase_ai_judge()/
    phase_adversarial_verify()/phase_hard_triage() entirely: one real Claude Code agent re-examines
    every finding gathered so far — re-probing live where it wants more evidence (exec-http.py /
    curl via its own Bash tool) — and independently decides confirmed/likely/false_positive/
    needs_review, final severity, and whether it collapses into another finding as the same root
    cause. No _det_oracle 36-class dispatch table, no HARD_INFO/_IMPACT/_CHAIN_REQ hardcoded class
    lists, no separate adversarial-verify.py second-judge subprocess.

    DELIBERATE ORDERING NOTE (see the plan's migration order): this is converted BEFORE Phase 5
    (the core hunting loop) is. Phase 5 still runs legacy/deterministic right now, so any
    verification regression here is attributable to the verifier alone, not entangled with a
    simultaneous change to what's finding things. This is the highest-stakes conversion in the
    whole rewrite — every one of the ~36 oracle-class false-positive fixes in this project's memory
    (CRLF marker matching, race-fire per-response ID pooling, idor-chain size-only confirmation,
    ssti-probe traceback matching, and more) lived in exactly the code this phase replaces, so the
    brief explicitly re-teaches the agent the hard-won lessons those fixes encoded, in prose, since
    there's no code left enforcing them.

    phase_methodology() (invariant/capability-graph/coverage-ledger bookkeeping) and
    phase_fingerprint() (endpoint-pattern flagging) are NOT folded in here — they're housekeeping/
    telemetry, not finding-verification judgment; left on the legacy path.

    Flag-gated: only called from main() when "verify" is in HUNT_AGENTIC_PHASES."""
    findings = STATE.get("findings", [])
    if not findings:
        return
    budget = 1800.0
    if deadline:
        budget = max(180.0, min(budget, deadline - time.time()))
    # one line per finding, truncated — the agent gets the real evidence/detail, not just a title
    f_sample = []
    for i, f in enumerate(findings[:120]):
        f_sample.append({
            "i": i, "title": f.get("title", ""), "cls": f.get("cls", ""),
            "endpoint": f.get("endpoint", ""), "sev": f.get("label", ""),
            "verdict": f.get("verdict", ""), "detail": str(f.get("detail", ""))[:500],
            "proof": f.get("proof"), "_det": bool(f.get("_det")),
        })
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET

    brief = (
        "# Verify + Triage + Dedup — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n\n"
        f"## In-scope (never test outside this)\n{scope_summary}\n"
        "There is no technical enforcement behind this. You are the only thing stopping an "
        "out-of-scope request.\n\n"
        f"## {len(f_sample)} finding(s) to independently re-examine\n"
        f"{json.dumps(f_sample, default=str)[:12000]}\n\n"
        "## Your job\n"
        "You are the FINAL, skeptical judge — every one of these was claimed by an earlier phase, "
        "but none of them should be trusted at face value. Re-examine each one:\n\n"
        "1. **Verify from real evidence, not the claim.** If `detail`/`proof` already shows a concrete, "
        "specific observation (exact response body/status/header that could only happen if the bug is "
        "real), you can judge from that. If it's vague or you're unsure, re-probe it live yourself "
        f"(`python3 {HERE}/exec-http.py --url <url> [--method ...]` from this directory, or curl) and "
        "look at the actual response before deciding.\n\n"
        "2. **Hard-won lessons from this exact class of mistake, re-taught in prose since no code "
        "enforces them anymore — apply this judgment yourself:**\n"
        "   - A response matching a marker/pattern ANYWHERE (e.g. in an echoed error message, a "
        "reflected value, a wrapper field) is NOT the same as the marker appearing as a NEW, "
        "attacker-controlled effect. Check WHERE and WHY it appears.\n"
        "   - Two responses being the same SIZE or SHAPE is not proof of identical content — read the "
        "actual bodies. A generic denial/error wrapper is often a consistent size regardless of input.\n"
        "   - A blocked/crashed exploitation attempt (garbled output, a framework's own error page) is "
        "not confirmed RCE/SSTI just because it looks unusual — distinguish a real payload execution "
        "from a broken request.\n"
        "   - For an auth/IDOR/BOLA claim: confirm the SAME request without proper authorization is "
        "actually denied (a real baseline), not just assumed — a finding that forgot to test the "
        "negative case is not proven.\n"
        "   - Security-header/CSP/clickjacking/version-disclosure/missing-header classes are informational "
        "at most, never Critical/High/Medium, regardless of how the finding describes itself.\n"
        "   - Only RCE, SQLi, SSTI, SSRF, IDOR/BOLA, authz/auth-bypass, deserialization, XXE, file-upload, "
        "OAuth, JWT, NoSQLi, LFI, command injection, XSS, mass-assignment, race conditions, and similar "
        "genuine-impact classes can be Critical/High/Medium — and only with real proof. CORS/open-"
        "redirect/host-header/cache-poisoning/clickjacking are info UNLESS they ride a proven chain to "
        "real impact.\n\n"
        "3. **Collapse duplicates.** If two or more findings describe the SAME root cause (same "
        "underlying bug tested via a different path, param, or tool), they are ONE bug — pick the "
        "best-evidenced one and mark the others as duplicates of it, don't let 10 findings about one "
        "misconfigured header count as 10 bugs.\n\n"
        f"## Output — append as you go, matching findings by their \"i\" index above\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-verify.jsonl (create it if missing):\n"
        '  {"type":"verdict","i":3,"verdict":"confirmed|likely|false_positive|needs_review",'
        '"sev":"critical|high|medium|low|info","reco":"submit|needs-work","note":"why, in one line"}\n'
        '  {"type":"dup","i":7,"duplicate_of":3,"why":"same root cause as #3, different param"}\n\n'
        "Begin now: go through every finding above, re-probe where you need more evidence, and emit "
        "a verdict line for each one. Don't skip any — an untouched finding keeps whatever verdict it "
        "already had, which defeats the point of this pass."
    )

    def _merge(lines):
        by_i = {}
        for i, f in enumerate(findings[:120]):
            by_i[i] = f
        sev_map = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i"}
        verdicts = dups = 0
        for r in lines:
            t = r.get("type")
            i = r.get("i")
            if not isinstance(i, int) or i not in by_i:
                continue
            f = by_i[i]
            if t == "verdict":
                v = str(r.get("verdict", "")).strip()
                if v in ("confirmed", "likely", "false_positive", "needs_review"):
                    f["verdict"] = v
                sev = r.get("sev")
                if sev and str(sev).lower() in sev_map:
                    f["sev"] = sev_map[str(sev).lower()]
                    f["label"] = SEVLABEL[f["sev"]]
                reco = str(r.get("reco", "")).strip()
                if reco in ("submit", "needs-work"):
                    f["reco"] = reco
                f["agent_verify_note"] = str(r.get("note", ""))[:300]
                # _proven(f) (checked by the legacy phase_hard_triage backstop still running after this —
                # see its call site comment) only looks at proof.proven/_det, neither of which this agent
                # sets anywhere else — without this, a "confirmed" verdict here gets silently flipped back
                # to "likely" and capped at medium by that backstop's RULE 2, undermining this phase's own
                # judgment the moment it runs. Setting proof.proven=True on a genuine confirm keeps the
                # two cooperating instead of the legacy floor fighting the agent that's supposed to replace it.
                if v == "confirmed":
                    f["proof"] = {"proven": True, "method": "agent-verify", "evidence": f["agent_verify_note"]}
                f["noise"] = f.get("verdict") in ("false_positive",) or f.get("sev") == "i" and f.get("reco") != "submit"
                verdicts += 1
            elif t == "dup":
                dup_of = r.get("duplicate_of")
                if isinstance(dup_of, int) and dup_of in by_i and dup_of != i:
                    f["noise"] = True
                    f["dup_of_index"] = dup_of
                    f["reco"] = "hold-duplicate"
                    dups += 1
        real = [f for f in STATE["findings"] if not f.get("noise")]
        STATE["stats"]["findings"] = len(real)
        STATE["stats"]["noise"] = len(STATE["findings"]) - len(real)
        STATE["stats"]["submit_ready"] = sum(1 for f in STATE["findings"] if f.get("reco") == "submit")
        log("out", "→ verify agent · " + str(verdicts) + " verdict(s) · " + str(dups) + " marked duplicate")

    ok = _run_phase_agent("verify agent", "Verify (agentic)", 91, brief, budget,
                           HUNT_DIR / "agent-verify.jsonl", _merge)
    if not ok:
        log("warn", "→ agentic verify produced nothing — findings keep whatever verdict earlier phases gave them")
    flush()


def _phase_chain_economics_agent(deadline=None):
    """Stage 6 of the full-agentic rewrite (see HUNTR full-agentic plan, 2026-10-25) — Phase 7:
    Chain-to-Impact + Economics. Replaces phase_chain()/phase_scenario()/phase_economics() entirely:
    one real Claude Code agent looks at the confirmed findings and reasons about which ones combine
    into a bigger-impact story (e.g. an info-leak + an authz bypass + a weak-token issue chaining to
    full account takeover), and estimates each finding's real-world value/priority — instead of a
    graph-reachability algorithm (_finding_edges/_reach over a hardcoded IMPACT_SEV table) and a
    separate EV-arithmetic formula.

    A chain is only worth reporting when the agent can state EVERY hop concretely from already-proven
    findings — composing a plausible-sounding narrative from unconfirmed steps is exactly the kind of
    overclaiming the rest of this rewrite has been fighting; the brief says so explicitly.

    Flag-gated: only called from main() when "chain_econ" is in HUNT_AGENTIC_PHASES."""
    finds = STATE.get("findings", [])
    confirmed = [f for f in finds if f.get("verdict") == "confirmed" and not f.get("noise")]
    if not confirmed:
        STATE["chains"] = []
        STATE["stats"]["chains"] = 0
        return
    budget = 900.0
    if deadline:
        budget = max(120.0, min(budget, deadline - time.time()))
    prog_intel = STATE.get("program_intel") or {}
    f_sample = []
    for i, f in enumerate(finds):
        if f.get("noise"):
            continue
        f_sample.append({"i": i, "title": f.get("title", ""), "cls": f.get("cls", ""),
                          "endpoint": f.get("endpoint", ""), "sev": f.get("label", ""),
                          "verdict": f.get("verdict", ""), "detail": str(f.get("detail", ""))[:300]})

    brief = (
        "# Chain-to-Impact + Economics — full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\n\n"
        f"## {len(f_sample)} non-noise finding(s)\n{json.dumps(f_sample, default=str)[:8000]}\n\n"
        + (f"## Reward table\n{json.dumps(prog_intel['reward_table'])[:400]}\n\n" if prog_intel.get("reward_table") else "")
        + "## Your job (two parts)\n"
        "1. **Chain findings into bigger impact, only where every hop is real.** Look for cases where "
        "two or more CONFIRMED findings combine into something worse than either alone (e.g. an "
        "information disclosure that reveals a token used by an authz bypass → account takeover; an "
        "open redirect that weaponizes an OAuth flaw; a CORS misconfig that turns an authenticated-only "
        "bug into one reachable cross-origin). A chain needs EVERY step backed by an actual confirmed "
        "finding above — never invent or assume an unconfirmed step just because the story sounds good. "
        "If nothing genuinely chains, say so; a hunt with zero chains is an honest result, not a "
        "failure.\n"
        "2. **Estimate real value/priority for each confirmed finding** (and each chain): how likely is "
        "a triager to accept it, roughly what would it realistically pay on this program (use the "
        "reward table if given, otherwise reason from severity and how major bug-bounty programs "
        "typically price this class of bug), and whether it's likely a near-duplicate of another "
        "finding already in this list.\n\n"
        f"## Output — append as you go\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-chain.jsonl (create it if missing). Two "
        "line shapes:\n"
        '  {"type":"chain","name":"...","sev":"critical|high|medium|low","steps":[{"i":3,"note":"what '
        'this step contributes"},{"i":7,"note":"..."}],"impact":"one line describing the end result"}\n'
        '  {"type":"value","i":3,"ev_band":"high|med|low","bounty_est":2000,"reco":"submit|needs-work|'
        'hold-duplicate","note":"why"}\n\n'
        "Begin now: look for genuine chains first, then value each finding. Stop once you've covered "
        "everything or you're repeating yourself."
    )

    def _merge(lines):
        chains = []
        valued = 0
        for r in lines:
            t = r.get("type")
            if t == "chain":
                name = str(r.get("name", "")).strip()
                steps_in = r.get("steps") or []
                if not name or not steps_in:
                    continue
                steps = []
                ok_chain = True
                for s in steps_in:
                    i = s.get("i")
                    if not isinstance(i, int) or i < 0 or i >= len(finds):
                        ok_chain = False
                        break
                    steps.append({"st": "done", "t": finds[i].get("cls", "") or finds[i].get("title", "")[:30],
                                  "note": str(s.get("note", ""))[:160], "fi": i})
                if not ok_chain:
                    continue
                sev_map = {"critical": "c", "high": "h", "medium": "m", "low": "l"}
                sev = sev_map.get(str(r.get("sev", "medium")).lower(), "m")
                chains.append({"sev": sev, "name": name, "tier": "PROVEN CHAIN", "status": "proven",
                                "impact": str(r.get("impact", ""))[:200], "cvss": "", "steps": steps})
                ep = finds[steps[0]["fi"]].get("endpoint", "") if steps else ""
                add_finding(sev, "Chain → " + name, str(r.get("impact", ""))[:500], ep, cls="Chain",
                            verdict="agent", det=False)
            elif t == "value":
                i = r.get("i")
                if not isinstance(i, int) or i < 0 or i >= len(finds):
                    continue
                f = finds[i]
                band = str(r.get("ev_band", "")).strip().lower()
                if band in ("high", "med", "low"):
                    f["ev_band"] = band
                    f["ev"] = {"high": 2500, "med": 700, "low": 150}[band]
                try:
                    f["bounty_est"] = int(r.get("bounty_est") or 0)
                except Exception:
                    pass
                reco = str(r.get("reco", "")).strip()
                if reco in ("submit", "needs-work", "hold-duplicate"):
                    f["reco"] = reco
                f["agent_value_note"] = str(r.get("note", ""))[:300]
                valued += 1
        chains.sort(key=lambda c: SEVRANK.get(c["sev"], 9))
        STATE["chains"] = chains
        STATE["stats"]["chains"] = len(chains)
        submit_now = [f for f in STATE["findings"] if f.get("reco") == "submit"]
        total_ev = sum(f.get("ev", 0) for f in submit_now)
        STATE["economics"] = {"pipeline_ev": total_ev, "submit_now": len(submit_now),
                               "top": sorted(({"title": f["title"], "sev": f["sev"], "ev": f.get("ev", 0),
                                                "endpoint": f.get("endpoint", "")} for f in submit_now),
                                              key=lambda x: -x["ev"])[:5]}
        STATE["stats"]["pipeline_ev"] = total_ev
        log("out", "→ chain+economics agent · " + str(len(chains)) + " chain(s) · " + str(valued) +
            " finding(s) valued · pipeline EV ~$" + format(total_ev, ","))

    ok = _run_phase_agent("chain+economics agent", "Chain+Economics (agentic)", 97, brief, budget,
                           HUNT_DIR / "agent-chain.jsonl", _merge)
    if not ok:
        STATE.setdefault("chains", [])
        log("out", "→ agentic chain+economics produced nothing — findings keep their existing values")
    flush()


def _scope_block():
    """Shared in/out-of-scope preamble for the agentic phases — the ONLY thing holding an autonomous
    agent inside scope, since these phases have no scope-guard code behind them (same framing as
    _phase_active_hunt_agent/_phase_recon_surface_agent)."""
    scope_summary = ", ".join(WEB_ASSETS)[:400] or TARGET
    denyf = HUNT_DIR / "scope.deny"
    deny_text = denyf.read_text(errors="ignore")[:800] if denyf.exists() else "(none written)"
    return (
        f"## In-scope (never test outside this)\n{scope_summary}\n"
        f"## Explicitly OUT OF SCOPE — never send a request here\n{deny_text}\n"
        "There is no technical enforcement behind this. You are the only thing stopping an "
        "out-of-scope request.\n"
    )


def _phase_deep_questions_agent(deadline=None):
    """Phase 9 — Deep-Questions / stuck-breaker agent (operator directive, 2026-10-30: "a phase 9
    agent that asks the questions a hunter could ask or command to dig deeper even if everything is
    locked"). Runs AFTER the main active-hunt loop, but BEFORE verify, so anything it surfaces flows
    through the same verify → chain → economics tail as any other finding.

    The rest of the pipeline tends to stop once the obvious, in-class surface is covered. A seasoned
    human hunter does not stop there — when a target looks locked down (auth walls, 401/403, WAF,
    "nothing left to test"), they start asking the second-order questions that open new surface:
    is there a v1/v2/beta/internal of this API? a mobile or legacy backend on another host? a
    forgotten subdomain? an undocumented parameter? a header the app trusts (X-Forwarded-*, X-Real-IP,
    X-Original-URL)? a different content-type or HTTP method that routes differently? a flow we never
    completed end-to-end? This agent generates those questions the way a top hunter would AND acts on
    them with real tools — it refuses to accept "exhausted/locked" as an answer.

    Flag-gated: only called from main() when "deep_questions" is in HUNT_AGENTIC_PHASES."""
    if NO_LLM or not STATE.get("endpoints"):
        return
    budget = 2400.0
    if deadline:
        budget = max(300.0, min(budget, deadline - time.time()))
    ep_sample = [e["url"] for e in STATE["endpoints"][:200]]
    finds = [f for f in STATE.get("findings", []) if not f.get("noise")]
    find_titles = [{"title": f.get("title", ""), "endpoint": f.get("endpoint", ""),
                    "cls": f.get("cls", ""), "sev": f.get("label", "")} for f in finds[:40]]
    cov = STATE.get("coverage", {})
    tested = STATE.get("tested", {})
    tested_count = sum(len(v) for v in tested.values()) if isinstance(tested, dict) else 0
    scope_block = _scope_block()

    brief = (
        "# Deep Questions — Phase 9 (stuck-breaker) full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n\n"
        f"{scope_block}\n"
        f"## What the hunt has already done\n"
        f"- {len(STATE['endpoints'])} endpoints mapped · ~{tested_count} endpoint×class cells tested · "
        f"coverage breadth {cov.get('breadth', 0)}%\n"
        f"- {len(finds)} finding(s) so far: {json.dumps(find_titles, default=str)[:3000]}\n"
        + _surface_brief(60)
        + "## Your job — be the hunter who refuses to accept 'locked' or 'exhausted'\n"
        "The normal pipeline has run every obvious in-class test on the obvious surface. You are the "
        "second-order pass: the experienced hunter who, staring at a target that looks fully locked "
        "down, starts asking the questions that open NEW surface — and then actually tries them. Don't "
        "re-run what's already been tested above; go sideways and deeper.\n\n"
        "Ask-and-try, concretely (these are prompts, not a checklist to recite — reason about which "
        "apply here, then execute the promising ones with real requests):\n"
        "  • **Version pivots** — is there a /v1 /v2 /v3 /beta /internal /legacy of an endpoint that's "
        "locked on the current version? Older versions often skip an authz check the new one added.\n"
        "  • **Alternate hosts/surfaces** — a mobile-app backend, an admin/staging host, an API "
        "subdomain, a different vhost (Host header swap) that serves the same app with weaker controls? "
        "(Only if in scope above.)\n"
        "  • **Trusted headers** — does the app trust X-Forwarded-For / X-Forwarded-Host / X-Real-IP / "
        "X-Original-URL / X-Rewrite-URL / X-Forwarded-Proto to make auth, routing, or ACL decisions?\n"
        "  • **Parameter mining** — hidden/undocumented params (debug=, admin=, test=, role=, "
        "internal=, format=, callback=), mass-assignment fields the UI never sends, params present in "
        "JS/old versions but not the current flow.\n"
        "  • **Method / content-type routing** — does PUT/PATCH/DELETE/OPTIONS or a different "
        "Content-Type (json vs form vs xml) reach a different, less-guarded code path?\n"
        "  • **Unfinished flows** — a multi-step flow (signup→verify→use, cart→checkout→pay, "
        "invite→accept) where the middle or final step was never exercised end-to-end.\n"
        "  • **State/role angles** — what changes if you repeat a request as a different role, after "
        "logout, with a stale/second token, or out of the intended order?\n\n"
        "You have real Bash + tools: curl, `python3 " + str(HERE) + "/exec-http.py --url <url> ...` "
        "(auto-captures evidence), subfinder/httpx/ffuf/gau/nuclei if a question calls for them. Back "
        "every claimed bug with a concrete observed response (a real before/after), never a guess — a "
        "skeptical verify pass runs after you.\n\n"
        "The same hard-won false-positive rules from the main hunt apply: a blocked/odd response is not "
        "a finding; confirm a real denied baseline before calling an authz/IDOR bug proven; "
        "security-header/CSP/clickjacking classes are informational at most.\n\n"
        f"## Output — append as you go, not all at the end\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-deep.jsonl (create it if missing):\n"
        '  {"type":"question","q":"the hunter-question you asked","tried":"what you actually did",'
        '"result":"what came back"}   ← log your reasoning trail; these are not findings\n'
        '  {"type":"finding","sev":"critical|high|medium|low|info","title":"...","detail":"what you '
        'observed concretely","endpoint":"https://.../x","cls":"idor","verdict":"confirmed|likely",'
        '"evidence":"the exact before/after proof"}\n\n'
        f"{scope_block}\n"
        "Begin now: generate the questions a top hunter would ask on THIS target given everything "
        "above, try the promising ones for real, and write a finding line the moment one lands. Stop "
        "when you've genuinely run out of new angles (not just when the easy ones are done) or you run "
        "out of budget."
    )

    def _merge(lines):
        n = q = 0
        for r in lines:
            t = r.get("type")
            if t == "question":
                q += 1
                qq = str(r.get("q", ""))[:120]
                res = str(r.get("result", ""))[:120]
                if qq:
                    log("out", "→ Q: " + qq + (" · " + res if res else ""))
                continue
            if t != "finding":
                continue
            title = str(r.get("title", "")).strip()
            endpoint = str(r.get("endpoint", "")).strip()
            detail = str(r.get("detail") or r.get("evidence") or "").strip()
            if not title or not endpoint or len(detail) < 10:
                continue
            verdict = str(r.get("verdict", "likely")).strip()
            if verdict not in ("confirmed", "likely"):
                verdict = "likely"
            evidence = str(r.get("evidence", ""))[:300]
            proof = {"proven": True, "method": "phase9-deep", "evidence": evidence} \
                if verdict == "confirmed" and evidence else None
            add_finding(str(r.get("sev", "medium")).strip().lower(), title, detail, endpoint,
                        cls=str(r.get("cls", "")), verdict=verdict, det=(verdict == "confirmed"),
                        proof=proof, source="phase9-deep")
            n += 1
        log("out", "→ deep-questions agent · " + str(q) + " question(s) tried · +" + str(n) + " finding(s)")

    ok = _run_phase_agent("deep-questions agent", "Deep Questions (agentic)", 89, brief, budget,
                           HUNT_DIR / "agent-deep.jsonl", _merge)
    if not ok:
        log("out", "→ deep-questions agent produced nothing new — surface looks genuinely covered this pass")
    flush()


def _phase_zeroday_agent(deadline=None):
    """Phase 10 — Zero-Day agent (operator directive, 2026-10-30: "a phase 10 for zero-day agent that
    does novel bypass techniques for 4xx and 5xx and hunts for novel vulns"). Runs after Phase 9,
    before verify.

    Every other phase treats a 401/403/404/405/429 or a 5xx as a dead end. This agent treats a block
    as the START of the work: it hunts the surface for endpoints that refuse or error, then applies
    creative bypass techniques to turn the block into access, and reasons about NOVEL vulnerability
    classes — parser/implementation quirks specific to THIS target's stack — rather than the templated
    classes the main loop already covered.

    Flag-gated: only called from main() when "zero_day" is in HUNT_AGENTIC_PHASES."""
    if NO_LLM or not STATE.get("endpoints"):
        return
    budget = 2400.0
    if deadline:
        budget = max(300.0, min(budget, deadline - time.time()))
    ep_sample = [e["url"] for e in STATE["endpoints"][:220]]
    scope_block = _scope_block()

    brief = (
        "# Zero-Day — Phase 10 (novel bypass + novel-vuln) full agentic phase\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n\n"
        f"{scope_block}\n"
        + _surface_brief(70)
        + "## Your job — turn blocks into access, and hunt the novel bug\n"
        "The rest of the hunt gave up wherever the server said no. You start there. Two tracks:\n\n"
        "### 1. Bypass the 4xx / 5xx\n"
        "First FIND the walls: probe the surface (curl / `python3 " + str(HERE) + "/exec-http.py`) and "
        "note every endpoint returning 401/403/404/405/429 or 5xx. Then, on each promising one, try to "
        "flip it to a success the way real 403-bypass research does — and only claim it when you see a "
        "concrete before→after (e.g. 403 → 200 with real content you shouldn't get):\n"
        "  • **Path mutation** — `/admin` vs `/admin/` `/admin/.` `/admin/..;/` `/./admin` `/%2e/admin` "
        "`/admin%20` `/admin%09` `/admin#` `/admin?` `/ADMIN` `/Admin`; double-encoding `%252e`; "
        "unicode/overlong-UTF8 normalization; trailing dot/space/tab/newline.\n"
        "  • **Path-override headers** — X-Original-URL / X-Rewrite-URL / X-Override-URL set to the "
        "blocked path while requesting an allowed one (front-end ACL vs back-end routing differential).\n"
        "  • **Identity/origin headers** — X-Forwarded-For / X-Real-IP / X-Client-IP = 127.0.0.1 / "
        "localhost / internal ranges; X-Forwarded-Host; X-Forwarded-Proto; Host-header swap to an "
        "internal vhost.\n"
        "  • **Method & protocol differentials** — swap GET↔POST↔PUT↔PATCH↔HEAD↔OPTIONS; "
        "X-HTTP-Method-Override; HTTP/1.0 vs /1.1 vs /2; request smuggling-style CL/TE or header "
        "parsing differentials between the edge and the origin.\n"
        "  • **Content-type / body differentials** — same endpoint as json vs form vs multipart vs xml; "
        "a parser that accepts one and skips a check present on another.\n"
        "  • **5xx as signal** — a 500 means you reached code the app didn't expect to run: malformed "
        "type, oversized field, null byte, deeply nested json, unexpected array-vs-object. Read the "
        "error — a stack trace / internal path / library version is itself a finding and often the "
        "thread that unravels a deeper bug.\n\n"
        "### 2. Hunt the novel vuln\n"
        "Beyond the templated classes: reason about THIS target's actual stack and look for the "
        "implementation-specific bug a scanner would never template — a parser differential between two "
        "components, a trust assumption between services, a state machine that can be driven into an "
        "impossible state, an encoding/normalization mismatch, a logic flaw unique to how THIS app "
        "composes its pieces. Form a specific hypothesis, test it for real, prove it with the exact "
        "request/response.\n\n"
        "Proof bar is the same as the rest of the hunt: a concrete observed effect, never 'this looked "
        "unusual'. A bypass is only real with the before(blocked)→after(allowed) pair captured. A "
        "verify pass runs after you.\n\n"
        f"## Output — append as you go, not all at the end\n"
        f"Write one JSON object per line to {HUNT_DIR}/agent-zeroday.jsonl (create it if missing):\n"
        '  {"type":"finding","sev":"critical|high|medium|low|info","title":"...","detail":"what you '
        'observed concretely","endpoint":"https://.../x","cls":"bypass|novel|...","verdict":"confirmed|'
        'likely","technique":"the exact mutation/header that worked","evidence":"before 403 → after 200 '
        '+ the proof"}\n\n'
        f"{scope_block}\n"
        "Begin now: map the blocked surface, work the bypasses, hunt the novel bug, and write a finding "
        "line the moment a block flips or a novel vuln proves out. Stop when you've worked the blocked "
        "surface and run out of credible novel hypotheses, or you run out of budget."
    )

    def _merge(lines):
        n = 0
        for r in lines:
            if r.get("type") != "finding":
                continue
            title = str(r.get("title", "")).strip()
            endpoint = str(r.get("endpoint", "")).strip()
            detail = str(r.get("detail") or r.get("evidence") or "").strip()
            if not title or not endpoint or len(detail) < 10:
                continue
            tech = str(r.get("technique", "")).strip()
            if tech:
                detail = (detail + " · technique: " + tech)[:700]
            verdict = str(r.get("verdict", "likely")).strip()
            if verdict not in ("confirmed", "likely"):
                verdict = "likely"
            evidence = str(r.get("evidence", ""))[:300]
            proof = {"proven": True, "method": "phase10-zeroday", "evidence": evidence} \
                if verdict == "confirmed" and evidence else None
            add_finding(str(r.get("sev", "medium")).strip().lower(), title, detail, endpoint,
                        cls=str(r.get("cls", "")) or "bypass", verdict=verdict,
                        det=(verdict == "confirmed"), proof=proof, source="phase10-zeroday")
            n += 1
        log("out", "→ zero-day agent · +" + str(n) + " bypass/novel finding(s)")

    ok = _run_phase_agent("zero-day agent", "Zero-Day (agentic)", 90, brief, budget,
                           HUNT_DIR / "agent-zeroday.jsonl", _merge)
    if not ok:
        log("out", "→ zero-day agent produced nothing — no blocks flipped and no novel bug proved this pass")
    flush()


def _phase_js_mine():
    """Pre-LLM JS mining — extract hidden API routes, tokens, and params from all JS files.

    Runs linkfinder + custom regex on every .js endpoint before the LLM phase so the
    agent digest already contains real API routes, Supabase URLs, and auth patterns
    rather than just crawler-discovered surface. Injects results into STATE["endpoints"]."""
    js_eps = [e["url"] for e in STATE.get("endpoints", [])
              if ".js" in e["url"].split("?")[0] and "node_modules" not in e["url"]]
    if not js_eps:
        return

    found_urls = set(e["url"] for e in STATE["endpoints"])
    new_routes = []
    new_keys = []

    import re as _re
    # patterns: fetch/axios calls, Supabase URLs, API routes, bearer tokens in source
    _API_PAT = _re.compile(
        r'(?:fetch|axios\.[a-z]+|request)\s*\(\s*["`\']([^"`\']{4,120})["`\']'
        r'|["`\'](/(?:api|v\d|graphql|rest|admin|auth|user|account)[^"`\'\s]{0,80})["`\']'
        r'|(https?://[a-zA-Z0-9._-]+\.supabase\.(?:co|io)/[^"`\'\s]{0,120})'
        r'|(SUPABASE_(?:URL|KEY|ANON)[^`"\'\s=]{0,5}\s*[=:]\s*["`\']([^"`\']{10,120})["`\'])',
        _re.IGNORECASE
    )

    domain = apex(TARGET)
    from urllib.parse import urlparse as _up, urljoin as _uj

    for js_url in js_eps[:30]:  # cap at 30 JS files
        res = _lead_fetch(js_url, timeout=15)
        body = res.get("body", "") or ""
        if not body or len(body) < 50:
            continue
        for m in _API_PAT.finditer(body[:80000]):
            for grp in m.groups():
                if not grp:
                    continue
                grp = grp.strip()
                if grp.startswith("/") and len(grp) > 1:
                    full = "https://" + domain + grp.split("?")[0].rstrip("/")
                    if full not in found_urls:
                        found_urls.add(full)
                        new_routes.append(full)
                elif grp.startswith("http"):
                    base = grp.split("?")[0].rstrip("/")
                    if base not in found_urls and domain in base:
                        found_urls.add(base)
                        new_routes.append(base)
                elif "KEY" in grp.upper() or "TOKEN" in grp.upper() or "SECRET" in grp.upper():
                    new_keys.append({"source": js_url, "value": grp[:120]})

    for route in new_routes:
        parsed = _up(route)
        STATE["endpoints"].append({"url": route, "host": parsed.netloc, "src": "js_mine"})
    STATE["stats"]["endpoints"] = len(STATE["endpoints"])

    if new_keys:
        STATE.setdefault("js_secrets", []).extend(new_keys)

    # GraphQL introspection probe — if any /graphql endpoint found, try introspection
    graphql_urls = [e["url"] for e in STATE.get("endpoints", [])
                    if "graphql" in e["url"].lower() or "gql" in e["url"].lower()]
    graphql_urls += [r for r in new_routes if "graphql" in r.lower() or "gql" in r.lower()]
    graphql_schemas = []
    _introspection_q = '{"query":"{__schema{types{name fields{name}}}}"}'
    for gql_url in graphql_urls[:5]:
        try:
            res = _lead_fetch(gql_url, method="POST",
                              headers={"Content-Type": "application/json"},
                              body=_introspection_q, timeout=10)
            body = res.get("body", "") or ""
            if "__schema" in body and "types" in body:
                STATE.setdefault("graphql_schemas", []).append({"url": gql_url, "schema": body[:3000]})
                graphql_schemas.append(gql_url)
                new_keys.append({"source": gql_url, "value": f"[GRAPHQL INTROSPECTION OPEN] {body[:200]}"})
        except Exception:
            pass

    # Supabase anon key auto-exploit — if we found a Supabase URL + anon key, try table enumeration
    sb_keys = [k for k in STATE.get("js_secrets", []) + new_keys
               if "supabase" in k.get("source", "").lower() or "SUPABASE" in k.get("value", "").upper()]
    if sb_keys:
        sb_url_match = _re.search(r'https://[a-zA-Z0-9]+\.supabase\.(?:co|io)',
                                  " ".join(k.get("value", "") for k in sb_keys))
        sb_key_match = _re.search(r'eyJ[A-Za-z0-9_\-\.]{20,}', " ".join(k.get("value", "") for k in sb_keys))
        if sb_url_match and sb_key_match:
            sb_base = sb_url_match.group(0)
            sb_key = sb_key_match.group(0)
            # probe common tables
            for tbl in ["users", "profiles", "orders", "payments", "secrets", "admin"]:
                try:
                    res = _lead_fetch(f"{sb_base}/rest/v1/{tbl}?select=*&limit=5",
                                      headers={"apikey": sb_key, "Authorization": f"Bearer {sb_key}"},
                                      timeout=8)
                    body = res.get("body", "") or ""
                    if res.get("status", 0) == 200 and body.startswith("["):
                        STATE.setdefault("supabase_leaks", []).append({
                            "table": tbl, "url": sb_base, "data": body[:500]
                        })
                        new_keys.append({"source": f"{sb_base}/rest/v1/{tbl}",
                                         "value": f"[SUPABASE TABLE OPEN] {tbl}: {body[:150]}"})
                except Exception:
                    pass

    if new_routes or new_keys or graphql_schemas:
        log("ok", f"◈ JS mine · +{len(new_routes)} route(s) · {len(new_keys)} secret(s)"
            f"{' · ' + str(len(graphql_schemas)) + ' GraphQL schema(s)' if graphql_schemas else ''}"
            f" in {len(js_eps)} JS file(s)")
        flush()


def _phase_param_discover():
    """Improvement: arjun + ffuf parameter discovery on the top endpoints.

    Runs arjun (GET/POST param discovery) and ffuf (path fuzzing) on the
    top 10 most interesting endpoints before the LLM sees the surface.
    Injects discovered params into STATE["endpoints"] metadata."""
    if not (has("arjun") or has("ffuf")):
        return
    eps = [e["url"] for e in STATE.get("endpoints", [])
           if e.get("src") != "js_mine"][:10]
    if not eps:
        return

    discovered = []
    wordlist = None
    # find a quick wordlist for ffuf
    for wl in ["/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
               "/usr/share/wordlists/dirb/common.txt",
               "/usr/share/seclists/Discovery/Web-Content/common.txt"]:
        if Path(wl).exists():
            wordlist = wl
            break

    for url in eps[:6]:
        # arjun: discover GET parameters
        if has("arjun"):
            try:
                out, _, rc = sh(["arjun", "-u", url, "--get", "-t", "8",
                                  "--stable", "-q"], timeout=45)
                if rc == 0 and out:
                    import re as _re2
                    params = _re2.findall(r'Parameter found: (\S+)', out)
                    if params:
                        # inject discovered params as endpoint variants
                        for p in params[:10]:
                            new_url = url + ("&" if "?" in url else "?") + p + "=FUZZ"
                            STATE["endpoints"].append({"url": new_url, "host": "", "src": "arjun"})
                            discovered.append(f"{p}@{url}")
            except Exception:
                pass
        # ffuf: quick path fuzz on the base URL
        if has("ffuf") and wordlist and "FUZZ" not in url:
            try:
                from urllib.parse import urlparse as _up2
                base = _up2(url)
                fuzz_url = f"{base.scheme}://{base.netloc}/FUZZ"
                out, _, rc = sh(["ffuf", "-u", fuzz_url, "-w", wordlist,
                                  "-mc", "200,201,204,301,302,307,401,403",
                                  "-t", "20", "-timeout", "5", "-fs", "0",
                                  "-s", "-maxtime", "20"], timeout=35)
                if rc == 0 and out:
                    for line in out.strip().splitlines()[:15]:
                        path = line.strip()
                        if path:
                            new_url = f"{base.scheme}://{base.netloc}/{path.lstrip('/')}"
                            found_urls = set(e["url"] for e in STATE["endpoints"])
                            if new_url not in found_urls:
                                STATE["endpoints"].append({"url": new_url, "host": base.netloc, "src": "ffuf"})
                                discovered.append(new_url)
            except Exception:
                pass

    if discovered:
        STATE["stats"]["endpoints"] = len(STATE["endpoints"])
        log("ok", f"◈ param/path discover · +{len(discovered)} paths/params discovered")
        flush()


def _start_background_scanners():
    """Improvement #4 — fire nuclei + subfinder in background threads before the agent loop.

    Results land in HUNT_DIR/nuclei_bg.txt and HUNT_DIR/subs_bg.txt.
    Claude can read them any time with bash("cat ~/.huntr/targets/.../nuclei_bg.txt").
    This means heavy scanners run in parallel with Claude's reasoning — not after."""
    domain = apex(TARGET)

    # PREVIOUSLY: these fire-and-forget daemon threads discarded sh()'s err/rc entirely. The design
    # (read results later as files in HUNT_DIR) means an empty/missing *_bg.txt was indistinguishable
    # from "the scanner ran and genuinely found nothing" — nobody could tell a timeout/missing-binary
    # from a clean negative. A sibling .err file makes the distinction visible without touching shared
    # STATE/log() from a background thread (which isn't lock-safe to do concurrently with the main loop).
    def _bg_fail(name, err, rc):
        try:
            (HUNT_DIR / (name + "_bg.err")).write_text((err or ("exit " + str(rc)))[:300])
        except Exception:
            pass

    def _nuclei():
        if not has("nuclei"):
            return
        out_f = str(HUNT_DIR / "nuclei_bg.txt")
        hosts = [e["url"] for e in STATE.get("endpoints", [])[:20]] or ["https://" + domain]
        input_f = str(HUNT_DIR / "nuclei_targets.txt")
        Path(input_f).write_text("\n".join(hosts) + "\n")
        _, err, rc = sh(["nuclei", "-l", input_f, "-severity", "critical,high,medium",
            "-silent", "-timeout", "8", "-o", out_f], timeout=300)
        if err in ("timeout", "not-found") or err.startswith("exec-error"):
            _bg_fail("nuclei", err, rc)

    def _subfinder():
        if not has("subfinder"):
            return
        _, err, rc = sh(["subfinder", "-d", domain, "-silent",
            "-o", str(HUNT_DIR / "subs_bg.txt")], timeout=120)
        if err in ("timeout", "not-found") or err.startswith("exec-error"):
            _bg_fail("subfinder", err, rc)

    def _gau():
        if not has("gau"):
            return
        out, err, rc = sh(["gau", "--subs", domain], timeout=90)
        if out:
            (HUNT_DIR / "gau_bg.txt").write_text(out)
        elif err in ("timeout", "not-found") or err.startswith("exec-error"):
            _bg_fail("gau", err, rc)

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


_AUTO_CHAIN_COOLDOWN = 180   # at most one auto-chain LLM call per 3 minutes, however many findings
                             # land in that window. Findings often arrive in a BURST — e.g. 25
                             # instances of one root cause probed at 25 paths — and this used to fire
                             # a brand-new chain-builder.py subprocess + LLM call for EVERY single one
                             # the moment there were 2+ total. It was silently dead (wrong CLI flag)
                             # until that was fixed; now that it actually runs, an un-throttled burst
                             # of ~24 redundant LLM calls on exactly that shape of cluster is a real
                             # cost/noise regression, so this debounces it.
_auto_chain_last = [0.0]
_auto_chain_busy = [False]


def _auto_chain_trigger():
    """Improvement #5 — after a new finding is recorded, auto-run chain-builder.

    Fires in a daemon thread so it doesn't block the agent loop. Debounced to one run per
    _AUTO_CHAIN_COOLDOWN and skipped while a previous run is still in flight — it always reads the
    latest findings when it does run, so nothing is lost, just coalesced.
    Results are appended to STATE['leads'] so the agent sees them in the next round."""
    cb = HERE / "chain-builder.py"
    if not cb.exists() or len(STATE["findings"]) < 2:
        return
    now = time.time()
    if _auto_chain_busy[0] or now - _auto_chain_last[0] < _AUTO_CHAIN_COOLDOWN:
        return
    _auto_chain_last[0] = now
    _auto_chain_busy[0] = True
    def _run():
        try:
            f_arg = json.dumps(STATE["findings"][-10:])
            tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            tmp.write(f_arg); tmp.close()
            out, _, rc = sh(
                [sys.executable, str(cb), "--findings-file", tmp.name, "--json"],
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
        finally:
            _auto_chain_busy[0] = False
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
            # improvement #4: auto-inject session token into authenticated hunts
            req_headers = dict(inp.get("headers") or {})
            if tok and authed and "authorization" not in {k.lower() for k in req_headers}:
                if tok.startswith("ey"):  # JWT-like → Bearer
                    req_headers.setdefault("Authorization", f"Bearer {tok}")
                else:  # cookie-style session
                    req_headers.setdefault("Cookie", tok)
            if tok2 and authed:
                req_headers.setdefault("X-Session-Token", tok2)
            res = _lead_fetch(url, method=str(inp.get("method","GET")),
                              body=inp.get("body"), headers=req_headers)
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
            # brain: record the winning path (last 15 tool calls before this finding)
            with _STATE_LOCK:
                _recent_log = list(STATE.get("lead_log", []))[-15:]
            try:
                _brain().record_winning_path(
                    _stack(), sev + "+" + str(inp.get("cls", "")),
                    _recent_log, TARGET, title
                )
                _brain().record_hit(_stack(), str(inp.get("cls", "unknown")), True)
            except Exception:
                pass
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


def phase_llm_lead(deadline, share=0.95, max_steps=2000):
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

    # dynamic steps: scale with surface size so tokens don't explode on large targets
    n_eps = len(STATE.get("endpoints") or [])
    max_steps = min(max_steps, max(80, n_eps * 3))  # ~3 steps per endpoint, never over caller cap
    steps_each = max(40, max_steps // 2)

    c = _creds()
    tok  = (c.get("session_token") or "").strip()
    tok2 = (c.get("token2") or "").strip()
    authed = (MODE != "black") and bool(tok)

    STATE.setdefault("lead_results", [])
    STATE.setdefault("leads", [])
    stage("LLM-led", 86)

    # improvement #4: start background scanners immediately
    _start_background_scanners()
    # improvement #2: JS mining — inject hidden API routes before LLM sees the surface
    _phase_js_mine()
    # improvement #5: param/path discovery (arjun + ffuf) before LLM phase
    _phase_param_discover()

    _use_tool_loop = (MODEL_LEAD.get("provider") == "anthropic")

    if not _use_tool_loop:
        _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps)
    elif llm_client._cli_mode():
        # Subscription auth (no API key → native tool-use is unreachable, see call_llm_with_tools'
        # own cli-mode refusal). PRIMARY path: the REAL Claude Code agent (operator directive
        # 2026-10-22) — real Bash/Read/Write tools, real task, no fictional persona. Earlier the same
        # day this looked unreliable (0/8) when tested on sonnet-5-5; once the model defaults were
        # reverted to sonnet-4-6/opus-4-8 (see the model-revert commit — 4.x doesn't carry the 5.x
        # generation's sharper autonomous-action caution), re-tested at 5/5 genuine completions: real
        # multi-request reasoning chains, real findings written in the correct format, zero refusals.
        # That's now BETTER than the JSON-harness-persona loop's own ~50% rate, so it's primary with
        # the full lead budget; the JSON loop is the fallback only if this produces nothing at all.
        ok = _phase_claude_code_hunt(lead_deadline, tok, tok2, authed)
        if not ok and time.time() < lead_deadline:
            log("warn", "→ Claude-Code-native hunt produced nothing — falling back to JSON-action loop")
            _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps)
    else:
        n_eps = len(STATE.get("endpoints", []))
        # improvement #5: dual-agent = Claude Haiku (creative) + Nemotron (execution)
        # Claude reasons over the surface and generates hypotheses; Nemotron does the
        # mechanical probe list — no OAuth doubling, no rate-limit collision.
        if n_eps >= 8:
            clusters = _graphify_clusters(n=2)
            if len(clusters) >= 2:
                steps_each = max(40, max_steps // 2)  # computed above; kept for clarity
                log("ok", f"◆ dual-agent mode · Haiku BROAD:{len(clusters[0])} + Haiku DEEP:{len(clusters[1])} endpoints")

                def _run_deep_agent():
                    # Second Haiku agent takes the DEEP cluster — same provider,
                    # serialized via _API_SEMAPHORE so no rate-limit collision
                    _phase_llm_lead_tool_use(
                        lead_deadline, tok, tok2, authed, steps_each,
                        surface_filter=set(clusters[1]), agent_label="DEEP")
                t = threading.Thread(target=_run_deep_agent, daemon=True)
                t.start()
                # First Haiku agent takes the BROAD cluster
                _phase_llm_lead_tool_use(
                    lead_deadline, tok, tok2, authed, steps_each,
                    surface_filter=set(clusters[0]), agent_label="BROAD")
                t.join(timeout=max(0, lead_deadline - time.time()))
            else:
                _phase_llm_lead_tool_use(lead_deadline, tok, tok2, authed, max_steps)
        else:
            _phase_llm_lead_tool_use(lead_deadline, tok, tok2, authed, max_steps)

    actions_taken = len(STATE.get("lead_log", []))
    log("ok", "✓ LLM-led · " + str(actions_taken) + " action(s) · " +
        str(len(STATE["findings"])) + " finding(s) so far")

    # If the tool-use agents produced nothing, retry the JSON loop on the SAME Anthropic tier
    # (operator policy: Anthropic only — no NVIDIA/Groq fallback).
    if actions_taken == 0 and time.time() < lead_deadline:
        log("ok", "◆ LLM-led fallback: 0 tool-use actions — running Anthropic JSON loop")
        _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps, force_model=None)

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
        # digest["endpoints"] is a list of URL strings; untested_cells are dicts with "ep" key
        digest["endpoints"] = [e for e in digest.get("endpoints", [])
                               if (e if isinstance(e, str) else e.get("url","")) in surface_filter]
        digest["untested_cells"] = [c for c in digest.get("untested_cells", [])
                                    if c.get("ep","") in surface_filter]

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
        "  Enumerate tables via Supabase error oracle; test JWTs (alg:none, weak secret)\n\n"
        "## MANDATORY FIRST STEPS (do these before anything else):\n"
        f"  1. bash('cat {HUNT_DIR}/nuclei_bg.txt 2>/dev/null || echo empty') — nuclei scan results\n"
        f"  2. bash('cat {HUNT_DIR}/gau_bg.txt 2>/dev/null | head -50 || echo empty') — historical URLs\n"
        f"  3. bash('cat {HUNT_DIR}/subs_bg.txt 2>/dev/null || echo empty') — subdomains\n"
        "  Only after reading those, proceed with your own hypothesis-driven testing.\n\n"
        "METHODOLOGY:\n"
        "1. READ background scan results (above) — they may already have findings\n"
        "2. JS analysis — grep _next/static/chunks for keys, fetch() calls, auth patterns\n"
        "3. Enumerate: subdomains, hidden routes, edge functions, GraphQL introspection\n"
        "4. Attack: hypothesis → bash/http_request → verify → scan_endpoint → record_finding\n"
        "5. Chain: CORS+XSS=ATO, IDOR+info=data breach, open-redirect+OAuth=token hijack\n"
        "6. record_finding ONLY with OBSERVED evidence (response body, tool output, scanner proof)\n\n"
        "DOORS NOT WALLS: treat 403/404/405/500/WAF as a signal and an opening, never a stop. 403 = the "
        "resource exists and is worth protecting → bypass it (headers, path tricks, method swap, encoding). "
        "404 = the route is hidden → find the sibling/versioned/shadow route. 500 = your input broke logic "
        "→ that's an injection/logic signal, dig in. After you understand the target, HYPOTHESISE "
        "target-specific bugs (the invariant the dev assumed + the one request that breaks it) — don't just "
        "run known checks and report whatever comes back.\n\n"
        "BE SKEPTICAL — the deterministic scanners running alongside you produce real false positives "
        "(e.g. a rate-limit probe matching a 3-letter string inside a random UUID, or a guessed-URL "
        "fallback testing a 404 page as if it were a real endpoint). Before record_finding, verify from "
        "the ACTUAL response, not from what a URL or param name merely suggests. Confirmation bar per class:\n"
        "   • Open redirect: CONFIRMED only by a 3xx status whose Location header points to an EXTERNAL "
        "domain you control, or a body meta/JS redirect to it. A 200, a rewrite header, or the param merely "
        "echoed in the body is NOT a redirect.\n"
        "   • CORS: CONFIRMED only if Access-Control-Allow-Origin reflects an attacker origin AND "
        "Access-Control-Allow-Credentials: true. ACAO: * without creds is informational.\n"
        "   • XSS/SSTI: CONFIRMED only if the payload executes/evaluates unescaped in the response, not if "
        "it is HTML-escaped or merely reflected as text.\n"
        "   • Auth/rate-limit bypass: CONFIRMED only against an endpoint you verified is a REAL auth-related "
        "endpoint (read its response body/schema first) — not one that merely matches an OTP/MFA/verify "
        "pattern in its URL string (that pattern can appear inside an unrelated ID, slug, or UUID).\n"
        "If evidence is ambiguous, keep digging or skip it — never upgrade 'reflected' to 'confirmed'.\n\n"
        "Skill playbook and past wins on similar targets are below — apply matching technique FIRST."
    )

    # brain: inject technique priority hint into sys_p
    try:
        _prio = _brain().get_technique_priority(_stack())
        if _prio:
            _prio_list = ", ".join(p["cls"] for p in _prio[:6])
            sys_p += f"\n\nBRAIN-PRIORITY: Based on {_stack()} history, lead with: {_prio_list} (highest confirmed hit rates)"
    except Exception:
        pass

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

    js_secrets = STATE.get("js_secrets", [])
    js_secrets_text = ""
    if js_secrets:
        js_secrets_text = "\n\n## JS-Mined Secrets/Keys (HIGH PRIORITY — verify and exploit)\n" + "\n".join(
            f"- {s['source']}: `{s['value']}`" for s in js_secrets[:20]
        )

    # brain: pull winning paths + technique priority + past notes + FP filters
    brain_text = ""
    try:
        _stk = _stack()
        _priorities = _brain().get_technique_priority(_stk)
        _paths = _brain().get_winning_paths(_stk, limit=3)
        _notes = _brain().read_hunt_notes(_stk, TARGET, limit=3)
        _fps = _brain().get_fp_filters(limit=15)

        if _priorities:
            top = [f"{p['cls']} ({p['hits']}/{p['attempts']})" for p in _priorities[:8]]
            brain_text += f"\n\n## Brain: Technique Priority for {_stk} stack\n(ordered by historical hit rate — lead with these)\n" + "\n".join(f"- {t}" for t in top)

        if _paths:
            brain_text += "\n\n## Brain: Winning Tool Sequences\n(exact steps that found bugs on similar targets)\n"
            for p in _paths:
                steps = [f"  {s.get('act','?')} → {str(s.get('detail',''))[:60]}" for s in (p.get("path") or [])[-8:]]
                brain_text += f"**{p.get('title','?')}** on {p.get('target','?')}:\n" + "\n".join(steps) + "\n"

        if _notes:
            brain_text += "\n\n## Brain: Notes from Past Hunts on Same Stack\n"
            for n in _notes:
                tag = "✓" if n.get("has_findings") else "○"
                brain_text += f"{tag} [{n.get('target','?')}]: {n.get('note','')[:300]}\n"

        if _fps:
            brain_text += "\n\n## Brain: False Positive Patterns to Avoid\n"
            for fp in _fps[:10]:
                brain_text += f"- {fp['pattern']} (seen {fp['count']}x) — {fp['reason']}\n"
    except Exception:
        pass

    initial_user = (
        "## Hunt State\n" +
        json.dumps(digest, default=str, indent=2)[:5000] +
        corpus_text +
        playbook_text +
        prior_lead_text +
        js_secrets_text +
        brain_text +
        "\n\n## Hunt State is ground truth — trust coverage_pct/brain_priority over your own memory\n"
        "of what you've tried: if context gets compacted, re-read ## Hunt State, not your own recollection.\n"
        "brain_priority is this stack's ACTUAL historical hit-rate across past hunts — lead with the\n"
        "highest hit_rate classes there before classes you merely find interesting.\n\n"
        "Begin the hunt. Map surface → identify targets → attack → record findings."
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
        # brain: track whether this tool type leads to findings
        try:
            _found_after = len(STATE["findings"]) > 0
            _brain().record_tool_use(name, _found_after)
        except Exception:
            pass
        # improvement #7: checkpoint conversation every 10 tool calls
        if step % 10 == 0:
            _save_conversation_checkpoint(messages_snapshot[0])
        if time.time() > lead_deadline:
            raise TimeoutError("lead budget exceeded")

    tools = _hunt_tools(authed)

    try:
        # Tool-use iterations run on the cheap tier — pinned to Sonnet 5.5 (operator: Anthropic only).
        tool_model = MODEL_CHEAP.get("model", "claude-sonnet-4-6")
        final_text, tool_log, err = llm_client.call_llm_with_tools(
            system=sys_p,
            initial_user=initial_user,
            tools=tools,
            tool_executor=executor,
            model=tool_model,
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
            # Operator policy: Anthropic ONLY — no NVIDIA/Groq fallback. On a rate-limit the JSON loop
            # stays on the Anthropic tier (it will pause/resume via RateLimitPause rather than switch providers).
            _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps, force_model=None)
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


def _phase_llm_lead_json(lead_deadline, tok, tok2, authed, max_steps, force_model=None):
    """JSON-action loop with real multi-turn feedback — Nemotron/non-Anthropic providers.

    Each action's actual HTTP response or scan result feeds back into the conversation
    thread so the LLM has compound context rather than restarting from scratch each step."""
    log("ok", "◆ LLM-led loop (JSON mode) · max " + str(max_steps) + " steps")
    tried = set()
    for _r in STATE.get("lead_results", []):
        if isinstance(_r.get("k"), list):
            tried.add(tuple(_r["k"]))
    stale = 0
    transport = 0

    # Framing matters: live-tested finding (same as agent_core's fallback loop). Asking the model to
    # "take an action" — i.e. claim it is itself making a real HTTP request — gets reliably refused
    # under claude -p ("I don't have network access in this session"), no matter the JSON shape or
    # wording of the action name. Asking it to PROPOSE a step for this harness to carry out for real,
    # with an explicit promise it will see the REAL result next turn, is not a capability claim and is
    # NOT refused. Verified live: the old "action" wording got "network egress is blocked" with zero
    # findings; this "propose" wording gets real proposals every round.
    sys_p = (
        "You are an elite bug bounty hunter on target " + str(TARGET) + ". You do NOT have network access "
        "or a shell yourself — this harness performs every request/command on your behalf and reports the "
        "REAL result back to you next turn. Reply STRICT JSON only, naming ONE step for the harness to run:\n"
        'Steps: {"propose":"probe","path":"/path"} | '
        '{"propose":"request","method":"GET","url":"…","headers":{},"body":"…"} | '
        '{"propose":"shell","command":"…"} — run a real shell command (cat/grep the recon files in '
        + str(HUNT_DIR) + "/ for JS secrets/API routes, or re-run subfinder/httpx/katana/nuclei/gau/jq "
        "yourself for a narrower slice than the background scan already covered) | "
        '{"propose":"test","endpoint":"…","class":"sqli|xss|ssti|ssrf|cors|redirect|idor|authz"} | '
        '{"propose":"remember","lead":"…","endpoint":"…"} | '
        '{"propose":"finding","severity":"c|h|m|l","title":"…","cls":"…","endpoint":"…","detail":"…","steps":"…"} | '
        '{"propose":"done","summary":"…"}\n'
        "MANDATORY FIRST STEPS before hypothesizing: shell `cat " + str(HUNT_DIR) + "/nuclei_bg.txt` , "
        "`cat " + str(HUNT_DIR) + "/gau_bg.txt | head -50` , `cat " + str(HUNT_DIR) + "/subs_bg.txt` — "
        "background recon may already have findings or routes worth attacking directly.\n"
        "Only report findings backed by a REAL result you were shown. 401/403 is a lead, not a vuln — "
        "403 means the resource exists and is worth protecting (try a bypass: headers, path tricks, method "
        "swap); 404 means the route is hidden (try sibling/versioned/shadow paths); 500 means your input "
        "broke logic (an injection/logic signal, dig in). Before 'finding', verify from the ACTUAL response "
        "body — a scanner hit, a URL that merely CONTAINS a keyword (e.g. 'otp'/'confirm' inside an unrelated "
        "UUID or slug), or a guessed endpoint that 404s is NOT evidence. Never upgrade 'reflected' to "
        "'confirmed'. Previous step results are in the conversation — use them to decide your next proposal."
    )

    # multi-turn conversation thread — LLM sees all previous action results
    conversation = []  # list of {"role": "user"/"assistant", "content": "..."}

    def _call_llm_threaded(messages):
        """Call LLM with full conversation thread, return JSON plan."""
        mdl = force_model or MODEL_LEAD
        provider = mdl.get("provider", "anthropic")
        if provider == "anthropic":
            # Anthropic multi-turn: use messages API directly
            import llm_client as _lc
            payload = {
                "model": mdl.get("model", "claude-sonnet-4-6"),
                "system": sys_p,
                "messages": messages,
                "max_tokens": 1500,
                "temperature": 0.1,
            }
            data, err, _ = _lc._anthropic_raw_request(payload, timeout=90)
            if data:
                content = data.get("content", [])
                text = "\n".join(b.get("text","") for b in content if b.get("type")=="text").strip()
                # parse JSON directly from the text response — balanced-bracket scan, not a greedy
                # span regex (see _extract_json_from_text's docstring for the live incident class
                # this avoids: trailing prose with a stray brace, e.g. a URL path param like
                # /api/users/{id} in a summary, used to silently swallow a real proposed action).
                try:
                    return json.loads(text)
                except Exception:
                    pass
                parsed = _extract_json_from_text(text)
                if parsed is not None:
                    return parsed
                return None
            return None
        else:
            # For Nemotron and others: flatten conversation into a single user message
            flat = json.dumps(state, default=str) if not messages else (
                json.dumps(state, default=str) + "\n\n## Previous Actions\n" +
                "\n".join(
                    f"[{m['role']}]: {m['content'][:300]}"
                    for m in messages[-10:]  # last 10 turns = enough context
                )
            )
            return llm_json(sys_p, flat, max_tokens=1500, timeout=90, _model=mdl)

    for step in range(max_steps):
        if time.time() > lead_deadline:
            log("warn", "⏱ LLM-led loop budget reached at step " + str(step))
            break
        check_pause()
        STATE["stage"] = "LLM-led " + str(step + 1)
        STATE["pct"] = min(94, 86 + int(step / max(1, max_steps) * 8))
        flush()
        state = _lead_digest()

        # build user message: digest on first turn, action result on subsequent turns
        if not conversation:
            usr_content = json.dumps(state, default=str)
        else:
            usr_content = json.dumps(state, default=str)  # always include fresh digest

        conversation.append({"role": "user", "content": usr_content})
        plan = _call_llm_threaded(conversation)
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
        act = (plan.get("propose") or plan.get("action") or "").lower().strip()
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

        elif act == "shell":
            cmd = str(plan.get("command") or "").strip()
            if not cmd:
                res = {"ok": False, "err": "missing command"}
            else:
                key = ("shell", cmd[:200])
                if key in tried:
                    res = {"ok": False, "err": "already ran"}
                else:
                    tried.add(key); cur_key = key
                    log("cmd", "$ " + cmd[:120])
                    out, err, rc = sh(["bash", "-c", cmd], timeout=60)
                    combined = (out + err).strip()
                    if len(combined) > 3500:
                        combined = llm_client.summarize_if_large(combined, threshold=3500, label="shell:" + cmd[:40])
                    res = {"ok": rc == 0, "exit": rc, "output": combined[:3500] or "(no output)"}
                    flush()

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
                with _STATE_LOCK:   # defensive — same STATE["leads"] mutation shape as _note_gated
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

            # improvement #3: feed real action result back into conversation thread
            # assistant said plan, user (system) replies with actual result
            conversation.append({"role": "assistant", "content": json.dumps(plan, default=str)})
            result_summary = json.dumps(res, default=str)[:800]
            conversation.append({"role": "user", "content": f"Action result: {result_summary}"})
            # keep thread bounded to avoid Nemotron context overflow
            if len(conversation) > 40:
                # keep first 2 (initial context) + last 38 (recent history)
                conversation = conversation[:2] + conversation[-38:]


def _phase_claude_code_hunt(lead_deadline, tok, tok2, authed, max_budget=None):
    """REAL Claude Code, not a simulated bug-bounty-harness persona — operator directive 2026-10-22
    ("I want HUNTR to act like Claude Code exactly"). PRIMARY hunting path under CLI-subscription auth.

    _phase_llm_lead_json instead asks `claude -p` to ROLEPLAY as an autonomous attacker following a
    fake JSON step-protocol. That fights the CLI's own baked-in identity (it's the real Claude Code
    product, not a blank completion endpoint). This function does the opposite: give Claude Code a
    real task, real Bash/Read/Write tools, and let it do exactly what the operator does when driving
    it by hand — which is the one thing proven to actually out-hunt the scripted sweep.

    RELIABILITY HISTORY (same day, worth keeping — model choice matters more than the mechanism):
    first tested on sonnet-5-5 → 0/8 clean completions. The 5.x generation's sharper injection/
    autonomous-action caution means keeping Claude Code's real identity intact also keeps its real
    suspicion of "a cold, non-interactive request to autonomously attack a named domain" — and it
    refused almost every time. Re-tested after the model defaults were reverted to sonnet-4-6/
    opus-4-8 (see the model-revert commit) → 5/5 genuine completions: real multi-request reasoning
    chains (e.g. hypothesising a javascript: URI bypass in a redirect param, confirming a CORS
    wildcard+credentials spec violation, testing cookie injection — all via real exec-http.py calls),
    real findings written in the correct format, zero refusals. 4.x doesn't carry the heightened
    caution, so it adopts a real task cleanly almost every time. Conclusion: this mechanism was never
    unreliable — sonnet-5-5 specifically was. Keep this on 4.x (MODEL_LEAD's default) going forward;
    re-verify with a fresh side-by-side before ever pointing this at a 5.x model again.

    max_budget: optionally cap this call's wall-clock time below the full lead_deadline (used for a
    bounded trial run; omit it to let Claude run until it decides the surface is covered or time's up).

    SAFETY: raw Bash+curl would bypass scope-guard's allow/deny enforcement entirely (see
    scope-enforcement-gap memory — this is the exact bug class that fix closed for every other call
    site). So Bash(curl *)/Bash(wget *) are denied and the brief instructs exec-http.py (scope-guarded,
    evidence-capturing, identity-aware) for every live request instead — Claude still reasons and
    decides what to test, it just can't throw a raw request at an out-of-scope host while doing it.
    This is a denylist, not a sandbox, so it's defense-in-depth, not a mechanical guarantee — same
    caveat scope-guard.py's own docstring already states for other paths."""
    cli = None
    try:
        import shutil as _shu
        cli = _shu.which("claude") or os.path.expanduser("~/.local/bin/claude")
    except Exception:
        pass
    if not cli or not os.path.exists(cli):
        log("warn", "→ claude CLI not found — cannot run Claude-Code-native hunt")
        return False

    digest = _lead_digest()
    c = _creds()
    cookie = (c.get("cookie") or "").strip()
    scope_summary = ", ".join(sorted(set(e.get("host", "") for e in STATE["endpoints"])))[:400]
    prog_intel = STATE.get("program_intel") or {}
    biz = STATE.get("biz_logic") or {}
    plan_targets = (STATE.get("plan") or {}).get("targets") or []
    top_plan = sorted(plan_targets, key=lambda t: -(t.get("priority") or 0))[:25]
    js_secrets = STATE.get("js_secrets", [])[:15]

    brief = (
        "# Authorized Security Engagement Brief\n\n"
        f"Target: {TARGET}\nProgram: {PROGRAM or TARGET}\nMode: {MODE}-box\n"
        f"In-scope hosts (scope.allow is the authoritative list, same directory): {scope_summary}\n\n"
        "This is a real, authorized bug bounty / VDP engagement being run by this machine's operator. "
        "You are hunting for genuine, exploitable vulnerabilities — not a simulation.\n\n"
        "## Rules\n"
        "1. Stay on the hosts listed above. Never test a host outside scope.allow.\n"
        "2. For EVERY live HTTP request, run: `python3 " + str(HERE / "exec-http.py") +
        " --url <url> [--method GET|POST|...] [--data '<body>'] [--identity session]` from this "
        "directory. It is scope-guarded (refuses out-of-scope hosts automatically), captures full "
        "request/response evidence to ./evidence/, and `--identity session` attaches the operator's "
        "real authenticated session where one is configured. Raw curl/wget are blocked — exec-http.py "
        "is the only way to actually reach the network from here.\n"
        "3. You also have direct access to this engine's existing scanner tools in " + str(HERE) +
        "/ if you want a mechanical check instead of hand-rolling one (auth-bypass.py, sqli-test.py, "
        "ssrf-probe.py, idor-chain.py, jwt-test.py, cors-test.py, mass-assign.py, and more — run with "
        "--help for usage). Use them when they save time; don't feel obligated to.\n"
        "4. DOORS NOT WALLS: treat 403/404/405/500/WAF as a signal, never a stop. 403 = worth "
        "protecting → try a bypass (headers, path tricks, method swap, encoding). 404 = hidden route → "
        "try sibling/versioned/shadow paths. 500 = your input broke logic → injection/logic signal, dig "
        "in. Hypothesize target-specific bugs (the invariant the dev assumed + the request that breaks "
        "it) instead of just running generic checks.\n"
        "5. Confirmation bar — verify from the ACTUAL response, not from what a URL/param name "
        "suggests: open redirect needs a 3xx to an external domain; CORS needs ACAO reflecting the "
        "attacker origin AND ACAC:true; XSS/SSTI needs the payload executing unescaped; an auth/rate-"
        "limit bypass needs you to have confirmed the endpoint is a real auth endpoint first (read its "
        "response body), not just a URL that happens to contain a keyword. Never upgrade 'reflected' to "
        "'confirmed'.\n"
        "6. For every CONFIRMED finding, append one line of JSON to " + str(HUNT_DIR / "agent-findings.jsonl") +
        " (create it if missing) with exactly these keys: "
        '{"title","severity":"critical|high|medium|low|info","cls","endpoint","evidence","reproduction"}. '
        "evidence = what you actually observed (status/body/headers/payload). reproduction = numbered "
        "steps. Do this as you go, not all at the end — if you run out of time partway through, "
        "whatever you've already written is kept.\n"
        + (("7. A knowledge graph of this target's surface exists at " + str(HUNT_DIR / "graphify-out" / "graph.json") +
            " (" + str((HUNT_DIR / 'graphify-out' / 'graph.json').stat().st_size // 1024) + "KB). Before guessing "
            "which endpoint relates to which, query it instead of reading the whole file: `graphify path "
            '"<endpoint-or-entity-A>" "<endpoint-or-entity-B>"` for the shortest relationship between two '
            "things (add --undirected if it reports no path — recon edges aren't always meaningfully "
            'directional), `graphify explain "<node>"` for what connects to one node, or `jq`/`grep` the '
            "JSON directly for something specific. This is usually cheaper and more precise than scrolling "
            "the whole endpoint list looking for a pattern.\n"
            ) if (HUNT_DIR / "graphify-out" / "graph.json").exists() else "")
        + "\n## What's already known about this target\n"
        f"Tech/scope hosts: {scope_summary}\n"
        + (f"Business logic model: {json.dumps(biz)[:1500]}\n" if biz else "")
        + (f"Reward table: {json.dumps(prog_intel.get('reward_table'))[:800]}\n" if prog_intel.get("reward_table") else "")
        + (f"JS-mined secrets/keys (verify + exploit): {json.dumps(js_secrets)[:1500]}\n" if js_secrets else "")
        + (f"Attack-planner's top-ranked targets ({len(top_plan)} of {len(plan_targets)}): "
           f"{json.dumps(top_plan)[:3000]}\n" if top_plan else "")
        + f"\nFull endpoint/coverage digest (untested cells, prior leads, brain priority): "
          f"{json.dumps(digest, default=str)[:4000]}\n\n"
        "Begin now: pick the highest-value target from the above, hypothesize, test it for real via "
        "exec-http.py, and keep going until you've covered the meaningful surface or run out of time."
    )
    # Audit trail only — Claude is NOT told to go read this. Live-tested 2026-10-22: "read file X and
    # carry out what it says" is structurally identical to an indirect prompt-injection pattern (an
    # untrusted file instructing the model to take action), and Claude Code's own injection defenses
    # refuse it outright ("the prior turn was already cut off by a safety classifier... I won't retry
    # a reworded version") — 100% reproducible, independent of roleplay/persona wording. The fix is to
    # never ask for indirect instruction-following at all: pass the brief as the operator's own direct
    # message (the `-p` argument itself), which is simply the normal, legitimate way to give Claude
    # Code a task — exactly how the operator used it by hand for the comparison that started this.
    try:
        (HUNT_DIR / "AGENT_BRIEF.md").write_text(brief)
    except Exception:
        pass   # non-fatal — it's only kept for the operator to inspect what was sent

    model = MODEL_LEAD.get("model") or "claude-sonnet-4-6"
    budget = max(60.0, lead_deadline - time.time())
    if max_budget:
        budget = min(budget, max_budget)
    log("ok", "◆ Claude-Code-native hunt · model=" + model + " · budget=" + str(int(budget)) + "s")
    cmd = [cli, "-p", brief,
           "--model", model,
           "--add-dir", str(HUNT_DIR),
           "--permission-mode", "bypassPermissions",
           "--allowedTools", "Bash", "Read", "Write",
           "--disallowedTools", "Bash(curl *)", "Bash(wget *)", "Edit", "WebFetch", "WebSearch",
           "--no-session-persistence"]
    env = dict(os.environ)
    cdir = os.environ.get("HUNT_CLAUDE_CLI_DIR") or (
        os.path.dirname(os.environ["HUNT_CLAUDE_CREDS"]) if os.environ.get("HUNT_CLAUDE_CREDS") else "")
    if cdir:
        env["CLAUDE_CONFIG_DIR"] = os.path.expanduser(cdir)
    try:
        r = subprocess.run(cmd, cwd=str(HUNT_DIR), capture_output=True, text=True,
                           timeout=budget, env=env)
        summary = (r.stdout or r.stderr or "").strip()
    except subprocess.TimeoutExpired as e:
        summary = ((e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
        log("warn", "⏱ Claude-Code-native hunt hit its time budget — reading whatever findings it wrote so far")
    except Exception as e:
        log("warn", "→ Claude-Code-native hunt failed to launch: " + str(e)[:200])
        return False

    before = len(STATE["findings"])
    fpath = HUNT_DIR / "agent-findings.jsonl"
    n_lines = 0
    if fpath.exists():
        for line in fpath.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            n_lines += 1
            try:
                f = json.loads(line)
            except Exception:
                continue
            title = str(f.get("title", "")).strip()
            evidence = str(f.get("evidence", "")).strip()
            endpoint = str(f.get("endpoint", "")).strip()
            if not title or not endpoint or len(evidence) < 20:
                continue
            sev_map = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i"}
            sev = sev_map.get(str(f.get("severity", "medium")).lower(), "m")
            with _STATE_LOCK:
                add_finding(sev, title, evidence, endpoint, cls=str(f.get("cls", "")),
                            verdict="agent", det=False)
                for sf in STATE["findings"]:
                    if sf.get("title") == title and not sf.get("steps"):
                        sf["steps"] = str(f.get("reproduction", ""))[:1000]
    new_findings = len(STATE["findings"]) - before
    # Success means it actually DID something — never treat a refusal's own explanatory text as
    # success. On the current (4.x) models this is now rare, but a refusal is articulate prose, not
    # an empty/error result, so `bool(summary)` alone would call it a "success" and skip the JSON
    # fallback for the rest of the budget on zero findings — keep this check regardless of which
    # model is active, since it's a 0-cost safety net against exactly that silent failure mode.
    _refusal_re = re.compile(r"i won't|i'm not going to|i don't have a way to verify|"
                              r"safety classifier|prompt.injection|i can't proceed|i won't continue", re.I)
    refused = bool(_refusal_re.search(summary[:400]))
    ok = n_lines > 0 and not refused
    STATE.setdefault("lead_log", []).append({
        "step": 0, "act": "claude_code_native", "ok": ok,
        "detail": ("refused" if refused else f"{n_lines} finding line(s) written, {new_findings} accepted")})
    if refused:
        log("warn", "→ Claude-Code-native hunt refused the task — " + summary[:160].replace("\n", " "))
    else:
        log("ok", "✓ Claude-Code-native hunt done · " + str(n_lines) + " finding(s) written · " +
            str(new_findings) + " accepted · " + summary[:200].replace("\n", " "))
    flush()
    return ok


def phase_plan():
    """Build a TARGET-SPECIFIC attack plan (attack-planner.py): endpoint×class cells ranked by THIS
    target's own sensitivity×ROI×stack-fit, each with a method, plus multi-step FLOWS (business-logic,
    IDOR/BOLA chains, reset-reuse, fee abuse) matched to the discovered endpoints. The adaptive sweep
    and the exploit-agent consume it — so the engine adapts per target instead of applying one matrix."""
    if not (HERE / "attack-planner.py").exists():
        return
    flush()  # the planner reads run.json; make sure recon/surface/harvest are persisted first
    stage("Plan", 38)
    log("cmd", "$ attack-planner — building a target-specific plan + attack flows")
    plan_args = ["--run", str(RUN), "--program", str(PROGRAM or TARGET), "--json"]
    # Pass reward table and biz_logic model so the planner ranks by actual bounty dollars
    prog_intel = STATE.get("program_intel") or {}
    if prog_intel.get("reward_table"):
        plan_args += ["--reward-table", json.dumps(prog_intel["reward_table"])]
    if STATE.get("biz_logic"):
        plan_args += ["--biz-logic", json.dumps(STATE["biz_logic"])]
    d = tool_json("attack-planner.py", plan_args, timeout=150)
    if not isinstance(d, dict) or not d.get("targets"):
        reason = (" (" + _LAST_TOOL_ERR + ")") if (d is None and _LAST_TOOL_ERR) else ""
        log("out", "→ planner produced no plan" + reason + " — falling back to the static class matrix")
        return
    STATE["plan"] = {"targets": d.get("targets", []), "flows": d.get("flows", [])}
    STATE["flows"] = d.get("flows", [])           # surfaced in Send/report as attack flows to run
    STATE["stats"]["plan_cells"] = len(d.get("targets", []))
    STATE["stats"]["flows"] = len(d.get("flows", []))
    log("ok", "✓ plan · " + str(len(d["targets"])) + " ranked cells · " + str(len(d.get("flows", []))) +
        " flows · " + str(d.get("note", ""))[:70])
    flush()


def phase_adaptive(deadline, max_cells=99999):
    """Coverage-to-100% loop: cover EVERY applicable (endpoint × class) cell, ranked by ROI and
    boosted by the LLM leads, until the ledger is drained or the budget/time is hit. Classes are
    INTERLEAVED so a budget cap doesn't spend everything on one class (sqli/ssti) and starve the rest."""
    c = _creds(); tok = (c.get("session_token") or "").strip(); tok2 = (c.get("token2") or "").strip()
    authed_ok = (MODE != "black") and bool(tok)
    leadeps = set((l.get("endpoint") or "").lower() for l in STATE.get("leads", []) if l.get("endpoint"))
    # classes scan_cell can actually test (explicit branches + the deterministic oracle cells)
    _ENG = {"cors", "redirect", "idor", "authz", "param", "xss", "sqli", "ssti", "ssrf", "race"} | set(_ORACLE_CELL.keys())
    _REN = {"open-redirect": "redirect", "auth-bypass": "authz"}   # planner vocab → engine vocab

    # ── PLAN-DRIVEN worklist (flexible, per-target) ──────────────────────────────────────────────
    # When attack-planner produced a plan, the sweep follows IT: cells ranked by this target's own
    # (sensitivity × ROI × stack-fit), each carrying the right METHOD (POST/JSON bodies get fuzzed,
    # not just query strings). Falls back to the static applicable-class matrix only when no plan.
    plan_targets = (STATE.get("plan") or {}).get("targets") or []
    work = []
    if plan_targets:
        for t in plan_targets:
            ep = t.get("endpoint"); cls = _REN.get(t.get("cls"), t.get("cls")); m = (t.get("method") or "GET").upper()
            if not ep or cls not in _ENG or cls in TESTED.get(ep, set()):
                continue
            if cls == "idor" and not authed_ok:
                continue
            work.append((-(t.get("priority", 0)), ep, cls, m))
        work.sort(key=lambda x: x[0])   # highest planner priority first
        log("ok", "↻ PLAN-DRIVEN sweep — " + str(len(work)) + " ranked cells (target-specific)" +
            ("" if authed_ok else " (unauth: idor skipped — no session)"))
    # COVERAGE TOP-UP (always runs): this is a "cover EVERY applicable cell" loop, so a
    # thin/degraded plan (e.g. HUNT_NO_LLM, where the planner can't enrich) must NOT be able
    # to silently skip whole classes like cors/ssti/redirect. After the plan's ranked cells,
    # append every applicable (ep × class) cell the plan didn't already queue and isn't TESTED.
    from collections import defaultdict
    queued = {(ep, cls) for _, ep, cls, _ in work}
    bycls = defaultdict(list)
    for e in STATE["endpoints"]:
        ep = e["url"]
        for cls in applicable_classes(ep):
            if cls in TESTED.get(ep, set()) or (ep, cls) in queued:
                continue
            if cls == "idor" and not authed_ok:
                continue  # IDOR/BOLA genuinely needs two identities; authz is proven unauth via the bypass matrix
            bycls[cls].append(ep)
    for cls in bycls:
        bycls[cls].sort(key=lambda ep: 0 if any(le and le in ep.lower() for le in leadeps) else 1)

    # ── bandit-priority dispatch: blend the static RANK table with THIS STACK's actual historical
    # hit-rate (hunt-brain.py), instead of scanning every class in the same fixed order every hunt
    # regardless of target. A class that hits 40% of the time on this stack gets scheduled before
    # one that's hit 2% of the time here, even if the static table ranks them the other way —
    # confidence-scaled by attempt count so 2 lucky hits don't outrank a well-established signal.
    _brain_prio = {}
    try:
        for p in _brain().get_technique_priority(_stack()):
            _brain_prio[p["cls"]] = p
    except Exception:
        _brain_prio = {}

    def _bandit_rank(cls):
        base = RANK.get(cls, 9)
        bp = _brain_prio.get(cls)
        if not bp or bp.get("attempts", 0) < 2:
            return base   # no reliable signal yet — fall back to the static prior untouched
        confidence = min(1.0, bp["attempts"] / 10.0)
        return base - (5.0 * bp["rate"] * confidence)   # higher hit-rate → earlier in the queue

    if _brain_prio:
        _top = sorted(_brain_prio.items(), key=lambda kv: -kv[1]["rate"])[:5]
        log("ok", "◆ bandit priority (" + _stack() + ") · " +
            ", ".join(c + " " + str(int(p["rate"] * 100)) + "% (" + str(p["hits"]) + "/" + str(p["attempts"]) + ", " + p["source"] + ")" for c, p in _top))

    _SLOW = {"cmdi", "deserialization"}
    def _rr(classes):
        w = []
        order = sorted(classes, key=_bandit_rank)
        while any(bycls[c] for c in order):
            for cls in order:
                if bycls[cls]:
                    w.append((RANK.get(cls, 9), bycls[cls].pop(0), cls, "GET"))
        return w
    topup = _rr([c for c in bycls if c not in _SLOW]) + _rr([c for c in bycls if c in _SLOW])
    work += topup
    if plan_targets:
        log("ok", "+ coverage top-up — " + str(len(topup)) + " applicable cell(s) the plan didn't rank")
    else:
        log("ok", "↻ adaptive coverage loop — " + str(len(work)) + " untested cells queued" +
            ("" if authed_ok else " (unauth: idor/authz skipped — no session)"))
    total = len(work)
    stage("Hunt", 40)
    done = 0
    # BUG FIX (2026-10-21): the worklist above queues one cell PER DISCOVERED ENDPOINT, and a crawler
    # routinely discovers dozens/hundreds of pre-existing resource instances sharing the same URL
    # shape (every image record behind one media proxy, every order behind one /orders/{id} route,
    # ...). For a pure parameter-injection/output-handling class, the vulnerability lives in the
    # SHARED handling code, not per-resource — live incident: 67 separate OAST round-trips (each with
    # its own wait-for-callback cycle) re-proving the identical SSRF sink on 67 different image
    # UUIDs, burning scan budget for zero new signal once the first one confirmed it. idor/authz/race
    # are deliberately excluded: per-resource access-control behavior genuinely differs there, so
    # every instance IS worth its own test (resource A denying cross-user access doesn't mean
    # resource B does too — that's the opposite assumption from the injection-class case).
    _SKIP_SIBLING_CLASSES = {"ssrf", "ssti", "sqli", "xss", "crlf", "redirect", "cors", "param",
                              "host-header", "nosqli", "ldap", "xpath", "cmdi"}
    _proven_shapes = set()   # (cls, normalized path shape) already confirmed this run
    skipped = 0
    for rank, ep, cls, meth in work[:max_cells]:
        if time.time() > deadline:
            log("warn", "⏱ budget reached — " + str(total - done) + " cells left TODO (resume to continue)")
            break
        shape_key = (cls, _norm_path_shape(ep)[0]) if cls in _SKIP_SIBLING_CLASSES else None
        if shape_key and shape_key in _proven_shapes:
            mark_tested(ep, cls)
            done += 1; skipped += 1
            continue
        before_n = len(STATE["findings"])
        log("cmd", "$ [" + cls + " " + meth + "] " + ep)
        scan_cell(ep, cls, tok, tok2, method=meth)
        if shape_key and any(nf.get("verdict") == "confirmed" for nf in STATE["findings"][before_n:]):
            _proven_shapes.add(shape_key)
        done += 1
        STATE["pct"] = min(86, 40 + int(done / max(1, min(total, max_cells)) * 46))
        STATE["stage"] = "Hunt " + str(done) + "/" + str(min(total, max_cells))
        flush()
    log("ok", "✓ adaptive loop · " + str(done) + "/" + str(total) + " cells scanned" +
        (f" ({skipped} skipped — {len(_proven_shapes)} shape(s) already proven on a sibling instance)" if skipped else ""))
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


def _norm_path_shape(ep):
    """Normalize id-shaped path segments (dashed UUIDs, bare numeric ids, long hex runs) to '{id}' so
    two URLs hitting the SAME vulnerable code path on DIFFERENT pre-existing resource instances
    (/media/image/<uuid-1>/resize vs /media/image/<uuid-2>/resize) collapse to one shape. Returns
    (host+path-shape, sorted-query-param-names). The dashed-UUID pattern MUST run before the
    bare-hex-run one — that one has no dash in its character class, so alone it only eats a UUID's
    first 8-char chunk and leaves the rest sitting in the "normalized" result unchanged."""
    try:
        import urllib.parse as up
        u = up.urlparse(ep or ""); loc = (u.netloc + u.path).lower().rstrip("/")
        loc = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/{id}", loc)
        loc = re.sub(r"/\d+", "/{id}", loc)
        loc = re.sub(r"/[0-9a-f]{8,}", "/{id}", loc)
        params = tuple(sorted(k.lower() for k, _ in up.parse_qsl(u.query)))
        return loc, params
    except Exception:
        return (ep or "").lower(), ()


def _find_sig(f):
    """Root-cause signature for a finding: same class + same endpoint SHAPE (host+path, with
    id-like path segments normalized) + same injected parameter name(s) = the SAME bug, however
    many tools — or however many different resource instances — reported it. Param names come from
    the URL query (reliable) — not the title, whose wording varies by tool.

    BUG FIX (2026-10-21): the path used to be compared RAW. A single vulnerable code path probed
    across many pre-existing resource instances (e.g. a media/image proxy with a blind-SSRF sink,
    hit via every image record a crawler discovered: /media/image/<uuid-1>/resize,
    /media/image/<uuid-2>/resize, ...) produced a DIFFERENT raw path per instance, so this pass
    never merged them — live incident: 67 separate "High · PROVEN" SSRF findings for the exact same
    sink on one hunt, each differing only by the UUID in the path. The second-pass
    _root_cause_sig() (exact `detail` text match) doesn't catch this either, since the OAST-proven
    SSRF evidence embeds a unique per-request callback token in its text, so no two of the 67
    findings have identical detail strings even though they're the same bug. See also
    _norm_path_shape(), used by phase_adaptive() to skip re-SCANNING (not just re-reporting) the
    same proven shape on sibling resource instances in the first place."""
    cls = _cls_key(f.get("cls"))
    ep = f.get("endpoint", "") or ""
    try:
        loc, params = _norm_path_shape(ep)
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
    fail_kinds = {}   # PREVIOUSLY: d is None (timeout/crash/missing tool) was silently treated as
                      # "0 findings for this call" — identical to a genuine clean negative, across
                      # up to 30 calls with zero trace. Aggregate instead of logging per-call (noisy).
    for cl in uniq[:30]:
        if time.time() > deadline:
            log("warn", "⏱ budget reached — API-test stopped"); break
        a = ["--url", cl.get("url", ""), "--method", cl.get("method", "GET"), "--ua", ua or "Mozilla/5.0 HUNTR", "--delay", delay]
        if cl.get("req_body"): a += ["--data", cl["req_body"]]
        if cookie: a += ["--cookie", cookie]
        if tok: a += ["--token", tok]
        d = tool_json("api-test.py", a, timeout=90)
        if d is None:
            kind = _LAST_TOOL_ERR or "unknown"
            fail_kinds[kind] = fail_kinds.get(kind, 0) + 1
            continue
        for f in (d or {}).get("findings", []):
            add_finding(f.get("severity", "h"), f.get("title") or (f.get("cls", "API") + " issue"),
                        f.get("detail") or "", f.get("endpoint") or cl.get("url", ""),
                        cls=f.get("cls", "API"), verdict=f.get("verdict", "likely"),
                        det=(f.get("verdict") == "confirmed"))
            n += 1
    log("ok" if n else "out", "✓ API-test · " + str(n) + " finding(s) on the runtime API surface")
    if fail_kinds:
        log("warn", "→ api-test: " + str(sum(fail_kinds.values())) + "/" + str(len(uniq[:30])) +
            " call(s) NOT actually tested (tool failure, not a clean negative) — " +
            ", ".join(k + " x" + str(v) for k, v in fail_kinds.items()))
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
    # steer the agent with the target-specific FLOWS from the attack plan (grounded in real endpoints)
    flows = (STATE.get("plan") or {}).get("flows") or STATE.get("flows") or []
    if flows:
        top = flows[:6]
        obj += ". Prioritize these target-specific attack flows: " + " | ".join(
            (str(f.get("name", "")) + " [" + str(f.get("severity", "")) + "] via " +
             ",".join((f.get("endpoints") or [])[:3])) for f in top)
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
        log("warn", "→ exploit-agent produced no result — " + (_LAST_TOOL_ERR or "session/LLM unavailable"))
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


def _root_cause_sig(f):
    """Signature for 'this is the SAME underlying bug, hit from a different endpoint' — e.g. one
    gateway/ALB/WAF-level control (auth wall, header injection point) reachable from N paths produces
    N findings whose evidence text is byte-identical apart from the endpoint. _find_sig() alone can't
    catch this (it's keyed on endpoint, by design, for the 'N tools, same endpoint' case). Keyed on
    (class, exact detail text) with a minimum length so short/generic details across genuinely
    different bugs don't accidentally collide."""
    cls = _cls_key(f.get("cls"))
    detail = (f.get("detail") or "").strip()
    if len(detail) < 24:
        return None
    return (cls, detail)


def phase_dedup():
    """Collapse intra-hunt duplicates: one root-cause bug detected by several tools/vectors (reflected
    + verified + OAST XSS on one param, or three SSTI hits on one endpoint) becomes ONE finding, keeping
    the strongest evidence. Cuts operator noise and makes the economics/chain views reflect real bugs.

    Runs under _STATE_LOCK: it reads STATE["findings"] then reassigns it wholesale, and a concurrent
    add_finding() (dual-agent threads, or one that's merely slow to notice its lead_deadline passed —
    see [[add-finding-race-2026-10-18]]) appending between the read and the reassignment would have
    its finding silently dropped from the new list otherwise. Idempotent — safe (and, per the second
    call at the very end of main(), necessary) to run more than once; see that call site's comment."""
    with _STATE_LOCK:
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

        # SECOND pass: same root cause, DIFFERENT endpoint (the above pass only catches same-endpoint
        # duplicates). 25 findings that are one ALB/WAF-level control hit from 25 paths must not count
        # as 25 confirmed bugs on the dashboard, in reports, or (previously) fed to chain-builder as if
        # independent — collapse to one finding, keeping every other endpoint in the blast radius visible.
        groups2 = {}
        for f in merged:
            sig = _root_cause_sig(f) or ("__unique__", id(f))
            groups2.setdefault(sig, []).append(f)
        merged2, removed2 = [], 0
        for sig, grp in groups2.items():
            if len(grp) == 1:
                merged2.extend(grp); continue
            grp.sort(key=_best_rank)
            keeper = grp[0]
            others = grp[1:]
            other_eps = [o.get("endpoint") for o in others if o.get("endpoint") and o.get("endpoint") != keeper.get("endpoint")]
            if other_eps:
                keeper["same_root_cause_endpoints"] = sorted(set((keeper.get("same_root_cause_endpoints") or []) + other_eps))
                n_total = 1 + len(keeper["same_root_cause_endpoints"])
                if "same root cause at" not in keeper.get("title", ""):
                    keeper["title"] = keeper.get("title", "").rstrip() + f"  — same root cause at {n_total} endpoints, not {n_total} separate bugs"
            merged2.append(keeper); removed2 += len(others)

        total_removed = removed + removed2
        _dedup_msg = None
        if total_removed:
            # preserve original ordering by first appearance
            order = {id(f): i for i, f in enumerate(finds)}
            merged2.sort(key=lambda f: order.get(id(f), 0))
            STATE["findings"] = merged2
            STATE["stats"]["findings"] = len(merged2)
            _dedup_msg = ("⊚ dedup · merged " + str(total_removed) + " duplicate detection(s) → " +
                          str(len(merged2)) + " distinct bug(s)" +
                          (f" ({removed2} of those were the same root cause at a different endpoint)" if removed2 else ""))
    # log()/flush() outside the lock — flush() serializes the WHOLE STATE dict to disk, which
    # shouldn't happen while holding the lock other callers need for their own (much smaller,
    # much more frequent) critical sections.
    if _dedup_msg:
        log("ok", _dedup_msg)
    _tag_novelty()


def _tag_novelty():
    """Auto-tag every finding with its zero-day eligibility via novelty-gate.py (no manual button).
    novel = unknown-to-vendor + verified + unique; known_nday = matched a scanner signature;
    duplicate = already disclosed/submitted; unverified = not yet confirmed. Stored on f['novelty']
    so the report/economics views and zeroday-ledger can tell a real 0-day from an n-day."""
    gate = HERE / "novelty-gate.py"
    if not gate.exists():
        return
    novel = 0
    fail_kinds = {}   # classified failure -> count, so one real problem (e.g. gate always timing
                       # out) is visible as a pattern instead of N identical silent "unchecked" tags
    for f in STATE.get("findings", []):
        if not f.get("endpoint") or not f.get("cls"):
            continue
        if f.get("novelty") and f.get("novelty") != "unchecked":
            # Already successfully tagged by a previous _tag_novelty() call. This now runs twice
            # per hunt (phase_dedup() runs a second time at the very end of main() — see
            # [[dedup-rerun-2026-10-18]]) — without this, a second pass that found nothing to
            # actually merge would still re-probe novelty-gate.py (a subprocess, up to 45s) for
            # EVERY finding a second time for zero benefit. "unchecked" (a prior failure) is
            # retried, matching this function's own fail_kinds log line's stated intent.
            continue
        try:
            r = subprocess.run(
                [sys.executable, "-I", str(gate), "--stdin", "--json"],
                input=json.dumps(f), capture_output=True, text=True, timeout=45, env=os.environ)
        except subprocess.TimeoutExpired:
            f["novelty"] = "unchecked"; f["novelty_error"] = "timeout"
            fail_kinds["timeout"] = fail_kinds.get("timeout", 0) + 1
            continue
        except Exception as e:
            f["novelty"] = "unchecked"; f["novelty_error"] = "exec-error: " + str(e)[:100]
            fail_kinds["exec-error"] = fail_kinds.get("exec-error", 0) + 1
            continue
        if r.returncode != 0:
            f["novelty"] = "unchecked"; f["novelty_error"] = "nonzero-exit(" + str(r.returncode) + "): " + (r.stderr or "").strip()[:150]
            fail_kinds["nonzero-exit"] = fail_kinds.get("nonzero-exit", 0) + 1
            continue
        try:
            res = json.loads((r.stdout or "").strip().splitlines()[-1])
        except Exception as e:
            f["novelty"] = "unchecked"; f["novelty_error"] = "parse-error: " + str(e)[:100]
            fail_kinds["parse-error"] = fail_kinds.get("parse-error", 0) + 1
            continue
        f["novelty"] = res.get("verdict", "unchecked")
        f.pop("novelty_error", None)
        if res.get("novel"):
            novel += 1
    if fail_kinds:
        log("warn", "→ novelty-gate: " + str(sum(fail_kinds.values())) +
            " finding(s) left 'unchecked' due to tool failure — " +
            ", ".join(k + " x" + str(v) for k, v in fail_kinds.items()) +
            " (zeroday-ledger will under-count real novelty until these are re-run)")
    if novel:
        log("ok", "★ novelty · " + str(novel) + " finding(s) flagged ZERO-DAY-eligible (novel + verified + unique)")
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
    if not isinstance(d, dict):
        # strong model failed — retry with Haiku before giving up
        log("warn", "→ AI judge: Sonnet unavailable — retrying with Haiku…")
        import time as _t2; _t2.sleep(5)
        d = llm_json(sys_p, json.dumps({"target": TARGET, "findings": items}), max_tokens=3200, timeout=120, _model=MODEL_CHEAP)
    if not isinstance(d, dict):
        log("warn", "→ AI judge unavailable (rate-limited) — findings marked NEEDS_TRIAGE; resume hunt to retry")
        for f in STATE["findings"]:
            if not f.get("verdict"):
                f["verdict"] = "needs_triage"
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
            # DOCTRINE: a record-time deterministic ORACLE confirmation (proof.proven is True — the
            # class oracle re-reproduced the bug over real HTTP) is AUTHORITATIVE. The LLM judge may
            # enrich it but must NEVER drop or downgrade it, no matter how eloquent its disproof —
            # letting the model override the oracle is exactly what re-introduces LLM false pos/neg.
            # (If an oracle itself over-fires, the fix belongs in the oracle, not in the judge.)
            oracle_proven = (f.get("proof") or {}).get("proven") is True
            if oracle_proven or (f.get("_det") and len(reason) < 40):
                f["detail"] = (f.get("detail", "") +
                               (" · note: AI judge disputed but a deterministic oracle reproduced this; oracle stands"
                                if oracle_proven else
                                " · note: AI judge flagged for review without a concrete disproof; tool evidence stands")).strip(" ·")
                f["judge_disputed"] = True
                if not f.get("verdict") or f.get("verdict") == "false_positive":
                    f["verdict"] = "confirmed" if oracle_proven else f.get("verdict", "")
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
            # brain: record FP pattern so future hunts avoid it
            try:
                _fp_pattern = (f.get("cls", "") + ":" + str(f.get("endpoint", ""))[:60])
                _fp_reason = str(j.get("reason", ""))[:150]
                _brain().record_fp(_fp_pattern, _fp_reason)
            except Exception:
                pass
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

# ── HARD TRIAGE GATE — the single authority on severity/verdict/submit ────────────────────────────
# HARD_INFO: never above info, never submittable on their own, regardless of what a scanner claimed.
_HARD_INFO = {"csp", "clickjack", "clickjacking", "hsts", "x-frame-options", "referrer-policy",
    "permissions-policy", "version", "banner", "info-leak", "info leak", "cookie", "tabnabbing",
    "exceptional-conditions", "exceptional conditions", "verbose-error", "graphql", "graphql-introspection",
    "param", "param/idor", "non_idempotent", "missing-header", "missing headers"}
# CHAIN_REQUIRED: info UNLESS part of a proven chain / proven real impact (CORS, redirect, etc.).
_CHAIN_REQ = {"cors", "open redirect", "open-redirect", "redirect", "host-header", "host header",
    "cache-poison", "web-cache-deception", "clickjacking"}
# IMPACT: the only classes that may be Critical/High/Medium — and only WITH real proof.
_IMPACT = {"rce", "sqli", "ssti", "ssrf", "idor", "bola", "authz", "auth bypass", "auth-bypass",
    "deserialization", "xxe", "file-upload", "oauth", "jwt", "nosqli", "lfi", "cmdi", "xss",
    "mass-assignment", "race", "ldap", "xpath", "websocket", "saml", "prototype-pollution",
    "fake-deposit", "fake deposit", "account-takeover", "ato", "chain", "invariant", "sqli-blind"}

def _proven(f):
    return bool((f.get("proof") or {}).get("proven")) or f.get("_det") is True


def phase_adversarial_verify(deadline=None):
    """Second, INDEPENDENT judge pass on every LLM-confirmed finding, before hard-triage locks in
    severity/submit decisions. Closes a real gap: phase_ai_judge is one model grading its own
    hunt's evidence in a batch — a single self-report. phase_agentic_polish already re-verifies
    'weak' verdicts via verify-one.py, but 'confirmed' was never in that WEAK set, so a confirmed
    finding has NEVER actually been challenged by anything other than the judge that confirmed it.

    verify-one.py (unchanged here, just now actually called on confirmed findings) already does
    the real adversarial work per finding: re-fetches the LIVE response as ground truth (not the
    scanner's stale claim), runs a deterministic proof agent first when possible, and — only for
    LLM-adjudicated confirms — runs a dedicated self-critique pass whose ONLY job is to try to
    produce a concrete disproof. A finding only survives if nothing can disprove it.

    Deterministically-proven findings (_proven(f)) skip this: they were already proven over real
    HTTP; asking an LLM to re-judge a mechanical proof only reintroduces the hallucination risk the
    oracle exists to avoid. Disagreement downgrades (never silently drops) — both judges' views stay
    visible on the finding, same quarantine discipline as phase_ai_judge."""
    cands = [(i, f) for i, f in enumerate(STATE["findings"])
             if f.get("verdict") == "confirmed" and not _proven(f) and not f.get("adversarial_checked")]
    if not cands:
        return
    stage("Adversarial-verify", 96)
    log("ok", "◆ adversarial verify · " + str(len(cands)) +
        " LLM-confirmed finding(s) get a second, independent judge pass before they're trusted")
    flush()  # verify-one.py reads/writes run.json directly — make sure it's current first
    kept, downgraded, checked = 0, 0, 0
    fail = {}
    for i, f in cands:
        if deadline and time.time() > deadline:
            log("warn", "⏱ budget reached — " + str(len(cands) - checked) +
                " confirmed finding(s) not yet adversarially re-checked (resume to continue)")
            break
        out, err, rc = sh([sys.executable, str(HERE / "verify-one.py"),
                           "--run", str(RUN), "--fi", str(i), "--json"], timeout=90)
        checked += 1
        try:
            d = json.loads((out or "").strip().splitlines()[-1])
        except Exception:
            kind = err if (err in ("timeout", "not-found") or err.startswith("exec-error")) else ("nonzero-exit(" + str(rc) + ")")
            fail[kind] = fail.get(kind, 0) + 1
            continue
        if not d.get("ok"):
            kind = "tool-error: " + str(d.get("error", ""))[:80]
            fail[kind] = fail.get(kind, 0) + 1
            continue
        _reload_findings()
        if i >= len(STATE["findings"]):
            continue
        STATE["findings"][i]["adversarial_checked"] = True
        if d.get("dropped") or d.get("verdict") == "false_positive":
            # downgrade, don't delete — both the original judge's confirm and the adversarial
            # pass's disproof stay on the finding (verify-one.py already writes judge_reason)
            STATE["findings"][i]["verdict"] = "likely"
            downgraded += 1
            log("warn", "  ✗ F" + str(i) + " downgraded on adversarial disagreement: " +
                str(STATE["findings"][i].get("judge_reason", ""))[:140])
        else:
            kept += 1
    flush()
    log("warn" if downgraded else "ok", "✓ adversarial verify · " + str(kept) + " survived · " +
        str(downgraded) + " downgraded on disagreement" +
        ((" · " + str(sum(fail.values())) + " not-yet-checked (" +
          ", ".join(k + " x" + str(v) for k, v in fail.items()) + ")") if fail else ""))


def _finding_is_noise(f):
    """Hard-ass gate: is this 'finding' actually NOT a real, reportable bug? True for a forced-info
    non-bug (CSP/clickjack/hidden-param/version/header — verdict 'info'), a dismissed FP, or a
    low/info-severity item that is NOT a PROVEN impact-class vuln. Noise items stay in STATE for the
    record but must never inflate the headline finding count or reach the submit queue. A proven
    impact-class bug (even low-sev) is a real finding; an unproven/weak low-or-info item is not."""
    v = (f.get("verdict") or "").lower()
    if v in ("info", "false_positive"):
        return True
    cls = (f.get("cls") or "").strip().lower()
    if f.get("sev") in ("i", "l") and not (_proven(f) and cls in _IMPACT):
        return True
    return False


def _real_findings():
    return [f for f in STATE.get("findings", []) if not _finding_is_noise(f)]

def phase_hard_triage():
    """FINAL, authoritative triage — overrides every scanner's optimistic grade. Three hard rules:
      1. HARD_INFO classes (CSP / clickjacking / headers / version / GraphQL-introspection / hidden-param
         / non-idempotent …) → forced sev=info, verdict=info, never submit. No scanner can promote them.
      2. 'confirmed' REQUIRES real proof (proof.proven or the deterministic oracle _det). No proof → the
         finding is a LEAD (verdict=likely, C/H capped to medium, reco=needs-work). Prove it or it's a lead.
      3. reco='submit' ONLY when: proven AND an IMPACT class AND sev in {c,h,m} AND not a likely-duplicate.
         CHAIN_REQUIRED classes (CORS/redirect/host-header/cache) submit only if they ride a proven chain.
    This is where 'confirmed High/Medium for info shit' dies."""
    chained = set()
    for c in STATE.get("chains", []):
        for ep in (c.get("endpoints") or []) if isinstance(c, dict) else []:
            chained.add(str(ep).lower())
    kept = {"submit": 0, "lead": 0, "info": 0}
    for f in STATE["findings"]:
        cls = (f.get("cls") or "").strip().lower()
        title = (f.get("title") or "").lower()
        ep = (f.get("endpoint") or "").lower()
        proven = _proven(f)
        # textual info tells, even if the class string is generic
        looks_info = (cls in _HARD_INFO or title.startswith("note:") or
                      any(k in title for k in ("hidden param", "introspection", "non-idempotent",
                      "non_idempotent", "missing header", "version disclos", "clickjack",
                      "content-security", "csp", "banner", "verbose error", "stack trace")))
        is_impact = cls in _IMPACT
        is_chainreq = cls in _CHAIN_REQ

        # RULE 1 — HARD_INFO: floor to info, kill confirmed/submit.
        if looks_info and not (proven and is_impact):
            f["sev"] = "i"; f["verdict"] = "info"; f["reco"] = "needs-work"; f.pop("_det", None)
            kept["info"] += 1; continue

        # RULE 2 — no real proof ⇒ cannot be confirmed; it is a LEAD.
        if not proven:
            if f.get("verdict") == "confirmed":
                f["verdict"] = "likely"
            if f.get("sev") in ("c", "h"):
                f["sev"] = "m"                    # unproven may not claim Critical/High
            f["reco"] = "needs-work"; f.pop("_det", None)
            kept["lead"] += 1; continue

        # RULE 3 — proven. Decide submit vs lead by impact + dup + chain.
        dup = f.get("dup")
        is_dup = isinstance(dup, (int, float)) and dup >= DUP_GATE
        chain_ok = (not is_chainreq) or (ep in chained) or any(ce in ep for ce in chained)
        if is_impact and chain_ok and not is_dup and f.get("sev") in ("c", "h", "m"):
            f["verdict"] = "confirmed"; f["reco"] = "submit"; kept["submit"] += 1
        else:
            # proven but low-value / unchained / dup → keep as a reviewed lead, not submit
            if is_chainreq and not chain_ok:
                f["sev"] = "i" if f.get("sev") == "i" else "l"
            f["reco"] = "needs-work"
            if f.get("verdict") == "confirmed" and not is_impact:
                f["verdict"] = "likely"
            kept["lead"] += 1
    # Tag noise and make the HEADLINE count honest (hard triage runs last → this is authoritative).
    # Non-bugs and unproven low/info items stay in STATE['findings'] (indices intact for chain links)
    # but are excluded from the count and flagged so the dashboard/submit queue can hide them.
    for f in STATE["findings"]:
        f["noise"] = _finding_is_noise(f)
    real = [f for f in STATE["findings"] if not f.get("noise")]
    STATE["stats"]["submit_ready"] = kept["submit"]
    STATE["stats"]["findings"] = len(real)
    STATE["stats"]["noise"] = len(STATE["findings"]) - len(real)
    log("ok", "⚖ hard triage · " + str(kept["submit"]) + " submit · " + str(kept["lead"]) +
        " lead · " + str(kept["info"]) + " info · " + str(len(real)) + " REAL finding(s) counted" +
        (" · " + str(STATE['stats']['noise']) + " non-bug/low-noise uncounted" if STATE["stats"]["noise"] else ""))
    flush()


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


def phase_scenario():
    """'Impossible scenario' engine: compose PROVEN primitives into multi-step kill-chains (ATO, cloud
    compromise, mass XSS, RCE) — claimed ONLY when every hop re-proves via the deterministic oracle.
    Shells to agent-scenario.py (templates + a gated LLM-creative pass). Writes STATE['scenarios']."""
    if not (HERE / "agent-scenario.py").exists():
        return
    proven_prims = sum(1 for f in STATE["findings"] if (f.get("proof") or {}).get("proven") or f.get("verdict") == "confirmed")
    if proven_prims < 1:
        return
    stage("Scenarios", 97)
    log("cmd", "$ scenario engine — composing proven primitives into kill-chains (every hop oracle-gated)")
    flush()
    c = _creds()
    # on a rate-limit pause the LLM-creative pass would just re-trip the limit; run templates only (0 LLM).
    payload = {"max_llm": 0 if os.environ.get("HUNTR_SCENARIO_NO_LLM") == "1" else 4}
    if (c.get("session_token") or "").strip():
        payload["session_token"] = c["session_token"]
    try:
        r = subprocess.run([sys.executable, str(HERE / "agent-scenario.py")], input=json.dumps(payload),
                           capture_output=True, text=True, timeout=240, env=dict(os.environ, HUNT_DIR=str(HUNT_DIR)))
        sd = json.loads((r.stdout or "").strip().splitlines()[-1])
        scen = sd.get("scenarios", []) if sd.get("ok") else []
        STATE["scenarios"] = scen
        STATE["stats"]["scenarios"] = len(scen)
        if scen:
            log("ok", "✦ " + str(len(scen)) + " proven kill-chain scenario(s) · " + str(sd.get("critical", 0)) +
                " critical — " + "; ".join(s.get("title", "")[:50] for s in scen[:3]))
            for s in scen[:6]:
                log("warn" if s.get("sev") == "c" else "out", "  ⛓ [" + str(s.get("sev", "")).upper() + "] " + s.get("title", "")[:90])
        else:
            log("out", "→ no fully-proven multi-step scenario composed from current primitives")
    except Exception as e:
        log("warn", "→ scenario engine skipped: " + str(e)[:120])
    flush()


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
    if nears and not NO_LLM:   # LLM only enriches the "how to prove the missing edge" strategy;
                               # deterministic mode still reports the near-miss chains + the edge to prove
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
        _dedup_fail = {}   # classified failure -> count. PREVIOUSLY: a timeout/crash here left
                           # f["dup"] simply unset, and phase_hard_triage's `isinstance(dup, (int,
                           # float))` reads unset identically to "checked, confirmed unique" — a
                           # dedup-check that silently failed could let an actual duplicate sail
                           # straight to the submit queue. Now it's at least visible and tagged.
        for f in STATE["findings"]:
            if deadline and time.time() > deadline:
                log("warn", "⏱ budget reached — dedup skipped for remaining findings")
                break
            d = tool_json("dedup-check.py", ["--class", _cls_key(f.get("cls")), "--endpoint", f.get("endpoint", ""),
                                             "--title", f.get("title", ""), "--json"], timeout=20)
            if isinstance(d, dict):
                dp = d.get("dup_score", d.get("dup", d.get("duplicate_pct")))
                if dp is not None:
                    try: f["dup"] = int(dp)
                    except Exception: pass
                f.pop("dup_check_failed", None)
            else:
                kind = _LAST_TOOL_ERR or "unknown"
                f["dup_check_failed"] = kind
                _dedup_fail[kind] = _dedup_fail.get(kind, 0) + 1
        if _dedup_fail:
            log("warn", "→ dedup-check: " + str(sum(_dedup_fail.values())) +
                " finding(s) have an UNKNOWN (not confirmed-unique) dup status due to tool failure — " +
                ", ".join(k + " x" + str(v) for k, v in _dedup_fail.items()) +
                " — review dup_check_failed findings manually before submitting")

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
    # improvement #6: lead write-back — partial wins (interesting probes from lead_log) → corpus
    # This seeds the next hunt with "we tried X on Y, got interesting response" so Haiku
    # doesn't waste its first 10 steps repeating the same recon.
    lead_log = STATE.get("lead_log", [])
    if cor.exists() and lead_log:
        mem = HERE / "hunt-memory.py"
        interesting_acts = [l for l in lead_log
                            if l.get("ok") and l.get("act") in ("http_request", "bash", "scan_endpoint")]
        for lead_entry in interesting_acts[:20]:
            detail = str(lead_entry.get("detail") or "")
            if len(detail) < 30:
                continue
            act = lead_entry.get("act", "probe")
            txt = f"[lead] {act}: {detail[:300]}"
            if mem and mem.exists():
                try:
                    sh([sys.executable, str(mem), "--add", "--kind", "lead",
                        "--cls", "probe", "--stack", stack,
                        "--program", str(PROGRAM or TARGET), "--reward", "0",
                        "--text", txt], timeout=20)
                except Exception:
                    pass

    if n:
        STATE["stats"]["learned"] = (STATE["stats"].get("learned") or 0) + n
        log("ok", "✓ learning loop · " + str(n) + " new rule(s)/situation(s) → corpus (stack=" +
            stack + " · " + str(len(picks)) + " confirmed finding(s) seen, rest already known)")
        flush()

    # brain: generate post-hunt note via Haiku and store it
    try:
        _stk = _stack()
        n_finds = len(STATE["findings"])
        n_actions = len(STATE.get("lead_log", []))
        top_endpoints = [e["url"] for e in STATE.get("endpoints", [])[:10]]
        leads_summary = [l.get("lead", "")[:100] for l in STATE.get("leads", [])[-5:]]
        hunt_summary = {
            "target": TARGET, "stack": _stk, "n_findings": n_finds,
            "n_actions": n_actions, "top_endpoints": top_endpoints,
            "leads": leads_summary, "findings": [
                {"title": f.get("title", ""), "cls": f.get("cls", ""), "sev": f.get("sev", "")}
                for f in STATE["findings"]
            ]
        }
        note_prompt = (
            "Write a 150-word structured post-hunt note for future reference. "
            "Cover: what was tested, what was interesting, what to try next time, and why this target was clean or vulnerable. "
            "Be specific about endpoint patterns, response anomalies, and technique effectiveness. "
            "Format: plain text, no markdown headers.\n\nHunt data:\n" + json.dumps(hunt_summary, default=str)[:3000]
        )
        note_resp = llm_json(
            'You are a security researcher writing a concise post-hunt note. Return JSON: {"note": "..."}',
            note_prompt, max_tokens=300, timeout=30, _model=MODEL_CHEAP
        )
        if note_resp and isinstance(note_resp, dict) and note_resp.get("note"):
            _brain().write_hunt_note(TARGET, _stk, note_resp["note"], bool(n_finds))
            log("ok", "◈ brain · post-hunt note written (" + str(len(note_resp["note"])) + " chars)")
    except Exception:
        pass

    # brain: log this hunt for cross-hunt consolidation trigger
    try:
        hunt_start = STATE.get("started", time.time())
        _brain().log_hunt(TARGET, _stack(), len(STATE["findings"]),
                         len(STATE.get("lead_log", [])), time.time() - hunt_start)
    except Exception:
        pass

    # close the loop → skill feedback ledger. Outcomes (what confirmed, what was a false positive
    # and WHY) feed the skill-upgrade pipeline so the matching hunt-* skill learns to stop producing
    # that FP and to lead with what actually paid. One append-only JSONL + a per-skill FEEDBACK note.
    try:
        _skills = Path.home() / ".claude" / "skills"
        confirmed_by_cls = {}
        for f in STATE["findings"]:
            if (f.get("verdict") or "").lower() == "confirmed":
                k = _cls_key(f.get("cls")) or "misc"
                confirmed_by_cls[k] = confirmed_by_cls.get(k, 0) + 1
        dismissed = [{"cls": _cls_key(x.get("cls")) or "misc",
                      "reason": (x.get("reason") or "")[:200], "title": (x.get("title") or "")[:90]}
                     for x in STATE.get("dropped", [])]
        rec = {"ts": int(time.time()), "target": TARGET, "stack": _stack(),
               "confirmed": confirmed_by_cls, "dismissed": dismissed}
        if _skills.is_dir():
            with open(_skills / ".hunt-outcomes.jsonl", "a") as _fh:
                _fh.write(json.dumps(rec) + "\n")
            # append the concrete FP reasons to the matching skill's FEEDBACK file (godlevel-upgrade reads it)
            fp_by_cls = {}
            for dsm in dismissed:
                fp_by_cls.setdefault(dsm["cls"], []).append(dsm["reason"])
            _CLS_SKILL = {"idor": "hunt-idor", "authz": "hunt-idor", "ssrf": "hunt-ssrf", "xss": "hunt-xss",
                          "sqli": "hunt-sqli", "ssti": "hunt-ssti", "redirect": "hunt-open-redirect",
                          "cors": "hunt-cors", "csrf": "hunt-csrf", "jwt": "hunt-jwt-crypto", "oauth": "hunt-oauth",
                          "source": "hunt-source-leak", "info": "hunt-source-leak", "misconfig": "hunt-api-misconfig"}
            for cls, reasons in fp_by_cls.items():
                sk = next((v for k, v in _CLS_SKILL.items() if k in cls), None)
                if sk and (_skills / sk).is_dir():
                    with open(_skills / sk / "FEEDBACK.md", "a") as _fb:
                        _fb.write("\n## FP seen " + time.strftime("%Y-%m-%d") + " on " + str(TARGET) + "\n")
                        for r in reasons[:5]:
                            if r:
                                _fb.write("- avoid: " + r + "\n")
            log("ok", "◈ learning loop · outcomes ledger + skill feedback written (" +
                str(sum(confirmed_by_cls.values())) + " confirmed, " + str(len(dismissed)) + " FP patterns)")
    except Exception:
        pass


def _upd_path(url):
    """Endpoint → path used as the corpus hint, so a learned rule says WHERE it paid."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
    except Exception:
        return str(url or "")



def phase_verify():
    """LLM-driven verification: for each finding, make targeted HTTP probes then ask Claude
    to read the live response and decide confirmed / false_positive / needs_review.

    The LLM sees the actual response — it reasons about the evidence the same way a human
    researcher would, catching coincidental numbers, sanitised output, CDN rewrites, etc.

    verified=true  → verdict 'confirmed'        (enters report queue)
    verified=false → verdict 'false_positive'   (auto-dismissed, hidden)
    verified=null  → verdict 'needs_review'     (manual triage)
    """
    import re as _re, urllib.request as _ur, urllib.error as _ue, urllib.parse as _up

    findings = STATE.get("findings", [])
    if not findings:
        return
    stage("Verify", 91)
    log("ok", f"⚡ LLM-verifying {len(findings)} finding(s)…")
    tok = STATE.get("token") or os.environ.get("HUNT_TOKEN", "")

    # ── live HTTP probe ──────────────────────────────────────────────────────
    class _NR(_ur.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw): return None

    def _probe(url, extra_h=None, follow=True, timeout=12):
        h = {"User-Agent": "Mozilla/5.0 (compatible; HUNTR-verify/2.0)"}
        if tok:
            h["Authorization"] = tok if tok.lower().startswith("bearer") else "Bearer " + tok
        if extra_h:
            h.update(extra_h)
        try:
            opener = _ur.build_opener() if follow else _ur.build_opener(_NR)
            req = _ur.Request(url, headers=h)
            with opener.open(req, timeout=timeout) as r:
                body = r.read(60_000).decode("utf-8", "ignore")
                rh = {k.lower(): v for k, v in r.getheaders()}
                return r.status, rh, body
        except _ue.HTTPError as e:
            body = e.read(40_000).decode("utf-8", "ignore") if e.fp else ""
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
        except Exception as ex:
            return 0, {}, f"connection error: {ex}"

    # ── build class-specific probes ──────────────────────────────────────────
    def _probes_for(f):
        cls = (f.get("cls") or "").lower()
        ep  = f.get("endpoint") or ""
        det = f.get("detail") or ""
        if not ep:
            return []
        try:
            parts = _up.urlparse(ep)
            qs = _up.parse_qsl(parts.query, keep_blank_values=True)
        except Exception:
            return [{"label": "baseline", "url": ep, "h": {}, "follow": True}]

        pm = _re.search(r"param[^'\"]*['\"]([^'\"]+)['\"]", det, _re.I)
        hint = pm.group(1) if pm else None
        pidx = [i for i, (k, _) in enumerate(qs) if not hint or k == hint] or list(range(len(qs)))

        def _u(i, val):
            nq = qs[:]; nq[i] = (nq[i][0], val)
            return _up.urlunparse(parts._replace(query=_up.urlencode(nq)))

        probes = [{"label": "baseline", "url": ep, "h": {}, "follow": True}]

        if cls in ("ssti", "template_injection"):
            for i in pidx[:2]:
                probes += [
                    {"label": f"ssti #{{{1337}*7}} p={qs[i][0]}",  "url": _u(i, "#{1337*7}"),  "h": {}, "follow": True},
                    {"label": f"ssti {{{{{1337}*7}}}} p={qs[i][0]}", "url": _u(i, "{{1337*7}}"), "h": {}, "follow": True},
                    {"label": f"ssti ${{{1337}*7}} p={qs[i][0]}",  "url": _u(i, "${1337*7}"),  "h": {}, "follow": True},
                ]
        elif cls in ("xss", "reflected_xss", "stored_xss", "dom_xss"):
            for i in pidx[:2]:
                probes += [
                    {"label": f"xss tag p={qs[i][0]}",  "url": _u(i, "<HUNTRXSSVERIFY>"),             "h": {}, "follow": True},
                    {"label": f"xss attr p={qs[i][0]}", "url": _u(i, '"><img src=x id=HUNTRVERIFY>'), "h": {}, "follow": True},
                ]
        elif cls == "cors":
            probes.append({"label": "cors evil origin",  "url": ep, "h": {"Origin": "https://evil-huntr-verify.com"}, "follow": True})
            probes.append({"label": "cors null origin",  "url": ep, "h": {"Origin": "null"},                          "follow": True})
        elif cls in ("redirect", "open_redirect"):
            for i in pidx[:2]:
                probes.append({"label": f"redirect p={qs[i][0]}", "url": _u(i, "https://evil-huntr-verify.com"), "h": {}, "follow": False})
        elif cls in ("sqli", "sql_injection"):
            for i in pidx[:1]:
                orig = qs[i][1]
                probes += [
                    {"label": f"sqli quote p={qs[i][0]}",       "url": _u(i, orig + "'"),                   "h": {}, "follow": True},
                    {"label": f"sqli true  p={qs[i][0]}",       "url": _u(i, orig + "' AND '1'='1"),        "h": {}, "follow": True},
                    {"label": f"sqli false p={qs[i][0]}",       "url": _u(i, orig + "' AND '1'='2"),        "h": {}, "follow": True},
                ]
        elif cls in ("lfi", "path_traversal", "lfi_rfi"):
            for i in pidx[:1]:
                probes += [
                    {"label": f"lfi traverse p={qs[i][0]}",    "url": _u(i, "../../../../etc/passwd"),          "h": {}, "follow": True},
                    {"label": f"lfi encoded  p={qs[i][0]}",    "url": _u(i, "..%2F..%2F..%2Fetc%2Fpasswd"),    "h": {}, "follow": True},
                ]
        elif cls == "ssrf":
            for i in pidx[:1]:
                probes.append({"label": f"ssrf metadata p={qs[i][0]}", "url": _u(i, "http://169.254.169.254/latest/meta-data/"), "h": {}, "follow": True})
        elif cls in ("authz", "idor", "bola"):
            probes.append({"label": "authz no-auth", "url": ep, "h": {"Authorization": "removed"}, "follow": True})
        # misconfig/info/jwt/param: baseline is enough — LLM reads what's there
        return probes

    # ── verification prompt ──────────────────────────────────────────────────
    VERIFY_SYS = (
        "You are a senior security researcher verifying bug bounty findings. "
        "You are skeptical and precise. You decide based solely on the evidence in the HTTP responses."
    )

    def _verify_prompt(f, probe_results):
        cls   = (f.get("cls") or "").lower()
        ep    = f.get("endpoint") or ""
        title = f.get("title") or ""
        det   = (f.get("detail") or "")[:800]

        probes_txt = ""
        for pr in probe_results:
            relevant_h = {k: v for k, v in pr["headers"].items()
                          if k in ("content-type", "location",
                                   "access-control-allow-origin",
                                   "access-control-allow-credentials",
                                   "set-cookie", "server", "x-powered-by")}
            probes_txt += (
                f"\n### probe: {pr['label']}  →  HTTP {pr['status']}\n"
                + (f"Headers: {json.dumps(relevant_h)}\n" if relevant_h else "")
                + f"Body (first 5000 chars):\n{pr['body'][:5000]}\n"
            )

        return (
            f"Verify whether this finding is real by examining the live HTTP probes below.\n\n"
            f"**Finding**\n"
            f"- Class: {cls}\n- Title: {title}\n- Endpoint: {ep}\n"
            f"- Scanner evidence: {det}\n\n"
            f"**Live HTTP Probes**\n{probes_txt}\n\n"
            f"**How to decide by class:**\n"
            f"- ssti: 9359 (=1337×7) must appear in the injected probe body AND be absent from the baseline AND the literal payload must NOT be reflected verbatim\n"
            f"- xss: <HUNTRXSSVERIFY> or HUNTRVERIFY must appear literally unescaped in the response body (not as &lt; entities)\n"
            f"- cors: Access-Control-Allow-Origin must exactly match the sent Origin 'https://evil-huntr-verify.com'\n"
            f"- redirect: Location header (3xx) must point to evil-huntr-verify.com\n"
            f"- sqli: SQL error message present in response, OR true-condition and false-condition bodies differ significantly in size/content\n"
            f"- lfi: /etc/passwd content (root:x:0:, daemon:, etc.) present in response\n"
            f"- ssrf: cloud metadata (169.254.169.254, ami-id, instance-id) present in response\n"
            f"- authz/idor: sensitive data returned with no auth (or with another user's credentials)\n"
            f"- misconfig/info: sensitive data visible in response\n"
            f"- jwt: forged alg:none token accepted (200) while unauthenticated returns 401/403\n\n"
            f"Use null when the finding class genuinely requires multi-step manual testing "
            f"(blind SSRF, stored XSS, IDOR with 2 accounts, race conditions, business logic, RCE/cmdi).\n\n"
            f"Reply ONLY with valid JSON — no explanation outside the JSON:\n"
            f'{{\"verified\": true|false|null, \"reason\": \"<one concise sentence>\"}}'
        )

    # ── main loop ────────────────────────────────────────────────────────────
    confirmed = dismissed = skipped = 0
    SKIP_AUTO = {"race", "race_condition", "rce", "cmdi", "logic", "business_logic", "ato"}

    for fi, f in enumerate(findings):
        cls = (f.get("cls") or "").lower()
        ep  = f.get("endpoint") or ""

        # DOCTRINE: a record-time deterministic ORACLE confirmation is authoritative — the LLM verifier
        # must never downgrade it. Keep it confirmed and move on (the oracle already reproduced the bug).
        if (f.get("proof") or {}).get("proven") is True:
            f["verdict"] = "confirmed"
            STATE["findings"][fi] = f
            confirmed += 1
            log("ok", f"  ✓ F{fi} oracle-proven [{cls}] · kept confirmed (LLM verify skipped)")
            continue

        if cls in SKIP_AUTO:
            if not f.get("verdict"):
                f["verdict"] = "needs_review"
            STATE["findings"][fi] = f
            skipped += 1
            log("out", f"  ? F{fi} skip-auto [{cls}] · {f.get('title','')[:55]}")
            continue

        # Source code findings (endpoint is a github blob URL) — verify via LLM code re-read,
        # not HTTP probe.  The verifier re-reads the exact file/line and asks the LLM:
        # "Is this actually exploitable?"
        is_source = ep and _re.search(r'github\.com|gitlab\.com|bitbucket\.org', ep, _re.I) and '/blob/' in ep
        if is_source:
            title  = f.get("title", "")
            detail = f.get("detail", "")
            text = llm_call(
                "You are a skeptical security researcher double-checking a finding.",
                f"Claimed finding:\nTitle: {title}\nLocation: {ep}\nDetail: {detail[:1200]}\n\n"
                "Is this a real, exploitable vulnerability? Or is it a false positive / theoretical risk?\n"
                "Consider: Is the vulnerable code path reachable? Is user input actually controllable? "
                "Is there any sanitisation we might have missed?\n\n"
                'Reply with ONLY JSON: {"verified": true|false|null, "reason": "<one sentence>"}',
                max_tokens=150, timeout=30, _model=MODEL_CHEAP
            )
            verdict_val = None
            reason = ""
            if text:
                try:
                    m = _re.search(r'\{[^{}]*"verified"[^{}]*\}', text, _re.S)
                    if m:
                        vj = json.loads(m.group())
                        verdict_val = vj.get("verified")
                        reason = vj.get("reason", "")
                except Exception:
                    reason = text[:150]
            if verdict_val is True:
                f["verdict"]   = "confirmed"
                f["verify_ev"] = reason
                confirmed += 1
                log("ok",   f"  ✓ F{fi} CONFIRMED (src) — {reason[:80]}")
            elif verdict_val is False:
                f["verdict"]   = "false_positive"
                f["verify_ev"] = reason
                dismissed += 1
                log("warn", f"  ✗ F{fi} DISMISSED (src) — {reason[:80]}")
            else:
                if not f.get("verdict"):
                    f["verdict"] = "needs_review"
                f["verify_ev"] = reason
                skipped += 1
                log("out",  f"  ? F{fi} manual (src) — {reason[:80]}")
            STATE["findings"][fi] = f
            flush()
            continue

        probes = _probes_for(f)
        if not probes:
            skipped += 1
            continue

        # Execute probes
        results = []
        for p in probes:
            h_override = {k: v for k, v in p["h"].items() if v != "removed"}
            if "Authorization" in p["h"] and p["h"]["Authorization"] == "removed":
                h_override["Authorization"] = ""
            status, hdrs, body = _probe(p["url"], extra_h=h_override or None, follow=p.get("follow", True))
            results.append({"label": p["label"], "url": p["url"], "status": status, "headers": hdrs, "body": body})

        # Ask the LLM
        prompt = _verify_prompt(f, results)
        text = llm_call(VERIFY_SYS, prompt, max_tokens=200, timeout=45, _model=MODEL_CHEAP)

        verdict_val = None
        reason = "LLM did not respond"
        if text:
            try:
                m = _re.search(r'\{[^{}]*"verified"[^{}]*\}', text, _re.S)
                if m:
                    vj = json.loads(m.group())
                    verdict_val = vj.get("verified")
                    reason = vj.get("reason", "")
            except Exception:
                reason = text[:150]

        if verdict_val is True:
            f["verdict"]   = "confirmed"
            f["verify_ev"] = reason
            confirmed += 1
            log("ok",   f"  ✓ F{fi} CONFIRMED — {reason[:80]}")
        elif verdict_val is False:
            f["verdict"]   = "false_positive"
            f["verify_ev"] = reason
            dismissed += 1
            log("warn", f"  ✗ F{fi} DISMISSED — {reason[:80]}")
        else:
            if not f.get("verdict"):
                f["verdict"] = "needs_review"
            f["verify_ev"] = reason
            skipped += 1
            log("out",  f"  ? F{fi} manual — {reason[:80]}")

        STATE["findings"][fi] = f
        flush()

    log("ok", f"⚡ verify done: {confirmed} confirmed · {dismissed} dismissed · {skipped} manual")


def phase_source_audit():
    """LLM-driven source code security hunt.

    The LLM acts as a security researcher: it reads the repo structure, selects the files
    most likely to have vulnerabilities, reads each one, and reports what it finds — exactly
    the way a human researcher does a code review in their editor.

    No regex. No hardcoded patterns. The LLM hunts.
    """
    if not SOURCE_ASSETS:
        return
    import tempfile, shutil, pathlib, subprocess

    stage("Source Audit", 10)
    log("ok", f"◆ source code hunt · {len(SOURCE_ASSETS)} repo(s)")

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="huntr-src-"))
    try:
        for repo_idx, repo_url in enumerate(SOURCE_ASSETS):
            pct = 10 + int(75 * repo_idx / max(len(SOURCE_ASSETS), 1))
            stage("Source Audit", pct)
            _src_hunt_repo(repo_url, tmpdir)
            flush()
    finally:
        shutil.rmtree(str(tmpdir), ignore_errors=True)

    stage("Source Audit", 88)
    nf = len(STATE.get("findings", []))
    log("ok", f"◆ source audit complete · {nf} finding(s) so far")
    flush()


def _src_hunt_repo(repo_url, tmpdir):
    """Clone one repo, then let the LLM hunt it top-to-bottom."""
    import pathlib, subprocess, re as _re

    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_dir = tmpdir / repo_name

    # ── clone ──────────────────────────────────────────────────────────────
    log("cmd", f"$ git clone --depth 100 {repo_url}")
    ret = subprocess.run(
        ["git", "clone", "--depth", "100", "--quiet", repo_url, str(repo_dir)],
        capture_output=True, timeout=180
    )
    if ret.returncode != 0:
        log("warn", f"  ✗ clone failed · {ret.stderr.decode()[:200]}")
        return
    log("ok", f"  ✓ cloned")

    # ── enumerate files ─────────────────────────────────────────────────────
    SKIP_DIRS = {'.git', 'node_modules', 'vendor', '__pycache__', '.cache',
                 'dist', 'build', '.next', 'target', 'out', '.gradle'}
    SKIP_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2',
                 '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz', '.bin', '.exe',
                 '.dll', '.so', '.dylib', '.lock', '.min.js', '.map'}
    all_files = []
    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(repo_dir)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.suffix.lower() in SKIP_EXTS or p.name.endswith(".min.js"):
            continue
        all_files.append(str(rel))
    all_files.sort()
    log("ok", f"  ✓ {len(all_files)} file(s) to review")
    if not all_files:
        return

    # ── Step 1: LLM selects which files to read ─────────────────────────────
    file_list_txt = "\n".join(all_files[:600])
    sel_prompt = (
        f"Repository: {repo_url}\n\n"
        f"Full file tree:\n{file_list_txt}\n\n"
        "You are a security researcher. Select up to 40 files to audit for vulnerabilities.\n"
        "Prioritise files that handle: authentication, authorisation, tokens/sessions/JWTs, "
        "passwords/crypto, database queries, file I/O, HTTP requests from server side (SSRF), "
        "command execution, deserialization, admin/internal endpoints, payment/billing, "
        "CI/CD workflows, environment/config files, API routes, middleware.\n\n"
        "Also include any file whose NAME suggests it might contain secrets "
        "(*.env*, config*, secrets*, credentials*, keys*).\n\n"
        "Reply ONLY with a JSON array of paths exactly as shown in the tree:\n"
        "[\"path/to/file.ext\", ...]"
    )
    sel_text = llm_call(
        "You are a security researcher selecting files for a paid bug bounty code audit.",
        sel_prompt, max_tokens=1000, timeout=45, _model=MODEL_LEAD
    )
    selected = []
    if sel_text:
        try:
            m = _re.search(r'\[.*?\]', sel_text, _re.S)
            if m:
                parsed = json.loads(m.group())
                valid = set(all_files)
                selected = [f for f in parsed if f in valid][:40]
        except Exception:
            pass
    if not selected:
        # Fallback: heuristic by filename
        PAT = _re.compile(
            r'auth|login|session|token|jwt|oauth|password|secret|crypt|hash|'
            r'route|controller|handler|middleware|api|database|db|sql|query|'
            r'config|\.env|upload|file|admin|user|account|payment|exec|shell|'
            r'deserializ|pickle|marshal|xml|parse|redirect|cors|csrf|signing|'
            r'key|webhook|callback', _re.I)
        selected = [f for f in all_files if PAT.search(f)][:40]
    log("ok", f"  → selected {len(selected)} file(s) to audit")

    # ── Step 2: LLM reads and hunts each file ──────────────────────────────
    HUNT_SYS = (
        "You are a senior security researcher doing a paid bug bounty source code audit. "
        "Find real, exploitable vulnerabilities with clear exploit paths. "
        "Be specific: name the function, the line range, and exactly why it is exploitable. "
        "Do not report theoretical risks or style issues."
    )

    def _read_file(rel):
        p = repo_dir / rel
        try:
            return p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    def _parse_findings(text, rel):
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                fj = json.loads(line)
                title  = fj.get("title", "")
                cls    = fj.get("cls", "")
                sev    = fj.get("sev", "m")
                detail = fj.get("detail", "")
                lineno = fj.get("line", 0)
                if not title or not cls:
                    continue
                ep = repo_url + "/blob/HEAD/" + (rel or "") + (f"#L{lineno}" if lineno else "")
                add_finding(sev, title, detail, ep, cls=cls, verdict="likely")
            except Exception:
                continue

    for rel in selected:
        code = _read_file(rel)
        if not code or not code.strip():
            continue
        log("out", f"  → hunting {rel}…")
        # Chunk large files (send max 3 × 6000-char chunks)
        chunks = [code[i:i+6000] for i in range(0, min(len(code), 18000), 6000)]
        for ci, chunk in enumerate(chunks):
            chunk_label = f" (part {ci+1}/{len(chunks)})" if len(chunks) > 1 else ""
            hunt_prompt = (
                f"Repository: {repo_url}\n"
                f"File: {rel}{chunk_label}\n\n"
                f"```\n{chunk}\n```\n\n"
                "Hunt this code for security vulnerabilities:\n"
                "- Hardcoded secrets (API keys, tokens, passwords, private keys, connection strings)\n"
                "- SQL/NoSQL injection (user input concatenated into queries)\n"
                "- Command injection (user input in subprocess/exec/os.system/shell)\n"
                "- Server-side template injection (user input rendered by template engine)\n"
                "- Path/directory traversal (user input in file open/read)\n"
                "- Insecure deserialization (pickle, yaml.load, eval, JSON.parse on untrusted)\n"
                "- Authentication flaws (missing checks, weak JWT, alg:none, hardcoded bypass)\n"
                "- Authorisation/IDOR flaws (missing ownership checks, user-controlled IDs)\n"
                "- SSRF (user-controlled URLs fetched server-side)\n"
                "- Cryptographic weaknesses (MD5/SHA1 for passwords, hardcoded IVs, ECB mode)\n"
                "- XSS (unescaped user input in HTML output)\n"
                "- Race conditions, logic flaws, privilege escalation\n"
                "- CI/CD issues (pull_request_target with write permissions, secrets in logs)\n\n"
                "For EACH real finding, output exactly one JSON object per line (no other text):\n"
                "{\"sev\":\"c|h|m|l\", \"cls\":\"sqli|cmdi|rce|ssti|ssrf|xss|idor|lfi|authz|hardcoded_secret|crypto|logic|cicd\", "
                "\"title\":\"short title\", \"line\":42, \"detail\":\"exact code + why exploitable + impact\"}\n\n"
                "If nothing exploitable found, output nothing."
            )
            text = llm_call(HUNT_SYS, hunt_prompt, max_tokens=1200, timeout=70, _model=MODEL_LEAD)
            if text:
                _parse_findings(text, rel)
        flush()

    # ── Step 3: Architecture-level review ───────────────────────────────────
    arch_ctx = ""
    for candidate in ["README.md", "README.rst", "package.json", "requirements.txt",
                      "Gemfile", "go.mod", "Cargo.toml", ".env.example",
                      "docker-compose.yml", "Dockerfile"]:
        p = repo_dir / candidate
        if p.exists():
            try:
                arch_ctx += f"\n--- {candidate} ---\n{p.read_text(errors='ignore')[:3000]}\n"
            except Exception:
                pass
    # Also include any CI workflow files
    for wf in list((repo_dir / ".github" / "workflows").glob("*.yml"))[:5] if (repo_dir / ".github" / "workflows").exists() else []:
        try:
            arch_ctx += f"\n--- .github/workflows/{wf.name} ---\n{wf.read_text(errors='ignore')[:2000]}\n"
        except Exception:
            pass

    if arch_ctx.strip():
        log("out", "  → architecture-level review…")
        arch_prompt = (
            f"Repository: {repo_url}\n"
            f"Total files: {len(all_files)}\n\n"
            f"Project configuration files:\n{arch_ctx}\n\n"
            "Review for systemic/architectural security issues:\n"
            "- Exposed secrets or credentials in config/env files\n"
            "- Vulnerable dependencies (check package names/versions for known CVEs)\n"
            "- Insecure defaults (debug mode on, verbose errors in production config)\n"
            "- Missing security headers or CORS wildcard in web config\n"
            "- CI/CD security issues (pull_request_target with secrets, artefact injection)\n"
            "- Insecure Docker config (running as root, exposed ports, no read-only fs)\n\n"
            "For each real issue:\n"
            "{\"sev\":\"c|h|m|l\", \"cls\":\"misconfig|hardcoded_secret|dependency|cicd|crypto\", "
            "\"title\":\"...\", \"file\":\"path\", \"line\":0, \"detail\":\"...\"}\n\n"
            "If nothing found, output nothing."
        )
        text = llm_call(
            "You are a senior security architect reviewing a repository for systemic vulnerabilities.",
            arch_prompt, max_tokens=1000, timeout=60, _model=MODEL_LEAD
        )
        if text:
            _parse_findings(text, "")


def _reload_findings():
    """Pull findings/chains back from run.json after an agent subprocess rewrote it, so STATE
    and the next flush() stay consistent. Call immediately after each tool, before any log()."""
    try:
        d = json.loads(RUN.read_text())
        if isinstance(d.get("findings"), list):
            STATE["findings"] = d["findings"]
        if isinstance(d.get("chains"), list):
            STATE["chains"] = d["chains"]
        STATE["stats"]["findings"] = len(STATE["findings"])
    except Exception:
        pass


def _sup_classify(tool, r_or_exc, fail):
    import subprocess as _sp
    if isinstance(r_or_exc, Exception):
        kind = "timeout" if isinstance(r_or_exc, _sp.TimeoutExpired) else ("exec-error: " + str(r_or_exc)[:100])
    elif r_or_exc.returncode != 0:
        kind = "nonzero-exit(" + str(r_or_exc.returncode) + "): " + (r_or_exc.stderr or "").strip()[-150:]
    else:
        return None, r_or_exc
    fail.setdefault(tool, {}); fail[tool][kind] = fail[tool].get(kind, 0) + 1
    return kind, None


def _sup_run(tool, args=None, stdin_payload=None, timeout=120, fail=None, env=None):
    """Classified subprocess helper for phase_supervisor — same contract as the one proven in
    phase_agentic_polish (timeout/crash/nonzero-exit all classified, nothing swallowed), kept as
    its own small copy rather than sharing phase_agentic_polish's closures so neither phase's
    already-tested behavior can be disturbed by changing the other.

    CAUGHT LIVE: agent_core.py's emit() always sys.exit(0), even for {"ok": false, "error": ...}
    (e.g. every agent-*.py specialist under HUNT_LLM_VIA_CLI=1, since call_llm_with_tools refuses
    native tool-use in CLI-subscription mode). That's a success-shaped failure — exit code 0, clean
    stdout — that returncode-only classification cannot see. A live run against httpbin.org hit
    exactly this and spun 2228 times with zero progress before the budget ran out. Now a JSON body
    with ok:false is classified as a real failure too, with the tool's own error message surfaced."""
    import subprocess as _sp
    fail = fail if fail is not None else {}
    env = env or dict(os.environ, HUNT_DIR=str(HUNT_DIR))
    cmd = [sys.executable, str(HERE / tool)] + (args or [])
    try:
        if stdin_payload is not None:
            r = _sp.run(cmd, input=json.dumps(stdin_payload), capture_output=True, text=True, timeout=timeout, env=env)
        else:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except Exception as e:
        _sup_classify(tool, e, fail); return None
    kind, r2 = _sup_classify(tool, r, fail)
    if r2 is None:
        return None
    try:
        body = json.loads((r2.stdout or "").strip().splitlines()[-1])
    except Exception:
        body = None
    if isinstance(body, dict) and body.get("ok") is False:
        kind2 = "tool-reported-failure: " + str(body.get("error", ""))[:150]
        fail.setdefault(tool, {}); fail[tool][kind2] = fail[tool].get(kind2, 0) + 1
        return None
    return r2  # None on any failure (already classified into `fail`), else the CompletedProcess


def phase_supervisor(deadline=None):
    """"Smarter than a loop" piece #2 — an EV-ranked COORDINATOR over HUNTR's specialist agents
    (verify-one/agent-exploit/agent-report/agent-postexploit/agent-chain), reading the SAME
    structured state (STATE["findings"]) every round as shared ground truth — instead of running
    every specialist on every eligible finding in one fixed, unconditional sequence regardless of
    what's actually worth doing right now (phase_agentic_polish's model). Each round: score every
    available action (one per finding/situation needing a specialist) by expected value — severity
    × what the action unlocks (a chain is worth more than a single PoC; impact-escalation on an
    already-proven Critical outranks writing a report for an unproven Low) — run the single
    highest-EV action, then RE-EVALUATE, because an action can change what's available next (a
    fresh PoC can make a chain newly viable, impact-escalation can bump severity and reorder
    everything below it). That re-evaluation after each step is the actual difference between a
    supervisor and a fixed pipeline: the pipeline commits to its order in advance, the supervisor
    doesn't. Additive: does not replace phase_agentic_polish, which still runs as the deterministic
    safety net for anything this budget-capped loop doesn't reach."""
    if "--no-supervisor" in sys.argv or not STATE.get("findings"):
        return
    # Budget bumped 2026-10-23 (900s/90+60N → 1800s/150+90N): this used to be tuned around a target
    # that was failing FAST (see the MAX_ATTEMPTS comment below) — agent-exploit.py returning a clean
    # {"ok": false} in a couple seconds meant the old ceiling was already generous. Now that the root
    # cause is fixed and verify/exploit/report/postexploit genuinely run their full reasoning loop
    # (tens of seconds each, real HTTP round trips via exec-http.py), the same wall-clock ceiling
    # covers far fewer real actions. Operator directive: no manual buttons, the user should only need
    # to read a FINISHED report — that requires enough budget to actually reach every eligible finding.
    deadline = deadline or (time.time() + min(1800, 150 + 90 * len(STATE["findings"])))
    stage("Supervisor", 99)
    flush()
    env = dict(os.environ, HUNT_DIR=str(HUNT_DIR))
    fail = {}
    SEV_EV = {"c": 4, "h": 3, "m": 2, "l": 1, "i": 0}
    WEAK = ("likely", "needs_triage", "needs_review", "manual", "agent")

    # CAUGHT LIVE against a real target (historical, root cause now fixed 2026-10-23 — see
    # cli-mode-identity-leak memory): with no retry cap, a persistently ineffective action (one that
    # runs, exits clean, but never actually sets poc/report/etc.) gets re-queued by _actions() forever
    # — nothing in the state ever changes, so it's the single highest-EV action EVERY round. A live run
    # spun this exact way 2228 times with zero progress before the budget ran out. Root cause THEN:
    # agent-exploit.py/agent-report.py/agent-postexploit.py all go through agent_core.run_agent() →
    # llm_client.call_llm() → _claude_cli_call() under CLI-subscription auth, and that call used
    # --append-system-prompt, which kept Claude Code's own real identity underneath the agent's
    # persona and got refused outright — a clean, fast, 100%-reproducible {"ok": false} every time.
    # Fixed by the same --system-prompt full-replace + --exclude-dynamic-system-prompt-sections +
    # --no-session-persistence change made to llm_client._claude_cli_call this session — live-verified
    # 2026-10-23: agent-exploit.py and agent-report.py both now complete successfully end to end
    # (real exec-http.py round trip, real PoC, real submission-grade report written to f["report"]).
    # The cap stays anyway — it bounds the damage from ANY persistently-failing action, including ones
    # a future change might introduce, not just this one (now-fixed) root cause.
    MAX_ATTEMPTS = 2
    attempts = {}
    exhausted = set()

    def _actions():
        acts = []
        for i, f in enumerate(STATE["findings"]):
            ev = SEV_EV.get(f.get("sev", "i"), 0)
            if f.get("verdict") in WEAK and not f.get("supervisor_verified") and ("verify", i) not in exhausted:
                acts.append((ev + 1, "verify", i))
                continue   # don't also queue exploit/report work for a finding not yet confirmed
            if f.get("verdict") != "confirmed":
                continue
            if _proven(f) and not f.get("impact_proven") and f.get("cls", "").lower() != "info" and ("postexploit", i) not in exhausted:
                acts.append((ev + 4, "postexploit", i))   # highest single-finding EV: Medium→Critical
            if not f.get("poc") and ("exploit", i) not in exhausted:
                acts.append((ev + 3, "exploit", i))
            if not f.get("report") and ("report", i) not in exhausted:
                acts.append((ev + (3 if f.get("poc") else 2), "report", i))  # worth more once a PoC exists
        nconf = sum(1 for f in STATE["findings"] if f.get("verdict") == "confirmed")
        if nconf >= 2 and not STATE.get("chains") and (HERE / "agent-chain.py").exists() and ("chain", None) not in exhausted:
            acts.append((10, "chain", None))   # multi-step escalation outranks any single-finding polish
        return sorted(acts, key=lambda a: -a[0])

    log("ok", "◆ supervisor · EV-ranked dispatch over verify/exploit/report/postexploit/chain")
    rounds, given_up = 0, 0
    while time.time() < deadline:
        acts = _actions()
        if not acts:
            break
        ev, kind, fi = acts[0]
        rounds += 1
        key = (kind, fi)
        attempts[key] = attempts.get(key, 0) + 1
        before_fail_count = sum(sum(k.values()) for k in fail.values())
        if kind == "verify":
            r = _sup_run("verify-one.py", args=["--run", str(RUN), "--fi", str(fi), "--json"], timeout=120, fail=fail, env=env)
            _reload_findings()
            if fi < len(STATE["findings"]):
                STATE["findings"][fi]["supervisor_verified"] = True
        elif kind == "exploit":
            _sup_run("agent-exploit.py", stdin_payload={"fi": fi}, timeout=200, fail=fail, env=env)
            _reload_findings()
        elif kind == "report":
            _sup_run("agent-report.py", stdin_payload={"fi": fi, "program": STATE.get("program", "")}, timeout=180, fail=fail, env=env)
            _reload_findings()
        elif kind == "postexploit":
            r = _sup_run("agent-postexploit.py", stdin_payload={"finding": STATE["findings"][fi]}, timeout=200, fail=fail, env=env)
            if r is not None:
                try:
                    pd = json.loads((r.stdout or "").strip().splitlines()[-1])
                except Exception as e:
                    fail.setdefault("agent-postexploit.py", {})
                    k = "parse-error: " + str(e)[:100]
                    fail["agent-postexploit.py"][k] = fail["agent-postexploit.py"].get(k, 0) + 1
                    pd = {}
                if pd.get("ok") and pd.get("impact_proven") and fi < len(STATE["findings"]):
                    STATE["findings"][fi]["impact_proven"] = True
                    STATE["findings"][fi]["impact_level"] = pd.get("impact_level", "")
                    STATE["findings"][fi]["impact_evidence"] = pd.get("evidence", "")
                    lvl = pd.get("impact_level", "").lower()[:1]
                    if lvl in ("c", "h") and STATE["findings"][fi].get("sev") not in ("c", "h"):
                        STATE["findings"][fi]["sev"] = lvl
                    flush()
        elif kind == "chain":
            _sup_run("agent-chain.py", stdin_payload={}, timeout=240, fail=fail, env=env)
            _reload_findings()
        # retry cap: if this (kind, fi) has now been tried MAX_ATTEMPTS times — succeeded or not —
        # stop offering it again. A success means the state already changed and _actions() won't
        # re-offer it anyway; capping the failure case is the part that actually matters, and
        # capping unconditionally is simpler and just as safe than trying to detect "no progress."
        new_fail_count = sum(sum(k.values()) for k in fail.values())
        ok = new_fail_count == before_fail_count
        # structured activity log — the dashboard's supervisor feed reads this; log() text alone
        # isn't machine-readable, so "gave up" moments were previously invisible outside the terminal.
        STATE.setdefault("supervisor_log", []).append({
            "ts": time.time(), "finding": fi, "kind": kind, "ok": ok, "attempt": attempts[key],
        })
        STATE["supervisor_log"] = STATE["supervisor_log"][-200:]
        if attempts[key] >= MAX_ATTEMPTS:
            exhausted.add(key)
            if not ok:
                given_up += 1
                log("warn", "→ supervisor: giving up on " + kind + " for F" + str(fi) +
                    " after " + str(MAX_ATTEMPTS) + " failed attempts — moving on")
        if rounds % 5 == 0:
            flush()

    nconf = sum(1 for f in STATE["findings"] if f.get("verdict") == "confirmed")
    log("ok", "✓ supervisor · " + str(rounds) + " EV-ranked action(s) dispatched" +
        (" (" + str(given_up) + " gave up after repeat failures)" if given_up else "") + " · " +
        str(nconf) + " confirmed" +
        (" · " + str(len(STATE.get("chains", []))) + " chain(s)" if STATE.get("chains") else ""))
    for tool, kinds in fail.items():
        log("warn", "→ " + tool + " failed " + str(sum(kinds.values())) + "x during supervisor dispatch — " +
            ", ".join(k + " x" + str(v) for k, v in kinds.items()))
    flush()


def phase_agentic_polish(deadline):
    """Rigorous agent pass — makes the autonomous hunt inherit the dashboard agents' rigor:
      1. re-verify every weak finding with the standalone judge (verify-one.py),
      2. build a verified PoC for each confirmed finding (agent-exploit.py),
      3. write a submission-grade report (agent-report.py).
    Additive and single-threaded here, so the flush→subprocess→reload handoff is race-free.
    Disable with --no-polish."""
    if "--no-polish" in sys.argv or not STATE.get("findings"):
        return
    import subprocess as _sp
    # dedicated window — the main hunt budget is usually spent by now, but the rigor pass
    # is worth its own time. Scale with finding count, capped at 15 min.
    deadline = time.time() + min(900, 90 + 60 * len(STATE["findings"]))
    stage("Agent-polish", 99)
    log("ok", "◆ agentic polish · rigorous re-verify + PoC + submission reports")
    flush()  # hand current findings to the agent tools via run.json
    env = dict(os.environ, HUNT_DIR=str(HUNT_DIR))

    # PREVIOUSLY: these two helpers discarded the subprocess result entirely — `except Exception:
    # pass`, no stdout/stderr/returncode even looked at. The rigor pass (re-verify weak findings,
    # build a PoC, write a submission report for every confirmed finding) could fail on every
    # single call, 100% silently: no PoC, no report, no re-verify, and the operator sees nothing
    # wrong except an empty poc/report field with no indication why. Now each call is classified
    # (timeout / crash / nonzero-exit) and failures are counted + logged once, aggregated.
    _polish_fail = {}

    def _classify_run(tool, r_or_exc, to):
        if isinstance(r_or_exc, Exception):
            kind = "timeout" if isinstance(r_or_exc, _sp.TimeoutExpired) else ("exec-error: " + str(r_or_exc)[:100])
        elif r_or_exc.returncode != 0:
            kind = "nonzero-exit(" + str(r_or_exc.returncode) + "): " + (r_or_exc.stderr or "").strip()[-150:]
        else:
            return None
        _polish_fail.setdefault(tool, {})
        _polish_fail[tool][kind] = _polish_fail[tool].get(kind, 0) + 1
        return kind

    def _argv_tool(tool, args, to):
        try:
            r = _sp.run([sys.executable, str(HERE / tool)] + args, capture_output=True, text=True, timeout=to, env=env)
        except Exception as e:
            _classify_run(tool, e, to); return False
        return _classify_run(tool, r, to) is None

    def _stdin_tool(tool, payload, to):
        try:
            r = _sp.run([sys.executable, str(HERE / tool)], input=json.dumps(payload),
                        capture_output=True, text=True, timeout=to, env=env)
        except Exception as e:
            _classify_run(tool, e, to); return False
        return _classify_run(tool, r, to) is None

    WEAK = ("likely", "needs_triage", "needs_review", "manual", "agent")
    weak = [i for i, f in enumerate(STATE["findings"]) if f.get("verdict") in WEAK]
    for i in weak:
        if time.time() > deadline:
            break
        _argv_tool("verify-one.py", ["--run", str(RUN), "--fi", str(i), "--json"], 120)
        _reload_findings()

    conf = [i for i, f in enumerate(STATE["findings"]) if f.get("verdict") == "confirmed"]
    for i in conf:
        if time.time() > deadline:
            break
        f = STATE["findings"][i]
        if not f.get("poc"):
            ok = _stdin_tool("agent-exploit.py", {"fi": i}, 200); _reload_findings()
            if ok and not STATE["findings"][i].get("poc"):
                # tool ran and exited 0 but still produced no PoC — distinct from "it crashed":
                # worth knowing this finding specifically resisted exploitation, not that the tool broke.
                STATE["findings"][i]["poc_attempted_no_result"] = True
        if not STATE["findings"][i].get("report"):
            _stdin_tool("agent-report.py", {"fi": i, "program": STATE.get("program", "")}, 180); _reload_findings()

    # prove IMPACT on proven findings — escalate existence → blast radius (Medium → Critical)
    if "--no-postexploit" not in sys.argv and (HERE / "agent-postexploit.py").exists():
        for i, f in enumerate(STATE["findings"]):
            if time.time() > deadline:
                break
            if f.get("proven") and not f.get("impact_proven") and f.get("cls", "").lower() not in ("info",):
                try:
                    pe = _sp.run([sys.executable, str(HERE / "agent-postexploit.py")], input=json.dumps({"finding": f}),
                                 capture_output=True, text=True, timeout=200, env=env)
                except Exception as e:
                    _classify_run("agent-postexploit.py", e, 200); continue
                kind = _classify_run("agent-postexploit.py", pe, 200)
                if kind:
                    continue
                try:
                    pd = json.loads((pe.stdout or "").strip().splitlines()[-1])
                except Exception as e:
                    _polish_fail.setdefault("agent-postexploit.py", {})
                    k = "parse-error: " + str(e)[:100]
                    _polish_fail["agent-postexploit.py"][k] = _polish_fail["agent-postexploit.py"].get(k, 0) + 1
                    continue
                if pd.get("ok") and pd.get("impact_proven"):
                    STATE["findings"][i]["impact_proven"] = True
                    STATE["findings"][i]["impact_level"] = pd.get("impact_level", "")
                    STATE["findings"][i]["impact_evidence"] = pd.get("evidence", "")
                    lvl = pd.get("impact_level", "").lower()[:1]
                    if lvl in ("c", "h") and STATE["findings"][i].get("sev") not in ("c", "h"):
                        STATE["findings"][i]["sev"] = lvl  # escalate severity to proven impact
                    flush()

    # real chaining — combine confirmed findings into higher-impact exploits (tested, not suggested)
    nconf = len([f for f in STATE["findings"] if f.get("verdict") == "confirmed"])
    if nconf >= 2 and time.time() < deadline and (HERE / "agent-chain.py").exists():
        _stdin_tool("agent-chain.py", {}, 240); _reload_findings()

    nproven = len([f for f in STATE["findings"] if f.get("proven")])
    log("ok", "✓ agentic polish · " + str(len(weak)) + " re-verified · " + str(nconf) +
        " confirmed (" + str(nproven) + " PROVEN) + PoC/report" +
        (" · " + str(len(STATE.get("chains", []))) + " chain(s)" if STATE.get("chains") else ""))
    for tool, kinds in _polish_fail.items():
        log("warn", "→ " + tool + " failed " + str(sum(kinds.values())) + "x during polish — " +
            ", ".join(k + " x" + str(v) for k, v in kinds.items()) +
            " — affected findings may be missing a PoC/report/re-verify; resume to retry")
    flush()


_AUTO_CDP_PORT = 9222   # default port; if taken, tries 9223..9231
_CDP_USER_DATA = Path(os.environ.get("HUNT_CDP_PROFILE", str(Path.home() / ".huntr" / "chrome-profile")))
_CDP_CHROME_BINS = [
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/snap/bin/chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def _cdp_alive(port):
    """Return True if something is listening on port and responds to /json/version (Chrome CDP)."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def _find_chrome():
    for b in _CDP_CHROME_BINS:
        if Path(b).exists():
            return b
    import shutil
    for name in ("google-chrome", "chromium", "chromium-browser"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _auto_cdp():
    """Ensure a debug Chrome is running and cdp_port is written into creds.json.

    1. If creds.json already has a cdp_port and it's alive → done (operator supplied it explicitly).
    2. Scan ports 9222..9231 for an already-running debug Chrome → adopt the first live one.
    3. If none found → launch Chrome with --remote-debugging-port and a persistent profile, write
       the port into creds.json and HUNT_CDP_PORT so every consumer sees it immediately.

    The launched Chrome is headless=false so the operator can log in if needed.  We write a
    sentinel file .hunt/chrome.pid so phase_spa_capture and the shutdown hook can tell our Chrome
    from one the user had already open.  If we fail to launch (no Chrome binary, sandbox issues)
    we log a warning and continue — CDP is an enhancement, not a hard requirement."""
    # Already in creds and alive → nothing to do
    c = _creds()
    if c.get("cdp_port") and _cdp_alive(int(c["cdp_port"])):
        log("ok", f"✓ CDP already attached on port {c['cdp_port']} (from creds)")
        os.environ["HUNT_CDP_PORT"] = str(c["cdp_port"])
        return

    # Scan for an already-running debug Chrome
    for port in range(9222, 9232):
        if _cdp_alive(port):
            log("ok", f"✓ CDP auto-detected on port {port} — attaching")
            _write_cdp_port(port)
            return

    # No running debug Chrome — launch one
    chrome = _find_chrome()
    if not chrome:
        log("warn", "⚠ CDP: no Chrome/Chromium binary found — SPA capture will run without a real session "
            "(localStorage-JWT SPAs may appear unauthenticated). Install google-chrome or chromium.")
        return

    port = _free_cdp_port()
    _CDP_USER_DATA.mkdir(parents=True, exist_ok=True)
    # Open Chrome directly at the target root so the operator sees exactly where to log in.
    # A fresh profile (first run) will show the target's login page instead of a blank tab.
    _lithost = re.sub(r"^\*\.", "", TARGET).split("/")[0].strip()
    _target_url = f"https://{_lithost}/"
    cmd = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={_CDP_USER_DATA}",
        "--no-first-run", "--no-default-browser-check",
        "--disable-background-networking", "--disable-sync",
        "--disable-translate", "--disable-extensions",
        "--disable-popup-blocking",
        "--window-size=1280,800",
        _target_url,   # open directly at the target — operator knows what to log into
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log("warn", f"⚠ CDP: could not launch Chrome — {e}. SPA capture unauthenticated.")
        return

    # Wait up to 8s for CDP to become responsive
    for _ in range(16):
        time.sleep(0.5)
        if _cdp_alive(port):
            break
    else:
        log("warn", f"⚠ CDP: Chrome launched (PID {proc.pid}) but CDP not responsive on port {port} after 8s")
        return

    # Persist PID so shutdown hook can kill only our Chrome, not one the user had open
    (HUNT_DIR / "chrome.pid").write_text(str(proc.pid))

    log("ok", f"✓ CDP: launched Chrome (PID {proc.pid}) on port {port} — log in to the target in the browser window, then the scan will use your real session")
    _write_cdp_port(port)


def _free_cdp_port():
    import socket
    for port in range(9222, 9232):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return 9222


def _teardown_auto_cdp():
    """Kill the Chrome we launched (tracked by chrome.pid), leave pre-existing ones alone."""
    pid_file = HUNT_DIR / "chrome.pid"
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
        pid_file.unlink(missing_ok=True)
        import signal as _sig
        os.kill(pid, _sig.SIGTERM)
        log("ok", f"✓ CDP: closed auto-launched Chrome (PID {pid})")
    except Exception:
        pass


def _write_cdp_port(port):
    """Write cdp_port into creds.json (creating it if absent) and export HUNT_CDP_PORT."""
    os.environ["HUNT_CDP_PORT"] = str(port)
    cf = HUNT_DIR / "creds.json"
    try:
        c = json.loads(cf.read_text()) if cf.exists() else {}
        c["cdp_port"] = port
        fd = os.open(cf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(c).encode())
        finally:
            os.close(fd)
    except Exception as e:
        log("warn", f"⚠ CDP: could not save cdp_port to creds.json — {e}")


def main():
    if not TARGET:
        STATE["status"] = "error"; STATE["stage"] = "No target"; flush()
        print("no --target"); return
    os.environ["HUNT_DIR"] = str(HUNT_DIR)  # so every engine tool shells into this workspace

    # BUG FIX (2026-10-29, caught live on a Shiji Utilities validation hunt): --resume must load the
    # prior run.json BEFORE anything below calls log()/flush() for the first time. log() unconditionally
    # flushes STATE to RUN (tmp-write + atomic replace) — _auto_cdp() alone calls log() on every one of
    # its paths (already-attached/auto-detected/launched/no-binary-found), all running before this used
    # to be computed. That first flush() wrote the freshly-initialized, still-empty STATE straight over
    # the real prior run.json (findings/endpoints/hosts/etc.) — so by the time load_resume() ran and
    # read RUN back, it read back the empty state it had just overwritten, always returned False, and
    # --resume silently redid the entire hunt from scratch (confirmed: a real run with 70 mapped
    # endpoints restarted recon/intel/auth+SPA from zero despite --resume being correctly in argv).
    # Computing resumed/RESUME here, before _auto_cdp() or anything else gets a chance to flush, closes
    # the race — STATE is merged with the prior run's data before the first flush() can ever fire.
    RESUME = "--resume" in sys.argv
    resumed = load_resume() if RESUME else False

    # ── AUTO-CDP: launch a debug Chrome if grey/white and none is already attached ────────────────
    # SPA localStorage sessions are unreachable without CDP — a fresh incognito browser has no
    # stored session and cookie/token fields can't help. Previously the operator had to manually
    # launch Chrome with --remote-debugging-port=9222 AND enter the port in the UI before starting.
    # Now: hunt-run detects or starts the debug Chrome itself and writes the port into creds.json
    # so every CDP consumer (browser-capture, js-api-harvest, huntrfetch WAF bypass) picks it up
    # with zero operator action. Only runs in grey/white mode (black-box never needs auth).
    if MODE != "black":
        _auto_cdp()
    # WAF survival: when a debug Chrome is attached (grey/white + creds.cdp_port), export the port so the
    # CDP-aware scanners (param-fuzz/idor-chain/auth-bypass via huntrfetch) route through the live session
    # and survive Cloudflare/Akamai. Other scanners ignore the var and keep using urllib (nothing breaks).
    try:
        _cp = str(_creds().get("cdp_port") or "").strip()
        if _cp and MODE != "black":
            os.environ["HUNT_CDP_PORT"] = _cp
    except Exception:
        pass
    # Program auth header(s) (e.g. Files.com's `X-FilesAPI-Auth: <token>`, where auth is NOT Bearer or
    # cookie). Export as HUNT_AUTH_HEADERS (JSON) so every scanner subprocess merges it and the
    # authenticated surface is actually reached. Also seed an exec-http/agent identity named 'session'.
    try:
        _ah = _auth_headers()
        if _ah and MODE != "black":
            os.environ["HUNT_AUTH_HEADERS"] = json.dumps(_ah)
            try:
                import importlib.util as _ilu
                _spec = _ilu.spec_from_file_location("agent_core", str(HERE / "agent_core.py"))
                _ac = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_ac)
                _ck = (_creds().get("cookie") or "").strip()
                _ac.set_identity("session", cookie=_ck or None, headers=_ah)
            except Exception:
                pass
    except Exception:
        pass
    try:
        (HUNT_DIR / "run.pid").write_text(str(os.getpid()))  # so the dashboard can pause/resume/stop
    except Exception:
        pass
    try:
        budget_sec = int(arg("--budget-sec", "86400") or 86400)  # default 24h — run until token expires
        deadline = time.time() + budget_sec
        cost_cap_usd = float(arg("--cost-cap-usd", "0") or 0)   # 0 = no cap (time budget is the only limit)
        if cost_cap_usd > 0:
            STATE["cost_cap_usd"] = cost_cap_usd
        if resumed:
            _RL["hit"] = False; _RL["cost_cap"] = False   # clear the pause flag — the operator says the limit has reset / cap was raised
            STATE["status"] = "running"; STATE.pop("paused_reason", None)
            log("ok", "▸ RESUMING · " + TARGET + " · reusing " + str(len(STATE["endpoints"])) +
                " endpoints · " + str(len(STATE["findings"])) + " finding(s) so far · " +
                str(sum(len(v) for v in TESTED.values())) + " cell(s) already done")
        else:
            log("ok", "▸ hunt started · " + TARGET + " · " + ",".join(SCOPE_TYPES) + " · " + MODE + "-box")
        # setup + surface mapping — skipped on resume (already mapped)
        if not resumed:
            phase_scope()
            if SOURCE_ASSETS and not WEB_ASSETS:
                # ── Source-only scope (GitHub/GitLab repos) ──────────────────
                # Skip the entire web/API pipeline. The LLM reads the code and hunts.
                log("ok", "◆ source-only scope — entering code review mode")
                phase_source_audit()
                phase_hard_triage()   # source findings go through the same hard gate
            else:
                # ── Web / API hunt ────────────────────────────────────────────
                # STRATUM 0 — Intelligence (BEFORE any probe is sent)
                if "intel" in HUNT_AGENTIC_PHASES:
                    _phase_intel_agent(deadline)   # full-agentic — disclosures/secrets/shodan/wayback/rewards, agent's own judgment
                else:
                    phase_program_intel()     # GOD METHODOLOGY: disclosures + Shodan + Wayback + GitHub org + reward table
                # STRATUM 1 — Surface mapping
                if "recon_surface" in HUNT_AGENTIC_PHASES:
                    _phase_recon_surface_agent(deadline)   # full-agentic pilot — see HUNTR full-agentic plan
                else:
                    phase_recon()             # DNS + HTTP probe + S3 buckets + GitHub dork
                    phase_mobile()            # mobile scope — APK backend hosts/endpoints/secrets
                    phase_surface()
                    phase_discover(deadline)  # ACTIVE discovery — unlinked paths + spec walk + BFS
                if "auth_spa" in HUNT_AGENTIC_PHASES:
                    _phase_auth_spa_agent(deadline)   # full-agentic — SPA capture + auth session + JWT/OAuth/session testing, all in one
                else:
                    phase_spa_capture()       # SPA runtime API discovery (real browser)
                if not NO_LLM and "recon_surface" not in HUNT_AGENTIC_PHASES:
                    phase_recon_agent()    # Claude reviews the baseline surface, decides what's worth digging into further
                    # (folded into _phase_recon_surface_agent itself when that flag is on — no separate enrichment pass needed)
                phase_memory_recall()     # long-term memory — analogous past situations (BEFORE plan so it informs it)
                # STRATUM 2 — Attack
                if "active_hunt" not in HUNT_AGENTIC_PHASES:
                    phase_active()        # Layer 1 — deterministic sweep; LLM gets real scan evidence (+ graphql-map + ws-probe + ssrf-probe)
                # (folded into _phase_active_hunt_agent itself when that flag is on — no separate deterministic sweep needed)
                if "auth_spa" not in HUNT_AGENTIC_PHASES:
                    phase_authed()            # Auth surface + JWT + IDOR diffing + multi-account auto-setup
                    phase_auth_deep()         # GOD METHODOLOGY: OAuth probe + reset host-header + MFA rate-limit + JWT expiry
                # (folded into _phase_auth_spa_agent itself when that flag is on — session/JWT/OAuth testing already done above)
                if "plan" in HUNT_AGENTIC_PHASES:
                    _phase_plan_agent(deadline)   # full-agentic — biz-logic model + authz probe + ranked plan, all in one
                else:
                    phase_biz_logic_map()     # GOD METHODOLOGY: map entities/roles/flows/value-ops before attacking
                    phase_authz_matrix()      # GOD METHODOLOGY: BFLA sweep + mass-assign on write endpoints
                if "active_hunt" not in HUNT_AGENTIC_PHASES:
                    phase_race_critical() # GOD METHODOLOGY: 25-thread race bursts + logic-fuzz on all value-flow endpoints
                # (folded into _phase_active_hunt_agent itself when that flag is on — agent fires its own concurrent bursts)
                # Rebuild the surface graph NOW, not just once back in phase_surface(). By this point
                # phase_recon_agent + phase_discover + phase_spa_capture + phase_biz_logic_map have all
                # added content the initial crawl never had — the graph Claude's hunting phase queries
                # (_phase_claude_code_hunt / phase_recon_agent) should reflect the full enriched surface
                # (including the business-logic model now in biz-logic.md), not just the bare endpoint
                # list from before recon finished. update=True: incremental re-extract on the graph
                # phase_surface() already built, not a fresh one.
                if not NO_LLM and STATE.get("endpoints"):
                    _build_surface_graph(STATE["endpoints"], update=True)
        else:
            log("out", "→ resume: skipping recon/surface (reusing mapped surface); continuing the hunt")
        if not (SOURCE_ASSETS and not WEB_ASSETS):
            # Web-hunt-only phases (skip for source-only).
            if "plan" not in HUNT_AGENTIC_PHASES:
                phase_plan()                             # target-specific attack plan + flows (flexible)
            elif resumed:
                log("out", "→ resume: skipping plan agent (reusing the plan already in run.json)")
            # (on a fresh run, _phase_plan_agent above already wrote STATE["plan"] — no separate call needed here)
            if "active_hunt" in HUNT_AGENTIC_PHASES:
                check_pause(); _phase_active_hunt_agent(deadline)   # full-agentic — see HUNTR full-agentic plan Phase 5:
                # replaces phase_adaptive/phase_llm_lead/phase_ai_direct/phase_api_test/phase_exploit_agent/
                # phase_oob entirely — one agent reasons continuously over the whole surface and decides
                # what's worth testing, instead of running them as separate layers.
            else:
                # REBUILT 2026-10-22 (operator: "these scripts won't find shit — rebuild HUNTR to reason
                # like Claude"): phase_llm_lead previously ran strictly AFTER phase_adaptive's full
                # deterministic sweep finished. On a real surface (3733 cells, live Databricks hunt) that
                # blind scan_cell sweep alone ran 4-5+ HOURS before Claude's reasoning agent got a single
                # turn — the operator compared the same target hunted by Claude Code directly and found
                # Claude Code's live reasoning (read the response, form a hypothesis, test it, chain it)
                # found real signal while HUNTR's scripted sweep mostly produced false positives (see
                # fp-otp-uuid-oauth-guessed-url memory). Sequencing the thing that actually reasons dead
                # last behind hours of mechanical pattern-matching meant it barely ran at all.
                # Fix: run them CONCURRENTLY against the same wall-clock deadline. phase_adaptive is
                # provably safe to background — it is 0-token (never calls the LLM, so it can never itself
                # raise RateLimitPause) and only checks time.time() > deadline to stop, no check_pause()
                # calls inside it. It still proceeds as a coverage backstop, immune to an LLM rate-limit
                # pause, while phase_llm_lead starts reasoning within seconds instead of hours later.
                # Thread safety already proven in this codebase: STATE mutations go through _STATE_LOCK
                # (add_finding/mark_tested), scope-guard's rate limiter is flock-protected for concurrent
                # requests (see rate-limit-race memory), and phase_llm_lead's own dual-agent BROAD+DEEP
                # mode already runs itself as two concurrent threads today.
                if not NO_LLM and not resumed:
                    _adapt_t = threading.Thread(target=phase_adaptive, args=(deadline,), daemon=True)
                    _adapt_t.start()
                    STATE["stage_parallel"] = "0-token coverage sweep running in background"
                    check_pause(); phase_llm_lead(deadline)      # Claude leads — reasons, hypothesizes, chains
                    _adapt_t.join(timeout=max(0, deadline - time.time()))
                    STATE.pop("stage_parallel", None)
                else:
                    phase_adaptive(deadline)                     # deterministic-only mode / resume: sweep alone
                if not NO_LLM:                               # LLM depth phases (skipped in deterministic-only mode)
                    check_pause(); phase_api_test(deadline)      # SPA-first — test captured runtime API
                    check_pause(); phase_ai_direct(deadline)     # Layer 2 — AI-directed (Haiku)
                    check_pause(); phase_exploit_agent(deadline) # Depth — LLM-driven exploitation
                    check_pause(); phase_oob(deadline)           # Blind/OOB fuzzing
            # Phase 9 — deep-questions agent (stuck-breaker): an elite-hunter pass that refuses to
            # accept "locked/exhausted" and digs deeper (version pivots, alt hosts, trusted headers,
            # param mining, unfinished flows). Runs after the main hunt but BEFORE verify, so whatever
            # it surfaces is validated + valued by the downstream tail like any other finding.
            if "deep_questions" in HUNT_AGENTIC_PHASES and not NO_LLM:
                check_pause(); _phase_deep_questions_agent(deadline)
            # Phase 10 — zero-day agent: treats every 4xx/5xx the normal classes gave up on as the
            # start of the work — novel bypass techniques to flip blocks into access, plus hunting
            # implementation-specific novel vulns a templated scanner would never find.
            if "zero_day" in HUNT_AGENTIC_PHASES and not NO_LLM:
                check_pause(); _phase_zeroday_agent(deadline)
        phase_dedup()
        phase_fingerprint()
        if not NO_LLM:
            if "verify" in HUNT_AGENTIC_PHASES:
                check_pause(); _phase_verify_agent(deadline)   # full-agentic — one judge re-examines + dedups + triages every finding
            else:
                check_pause(); phase_verify()               # LLM re-verifies every finding: confirmed / dismissed / manual
                check_pause(); phase_ai_judge()              # Layer 3 — strong-model validation
                check_pause(); phase_adversarial_verify(deadline)  # Layer 4 — independent second judge, confirmed-only
            check_pause(); phase_methodology(deadline)
        if "chain_econ" in HUNT_AGENTIC_PHASES and not NO_LLM:
            check_pause(); _phase_chain_economics_agent(deadline)   # full-agentic — chains + EV, agent's own judgment
        else:
            check_pause(); phase_chain()                 # Chain-to-Impact — deterministic core (proven + near-miss chains);
                                                         #   LLM only enriches near-miss strategy, so it runs in NO_LLM too
            phase_scenario()                             # "impossible scenario" engine — oracle-gated kill-chains
            phase_economics()                            # Economics brain
        # TRANSITIONAL (full-agentic rewrite, 2026-10-25): phase_dedup()/phase_hard_triage() stay on
        # the legacy path even when "verify" is agentic, because phase_supervisor/phase_agentic_polish
        # below (Phase 8 — not yet converted) can still add NEW findings this pass's agent never saw.
        # Once Phase 8 is converted this backstop goes away; until then it's a deliberate, documented
        # safety net, not a contradiction of "no deterministic oracle code" — it never overrides a
        # verdict _phase_verify_agent already set, it only floors severity for whatever legacy code
        # still adds after it runs.
        phase_hard_triage()                          # FINAL authority: prove-it-or-lead; info-class capped
        if not NO_LLM:
            phase_learn()                                # close the loop → learned rules for the NEXT hunt
            # REMOVED phase_auto_reports() 2026-10-23: redundant with phase_supervisor's agent-report.py
            # dispatch below (same job, submission-grade template, correct "report" field) AND it had a
            # real bug — it wrote its own report summary into f["reco"], clobbering phase_economics'
            # routing decision ("submit"/"needs-work"/"hold-duplicate") with prose. phase_supervisor
            # never touches f["reco"], so removing this is a strict fix, not just a dedup.
            check_pause(); phase_supervisor(deadline)     # EV-ranked coordinator — does the highest-value work first
            check_pause(); phase_agentic_polish(deadline) # deterministic safety net for whatever the supervisor didn't reach
            # dedup again LAST too, same reasoning as hard_triage below: phase_supervisor/agentic_polish
            # can add new findings, and a dual-agent DEEP-thread from the much earlier phase_llm_lead
            # may still be finishing up (daemon thread, joined with a timeout — not a hard join) and
            # adding its own. Any of those could share a root cause with an already-deduped cluster
            # from the single earlier phase_dedup() call and would otherwise never get merged into it,
            # quietly re-inflating the exact "N confirmed" count the dedup pass exists to fix.
            phase_dedup()
            # economics too: dedup's _best_rank can promote a late-arriving finding to be the new
            # "keeper" of a cluster (if it happens to outrank the original — e.g. _det=True where the
            # original wasn't). That keeper never went through the single earlier phase_economics()
            # call and would be missing ev/reco entirely, so it would never route to "submit" no
            # matter how real it is. phase_economics() is pure/deterministic (priors.json + arithmetic,
            # no LLM, no network) and recomputes ev/reco for every finding unconditionally each call,
            # so re-running it here is cheap and simply fixes up whatever dedup just reshuffled.
            phase_economics()
            phase_hard_triage()                          # run again LAST — polish cannot smuggle anything past the gate
            # POST-HUNT deep graph rebuild: findings are now fully settled (post-supervisor PoC/
            # report/impact, post-dedup, post-economics) — this is the one build that actually has
            # confirmed findings to encode as REQUIRES/ENABLES exploit-chain edges (see
            # _build_surface_graph's deep= docstring). Feeds any later chain-building or report
            # enrichment a real attack-chain graph to query instead of a flat finding list.
            if not NO_LLM and STATE.get("endpoints"):
                _build_surface_graph(STATE["endpoints"], deep=True, update=True, blocking=True)
                _merge_into_global_graph()
        STATE["status"] = "done"
        stage("Done", 100)
        nf = len(_real_findings()); cov = STATE["coverage"]
        log("ok", "■ hunt finished · " + str(nf) + " finding" + ("" if nf == 1 else "s") +
            " · " + str(len(STATE["leads"])) + " leads · " + str(len(STATE["chains"])) + " chains · coverage " +
            str(cov.get("breadth", 0)) + "%")
        _teardown_auto_cdp()
    except RateLimitPause:
        if _RL.get("cost_cap"):
            STATE["status"] = "paused"; STATE["paused_reason"] = "cost-cap"
            log("warn", "⏸ PAUSED — spend cap reached ($" + str(STATE.get("cost_usd", 0)) + " ≥ $" +
                str(STATE.get("cost_cap_usd")) + ") · findings + coverage saved · raise the cap (or confirm "
                "the spend) and click Resume")
        else:
            STATE["status"] = "paused"; STATE["paused_reason"] = "rate-limit"
            ra = _RL.get("retry_after", 0)
            log("warn", "⏸ PAUSED — account rate limit reached" + (" (retry ~" + str(ra) + "s)" if ra else "") +
                " · findings + coverage saved · click Resume when the limit resets")
        # A pause can fire mid-pipeline (any check_pause), skipping the whole deterministic TAIL that
        # normally runs after the LLM phases — including phase_economics (assigns each finding's `reco`:
        # submit / hold-duplicate / needs-work). Without it every proven finding has reco=None, so nothing
        # is routed to submit (ev_recall → 0) even though the bugs are real + oracle-proven. These tail
        # phases are 0-token deterministic, so run them here too; each guarded so one failing can't lose
        # the saved state. (phase_learn is NOT run here — it calls the LLM and would re-hit the limit.)
        for _dp in (phase_dedup, phase_economics, phase_hard_triage):
            try:
                _dp()
            except Exception:
                pass
        # the scenario engine is deterministic (templates re-prove via oracle, 0 LLM) — still run it on a
        # pause so the proven primitives gathered so far are composed into kill-chains regardless.
        try:
            os.environ["HUNTR_SCENARIO_NO_LLM"] = "1"
            phase_scenario()
        except Exception:
            pass
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
