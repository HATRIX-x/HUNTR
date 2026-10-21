#!/usr/bin/env python3
"""
agent_core.py — shared infrastructure for HUNTR's specialized agents.

Every agent is the same shape: an Anthropic tool-use loop (Claude Pro OAuth, Haiku-first
because Sonnet rate-limits on Pro) + a focused toolset + a prompt. This module holds the
loop, the common tools (scope-guarded http_request, engine-tool runner), and run.json I/O
so each agent script stays thin.

NEVER uses the Anthropic API key directly — llm_client resolves OAuth.
"""
import os, sys, json, subprocess, importlib.util, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
HUNT_DIR = Path(os.environ.get("HUNT_DIR", "./.hunt"))
RUN = HUNT_DIR / "run.json"
IDS = HUNT_DIR / "identities.json"
EV = HUNT_DIR / "evidence"

# Haiku first: fast + available on Pro; Sonnet is a quality fallback that often 429s.
MODELS = ("claude-haiku-4-5-20251001", "claude-sonnet-4-6")


def load_lc():
    spec = importlib.util.spec_from_file_location("llm_client", str(HERE / "llm_client.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


_LC = None
def lc():
    global _LC
    if _LC is None:
        _LC = load_lc()
    return _LC


# ── run.json I/O ──
def read_run():
    try:
        return json.loads(RUN.read_text())
    except Exception:
        return {}


def write_run(d):
    tmp = RUN.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d)); tmp.replace(RUN)


def findings():
    return read_run().get("findings", [])


def append_finding(f):
    """Append a new finding to run.json atomically. Returns its index."""
    d = read_run()
    d.setdefault("findings", []).append(f)
    d.setdefault("stats", {})["findings"] = len(d["findings"])
    write_run(d)
    return len(d["findings"]) - 1


def update_finding(i, patch):
    d = read_run()
    fs = d.get("findings", [])
    if 0 <= i < len(fs):
        fs[i].update(patch)
        write_run(d)
        return True
    return False


# ── identities ──
def has_identity(name):
    try:
        return name in json.loads(IDS.read_text())
    except Exception:
        return False


def set_identity(name, cookie=None, authorization=None, headers=None):
    ids = {}
    if IDS.exists():
        try:
            ids = json.loads(IDS.read_text())
        except Exception:
            ids = {}
    ent = {}
    if cookie:
        ent["cookieHeader"] = cookie
    if authorization:
        ent["authorization"] = authorization
    if headers:
        ent["headers"] = headers
    ids[name] = ent
    IDS.write_text(json.dumps(ids))


# ── scope-guarded HTTP — routes through the shared huntrlib.spine (the one engine HTTP path) ──
def exec_http(method, url, data=None, identity=None, timeout=45):
    try:
        spec = importlib.util.spec_from_file_location("huntrlib", str(HERE / "huntrlib.py"))
        hl = importlib.util.module_from_spec(spec); spec.loader.exec_module(hl)
        r = hl.spine(url, method=method, data=data, identity=identity, timeout=timeout)
    except Exception as e:
        return "error: " + str(e)[:160]
    summary = r.get("raw", "")
    heads = (r.get("headers") or "")[:2200]
    body = (r.get("body") or "")[:1600]
    resp_text = (heads + ("\n\n[body]\n" + body if body.strip() else "")) if heads else ""
    return (summary + ("\n\n" + resp_text if resp_text else ""))[:5000] or "(no output)"


def run_engine_tool(tool, args, timeout=120):
    """Run any engine tool as a subprocess with HUNT_DIR pinned. Returns combined output."""
    try:
        r = subprocess.run([sys.executable, str(HERE / tool)] + [str(a) for a in args],
                           capture_output=True, text=True, timeout=timeout, env=os.environ)
        return (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        return "error: tool timed out"
    except FileNotFoundError:
        return "error: tool not found: " + tool


# ── the common http_request tool definition ──
def http_tool_def(session_available=False):
    return {
        "name": "http_request",
        "description": ("Make a REAL HTTP request through scope-guard against an in-scope host. "
                        "Returns the status line, response headers, and a body snippet. Use it to test "
                        "live behaviour — read the actual Location / Access-Control-Allow-Origin / "
                        "Set-Cookie headers and body. Out-of-scope hosts are refused automatically."
                        + (" An operator session identity is available (use_session:true)."
                           if session_available else "")),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]},
                "url": {"type": "string"},
                "data": {"type": "string"},
                "identity": {"type": "string", "description": "named identity to send as (e.g. session, idA, idB)"},
                "use_session": {"type": "boolean"},
            },
            "required": ["url"],
        },
    }


def http_handler(inp):
    ident = inp.get("identity")
    if inp.get("use_session") and not ident:
        ident = "session"
    return exec_http(inp.get("method", "GET"), inp.get("url", ""), inp.get("data"), ident)


# ── the agent loop ──
def _tools_text(tools):
    lines = []
    for t in tools:
        name = t.get("name", "")
        props = (t.get("input_schema") or {}).get("properties", {})
        req = (t.get("input_schema") or {}).get("required", [])
        lines.append("- " + name + "(" + ", ".join(props.keys()) + "): " + t.get("description", "")
                     + (" [required: " + ", ".join(req) + "]" if req else ""))
    return "\n".join(lines)


_URL_RE = re.compile(r'https?://[^\s"\'<>\\]+')
_PARAM_RE = re.compile(r'"param"\s*:\s*"([^"]+)"')
# Tools that imply a REAL outbound action (network/browser). Live-tested finding: under
# claude -p (the sanctioned subscription path), the model reasons about its OWN actual sandbox
# and reliably REFUSES to emit a tool-call JSON for these — "I don't have network/file-write
# access in this session" — no matter how the prompt frames it, because it isn't playing along
# with a fictional harness, it's reporting what it (correctly, for itself) believes is true.
# Asking never works, so we never ask: run them ourselves before the model sees the prompt at
# all, and hand the result over as evidence it reasons about instead of an action it declines.
# Cheap ones (plain HTTP) get up to 3 URLs; CDP browser oracles are heavier (several round trips
# each with settle delays) so they're capped to the finding's own primary endpoint.
_AUTO_RUN_CHEAP = ("http_request", "bypass_matrix")
_AUTO_RUN_BROWSER = ("domxss_proof", "client_pp_proof", "client_redirect_proof")
_AUTO_RUN_TOOLS = _AUTO_RUN_CHEAP + _AUTO_RUN_BROWSER


def _extract_urls(text, cap=3):
    seen = []
    for m in _URL_RE.findall(text or ""):
        u = m.rstrip('.,;)]}"\'')
        if u not in seen:
            seen.append(u)
        if len(seen) >= cap:
            break
    return seen


def _extract_param(text):
    m = _PARAM_RE.search(text or "")
    return m.group(1) if m else None


def _json_action_loop(system, user, tools, handlers, max_rounds=6, max_tokens=1600, timeout=60):
    """Fallback for CLI-subscription mode (HUNT_LLM_VIA_CLI=1), where `claude -p` has no native
    tool-calling, so call_llm_with_tools refuses outright. Pre-runs any network/browser-side-effecting
    tool deterministically (see _AUTO_RUN_TOOLS) and hands the model the result as evidence;
    remaining bookkeeping tools (record_finding, save_identity, …) are driven one JSON decision
    at a time over call_llm, which DOES work in CLI mode. Same (reply, tool_log, err) shape as
    run_agent / call_llm_with_tools."""
    tool_log = []
    model_tools = [t for t in tools if t.get("name") not in _AUTO_RUN_TOOLS]
    cheap_names = [t["name"] for t in tools if t.get("name") in _AUTO_RUN_CHEAP and t["name"] in handlers]
    browser_names = [t["name"] for t in tools if t.get("name") in _AUTO_RUN_BROWSER and t["name"] in handlers]
    auto_names = cheap_names + browser_names

    lines = []
    if cheap_names:
        name = "http_request" if "http_request" in cheap_names else cheap_names[0]
        for u in _extract_urls(user, cap=3):
            try:
                res = handlers[name]({"method": "GET", "url": u})
            except Exception as e:
                res = "error: " + str(e)[:200]
            res = str(res)
            tool_log.append({"name": name, "input": {"url": u}, "result": res[:600]})
            lines.append("### " + name + " " + u + "\n" + res[:1200])
    if browser_names:
        param = _extract_param(user)
        for u in _extract_urls(user, cap=1):
            for name in browser_names:
                try:
                    res = handlers[name]({"url": u, "param": param})
                except Exception as e:
                    res = "error: " + str(e)[:200]
                res = str(res)
                tool_log.append({"name": name, "input": {"url": u, "param": param}, "result": res[:600]})
                lines.append("### " + name + " " + u + "\n" + res[:800])
    prefetch_text = (("\n\n## Live evidence (already fetched/proven for you by the harness — "
                       "do not ask to run it again)\n" + "\n\n".join(lines)) if lines else "")

    sys_json = system
    if model_tools:
        # Framing matters: live-tested finding. Asking the model to "call a tool" (i.e. CLAIM it is
        # performing a real network/browser action itself) gets reliably refused under claude -p — it
        # reasons about its OWN actual sandbox and reports "I don't have network access," no matter the
        # JSON shape. Asking it to PROPOSE a step for an external harness to carry out, with the explicit
        # promise that it will see the REAL result next turn, is not a capability claim and is NOT refused
        # — verified live for both network tools and bookkeeping tools, so this framing is used uniformly.
        sys_json += ("\n\n--- STEP PROTOCOL ---\n"
                     "You do not perform these steps yourself — a separate deterministic harness carries "
                     "out whatever you propose and reports the REAL result back to you next turn. Each turn, "
                     "reply with STRICT JSON only, one proposal, nothing else:\n"
                     '  {"propose": "<name>", "input": {...}}   — have the harness run this step for real\n'
                     '  {"propose": "done", "text": "<final answer>"}   — you have enough evidence to conclude\n\n'
                     "Available steps:\n" + _tools_text(model_tools))
    elif auto_names:
        sys_json += "\n\nGive your final answer directly as plain text — no JSON wrapper needed."

    transcript = user + prefetch_text
    reply_text, err = None, None
    for _i in range(max(1, max_rounds)):
        out, call_err = lc().call_llm(sys_json, transcript, timeout=timeout, max_tokens=max_tokens)
        if not out:
            err = call_err or "no response"
            break
        m = re.search(r"\{.*\}", out, re.S)
        action = None
        if m:
            try:
                action = json.loads(m.group(0))
            except Exception:
                action = None
        if not isinstance(action, dict) or not model_tools:
            reply_text = out.strip()
            break
        proposal = action.get("propose")
        if proposal == "done" or proposal not in handlers:
            reply_text = (str(action.get("text", "")).strip() if "text" in action else "") or out.strip()
            break
        name, inp = proposal, (action.get("input") or {})
        try:
            result = handlers[name](inp)
        except Exception as e:
            result = "error: " + str(e)[:200]
        result = str(result)
        tool_log.append({"name": name, "input": {k: inp.get(k) for k in list(inp)[:4]}, "result": result[:600]})
        transcript += ("\n\n[assistant proposed]\n" + m.group(0) +
                       "\n\n[harness ran it for real — RESULT for " + name + "]\n" + result[:3000])
    if reply_text is None and err is None:
        err = "max rounds reached without a final answer"
    return reply_text, tool_log, err


def run_agent(system, user, tools, handlers, max_rounds=6, max_tokens=1600, timeout=60):
    """
    tools    : list of Anthropic tool defs
    handlers : {tool_name: fn(input_dict) -> str}
    returns  : (reply_text_or_None, tool_log, error_or_None)
    """
    if lc()._cli_mode():
        return _json_action_loop(system, user, tools, handlers, max_rounds, max_tokens, timeout)

    tool_log = []

    def executor(name, inp):
        fn = handlers.get(name)
        if not fn:
            return "unknown tool: " + name
        try:
            res = fn(inp)
        except Exception as e:
            res = "error: " + str(e)[:200]
        res = str(res)
        tool_log.append({"name": name, "input": {k: inp.get(k) for k in list(inp)[:4]}, "result": res[:600]})
        return res

    reply = err = None
    for mdl in MODELS:
        try:
            reply, _tl, err = lc().call_llm_with_tools(
                system, user, tools, executor,
                model=mdl, max_tokens=max_tokens, timeout=timeout, max_tool_rounds=max_rounds)
        except Exception as e:
            reply, err = None, str(e)
        if reply:
            break
    return reply, tool_log, err


# ── skill injection: map a finding's class to its hunt-* methodology playbook ──
_SKILL_ROOT = Path.home() / ".claude" / "skills"
_SKILL_CACHE = {}
# keyword (matched against class+title, longest first) → hunt-* skill dir name
_CLASS_SKILL = [
    ("auth-bypass", "hunt-auth-bypass"), ("auth bypass", "hunt-auth-bypass"),
    ("open redirect", "hunt-open-redirect"), ("open-redirect", "hunt-open-redirect"),
    ("source-leak", "hunt-source-leak"), ("source leak", "hunt-source-leak"),
    ("host header", "hunt-host-header"), ("prototype", "hunt-prototype-pollution"),
    ("deserial", "hunt-deserialization"), ("smuggl", "hunt-http-smuggling"),
    ("business", "hunt-business-logic"), ("clickjack", "hunt-clickjacking"),
    ("shadow", "hunt-shadow-api"), ("websocket", "hunt-websocket"),
    ("takeover", "hunt-subdomain"), ("subdomain", "hunt-subdomain"),
    ("idor", "hunt-idor"), ("bola", "hunt-idor"), ("authz", "hunt-idor"), ("access", "hunt-idor"),
    ("ssrf", "hunt-ssrf"), ("ssti", "hunt-ssti"), ("sqli", "hunt-sqli"), ("sql", "hunt-sqli"),
    ("xss", "hunt-xss"), ("xxe", "hunt-xxe"), ("lfi", "hunt-lfi"), ("rce", "hunt-rce"),
    ("race", "hunt-race"), ("cors", "hunt-cors"), ("csrf", "hunt-csrf"), ("jwt", "hunt-jwt-crypto"),
    ("oauth", "hunt-oauth"), ("graphql", "hunt-graphql"), ("upload", "hunt-file-upload"),
    ("redirect", "hunt-open-redirect"), ("secret", "hunt-source-leak"), ("disclosure", "hunt-source-leak"),
    ("leak", "hunt-source-leak"), ("misconfig", "hunt-api-misconfig"), ("cache", "hunt-cache-poison"),
    ("ato", "hunt-ato"), ("mfa", "hunt-mfa-bypass"), ("redirect", "hunt-open-redirect"),
    ("param", "hunt-idor"), ("secret", "hunt-source-leak"),
]


def _read_skill(name):
    if name in _SKILL_CACHE:
        return _SKILL_CACHE[name]
    f = _SKILL_ROOT / name / "SKILL.md"
    txt = ""
    try:
        if f.exists():
            txt = f.read_text(errors="ignore")
    except Exception:
        txt = ""
    _SKILL_CACHE[name] = txt
    return txt


def skill_for(text="", budget=3200, by_name=None):
    """Return a hunt-* skill's methodology (payloads, targets, bypasses, CVSS) for a vuln
    class/title, trimmed to budget, for injection into an agent's system prompt."""
    if by_name:
        picked = by_name
    else:
        t = (text or "").lower()
        picked = None
        for kw, sk in _CLASS_SKILL:
            if kw in t:
                picked = sk
                break
        if not picked and _SKILL_ROOT.is_dir():
            toks = set(re.findall(r"[a-z]{4,}", t))
            best = (0, None)
            for d in sorted(_SKILL_ROOT.glob("hunt-*")):
                nm = d.name.replace("hunt-", "")
                score = sum(1 for x in toks if x == nm or x in nm or nm in x)
                if score > best[0]:
                    best = (score, d.name)
            picked = best[1]
    if not picked:
        return ""
    txt = _read_skill(picked)
    if not txt:
        return ""
    txt = re.sub(r"^---.*?---\s*", "", txt, flags=re.S)  # drop frontmatter
    return "\n\n--- METHODOLOGY (from skill " + picked + ", built from real bug-bounty reports) ---\n" + txt[:budget]


# ── plugin ecosystem: user-droppable custom oracles/provers (open > closed) ──
_PLUGINS = None
def load_plugins():
    """Auto-discover custom provers in HUNTR/plugins/*.py. A plugin exposes:
        CLASS = "myvuln"  (str or list of class keywords)
        def prove(finding: dict, http) -> {"proven": bool|None, "method": str, "evidence": str}
    where `http(method,url,**kw)` is the scope-guarded spine. Returns {class_keyword: prove_fn}.
    This lets anyone extend HUNTR's coverage without touching the core — a closed tool (XBOW) can't."""
    global _PLUGINS
    if _PLUGINS is not None:
        return _PLUGINS
    _PLUGINS = {}
    pdir = HERE.parent / "plugins"
    if pdir.is_dir():
        for pf in sorted(pdir.glob("*.py")):
            if pf.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location("plugin_" + pf.stem, str(pf))
                mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
                cls = getattr(mod, "CLASS", None)
                fn = getattr(mod, "prove", None)
                if cls and callable(fn):
                    for c in ([cls] if isinstance(cls, str) else list(cls)):
                        _PLUGINS[str(c).lower()] = fn
            except Exception:
                continue
    return _PLUGINS


def plugin_prove(finding):
    """If a plugin matches the finding's class, run it (scope-guarded http passed in). Returns its
    verdict dict or None."""
    plugins = load_plugins()
    if not plugins:
        return None
    blob = ((finding.get("cls") or "") + " " + (finding.get("title") or "")).lower()
    for kw, fn in plugins.items():
        if kw in blob:
            def _http(method, url, **kw2):
                return exec_http(method, url, kw2.get("data"), kw2.get("identity"))
            try:
                return fn(finding, _http)
            except Exception as e:
                return {"proven": None, "method": "plugin-error", "evidence": str(e)[:120]}
    return None


def read_stdin_json():
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:
        return {}


def emit(d):
    print(json.dumps(d)); sys.exit(0)
