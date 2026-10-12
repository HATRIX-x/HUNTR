#!/usr/bin/env python3
"""
llm_client — unified LLM provider abstraction for HUNTR.
Supports: Anthropic (Claude), NVIDIA (Nemotron), OpenAI-compatible endpoints.

Configuration via environment:
  HUNT_LLM_PROVIDER      "anthropic" | "nvidia" | "openai"  (default: "nvidia")
  HUNT_LLM_MODEL         model name override
  HUNT_LLM_API_KEY       API key for the provider
  HUNT_LLM_BASE_URL      base URL for OpenAI-compatible endpoints
  HUNT_LLM_TEMPERATURE   sampling temperature (default: 0.1)
  HUNT_LLM_MAX_TOKENS    max tokens (default: 2500)

Provider specifics:
  - anthropic: Uses api.anthropic.com, x-api-key header, anthropic-version
  - nvidia:    Uses NVIDIA NIM endpoint (base_url + /v1/chat/completions), Bearer auth
  - openai:    Uses base_url + /v1/chat/completions, Bearer auth
"""

import os
import json
import ssl
import sys
import re
import time
import shutil
import subprocess
import concurrent.futures
import threading
from pathlib import Path
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError

# ── cross-process LLM slot pool ──
# Caps concurrent LLM calls across ALL workers (fleet) so N parallel hunts never blow the account
# rate limit. HUNTR_LLM_SLOTS=N enables it (default: no cap). Implemented as atomic lock files, so it
# works across processes and machines sharing storage — the "rate-governed shared LLM pool".
_LLM_SLOT_DIR = Path(os.environ.get("HUNTR_LLM_SLOT_DIR", str(Path.home() / ".huntr" / "llm_slots")))


def _llm_slots():
    try:
        return int(os.environ.get("HUNTR_LLM_SLOTS", "0") or 0)
    except Exception:
        return 0


def _llm_slot_acquire():
    n = _llm_slots()
    if n <= 0:
        return None
    _LLM_SLOT_DIR.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + 120
    while time.time() < deadline:
        for i in range(n):
            lp = _LLM_SLOT_DIR / ("slot%d.lock" % i)
            try:
                fd = os.open(str(lp), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode()); os.close(fd)
                return lp
            except FileExistsError:
                # reclaim a stale slot (holder dead / >300s old)
                try:
                    if time.time() - lp.stat().st_mtime > 300:
                        lp.unlink(missing_ok=True)
                except Exception:
                    pass
        time.sleep(0.4)
    return None  # couldn't get a slot in time — proceed rather than deadlock


def _llm_slot_release(lp):
    if lp:
        try:
            Path(lp).unlink(missing_ok=True)
        except Exception:
            pass

# Key files searched in order (first hit wins, existing env vars always win).
ENV_FILES = [
    Path.home() / ".config" / "huntr" / "llm.env",
    Path(__file__).resolve().parent / ".env",
]


def _load_env_files():
    """Load NVIDIA_API_KEY / provider keys from disk so standalone tool runs work too."""
    for f in ENV_FILES:
        try:
            if not f.exists():
                continue
            for line in f.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip().strip('"').strip("'")
                # an empty value in the file must not shadow a real exported var
                if v:
                    os.environ.setdefault(k.strip(), v)
        except Exception:
            pass


_load_env_files()


def _strip_reasoning(data):
    """Pull the final answer out of an OpenAI-style reply.

    Nemotron 3 reasoning models may answer with reasoning_content (chain of thought) and/or
    a <think> block inside content. Downstream tools all want the final answer only —
    leaking raw reasoning into findings/reports would be noise, so drop it.
    """
    msg = (data.get("choices") or [{}])[0].get("message") or {}
    txt = msg.get("content") or ""
    if "<think>" in txt and "</think>" in txt:
        txt = txt.split("</think>", 1)[1].strip()
    elif txt.lstrip().startswith("<think>"):
        txt = ""
    return txt.strip()


# Provider configs
PROVIDERS = {
    "anthropic": {
        "default_base": "https://api.anthropic.com",
        "chat_path": "/v1/messages",
        "auth_header": "x-api-key",
        "extra_headers": {"anthropic-version": "2023-06-01"},
        # Anthropic native format — strip keys the Messages API rejects: enable_thinking is not a valid
        # param; temperature + top_p cannot both be sent (drop top_p); and newer models (Opus 4.8) REJECT
        # `temperature` outright ("deprecated for this model") → drop it for claude-opus* too.
        "format_request": lambda body: {k: v for k, v in body.items()
                                        if k not in ("enable_thinking", "top_p")
                                        and not (k == "temperature" and str(body.get("model", "")).startswith("claude-opus"))},
        "parse_response": lambda data: next(
            (c.get("text", "") for c in data.get("content", []) if c.get("type") == "text"),
            (data.get("content", [{}])[0].get("text", "") if data.get("content") else "")),
    },
    "nvidia": {
        "default_base": "https://integrate.api.nvidia.com",
        "chat_path": "/v1/chat/completions",
        "auth_header": "authorization",
        "auth_scheme": "Bearer",
        "extra_headers": {},
        "format_request": lambda body: {
            "model": body.get("model"),
            "messages": [{"role": "system", "content": body.get("system", "")}] + body.get("messages", []),
            "max_tokens": body.get("max_tokens", 2500),
            "temperature": body.get("temperature", 0.1),
            "top_p": body.get("top_p", 0.95),
            # Nemotron 3 is a reasoning model — enable_thinking surfaces its chain of thought
            # in reasoning_content, which we strip from the final text (see parse_response).
            **({"chat_template_kwargs": {"enable_thinking": True}}
               if body.get("enable_thinking", True) else {}),
        },
        "parse_response": _strip_reasoning,
    },
    "openai": {
        "default_base": "https://api.openai.com",
        "chat_path": "/v1/chat/completions",
        "auth_header": "authorization",
        "auth_scheme": "Bearer",
        "extra_headers": {},
        "format_request": lambda body: {
            "model": body.get("model"),
            "messages": [{"role": "system", "content": body.get("system", "")}] + body.get("messages", []),
            "max_tokens": body.get("max_tokens", 2500),
            "temperature": body.get("temperature", 0.1),
        },
        "parse_response": lambda data: data.get("choices", [{}])[0].get("message", {}).get("content", ""),
    },
}


def get_provider_config():
    """Resolve provider configuration from environment.

    NVIDIA Nemotron 3 Ultra is the default. HUNT_LLM_PROVIDER only overrides it when it
    names a provider we actually support on its own — a stale/foreign value like
    "groq,anthropic" left over from another tool no longer silently hijacks the default.
    """
    provider = "anthropic"   # operator policy: Anthropic (Opus 4.8 / Sonnet 4.6) is the default engine
    provider_env = os.environ.get("HUNT_LLM_PROVIDER", "").strip().lower()
    if provider_env:
        if provider_env in PROVIDERS:
            provider = provider_env
        else:
            # A comma-chain like "groq,anthropic" left over from another tool is not a single
            # provider we support. Rather than silently fall through, pick the first supported
            # provider named in the chain (so "groq,anthropic" -> anthropic); if none is
            # supported, keep the anthropic default. Either way the log names what we ACTUALLY use.
            picked = next((p for p in (x.strip() for x in provider_env.split(",")) if p in PROVIDERS), None)
            if picked:
                provider = picked
            print(f"[llm_client] HUNT_LLM_PROVIDER={provider_env!r} is not a single supported "
                  f"provider ({' | '.join(PROVIDERS)}); using {provider!r}.", file=sys.stderr)

    config = PROVIDERS[provider].copy()
    config["provider"] = provider
    config["base_url"] = os.environ.get("HUNT_LLM_BASE_URL", config["default_base"])
    config["model"] = os.environ.get("HUNT_LLM_MODEL", _default_model(provider))
    config["api_key"] = _key_for(provider)
    config["temperature"] = float(os.environ.get("HUNT_LLM_TEMPERATURE", "0.1"))
    config["top_p"] = float(os.environ.get("HUNT_LLM_TOP_P", "0.95"))
    config["enable_thinking"] = os.environ.get("HUNT_LLM_THINKING", "1") != "0"
    config["max_tokens"] = int(os.environ.get("HUNT_LLM_MAX_TOKENS", "2500"))
    return config


def _default_model(provider):
    """Default model per provider. IDs verified against the live catalogues."""
    defaults = {
        "anthropic": "claude-sonnet-4-6",
        # https://build.nvidia.com/models — Nemotron 3 family (real published IDs)
        "nvidia": "nvidia/nemotron-3-ultra-550b-a55b",
        "openai": "gpt-4o",
    }
    return defaults.get(provider, "claude-sonnet-4-6")


# Cheap/fast sibling of the flagship, same family — used for mechanical + high-volume work
NEMOTRON_CHEAP = "nvidia/nemotron-3.5-lightning-30b-a3b"
NEMOTRON_STRONG = "nvidia/nemotron-3-ultra-550b-a55b"


def _key_for(provider):
    """API key lookup, in order: explicit HUNT_LLM_API_KEY, then the provider's own var."""
    explicit = os.environ.get("HUNT_LLM_API_KEY", "").strip()
    if explicit:
        return explicit
    for var in {"nvidia": ("NVIDIA_API_KEY", "NGC_API_KEY"),
                "anthropic": ("ANTHROPIC_API_KEY",),
                "openai": ("OPENAI_API_KEY",)}.get(provider, ()):
        v = os.environ.get(var, "").strip()
        if v:
            return v
    return ""


def _claude_cli_call(system, user, model, timeout=180):
    """Run a completion through the `claude` CLI (-p) instead of the raw API.

    The Pro subscription OAuth token is 429-blocked when POSTed to /v1/messages by a third-party app, but
    the CLI is the SANCTIONED way to use the subscription — so this path works on a Pro account with no key
    and respects the normal session usage limits. HUNT_CLAUDE_CLI_DIR (or the dir of HUNT_CLAUDE_CREDS)
    selects which logged-in account to bill, so the engine can use a SEPARATE account from Claude Code.
    Returns (text, error)."""
    cli = shutil.which("claude") or os.path.expanduser("~/.local/bin/claude")
    if not os.path.exists(cli):
        return None, "claude CLI not found (install Claude Code or set PATH)"
    env = dict(os.environ)
    cdir = os.environ.get("HUNT_CLAUDE_CLI_DIR") or (
        os.path.dirname(os.environ["HUNT_CLAUDE_CREDS"]) if os.environ.get("HUNT_CLAUDE_CREDS") else "")
    if cdir:
        env["CLAUDE_CONFIG_DIR"] = os.path.expanduser(cdir)
    # a pure completion: our prompt only, no tool access, no inherited model override
    env.pop("ANTHROPIC_MODEL", None)
    cmd = [cli, "-p", user or "", "--model", model or "claude-sonnet-4-6"]
    if system:
        cmd += ["--append-system-prompt", system]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, "claude-cli timeout"
    except Exception as e:
        return None, "claude-cli error: " + str(e)[:200]
    out = (r.stdout or "").strip()
    # The CLI prints usage-limit / auth notices to STDOUT as plain prose (not an error exit), e.g.
    # "You've hit your session limit · resets 5:10pm". Detect these so callers get a real error instead
    # of trying to parse the notice as content (which silently produced garbage summaries).
    low = out.lower()
    if out and len(out) < 400 and any(k in low for k in (
            "hit your session limit", "hit your limit", "usage limit", "rate limit", "resets ",
            "please run /login", "/login", "invalid api key", "credit balance is too low",
            "out of credit", "quota")):
        return None, "claude-cli limit/auth: " + out[:160]
    if out:
        return out, None
    return None, "claude-cli empty (rc=%s): %s" % (r.returncode, (r.stderr or "")[:200])


def _cli_mode():
    return os.environ.get("HUNT_LLM_VIA_CLI") == "1"


def _claude_oauth_headers():
    """Return (extra_headers, bearer_token) from Claude Code login, or ({}, None)."""
    try:
        import importlib.util as _il
        _spec = _il.spec_from_file_location(
            "llm_auth",
            str(Path(__file__).resolve().parent / "llm_auth.py"),
        )
        _m = _il.module_from_spec(_spec)
        _spec.loader.exec_module(_m)
        h, mode = _m.llm_headers()
        if mode in ("api-key", "claude-account") and h:
            return h, mode
    except Exception:
        pass
    return {}, None


def call_llm(system, user, model=None, max_tokens=None, temperature=None,
              api_key=None, provider=None, base_url=None, timeout=120,
              top_p=None, enable_thinking=None):
    """
    Call the configured LLM provider (default: NVIDIA Nemotron 3 Ultra).
    Returns (text, error) where error is None on success.
    """
    # CLI backend (HUNT_LLM_VIA_CLI=1): run Anthropic completions through the `claude` CLI, which is the
    # sanctioned subscription path (the raw OAuth API key is 429-blocked). Used for a model that is Claude.
    if _cli_mode():
        _m = (model or "").strip()
        if not _m:
            _m = os.environ.get("HUNT_MODEL_MID") or "claude-sonnet-4-6"
        if _m.startswith("claude") or (provider or "").lower().strip() == "anthropic":
            return _claude_cli_call(system, user, _m if _m.startswith("claude") else "claude-sonnet-4-6",
                                    timeout=timeout)
    if provider:
        prov = provider.lower().strip()
        if prov not in PROVIDERS:
            return None, f"Unknown provider: {provider} (expected {' | '.join(PROVIDERS)})"
        config = PROVIDERS[prov].copy()
        config["provider"] = prov
        config["base_url"] = base_url or config["default_base"]
        config["model"] = model or _default_model(prov)
        config["max_tokens"] = int(os.environ.get("HUNT_LLM_MAX_TOKENS", "2500"))
        config["temperature"] = float(os.environ.get("HUNT_LLM_TEMPERATURE", "0.1"))
        config["top_p"] = float(os.environ.get("HUNT_LLM_TOP_P", "0.95"))
        config["enable_thinking"] = os.environ.get("HUNT_LLM_THINKING", "1") != "0"
        config["api_key"] = _key_for(prov)
    else:
        config = get_provider_config()

    # Override from args
    config["model"] = model or config["model"]
    config["max_tokens"] = max_tokens or config["max_tokens"]
    config["temperature"] = temperature if temperature is not None else config["temperature"]
    config["api_key"] = api_key or config["api_key"]
    if base_url:
        config["base_url"] = base_url
    
    # Anthropic fallback: use Claude Code OAuth when no API key is configured
    _oauth_override = {}
    if not config["api_key"] and config["provider"] == "anthropic":
        _oauth_hdrs, _oauth_mode = _claude_oauth_headers()
        if _oauth_mode == "claude-account":
            # Bearer auth — override the x-api-key scheme entirely
            config["api_key"] = "__oauth__"
            _oauth_override = _oauth_hdrs
        elif _oauth_mode == "api-key":
            # llm_auth resolved an API key we missed
            config["api_key"] = _oauth_hdrs.get("x-api-key", "")

    if not config["api_key"]:
        return None, f"No API key for {config['provider']} (set ANTHROPIC_API_KEY, or run 'claude login')"

    # Build request
    payload = {
        "model": config["model"],
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "max_tokens": config["max_tokens"],
        "temperature": config["temperature"],
        "top_p": top_p if top_p is not None else config.get("top_p", 0.95),
        "enable_thinking": (enable_thinking if enable_thinking is not None
                            else config.get("enable_thinking", True)),
    }
    payload = config["format_request"](payload)
    
    url = config["base_url"].rstrip("/") + config["chat_path"]
    
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
    }
    for k, v in config.get("extra_headers", {}).items():
        headers[k] = v
    
    if _oauth_override:
        # OAuth path: llm_auth already built the exact headers we need
        headers.update(_oauth_override)
    else:
        auth_header = config.get("auth_header", "authorization")
        auth_scheme = config.get("auth_scheme", "Bearer")
        headers[auth_header] = f"{auth_scheme} {config['api_key']}"
    
    # Make request
    body = json.dumps(payload).encode()
    req = Request(url, data=body, headers=headers, method="POST")

    handlers = [HTTPSHandler(context=ssl.create_default_context()), HTTPHandler()]
    opener = build_opener(*handlers)

    _slot = _llm_slot_acquire()  # cross-process LLM pool: bounds concurrent calls across all workers
    try:
        import time as _t
        last = None
        # Bounded retry so a TRANSIENT 429/5xx rides through (honors Retry-After, capped) instead of
        # dropping the call ("LLM did not respond"). A SUSTAINED limit still surfaces the 429 to the
        # caller, where hunt-run raises RateLimitPause (pause + resume) rather than sleep-burning budget.
        _RETRIES = int(os.environ.get("HUNT_LLM_RETRIES", "3"))
        for attempt in range(_RETRIES + 1):
            try:
                with opener.open(req, timeout=timeout) as r:
                    data = json.loads(r.read().decode("utf-8"))
                    return config["parse_response"](data), None
            except HTTPError as e:
                try: raw = e.read().decode("utf-8")
                except Exception: raw = ""
                last = f"HTTP {e.code}: {raw}"
                if e.code in (429, 500, 502, 503, 504, 529) and attempt < _RETRIES:
                    try: ra = int(e.headers.get("retry-after", 0))
                    except Exception: ra = 0
                    _t.sleep(min(ra if ra > 0 else 8 * (attempt + 1), 25))
                    continue
                return None, last
            except Exception as ex:
                last = f"{type(ex).__name__}: {ex}"
                if attempt < _RETRIES:
                    _t.sleep(min(6 * (attempt + 1), 20)); continue
                return None, last
        return None, last
    finally:
        _llm_slot_release(_slot)


def llm_available():
    """Check if any LLM provider is configured."""
    try:
        config = get_provider_config()
        return bool(config["api_key"])
    except Exception:
        return False


def llm_info():
    """Return info about the current LLM configuration."""
    config = get_provider_config()
    return {
        "provider": config["provider"],
        "model": config["model"],
        "base_url": config["base_url"],
        "has_key": bool(config["api_key"]),
    }


def _anthropic_auth_headers():
    """Resolve Anthropic auth headers: API key wins, then Claude Code OAuth."""
    key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if key:
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    h, mode = _claude_oauth_headers()
    if mode in ("api-key", "claude-account") and h:
        return h
    return {}


_API_SEMAPHORE = threading.Semaphore(1)  # only one concurrent Anthropic call per process


def _anthropic_raw_request(payload, timeout=120):
    """POST to api.anthropic.com/v1/messages, return (raw_data_dict, error_str).
    Returns retry_after (int seconds) as third element when 429."""
    # CLI mode: the raw OAuth key is 429-blocked, so run the SAME request through the `claude` CLI (the
    # sanctioned subscription path). Flatten system + the conversation into one prompt and return the
    # result shaped like an Anthropic /v1/messages response so every caller (call_claude, the summarizer,
    # the lead multi-turn loop) keeps working unchanged. This makes ALL Anthropic paths use the subscription.
    if _cli_mode():
        model = payload.get("model") or os.environ.get("HUNT_MODEL_MID") or "claude-sonnet-4-6"
        if not str(model).startswith("claude"):
            model = "claude-sonnet-4-6"
        system = payload.get("system") or ""
        parts = []
        for m in payload.get("messages", []):
            role = m.get("role", "user")
            content = m.get("content", "")
            if isinstance(content, list):   # content blocks → join their text
                content = "\n".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
            parts.append(f"[{role}] {content}")
        user = "\n\n".join(parts) if parts else ""
        txt, err = _claude_cli_call(system, user, model, timeout=timeout)
        if err:
            return None, err, 0
        return {"content": [{"type": "text", "text": txt}], "stop_reason": "end_turn",
                "role": "assistant", "model": model}, None, 0
    auth = _anthropic_auth_headers()
    if not auth:
        return None, "No Anthropic credential (set ANTHROPIC_API_KEY or run 'claude login')", 0
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
    }
    headers.update(auth)
    body = json.dumps(payload).encode()
    req = Request("https://api.anthropic.com/v1/messages", data=body, headers=headers, method="POST")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), HTTPHandler())
    try:
        with opener.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8")), None, 0
    except HTTPError as e:
        retry_after = 0
        try:
            retry_after = int(e.headers.get("retry-after", 0))
        except Exception:
            pass
        try:
            raw = e.read().decode("utf-8")
        except Exception:
            raw = ""
        return None, f"HTTP {e.code}: {raw}", retry_after
    except Exception as ex:
        return None, f"{type(ex).__name__}: {ex}", 0


def summarize_if_large(text, threshold=3500, label="tool output"):
    """Improvement #6 — Haiku pass on large tool outputs before feeding to Sonnet.

    Spends ~$0.002 of Haiku to compress 12K tokens of raw scanner/bash output
    down to ~800 tokens of signal. Net saving: ~11K Sonnet tokens per large call.
    Falls back to hard truncation when Haiku is unavailable."""
    if not text or len(text) <= threshold:
        return text
    _sys = ("You are a security tool output parser. Extract ONLY security-relevant signal: credentials, "
            "endpoints, vulnerability indicators, error messages, interesting headers, and anomalies. "
            "Drop noise. Be concise. Plain text only.")
    _usr = f"Summarize this {label} ({len(text)} chars) — keep only security-relevant findings:\n\n" + text[:16000]
    # CLI mode: run the summarizer through the sanctioned `claude` CLI (subscription), not the raw API.
    if _cli_mode():
        s, e = _claude_cli_call(_sys, _usr, "claude-sonnet-4-6", timeout=60)
        if s and not e:
            return f"[summarized from {len(text)} chars]\n{s}"
        return text[:threshold] + f"\n…[truncated: {len(text)} chars total]"
    auth = _anthropic_auth_headers()
    if not auth:
        return text[:threshold] + f"\n…[truncated: {len(text)} chars total]"
    payload = {
        "model": "claude-sonnet-4-6",
        "system": _sys,
        "messages": [{"role": "user", "content": _usr}],
        "max_tokens": 900,
        "temperature": 0.0,
    }
    headers = {"content-type": "application/json", "accept": "application/json"}
    headers.update(auth)
    body = json.dumps(payload).encode()
    req = Request("https://api.anthropic.com/v1/messages", data=body, headers=headers, method="POST")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), HTTPHandler())
    try:
        with opener.open(req, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8"))
            content = data.get("content", [])
            summary = "\n".join(b.get("text","") for b in content if b.get("type")=="text").strip()
            if summary:
                return f"[Haiku-summarized from {len(text)} chars]\n{summary}"
    except Exception:
        pass
    return text[:threshold] + f"\n…[truncated: {len(text)} chars total]"


def call_llm_with_tools(system, initial_user, tools, tool_executor,
                        model=None, max_tokens=4096, timeout=120,
                        on_tool_call=None, max_tool_rounds=200):
    """
    Multi-turn Anthropic tool-use conversation via OAuth or API key.

    Claude gets real tools (bash, http_request, record_finding, etc.) and calls them
    in a real feedback loop — same architecture as Claude Code itself. Each tool_use
    block is executed by tool_executor(name, input) -> str, the raw result is fed back,
    and Claude continues until it either stops calling tools or calls the 'done' tool.

    Args:
        system:         system prompt
        initial_user:   first user message (the hunt digest)
        tools:          list of Anthropic tool definition dicts
        tool_executor:  callable(name: str, input: dict) -> str
        model:          model id (default: claude-sonnet-4-6)
        max_tokens:     per-turn token budget
        timeout:        HTTP timeout per request
        on_tool_call:   optional callback(name, input, result) for logging
        max_tool_rounds: hard cap on tool-call rounds to prevent infinite loops

    Returns:
        (final_text, tool_calls_log, error)
        tool_calls_log: list of {name, input_summary, result_summary}
    """
    # CLI mode: `claude -p` cannot drive the engine's custom tool definitions + scope-guarded executor
    # (native function-calling over the raw API). Signal the caller to use its JSON-action fallback loop,
    # which issues one decision at a time through call_llm (→ CLI). So tool-use still runs on the subscription.
    if _cli_mode():
        return None, [], "cli-mode: native tool-use unavailable — use JSON-action loop"
    mdl = model or "claude-sonnet-4-6"
    messages = [{"role": "user", "content": initial_user}]
    tool_calls_log = []
    done_signal = False

    for _round in range(max_tool_rounds):
        payload = {
            "model": mdl,
            "system": system,
            "messages": messages,
            "tools": tools,
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }

        # retry transient 5xx / 429 up to 6 times with backoff; semaphore prevents
        # concurrent agents from piling up simultaneous OAuth calls
        import time as _time
        data, err = None, None
        with _API_SEMAPHORE:
            for attempt in range(6):
                data, err, retry_after = _anthropic_raw_request(payload, timeout)
                if data:
                    break
                if err and ("429" in err or "529" in err):
                    wait = retry_after if retry_after > 0 else min(120, 15 * (attempt + 1))
                    _time.sleep(wait)
                elif err and re.search(r"\b5\d\d\b", err or ""):
                    _time.sleep(3.5 * (2 ** attempt))
                else:
                    break

        if err and not data:
            return None, tool_calls_log, err

        stop_reason = data.get("stop_reason", "end_turn")
        content = data.get("content", [])

        # collect text blocks
        text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
        final_text = "\n".join(p for p in text_parts if p).strip()

        if stop_reason == "end_turn":
            return final_text, tool_calls_log, None

        if stop_reason != "tool_use":
            # max_tokens hit or unexpected stop
            return final_text, tool_calls_log, f"stop_reason={stop_reason}"

        # --- execute tool calls (parallel when multiple arrive) ---
        tool_use_blocks = [b for b in content if b.get("type") == "tool_use"]

        def _run_one(block):
            tid  = block["id"]
            name = block["name"]
            inp  = block.get("input", {})
            result = tool_executor(name, inp)
            result_str = str(result)
            # improvement #6: summarize large outputs before they hit Sonnet's context
            if len(result_str) > 3500 and name != "done":
                result_str = summarize_if_large(result_str, threshold=3500, label=name)
            result_str = result_str[:12000]
            return tid, name, inp, result_str

        tool_results = []
        if len(tool_use_blocks) > 1:
            # improvement #1: parallel tool execution
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(len(tool_use_blocks), 6)
            ) as pool:
                futures = [pool.submit(_run_one, b) for b in tool_use_blocks]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
        else:
            results = [_run_one(b) for b in tool_use_blocks]

        for tid, name, inp, result_str in results:
            tool_calls_log.append({
                "name": name,
                "input_summary": str(inp)[:300],
                "result_summary": result_str[:300],
            })
            if on_tool_call:
                on_tool_call(name, inp, result_str)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tid,
                "content": result_str,
            })
            if name == "done" or result_str == "__DONE__":
                done_signal = True

        # advance conversation
        messages.append({"role": "assistant", "content": content})
        messages.append({"role": "user",      "content": tool_results})

        if done_signal:
            return final_text, tool_calls_log, None

    return None, tool_calls_log, f"max_tool_rounds ({max_tool_rounds}) reached"


if __name__ == "__main__":
    # Quick test
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        info = llm_info()
        print(f"Provider: {info['provider']}")
        print(f"Model: {info['model']}")
        print(f"Base URL: {info['base_url']}")
        print(f"Has API Key: {info['has_key']}")
        if info['has_key']:
            text, err = call_llm("You are a helpful assistant.", "Say hello in one word.")
            print(f"Response: {text}")
            print(f"Error: {err}")