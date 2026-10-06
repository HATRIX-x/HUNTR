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
from pathlib import Path
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError

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
        "format_request": lambda body: body,  # Anthropic native format
        "parse_response": lambda data: data.get("content", [{}])[0].get("text", ""),
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
    provider = "nvidia"
    provider_env = os.environ.get("HUNT_LLM_PROVIDER", "").strip().lower()
    if provider_env:
        if provider_env in PROVIDERS:
            provider = provider_env
        else:
            # Legacy comma-chains (e.g. "groq,anthropic") left over from other tools used to
            # silently hijack the default. Nemotron 3 Ultra is the intended engine, so a chain
            # is ignored — set HUNT_LLM_PROVIDER to a single provider to switch away from it.
            print(f"[llm_client] ignoring HUNT_LLM_PROVIDER={provider_env!r} (expected a single "
                  f"provider: {' | '.join(PROVIDERS)}). Using nvidia / Nemotron 3 Ultra.",
                  file=sys.stderr)

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
    return defaults.get(provider, "nvidia/nemotron-3-ultra-550b-a55b")


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
    
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read()
            data = json.loads(raw.decode("utf-8"))
            text = config["parse_response"](data)
            return text, None
    except HTTPError as e:
        try:
            raw = e.read().decode("utf-8")
        except Exception:
            raw = ""
        return None, f"HTTP {e.code}: {raw}"
    except Exception as ex:
        return None, f"{type(ex).__name__}: {ex}"


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