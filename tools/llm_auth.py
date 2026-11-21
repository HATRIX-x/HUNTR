#!/usr/bin/env python3
"""
llm_auth.py — one place the HUNTR engine resolves how to authenticate to the
Claude API. Import this from any tool that calls https://api.anthropic.com.

Resolution order (first match wins):
  1. ANTHROPIC_API_KEY  -> sent as `x-api-key` (production / each user's own key)
  2. Linked Claude account OAuth (~/.claude/.credentials.json, written by
     Claude Code login) -> sent as `Authorization: Bearer` + the oauth beta
     header. LOCAL TESTING ONLY — a Claude subscription is not licensed to power
     a product's automated calls; ship with API keys.

Usage:
    from llm_auth import llm_headers
    headers, mode = llm_headers()          # mode: "api-key" | "claude-account"
    headers["content-type"] = "application/json"
    # ... urllib.request.Request(URL, data=payload, headers=headers)

`mode` is None and headers is {} when no credential is available — callers
should surface a clear "connect your Claude account or set ANTHROPIC_API_KEY"
message instead of sending an unauthenticated request.
"""
import os
import json
import time

API_VERSION = "2023-06-01"
OAUTH_BETA = "oauth-2025-04-20"
# The engine can hunt on a SEPARATE Claude account from the one Claude Code is logged into, so their
# subscription quotas do not collide: set HUNT_CLAUDE_CREDS to a second account's credentials.json
# (preferred — carries expiry), or HUNT_CLAUDE_OAUTH_TOKEN to a raw accessToken (quick, no refresh).
CREDS_PATH = os.path.expanduser(os.environ.get("HUNT_CLAUDE_CREDS") or "~/.claude/.credentials.json")
# skew: treat a token expiring within 2 min as already expired
EXPIRY_SKEW_MS = 120_000


def _read_oauth():
    """Return (access_token, expires_at_ms). A raw token override wins, then HUNT_CLAUDE_CREDS / default."""
    raw = (os.environ.get("HUNT_CLAUDE_OAUTH_TOKEN") or "").strip()
    if raw:
        return raw, int(time.time() * 1000) + 6 * 3600 * 1000   # assume ~6h validity for a pasted token
    path = os.path.expanduser(os.environ.get("HUNT_CLAUDE_CREDS") or "~/.claude/.credentials.json")
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None, 0
    o = d.get("claudeAiOauth") or {}
    tok = o.get("accessToken")
    exp = o.get("expiresAt") or 0
    if not tok:
        return None, 0
    return tok, exp


def account_status():
    """Lightweight status for a UI/endpoint. Never returns the token itself."""
    tok, exp = _read_oauth()
    if not tok:
        return {"linked": False}
    now = time.time() * 1000
    try:
        with open(CREDS_PATH) as f:
            o = (json.load(f).get("claudeAiOauth") or {})
    except (OSError, ValueError):
        o = {}
    return {
        "linked": True,
        "valid": exp - EXPIRY_SKEW_MS > now,
        "expires_at": exp,
        "subscription": o.get("subscriptionType") or "",
        "tier": o.get("rateLimitTier") or "",
    }


def llm_headers():
    """Resolve auth headers. Returns (headers_dict, mode)."""
    key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if key:
        return {"x-api-key": key, "anthropic-version": API_VERSION}, "api-key"

    tok, exp = _read_oauth()
    if tok:
        now = time.time() * 1000
        if exp - EXPIRY_SKEW_MS > now:
            return ({
                "authorization": "Bearer " + tok,
                "anthropic-version": API_VERSION,
                "anthropic-beta": OAUTH_BETA,
            }, "claude-account")
        # token present but stale — Claude Code refreshes it while running.
        return {}, "expired"

    return {}, None


if __name__ == "__main__":
    # self-check: print resolution + status (no secrets)
    h, mode = llm_headers()
    print("mode:", mode)
    print("has_auth_header:", bool(h))
    print("status:", json.dumps(account_status()))
