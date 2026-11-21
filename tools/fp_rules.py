#!/usr/bin/env python3
"""
fp_rules.py — deterministic false-positive guards shared by the engine (add_finding) and the
rigorous judge (verify-one). These encode hard, non-LLM truths so the most common noise never
reaches 'high' severity, regardless of what a scanner or model claims.

Durable guarantee: a finding whose evidence is ONLY public-by-design identifiers (and contains
no real secret) is forced to info. A real secret pattern present → never downgraded.
"""
import re

# Real secrets — if ANY of these appear, the finding is NOT public-by-design (do not downgrade).
SECRET_PATTERNS = [
    r"\bsk_live_[0-9a-zA-Z]{10,}", r"\bsk_test_[0-9a-zA-Z]{10,}",   # Stripe secret
    r"\brk_live_[0-9a-zA-Z]{10,}",                                   # Stripe restricted
    r"\bAKIA[0-9A-Z]{16}\b",                                         # AWS access key id
    r"aws_secret_access_key", r"\bASIA[0-9A-Z]{16}\b",
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",       # private keys
    r"\bgh[pousr]_[0-9A-Za-z]{30,}",                                 # GitHub tokens
    r"\bxox[baprs]-[0-9A-Za-z-]{10,}",                               # Slack tokens
    r"\bSK[0-9a-f]{32}\b",                                           # Twilio
    r"\bAIza[0-9A-Za-z_\-]{35}\b(?=.*(?:server|unrestricted))",      # Google key flagged server-side
    r"client_secret\s*[=:]\s*['\"]?[0-9a-zA-Z\-_]{16,}",            # OAuth client secret
    r"\b[A-Za-z0-9_]*(?:private|secret)_key\s*[=:]\s*['\"]?[0-9a-zA-Z\-_]{12,}",
    r"\bbearer\s+ey[JA-Za-z0-9._\-]{20,}",                           # a real bearer JWT in evidence
    r"password\s*[=:]\s*['\"][^'\"]{6,}",
]

# Public-by-design identifiers — shipped to every browser, grant no privileged action.
PUBLIC_PATTERNS = [
    (r"\bNEXT_PUBLIC_[A-Z0-9_]+", "NEXT_PUBLIC_* is a Next.js public env var, shipped to the client by design"),
    (r"\b6L[0-9A-Za-z_\-]{38}\b", "reCAPTCHA SITE key is public by design (the secret key stays server-side)"),
    (r"\bpk_live_[0-9a-zA-Z]{10,}", "Stripe PUBLISHABLE key (pk_) is designed to be public"),
    (r"\bpk_test_[0-9a-zA-Z]{10,}", "Stripe test publishable key is public by design"),
    (r"sentry[-_]?public[-_]?key|@o\d+\.ingest\.sentry\.io|https://[0-9a-f]{32}@", "Sentry public DSN can only SUBMIT events, never read them — public by design"),
    (r"mixpanel[-_]?project[-_]?token|MIXPANEL_PROJECT_TOKEN", "Mixpanel PROJECT token is a public client identifier"),
    (r"wallet[-_]?connect[-_]?project[-_]?id|WALLET_CONNECT_PROJECT_ID", "WalletConnect PROJECT id is a public client identifier"),
    (r"\bUA-\d{4,}-\d+\b|\bG-[A-Z0-9]{8,}\b|\bGTM-[A-Z0-9]{5,}\b", "Google Analytics / GTM id is public by design"),
    (r"intercom[-_]?app[-_]?id|\bapp_id['\"]?\s*[:=]\s*['\"][a-z0-9]{8}['\"]", "Intercom app id is public by design"),
    (r"\bphc_[0-9A-Za-z]{30,}", "PostHog project API key is a public client key"),
    (r"segment[-_]?write[-_]?key", "Segment write key is a public client key"),
    (r"algolia.*application[-_]?id|\bNEXT_PUBLIC_ALGOLIA", "Algolia application id + search key are public by design"),
]


def secret_present(text):
    t = text or ""
    return any(re.search(p, t, re.I) for p in SECRET_PATTERNS)


def public_by_design(text):
    """Return a reason string if the evidence is public-by-design (and holds no real secret),
    else ''. Used to force such findings to info."""
    t = text or ""
    if secret_present(t):
        return ""
    for pat, reason in PUBLIC_PATTERNS:
        if re.search(pat, t, re.I):
            return reason
    return ""


# Classes that are only real with a live-confirmed response — a text claim is never enough.
NEEDS_LIVE = {"redirect", "open-redirect", "cors", "xss", "ssti", "sqli", "lfi", "ssrf"}


def should_downgrade(title, detail, cls=""):
    """Returns (downgrade: bool, reason: str). True → force severity to info."""
    blob = (title or "") + " " + (detail or "")
    reason = public_by_design(blob)
    if reason:
        return True, reason
    return False, ""
