#!/usr/bin/env python3
"""
scope_audit — read-only, post-hoc scope visibility. NOT a gate.

Scope enforcement in the full-agentic rewrite is pure agent judgment, inlined into every phase
brief — there is no technical enforcement behind it. This module keeps only the pure glob-matching
functions scope-guard.py used to gate requests with, stripped of all blocking/subprocess code, so a
phase can log (never block, delay, or modify) which hosts it touched and flag anything outside
scope.allow/scope.deny for the operator to see on the live dashboard.
"""
import fnmatch
import urllib.parse
from pathlib import Path


def load_patterns(p: Path):
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


def host_of(url):
    if "://" not in url:
        url = "http://" + url
    return (urllib.parse.urlparse(url).hostname or "").lower()


def host_variants(url):
    """Every spelling of a host we may see in the allowlist (bare host and host:port)."""
    if "://" not in url:
        url = "http://" + url
    p = urllib.parse.urlparse(url)
    h = (p.hostname or "").lower()
    out = [h] if h else []
    try:
        if p.port:
            out.append("%s:%d" % (h, p.port))
    except ValueError:
        pass
    return [v for v in out if v]


def _specificity(pattern):
    """(tier, -length): an exact literal pattern is tier 0 (always more specific than a wildcard,
    tier 1); within a tier, a longer pattern is more specific. Smaller tuple = more specific."""
    return (0 if "*" not in pattern else 1, -len(pattern))


def in_scope(host, variants=None, allow_path: Path = None, deny_path: Path = None):
    """Audit-only scope check: most-specific matching pattern wins regardless of which list it's
    in (ties go to deny). Returns (bool, reason) — informational only, never used to block."""
    if not host:
        return False, "no host parsed from URL"
    allow = load_patterns(allow_path) if allow_path else []
    deny = load_patterns(deny_path) if deny_path else []
    if not allow:
        return False, "no allowlist configured"
    names = [host] + [v for v in (variants or []) if v != host]
    best = None  # (specificity, is_allow, pattern)
    for d in deny:
        for n in names:
            if n == d or fnmatch.fnmatch(n, d):
                cand = (_specificity(d), False, d)
                if best is None or cand[0] < best[0]:
                    best = cand
    for a in allow:
        for n in names:
            if n == a or fnmatch.fnmatch(n, a):
                cand = (_specificity(a), True, a)
                if best is None or cand[0] < best[0]:
                    best = cand
    if best is None:
        return False, "host not in allowlist"
    _, is_allow, pat = best
    if is_allow:
        return True, f"matches allow '{pat}'"
    return False, f"host matches DENY pattern '{pat}'"
