#!/usr/bin/env python3
"""
scope_ingest — the single, deterministic-first entry that turns any paste (a host,
a URL list, or a whole HackerOne/YesWeHack program page) into ONE canonical scope
object the whole engine reads.

Why this exists: the old flow had two incompatible paths from the same box —
"Confirm & summarize" ran an LLM-only parse, while "Start hunt" on a raw page fed
the entire page to hunt-run.py --target, which whitespace-split it into hundreds of
junk "assets" (every word on the page). This module makes extraction deterministic
and reliable FIRST (hosts/URLs/CIDRs/repos, in-scope vs out-of-scope split, type
classification), then LETS the LLM enrich only the unstructured bits
(rewards/rules/caps/policy) — and only when credentials exist. The asset list never
depends on the model being up.

Pipeline:
  1. detect_shape   host | url_list | program_page         (pure regex)
  2. extract        assets + in/out-of-scope split          (deterministic, always)
  3. enrich         rewards/rules/focus/… via LLM           (optional, grounded)
  4. canonicalize   dedup, normalize, classify, allow/deny  (deterministic)
  5. persist        scope.allow / scope.deny / program.json (single source of truth)

CLI:  scope_ingest.py [--json] [--no-enrich] [--persist <hunt_dir>]   (text on stdin or --text)
Importable:  detect_shape, extract_assets, classify, canonicalize, ingest, persist
"""
import sys
import os
import re
import json
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# ── regexes (strict enough that prose words like "Rewards"/"Critical"/"$500" never match) ──
REPO_RE = re.compile(r'(?:https?://)?(?:github\.com|gitlab\.com|bitbucket\.org)/[\w.-]+/[\w.-]+', re.I)
MOBILE_RE = re.compile(r'(?:https?://)?(?:play\.google\.com|apps\.apple\.com|itunes\.apple\.com)/\S+'
                       r'|\b[\w.-]+\.(?:apk|ipa)\b', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')
# host: optional scheme, optional *., 1+ labels, a 2+ alpha TLD, optional :port and /path
HOST_RE = re.compile(
    r'(?:https?://)?(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'
    r'(?::\d+)?(?:/[^\s,)\]}"\'<>]*)?', re.I)

OUT_HEADINGS = re.compile(r'out[\s_-]*of[\s_-]*scope|not[\s]+in[\s]+scope|excluded|ineligible|'
                          r'out[\s]+of[\s]+bounds', re.I)
SCOPE_KW = ("in scope", "out of scope", "out-of-scope", "rewards", "eligible",
            "excluded", "bounty", "severity", "reward", "hall of fame", "swag")


def _strip(asset):
    """Normalize an asset: drop scheme, lowercase host, strip trailing slash/port on bare hosts."""
    a = asset.strip().strip(".,;")
    a = re.sub(r'^https?://', '', a, flags=re.I)
    a = a.rstrip('/')
    return a.lower()


def extract_raw(text):
    """All asset-like tokens, in order, deduped, each tagged with a rough kind."""
    found = []
    seen = set()

    def add(tok, kind):
        n = _strip(tok)
        if n and n not in seen:
            seen.add(n)
            found.append((n, kind))

    for m in REPO_RE.finditer(text):
        add(m.group(0), "source")
    for m in MOBILE_RE.finditer(text):
        add(m.group(0), "mobile")
    for m in IP_RE.finditer(text):
        add(m.group(0), "ip")
    for m in HOST_RE.finditer(text):
        tok = m.group(0)
        # don't double-count repo/mobile hosts already captured
        if _strip(tok) in seen:
            continue
        add(tok, "host")
    return found


def classify(asset, kind="host"):
    """web | api | mobile | source | other."""
    a = asset.lower()
    if kind == "source" or REPO_RE.search(asset):
        return "source"
    if kind == "mobile" or MOBILE_RE.search(asset):
        return "mobile"
    if kind == "ip" or IP_RE.fullmatch(asset.split("/")[0] + ("/" + asset.split("/")[1] if "/" in asset else "")):
        return "other"
    host = a.split("/")[0]
    if host.startswith("api.") or ".api." in host or "/api" in a or host.startswith("graphql") or "/graphql" in a:
        return "api"
    return "web"


def detect_shape(text):
    t = text.strip()
    words = t.split()
    assets = extract_raw(t)
    low = t.lower()
    if any(k in low for k in SCOPE_KW) or len(words) > 40:
        return "program_page"
    if len(words) <= 6 and assets:
        return "hosts"
    if assets and len(assets) >= max(1, len([l for l in t.splitlines() if l.strip()]) - 1):
        return "url_list"
    return "program_page" if len(words) > 12 else "hosts"


def extract_assets(text):
    """Deterministic in-scope / out-of-scope split. Returns (in_scope, out_of_scope)
    where each item is {"asset","type"}."""
    m = OUT_HEADINGS.search(text)
    in_text, out_text = (text[:m.start()], text[m.start():]) if m else (text, "")
    in_assets = [{"asset": a, "type": classify(a, k)} for a, k in extract_raw(in_text)]
    out_assets = [{"asset": a, "type": classify(a, k)} for a, k in extract_raw(out_text)]
    # an asset listed as out-of-scope must not also appear in-scope
    out_set = {o["asset"] for o in out_assets}
    in_assets = [a for a in in_assets if a["asset"] not in out_set]
    return in_assets, out_assets


def canonicalize(in_assets, out_assets):
    """Dedup + build allow/deny pattern lists + the hunt target list (web+api only)."""
    seen = set()
    in_clean = []
    for a in in_assets:
        if a["asset"] not in seen:
            seen.add(a["asset"])
            in_clean.append(a)
    allow = [a["asset"] for a in in_clean]
    deny = sorted({o["asset"] for o in out_assets})
    targets = [a["asset"] for a in in_clean if a["type"] in ("web", "api")]
    return in_clean, allow, deny, targets


def source_hash(text):
    return hashlib.sha1(text.strip().encode("utf-8", "ignore")).hexdigest()[:16]


def _enrich(text, base):
    """LLM enrichment of the unstructured fields — only if creds exist. Augments
    base (never replaces the deterministic asset list). Degrades silently."""
    try:
        import llm_auth
        _, mode = llm_auth.llm_headers()
        if not mode:
            return base, False
    except Exception:
        return base, False
    try:
        import llm_client
        model = os.environ.get("HUNT_MODEL_INTAKE", "claude-haiku-5-5")
        system = ("Extract bug-bounty program metadata as strict JSON with keys: "
                  "program, platform, summary, rewards, severity_rewards (list of {severity,amount}), "
                  "rules (list), focus (list), ua_required, rate_limit, poc_required (bool), ai_policy. "
                  "Only metadata — do NOT invent scope assets. Return JSON only.")
        txt, err = llm_client.call_llm(system, text[:12000], model=model, max_tokens=1200, timeout=90)
        if err or not txt:
            return base, False
        t = re.sub(r"^\s*```(?:json)?|```\s*$", "", txt.strip(), flags=re.I | re.M).strip()
        m = re.search(r"\{.*\}", t, re.S)
        meta = json.loads(m.group(0) if m else t)
        for k in ("program", "platform", "summary", "rewards", "severity_rewards",
                  "rules", "focus", "ua_required", "rate_limit", "poc_required", "ai_policy"):
            if meta.get(k) not in (None, "", [], {}):
                base[k] = meta[k]
        base["model"] = model
        return base, True
    except Exception:
        return base, False


def ingest(text, enrich=True):
    """Text → canonical scope object. Deterministic asset list always; LLM metadata optional."""
    shape = detect_shape(text)
    in_assets, out_assets = extract_assets(text)
    in_clean, allow, deny, targets = canonicalize(in_assets, out_assets)
    scope = {
        "shape": shape,
        "program": "", "platform": "", "summary": "",
        "in_scope": in_clean, "out_of_scope": out_assets,
        "allow": allow, "deny": deny, "targets": targets,
        "rewards": "", "severity_rewards": [], "rules": [], "focus": [],
        "ua_required": "", "rate_limit": "", "poc_required": False, "ai_policy": "",
        "source_hash": source_hash(text), "enriched": False, "model": "deterministic",
    }
    if enrich and targets:
        scope, did = _enrich(text, scope)
        scope["enriched"] = did
    return scope


def persist(scope, hunt_dir):
    """Write the canonical scope as the single source of truth for the hunt."""
    hd = Path(hunt_dir)
    hd.mkdir(parents=True, exist_ok=True)
    if scope.get("allow"):
        (hd / "scope.allow").write_text("\n".join(scope["allow"]) + "\n")
    if scope.get("deny"):
        (hd / "scope.deny").write_text("\n".join(scope["deny"]) + "\n")
    (hd / "program.json").write_text(json.dumps(scope, indent=2))
    return hd


def _arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def main():
    text = _arg("--text") or (sys.stdin.read() if not sys.stdin.isatty() else "")
    if not text.strip():
        print(json.dumps({"error": "no text", "in_scope": [], "out_of_scope": []}))
        return
    scope = ingest(text, enrich="--no-enrich" not in sys.argv)
    if "--persist" in sys.argv:
        persist(scope, _arg("--persist"))
    print(json.dumps(scope))


if __name__ == "__main__":
    main()
