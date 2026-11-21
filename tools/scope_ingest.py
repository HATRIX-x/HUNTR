#!/usr/bin/env python3
"""
scope_ingest — the single, deterministic-first entry that turns any paste (a host,
a URL list, or a whole HackerOne/YesWeHack program page) into ONE canonical scope
object the whole engine reads.

Why this exists: the old flow had two incompatible paths from the same box —
"Confirm & summarize" ran an LLM-only parse, while "Start hunt" on a raw page fed
the entire page to hunt-run.py --target, which whitespace-split it into hundreds of
junk "assets" (every word on the page). This module makes extraction deterministic
and reliable FIRST (hosts/URLs/CIDRs/repos found by regex — this NEVER depends on
the model being up), then hands classification (which of those hosts are actually
IN scope) to Haiku 5.5 when available.

Why classification needs the model, not just regex: the naive fallback below
(extract_assets / OUT_HEADINGS) splits in/out at the FIRST "out of scope"-ish
keyword anywhere on the page. Real program pages routinely put an "out of scope"
summary/exclusions blurb, or a "known findings" table, BEFORE the real Assets/Scope
table — on Exodus's H1 page the real Assets table (*.exodus.io, Wildcard/High/
Eligible) sits ~10k chars after that first keyword, so the naive split dumped the
explicit, eligible wildcard asset into DENY along with everything else (0 in-scope,
15 out — see tests/test_scope_ingest.py::ScopeIngestLLM for the regression). A
position-based heuristic cannot fix this; it requires reading what the page says
ABOUT each specific asset. See [[scope-classifier-haiku]] memory.

Pipeline:
  1. detect_shape   host | url_list | program_page             (pure regex)
  2. extract        candidate assets (deterministic, always) + a DETERMINISTIC
                     in/out/ split as the offline fallback floor
  3. classify        Haiku 5.5 judges each candidate in/out/ambiguous from the FULL
                     page context (only when creds exist; replaces step 2's split
                     wholesale on success, never on failure) — grounded to the
                     candidate list, never invents an asset. Unsure → "ambiguous",
                     denied by default until a human confirms (never silently "in").
  4. enrich         rewards/rules/focus/… via LLM               (optional, grounded)
  5. canonicalize   dedup, normalize, classify, allow/deny      (deterministic)
  6. persist        scope.allow / scope.deny / program.json     (single source of truth)

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


_OPEN_SCOPE_RE = re.compile(
    r"open[\s-]*scope\s*(?:policy|:)|even if not (?:listed|in scope)|any[\w.\s-]{2,40}-owned (?:asset|domain)",
    re.I)


def _root_domain(host):
    """Last two dot-labels of a host — a cheap eTLD+1-ish root, good enough to widen an
    explicit in-scope asset into an Open-Scope wildcard (see _open_scope_wildcards)."""
    parts = host.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _open_scope_wildcards(text_fields, in_clean):
    """Caught live (2026-10-21): a hunt on Databricks's HackerOne program recorded real,
    'confirmed' findings against www.databricks.com/login.databricks.com/microsites.databricks.com
    — none literally in scope.allow, because none of those exact subdomains appeared as a token
    anywhere on the program PAGE (they were only discovered live, by crawling, mid-hunt). But the
    program's own text says "an Open Scope policy for all Databricks-owned assets" / "Open Scope:
    any Databricks-owned asset, even if not listed in scope" — by definition an open-ended policy
    like that can never be captured as a finite list of literal hosts; per-candidate classification
    (classify()/_classify_scope_llm) only ever judges tokens that already appear on the page, so it
    structurally cannot cover a host discovered later that was never mentioned by name.
    Detect that policy phrasing (regex, so this works with or without LLM enrichment — it also
    checks the raw program text, not just the enriched summary/focus) and derive a '*.<root>'
    wildcard per distinct root domain already seen among the EXPLICIT in-scope web/api assets, so a
    newly-discovered subdomain sharing that root is allowed too. This never widens past an existing
    explicit DENY: scope-guard.py's in_scope() checks deny before allow, so a narrower exclusion
    like '*.cloud.databricks.com' (Ineligible wildcard) still wins over the broader Open-Scope one
    even though they share the same root domain."""
    text = " ".join(str(f) for f in text_fields if f)
    if not _OPEN_SCOPE_RE.search(text):
        return []
    roots = sorted({_root_domain(a["asset"].split("/")[0]) for a in in_clean
                    if a.get("type") in ("web", "api") and "." in a["asset"]})
    return [f"*.{r}" for r in roots]


def canonicalize(in_assets, out_assets, ambiguous=None):
    """Dedup + build allow/deny pattern lists + the hunt target list (web+api only).
    `ambiguous` (classifier couldn't tell in vs out from the page text) is defensively
    DENIED — never auto-hunted — until a human confirms it; shown separately in the UI
    rather than silently dropped into either bucket."""
    ambiguous = ambiguous or []
    seen = set()
    in_clean = []
    for a in in_assets:
        if a["asset"] not in seen:
            seen.add(a["asset"])
            in_clean.append(a)
    allow = [a["asset"] for a in in_clean]
    deny = sorted({o["asset"] for o in out_assets} | {a["asset"] for a in ambiguous})
    targets = [a["asset"] for a in in_clean if a["type"] in ("web", "api")]
    return in_clean, allow, deny, targets


CLASSIFY_SYS = (
    "You are a meticulous bug-bounty scope auditor. You are given the FULL program page text and a "
    "list of CANDIDATE assets already extracted from it (hosts/domains/repos/mobile apps/package "
    "names). For EACH candidate decide:\n"
    "  in         — explicitly declared IN SCOPE: appears in an actual Scope/Assets/'In Scope' "
    "section or table, typically with an eligibility/severity/reward marker (Wildcard, Eligible, "
    "High/Critical, a bounty amount). A wildcard like '*.company.com' covers its subdomains.\n"
    "  out        — the page explicitly excludes it: 'DO NOT test', a stated host/feature ban, an "
    "explicit out-of-scope/excluded list entry, or it is clearly a 3rd-party/cookie/analytics/"
    "leaderboard/unrelated-company domain, not the program owner's own asset.\n"
    "  ambiguous  — you cannot tell from the text alone: e.g. it is mentioned ONLY in a 'known "
    "findings' / 'already reported' table mapping Asset -> one specific finding class (that is NOT "
    "a full exclusion — see rule 2), or it is a different root domain never listed in the actual "
    "assets table, or scope status genuinely isn't stated.\n"
    "CRITICAL RULES — this gates real network requests against someone else's production "
    "infrastructure; a wrong verdict has real consequences:\n"
    "1. A keyword like 'out of scope' appearing elsewhere on the page (a summary blurb, an unrelated "
    "exclusions list) is NOT evidence about a DIFFERENT asset. Judge each candidate ONLY by what the "
    "page says ABOUT THAT SPECIFIC ASSET — never by which section happens to be textually nearby or "
    "earlier in reading order.\n"
    "2. A host listed ONLY in a 'known/already-reported finding class' table is NOT fully out of "
    "scope unless the page SEPARATELY says not to test that host/feature at all — classify it 'in' "
    "(it is still a live, testable asset) and put the one excluded finding class in `note` so that "
    "specific known issue isn't re-reported. If the page separately bans testing the host/feature "
    "entirely (e.g. 'DO NOT test X'), classify 'out' instead.\n"
    "3. When genuinely unsure, choose 'ambiguous'. NEVER guess 'in' to be generous, and NEVER classify "
    "a real asset 'out' just because exclusion language appears earlier in the page than its listing.\n"
    "4. Only classify candidates from the given list — never invent a new one.\n"
    "Return ONLY this JSON, no prose, no code fences:\n"
    "{\"classifications\":[{\"asset\":\"\",\"verdict\":\"in\"|\"out\"|\"ambiguous\",\"reason\":\"\","
    "\"note\":\"\"}]}\n"
    "`reason` is one short clause citing what the page actually says. `note` is used only for rule 2 "
    "(the specific known/excluded finding class on an otherwise in-scope asset); else \"\"."
)


def _classify_scope_llm(text, candidates):
    """Ground-truth in/out/ambiguous classification via Haiku 5.5 — judges each deterministically
    DISCOVERED candidate (regex still owns discovery — the model never invents an asset) by what the
    page says about THAT asset, fixing what the position-based OUT_HEADINGS split structurally cannot.
    Returns (verdicts: {asset: {"verdict","reason","note"}}, ok). ok=False → caller keeps the
    deterministic fallback split (offline-safe; same floor as before this existed)."""
    if not candidates:
        return {}, False
    try:
        import llm_auth
        _, mode = llm_auth.llm_headers()
        if not mode:
            return {}, False
    except Exception:
        return {}, False
    try:
        import llm_client
        model = os.environ.get("HUNT_MODEL_INTAKE", "claude-haiku-5-5")
        cand_list = "\n".join(sorted({a for a, _ in candidates}))
        body = text
        cut = body.find("# Netscape HTTP Cookie File")
        if cut > 500:
            body = body[:cut]
        user = "CANDIDATES (classify every one of these, nothing else):\n" + cand_list + \
               "\n\nFULL PAGE TEXT:\n" + body[:40000]
        txt, err = llm_client.call_llm(CLASSIFY_SYS, user, model=model, max_tokens=3000, timeout=90)
        if err or not txt:
            return {}, False
        t = re.sub(r"^\s*```(?:json)?|```\s*$", "", txt.strip(), flags=re.I | re.M).strip()
        m = re.search(r"\{.*\}", t, re.S)
        data = json.loads(m.group(0) if m else t)
        cand_set = {a for a, _ in candidates}
        verdicts = {}
        for c in (data.get("classifications") or []):
            a = _strip(str(c.get("asset", "")))
            v = c.get("verdict")
            if a in cand_set and v in ("in", "out", "ambiguous"):
                verdicts[a] = {"verdict": v, "reason": str(c.get("reason", ""))[:200],
                               "note": str(c.get("note", ""))[:200]}
        return verdicts, bool(verdicts)
    except Exception:
        return {}, False


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
    """Text → canonical scope object. Deterministic asset DISCOVERY always; CLASSIFICATION (which
    discovered hosts are actually in scope) goes to Haiku 5.5 when creds exist — see
    _classify_scope_llm for why the naive position-based split fails on real program pages. Falls
    back to the deterministic split (offline-safe) if the model is unavailable or fails."""
    shape = detect_shape(text)
    candidates = extract_raw(text)
    in_assets, out_assets = extract_assets(text)   # deterministic fallback floor — always computed
    ambiguous = []
    classifier = "deterministic"
    if enrich and shape == "program_page" and candidates:
        verdicts, ok = _classify_scope_llm(text, candidates)
        if ok:
            classifier = os.environ.get("HUNT_MODEL_INTAKE", "claude-haiku-5-5")
            in_assets, out_assets, ambiguous = [], [], []
            for a, kind in candidates:
                t = classify(a, kind)
                v = verdicts.get(a)
                if not v:   # model skipped it — safe default is visible uncertainty, not silent "in"
                    ambiguous.append({"asset": a, "type": t, "reason": "unclassified by model"})
                elif v["verdict"] == "in":
                    in_assets.append({"asset": a, "type": t, "note": v.get("note", "")})
                elif v["verdict"] == "out":
                    out_assets.append({"asset": a, "type": t, "reason": v.get("reason", "")})
                else:
                    ambiguous.append({"asset": a, "type": t, "reason": v.get("reason", "")})
    in_clean, allow, deny, targets = canonicalize(in_assets, out_assets, ambiguous)
    scope = {
        "shape": shape,
        "program": "", "platform": "", "summary": "",
        "in_scope": in_clean, "out_of_scope": out_assets, "ambiguous": ambiguous,
        "allow": allow, "deny": deny, "targets": targets,
        "rewards": "", "severity_rewards": [], "rules": [], "focus": [],
        "ua_required": "", "rate_limit": "", "poc_required": False, "ai_policy": "",
        "source_hash": source_hash(text), "enriched": False,
        "model": "deterministic", "asset_classifier": classifier,
    }
    if enrich and targets:
        scope, did = _enrich(text, scope)
        scope["enriched"] = did
    open_wild = _open_scope_wildcards(
        [text, scope.get("summary"), " ".join(scope.get("focus") or []), " ".join(scope.get("rules") or [])],
        in_clean)
    if open_wild:
        scope["allow"] = sorted(set(scope["allow"]) | set(open_wild))
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
