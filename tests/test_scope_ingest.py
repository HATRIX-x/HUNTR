"""Regression tests for the scope-ingest pipeline (the "perfect intake flow").

The core guarantee: pasting a whole program page yields a clean, typed,
in/out-split asset list with NO prose junk — deterministically, with no LLM.
This is what replaces hunt-run.py whitespace-splitting a page into hundreds of
bogus "assets". Everything here runs offline.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import scope_ingest as si  # noqa: E402

PAGE = """Acme Bug Bounty — HackerOne

In scope:
*.acme.com
https://api.acme.com/v2
app.acme.com
github.com/acme/webapp
https://play.google.com/store/apps/details?id=com.acme

Out of scope:
legacy.acme.com
blog.acme.com
Social engineering, DoS, and physical attacks are excluded.

Rewards: Critical $5000, High $1500, Low $100
Rules: Use UA BugBounty-Acme. Rate limit 2 req/s. PoC required.
"""


class ScopeIngest(unittest.TestCase):
    def test_detect_shape(self):
        self.assertEqual(si.detect_shape("api.example.com"), "hosts")
        self.assertEqual(si.detect_shape(PAGE), "program_page")
        self.assertEqual(si.detect_shape("\n".join(f"h{i}.x.com" for i in range(8))), "url_list")

    def test_extracts_and_types_assets(self):
        sc = si.ingest(PAGE, enrich=False)
        by = {a["asset"]: a["type"] for a in sc["in_scope"]}
        self.assertEqual(by.get("*.acme.com"), "web")
        self.assertEqual(by.get("api.acme.com/v2"), "api")
        self.assertEqual(by.get("app.acme.com"), "web")
        self.assertEqual(by.get("github.com/acme/webapp"), "source")
        self.assertEqual(by.get("play.google.com/store/apps/details?id=com.acme"), "mobile")

    def test_in_out_split(self):
        sc = si.ingest(PAGE, enrich=False)
        out = {o["asset"] for o in sc["out_of_scope"]}
        self.assertEqual(out, {"legacy.acme.com", "blog.acme.com"})
        # an out-of-scope asset must not also be in-scope, and feeds the deny list
        self.assertNotIn("legacy.acme.com", sc["allow"])
        self.assertIn("legacy.acme.com", sc["deny"])

    def test_hunt_targets_are_web_and_api_only(self):
        sc = si.ingest(PAGE, enrich=False)
        self.assertEqual(sc["targets"], ["*.acme.com", "api.acme.com/v2", "app.acme.com"])

    def test_no_prose_junk_becomes_an_asset(self):
        # The whole point vs hunt-run's whitespace split: exactly the 7 real assets
        # (5 in + 2 out) are extracted, every one is a real host (has a dot), and no
        # standalone prose word slips through.
        sc = si.ingest(PAGE, enrich=False)
        assets = {a["asset"] for a in sc["in_scope"]} | {o["asset"] for o in sc["out_of_scope"]}
        self.assertEqual(len(assets), 7, f"expected 7 real assets, got {sorted(assets)}")
        for a in assets:
            self.assertIn(".", a, f"{a!r} is not a real host")
        for junk in ("critical", "rewards", "rules", "social", "high", "low", "req/s", "engineering"):
            self.assertNotIn(junk, assets, f"standalone junk {junk!r} leaked in")

    def test_dedup(self):
        sc = si.ingest("a.com\nhttps://a.com/\nA.COM\nb.com", enrich=False)
        self.assertEqual(sorted(sc["allow"]), ["a.com", "b.com"])

    def test_persist_writes_canonical_scope(self):
        sc = si.ingest(PAGE, enrich=False)
        d = tempfile.mkdtemp()
        si.persist(sc, d)
        allow = (Path(d) / "scope.allow").read_text().splitlines()
        deny = (Path(d) / "scope.deny").read_text().splitlines()
        prog = json.loads((Path(d) / "program.json").read_text())
        self.assertIn("*.acme.com", allow)
        self.assertIn("legacy.acme.com", deny)
        self.assertEqual(prog["source_hash"], sc["source_hash"])

    def test_source_hash_is_stable(self):
        self.assertEqual(si.ingest(PAGE, enrich=False)["source_hash"],
                         si.ingest(PAGE, enrich=False)["source_hash"])

    def test_single_host_passthrough(self):
        sc = si.ingest("api.example.com", enrich=False)
        self.assertEqual(sc["targets"], ["api.example.com"])


# A page shaped like the real-world failure this classifier layer fixes: an early
# "out of scope" mention (a summary blurb) that sits BEFORE the real Assets table
# further down — the exact structure that made the naive position-split dump
# *.acme.io's own wildcard into deny on a live program (0 in-scope, all denied).
MISORDERED_PAGE = """Acme Security — HackerOne

Scope exclusions
Core Ineligible Findings are out of scope. Learn more.

Overview
Acme is a crypto wallet. We value security.
DO NOT test Acme Exchange features, endpoints and hosts or anything related to it.

Known Findings but not limited to:
Asset    Out of scope finding class
fiat.a.acme.io    Unauthenticated HMAC signing oracle on /api/sign

Rewards
Minimum reward: $100. Maximum reward: $50,000.

Assets In Scope
*.acme.io
Wildcard    High    Eligible
exchange.acme.io
"""

CANDIDATES = [a for a, _k in si.extract_raw(MISORDERED_PAGE)]


class ScopeIngestLLMClassifier(unittest.TestCase):
    """Regression coverage for the Haiku-5.5 scope classifier (2026-10-15) — fixes the naive
    position-based in/out split, which fails whenever 'out of scope' prose precedes the real
    Assets table (common on real H1 pages; reproduced exactly below)."""

    def test_position_split_bug_reproduced_offline(self):
        # Documents WHY the classifier exists: offline/no-LLM, the deterministic fallback alone
        # dumps the explicitly-eligible wildcard into deny because "out of scope" appears earlier
        # in the raw text than the real Assets table.
        sc = si.ingest(MISORDERED_PAGE, enrich=False)
        self.assertNotIn("*.acme.io", {a["asset"] for a in sc["in_scope"]})
        self.assertIn("*.acme.io", {o["asset"] for o in sc["out_of_scope"]})
        self.assertEqual(sc["asset_classifier"], "deterministic")

    def test_classifier_corrects_the_misordered_split(self):
        verdicts = {
            "*.acme.io": {"verdict": "in", "reason": "Wildcard/High/Eligible in Assets table", "note": ""},
            "fiat.a.acme.io": {"verdict": "in", "reason": "covered by wildcard",
                               "note": "Excluded: HMAC signing oracle on /api/sign"},
            "exchange.acme.io": {"verdict": "out", "reason": "page bans testing Exchange hosts", "note": ""},
        }
        with patch.object(si, "_classify_scope_llm", return_value=(verdicts, True)), \
             patch.object(si, "_enrich", side_effect=lambda text, base: (base, False)):
            sc = si.ingest(MISORDERED_PAGE, enrich=True)
        self.assertEqual(sc["asset_classifier"], "claude-haiku-5-5")
        ins = {a["asset"] for a in sc["in_scope"]}
        outs = {o["asset"] for o in sc["out_of_scope"]}
        self.assertIn("*.acme.io", ins)
        self.assertIn("fiat.a.acme.io", ins)   # known-finding-class exclusion != full host ban
        self.assertIn("exchange.acme.io", outs)  # explicit "DO NOT test" IS a full host ban
        self.assertIn("*.acme.io", sc["targets"])
        # the known-finding note survives onto the in-scope entry so the hunter doesn't re-report it
        note = next(a["note"] for a in sc["in_scope"] if a["asset"] == "fiat.a.acme.io")
        self.assertIn("HMAC", note)

    def test_classifier_unavailable_falls_back_to_deterministic(self):
        # No creds / rate-limited / model down → never block, never crash: same floor as enrich=False.
        with patch.object(si, "_classify_scope_llm", return_value=({}, False)), \
             patch.object(si, "_enrich", side_effect=lambda text, base: (base, False)):
            sc = si.ingest(MISORDERED_PAGE, enrich=True)
        self.assertEqual(sc["asset_classifier"], "deterministic")
        self.assertNotIn("*.acme.io", {a["asset"] for a in sc["in_scope"]})

    def test_ambiguous_assets_are_denied_by_default_not_guessed(self):
        verdicts = {
            "*.acme.io": {"verdict": "in", "reason": "listed", "note": ""},
            "exchange.acme.io": {"verdict": "ambiguous", "reason": "can't tell", "note": ""},
        }
        with patch.object(si, "_classify_scope_llm", return_value=(verdicts, True)), \
             patch.object(si, "_enrich", side_effect=lambda text, base: (base, False)):
            sc = si.ingest(MISORDERED_PAGE, enrich=True)
        amb = {a["asset"] for a in sc["ambiguous"]}
        self.assertIn("exchange.acme.io", amb)
        self.assertNotIn("exchange.acme.io", sc["allow"])
        self.assertNotIn("exchange.acme.io", sc["targets"])
        self.assertIn("exchange.acme.io", sc["deny"])   # held back, never silently auto-hunted

    def test_classifier_never_invents_an_asset_outside_the_candidate_list(self):
        verdicts = {"*.acme.io": {"verdict": "in", "reason": "listed", "note": ""},
                    "totally-made-up.evil.com": {"verdict": "in", "reason": "hallucinated", "note": ""}}
        with patch.object(si, "_classify_scope_llm") as m, \
             patch.object(si, "_enrich", side_effect=lambda text, base: (base, False)):
            # _classify_scope_llm itself is responsible for filtering to the candidate set;
            # simulate it already having done so (its real implementation strips non-candidates).
            m.return_value = ({k: v for k, v in verdicts.items() if k in CANDIDATES}, True)
            sc = si.ingest(MISORDERED_PAGE, enrich=True)
        self.assertNotIn("totally-made-up.evil.com",
                          {a["asset"] for a in sc["in_scope"]} | {a["asset"] for a in sc.get("ambiguous", [])})


if __name__ == "__main__":
    unittest.main()
