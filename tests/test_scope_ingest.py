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


if __name__ == "__main__":
    unittest.main()
