"""Bet #4 regression test: the money-weighted, FP-penalized scoreboard.

Validates the metric designed to beat a volume-first competitor: proven, high-$
findings score; unproven ones don't; false-positive submissions are penalized.
Volume can't game it. Pure (no network/LLM) — scores synthetic runs.
"""
import importlib.util
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _hb():
    spec = importlib.util.spec_from_file_location("hunt_bench", TOOLS / "hunt-bench.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


HB = _hb()
SUITE = {"name": "t", "target": "127.0.0.1:9", "expected": [
    {"class": "sqli", "path": "/p", "sev": "c"},   # $5000
    {"class": "xss",  "path": "/s", "sev": "m"},   # $400
]}


def _run(findings):
    return {"findings": findings, "endpoints": [], "status": "done"}


class BenchScore(unittest.TestCase):
    def test_dollar_recall_weights_by_severity_and_proof(self):
        # sqli proven (crit $5000), xss found but NOT proven (med $400 -> 0)
        r = HB.score_suite(SUITE, _run([
            {"cls": "SQLi", "endpoint": "http://x/p?id=1", "verdict": "confirmed",
             "proof": {"proven": True}},
            {"cls": "XSS", "endpoint": "http://x/s?q=1", "verdict": "likely"},
        ]))
        self.assertEqual(r["dollars_possible"], 5400)
        self.assertEqual(r["dollars_found"], 5000)          # only the proven critical counts
        self.assertEqual(r["dollar_recall"], round(5000 / 5400, 3))
        self.assertEqual(r["proof_rate"], 0.5)              # 1 of 2 proven
        self.assertEqual(r["fp_rate"], 0.0)
        self.assertEqual(r["huntr_score"], round((5000 / 5400) * 0.5 * 1.0, 3))

    def test_false_positive_submit_penalizes_score(self):
        # both real bugs proven, PLUS a junk submit-ready finding of an unplanted class
        clean = HB.score_suite(SUITE, _run([
            {"cls": "SQLi", "endpoint": "http://x/p?id=1", "verdict": "confirmed", "proof": {"proven": True}, "reco": "submit"},
            {"cls": "XSS", "endpoint": "http://x/s?q=1", "verdict": "confirmed", "proof": {"proven": True}, "reco": "submit"},
        ]))
        noisy = HB.score_suite(SUITE, _run([
            {"cls": "SQLi", "endpoint": "http://x/p?id=1", "verdict": "confirmed", "proof": {"proven": True}, "reco": "submit"},
            {"cls": "XSS", "endpoint": "http://x/s?q=1", "verdict": "confirmed", "proof": {"proven": True}, "reco": "submit"},
            {"cls": "jwt", "endpoint": "http://x/token", "verdict": "confirmed", "reco": "submit"},  # junk submit
        ]))
        self.assertEqual(clean["fp_rate"], 0.0)
        self.assertGreater(noisy["fp_rate"], 0.0)
        self.assertLess(noisy["huntr_score"], clean["huntr_score"],
                        "a false-positive submission must lower the HUNTR Score")

    def test_perfect_proven_capture_scores_high(self):
        r = HB.score_suite(SUITE, _run([
            {"cls": "SQLi", "endpoint": "http://x/p?id=1", "verdict": "confirmed", "proof": {"proven": True}},
            {"cls": "XSS", "endpoint": "http://x/s?q=1", "verdict": "confirmed", "proof": {"proven": True}},
        ]))
        self.assertEqual(r["dollar_recall"], 1.0)
        self.assertEqual(r["proof_rate"], 1.0)
        self.assertEqual(r["huntr_score"], 1.0)


if __name__ == "__main__":
    unittest.main()
