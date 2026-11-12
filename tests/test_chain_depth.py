"""Bet #2 regression test: deterministic capability chaining (depth / $-recall).

The engine composes individually-modest findings into higher-severity CHAINS that
reach critical impact (account-takeover, cloud-role, db-read) — the depth a
volume-first per-finding scanner misses, and the reason HUNTR optimizes for
dollars (one critical chain > many lows), not bug-count. This runs with NO LLM:
_finding_edges maps each finding to capability edges and _reach composes them by
graph reachability. No network, no model.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _load_hunt_run():
    # hunt-run runs setup at import (argv + HUNT_DIR); sandbox both.
    os.environ["HUNT_DIR"] = tempfile.mkdtemp(prefix="huntr-chain-")
    os.environ["HUNT_NO_LLM"] = "1"
    saved = sys.argv
    sys.argv = ["hunt-run.py", "--target", "lab.example", "--no-llm"]
    try:
        spec = importlib.util.spec_from_file_location("hunt_run", TOOLS / "hunt-run.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.argv = saved


HR = _load_hunt_run()


def _edges(findings, start="anon"):
    out = []
    for fi, f in enumerate(findings):
        for (frm, prim, to, status, imp, link) in HR._finding_edges(f, fi, start):
            out.append({"frm": frm, "prim": prim, "to": to, "status": status, "impact": imp, "fi": link})
    return out


class ChainDepth(unittest.TestCase):
    def test_single_finding_maps_to_escalation_chain(self):
        # an IDOR alone is a near-miss to account-takeover (one unproven edge away)
        e = _edges([{"cls": "IDOR", "title": "cross-user read", "endpoint": "/account?uid=1"}])
        self.assertTrue(any(x["to"] == "other-user-data" and x["status"] == "proven" for x in e))
        self.assertTrue(any(x["to"] == "account-takeover" and x["status"] == "unproven" for x in e))

    def test_proven_primitive_reaches_impact(self):
        # SSTI/SQLi are proven straight to critical impact (rce / db-read)
        e = _edges([{"cls": "SSTI", "endpoint": "/greet?name=x"},
                    {"cls": "SQLi", "endpoint": "/product?id=1"}])
        proven = HR._reach(e, {"anon"}, {"proven"})
        self.assertIn("rce", proven)
        self.assertIn("db-read", proven)

    def test_near_miss_detected_only_with_unproven_edges(self):
        # account-takeover is NOT reachable with proven edges alone, but IS one
        # unproven edge away — the single highest-leverage next step.
        e = _edges([{"cls": "cors", "endpoint": "/api/data"},
                    {"cls": "xss", "endpoint": "/search?q=x"}])
        proven = HR._reach(e, {"anon"}, {"proven"})
        allr = HR._reach(e, {"anon"}, {"proven", "unproven"})
        self.assertNotIn("account-takeover", proven)
        self.assertIn("account-takeover", allr)

    def test_impact_nodes_carry_escalated_severity(self):
        # chaining reports at ESCALATED impact — account-takeover/rce are critical
        self.assertEqual(HR.IMPACT_SEV.get("account-takeover"), "c")
        self.assertEqual(HR.IMPACT_SEV.get("rce"), "c")
        self.assertIn(HR.IMPACT_SEV.get("db-read"), ("c", "h"))

    def test_mixed_findings_compose_many_impact_paths(self):
        # a realistic finding set composes into multiple critical-impact chains
        finds = [{"cls": c, "endpoint": "/x"} for c in ("sqli", "ssrf", "idor", "authz", "xss", "cors", "ssti")]
        allr = HR._reach(_edges(finds), {"anon"}, {"proven", "unproven"})
        criticals = [n for n in allr if HR.IMPACT_SEV.get(n) == "c"]
        self.assertGreaterEqual(len(criticals), 2,
                                f"expected several critical-impact chains, got {criticals}")


if __name__ == "__main__":
    unittest.main()
