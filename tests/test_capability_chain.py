"""Phase-4 regression tests: automatic capability chaining (exploitation depth).

Proves HUNTR composes confirmed primitives into a higher-severity chain that no
single finding represents — the LLM-native depth XBOW's per-finding scanners
miss — deterministically, by graph reachability. No network, no LLM.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import capability_edges  # noqa: E402  (importable: underscore name, tools on path)


def _capgraph():
    spec = importlib.util.spec_from_file_location("capability_graph", TOOLS / "capability-graph.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


CG = _capgraph()


def _findings(last_status="proven"):
    # three independent findings; chained they reach a CRITICAL goal no one finding holds
    return [
        {"class": "idor", "endpoint": "/api/orders/{id}",
         "from": "userA", "to": "userB_token", "impact": "-", "status": "proven"},
        {"class": "mass_assign", "endpoint": "/user/update",
         "from": "userB_token", "to": "admin_capability", "impact": "-", "status": "proven"},
        {"class": "authz", "endpoint": "/admin/tenants",
         "from": "admin_capability", "to": "all_tenants", "impact": "c", "status": last_status},
    ]


class CapabilityChain(unittest.TestCase):
    def test_three_findings_compose_into_one_critical_chain(self):
        edges = capability_edges.edges_from_findings(_findings())
        res = CG.analyze(edges, {"anon", "userA"})
        chains = res["proven_chains"]
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["node"], "all_tenants")
        self.assertEqual(chains[0]["sev"], "c")
        # the chain is 3 hops — longer than any single finding
        self.assertEqual(len(chains[0]["path"]), 3)
        self.assertEqual([e["to"] for e in chains[0]["path"]],
                         ["userB_token", "admin_capability", "all_tenants"])

    def test_unproven_last_edge_becomes_near_miss_with_next_step(self):
        # the final hop is only a hypothesis → the goal is a NEAR MISS, and the
        # engine names the single highest-leverage edge left to prove.
        edges = capability_edges.edges_from_findings(_findings(last_status="unproven"))
        res = CG.analyze(edges, {"anon", "userA"})
        self.assertEqual(res["proven_chains"], [])
        self.assertEqual(len(res["near"]), 1)
        self.assertEqual(res["near"][0]["node"], "all_tenants")
        self.assertIsNotNone(res["best_next"])
        self.assertEqual(res["best_next"]["to"], "all_tenants")
        self.assertEqual(res["best_next"]["unlocks"], "all_tenants")

    def test_untagged_finding_uses_class_default(self):
        # a finding with no explicit from/to still participates, via the class map
        e = capability_edges.edge_from_finding({"class": "sqli", "endpoint": "/search"})
        self.assertIsNotNone(e)
        self.assertEqual((e["frm"], e["to"]), ("anon", "db_read"))

    def test_unmappable_finding_is_skipped(self):
        self.assertIsNone(capability_edges.edge_from_finding({"class": "totally-unknown"}))


if __name__ == "__main__":
    unittest.main()
