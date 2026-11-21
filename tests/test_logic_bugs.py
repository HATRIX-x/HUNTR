"""Phase-4 regression tests: business-logic exploitation against a live target.

Runs the real mass-assign engine against tests/mock_target.py and asserts it
CONFIRMS the mass-assignable endpoint (sensitive fields stick, observed on GET)
while clearing the allowlisted one — end-to-end logic-bug detection, the class
XBOW's mechanical scanners are weakest on. No LLM, no external network.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "tests"
MASS_ASSIGN = REPO / "tools" / "mass-assign.py"
sys.path.insert(0, str(TESTS))


class LogicBugs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import mock_target
        cls.mod = mock_target
        cls.srv, cls.base = mock_target.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _run(self, path):
        self.mod.reset_db()
        r = subprocess.run(
            [sys.executable, str(MASS_ASSIGN), "--url", f"{self.base}{path}",
             "--id", "victim-1", "--verify-get", f"{self.base}/user/{{id}}", "--json"],
            capture_output=True, text=True, timeout=60)
        return r.returncode, json.loads(r.stdout)

    def test_vulnerable_endpoint_confirms_privesc(self):
        _code, res = self._run("/user/update")
        # sensitive fields actually STUCK (observed on GET) — a real privesc
        self.assertGreaterEqual(res["confirmed"], 1, "at least one field stuck on GET")
        self.assertIn("PRIVESC", res["impacts"])

    def test_allowlisted_endpoint_confirms_nothing(self):
        # The allowlist blocks every observable field, so nothing is CONFIRMED
        # reflected. (Write-only fields like password still read as "accepted,
        # confirm by login" since a 204 can't be disproven via GET — that's
        # honest, not a confirmed bug.) The engine's confirmed count is the
        # signal that separates a real mass-assignment from a safe endpoint.
        _code, res = self._run("/strict/update")
        self.assertEqual(res["confirmed"], 0)


if __name__ == "__main__":
    unittest.main()
