"""Regression guard for the recon ENUMERATION FLOOR (2026-11-18).

When "recon_surface" is agentic, _phase_recon_surface_agent used to be the SOLE source of attack
surface — the deterministic enumeration only ran on the legacy else-branch. An agent that decided
"surface covered" early therefore left the rest undiscovered, with nothing underneath able to prove
the surface was incomplete (the Shiji /system/v1/* incident: 50+ live bugs under a path HUNTR never
mapped). The fix runs phase_recon/phase_mobile/phase_surface/phase_discover as a guaranteed FLOOR
*inside* the phase function (so both the fresh-run and resume-healing call sites get it), records
STATE["recon_floor"] as a coverage denominator, and the agent can only ADD to that surface.

These are real behavioral tests: the module imports under a controlled argv, the enumeration phases
and the agent dispatch are monkeypatched, and we assert (1) the floor runs BEFORE the agent, (2) the
denominator is recorded, and (3) a no-op agent still leaves the floor surface intact.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"


def _load_hunt_run():
    """hunt-run.py reads argv/env at import time (it is the detached runner the server spawns), so
    load it once under a controlled argv + a throwaway HUNT_DIR — the same reason the sibling tests
    treat this module specially. Its name has a hyphen, so it is loaded by file path."""
    d = tempfile.mkdtemp(prefix="huntr-floor-test-")
    os.environ["HUNT_DIR"] = d
    sys.argv = ["hunt-run.py", "--target", "example.com", "--hunt-dir", d]
    spec = importlib.util.spec_from_file_location("hunt_run_under_test", TOOLS / "hunt-run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ReconEnumerationFloorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load_hunt_run()

    def setUp(self):
        m = self.m
        # Reset the surface each test; keep a minimal STATE shape the phase touches.
        m.STATE["hosts"] = []
        m.STATE["endpoints"] = []
        m.STATE.setdefault("stats", {})
        m.STATE.pop("recon_floor", None)
        self._order = []
        # Save originals to restore in tearDown.
        self._saved = {n: getattr(m, n) for n in (
            "phase_recon", "phase_mobile", "phase_surface", "phase_discover",
            "_run_phase_agent", "_surface_brief", "_phase_budget", "log", "flush", "stage",
        )}

        def _recon():
            self._order.append("phase_recon")
            m.STATE["hosts"] = [{"host": "a.example.com", "status": 200},
                                {"host": "b.example.com", "status": 200}]

        def _mobile():
            self._order.append("phase_mobile")

        def _surface():
            self._order.append("phase_surface")
            m.STATE["endpoints"] = [{"url": "https://a.example.com/api/x", "host": "a.example.com"},
                                    {"url": "https://a.example.com/api/y", "host": "a.example.com"},
                                    {"url": "https://b.example.com/login", "host": "b.example.com"}]

        def _discover(deadline=None):
            self._order.append("phase_discover")

        m.phase_recon = _recon
        m.phase_mobile = _mobile
        m.phase_surface = _surface
        m.phase_discover = _discover
        m._surface_brief = lambda *a, **k: ""
        m._phase_budget = lambda *a, **k: 60.0
        m.log = lambda *a, **k: None
        m.flush = lambda *a, **k: None
        m.stage = lambda *a, **k: None

    def tearDown(self):
        for n, fn in self._saved.items():
            setattr(self.m, n, fn)

    def test_floor_runs_before_agent_and_records_denominator(self):
        m = self.m

        def _agent(*args, **kwargs):
            # The agent dispatch must happen AFTER all four enumeration phases.
            self._order.append("agent")
            return True

        m._run_phase_agent = _agent
        m._phase_recon_surface_agent(deadline=None)

        self.assertEqual(
            self._order,
            ["phase_recon", "phase_mobile", "phase_surface", "phase_discover", "agent"],
            "enumeration floor must run (in order) BEFORE the agent is dispatched",
        )
        floor = m.STATE.get("recon_floor")
        self.assertIsNotNone(floor, "STATE['recon_floor'] denominator must be recorded")
        self.assertEqual(floor["hosts"], 2)
        self.assertEqual(floor["endpoints"], 3)

    def test_noop_agent_preserves_floor_surface(self):
        m = self.m

        # Agent finds nothing / fails — the old code called this "little/no surface this run".
        def _agent(*args, **kwargs):
            return False

        m._run_phase_agent = _agent
        m._phase_recon_surface_agent(deadline=None)

        # The floor surface survives: the agent being empty cannot shrink the denominator.
        self.assertEqual(len(m.STATE["hosts"]), 2)
        self.assertEqual(len(m.STATE["endpoints"]), 3)
        self.assertEqual(m.STATE["recon_floor"]["endpoints"], 3)

    def test_floor_helper_is_called_by_phase(self):
        """The floor must live inside the phase function (not only in main()), so the resume
        setup-healing loop — which calls _phase_recon_surface_agent directly — gets it too."""
        m = self.m
        called = {"floor": False}
        saved_floor = m._recon_enumeration_floor

        def _floor(deadline=None):
            called["floor"] = True
            saved_floor(deadline)

        m._recon_enumeration_floor = _floor
        m._run_phase_agent = lambda *a, **k: True
        try:
            m._phase_recon_surface_agent(deadline=None)
        finally:
            m._recon_enumeration_floor = saved_floor
        self.assertTrue(called["floor"], "_phase_recon_surface_agent must invoke the enumeration floor")


if __name__ == "__main__":
    unittest.main()
