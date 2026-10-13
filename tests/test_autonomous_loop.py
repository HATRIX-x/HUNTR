"""Phase-3 regression test: the autonomous hunt loop, end-to-end.

Runs the REAL engine (hunt-run.py) in deterministic-only mode (HUNT_NO_LLM=1)
against the planted-vuln lab and asserts the properties that make HUNTR's
autonomy trustworthy — and better than a volume-first autonomous scanner:

  • it runs UNATTENDED to completion (no human, no LLM/account needed)
  • it FINDS and ORACLE-PROVES real bugs (sqli/xss/ssrf/… on the lab)
  • ZERO false positives among what it reports
  • it NEVER auto-submits — findings are graded submit/lead/info for a human
  • it leaves a replayable AUDIT TRAIL (run.json findings + coverage + run.log)

Slow (runs the full engine), so gated behind HUNT_RUN_SLOW=1 — `make verify-hunt`
and CI set it; the fast `make verify` skips it.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
LAB = REPO / "bench" / "labs.py"

CORE_CLASSES = {"sqli", "xss", "ssrf", "idor", "lfi", "nosqli", "cmdi", "authz", "graphql"}


def _norm(c):
    c = (c or "").lower()
    if "nosql" in c:
        return "nosqli"
    if "sql" in c:
        return "sqli"
    for k in CORE_CLASSES:
        if k in c:
            return k
    return c


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@unittest.skipUnless(os.environ.get("HUNT_RUN_SLOW") == "1",
                     "slow autonomous-loop test — set HUNT_RUN_SLOW=1 (make verify-hunt)")
class AutonomousLoop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.lab = subprocess.Popen([sys.executable, str(LAB), "--port", str(cls.port)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import urllib.request
        base = f"http://127.0.0.1:{cls.port}/"
        for _ in range(40):
            try:
                urllib.request.urlopen(base, timeout=1); break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("lab did not come up")

        cls.hd = Path(tempfile.mkdtemp(prefix="huntr-auto-")) / ".hunt"
        cls.hd.mkdir(parents=True)
        env = dict(os.environ, HUNT_DIR=str(cls.hd), HUNT_NO_LLM="1",
                   HUNT_SINGLE="1", HUNT_NO_BRUTE="1")
        logf = open(cls.hd / "run.log", "w")
        cls.proc = subprocess.Popen(
            [sys.executable, str(TOOLS / "hunt-run.py"), "--target", f"127.0.0.1:{cls.port}",
             "--mode", "black", "--scope-types", "web,api", "--budget-sec", "300"],
            stdout=logf, stderr=subprocess.STDOUT, env=env)

        # wait for the unattended run to finish (status done/stopped) or a hard cap
        cls.rj = None
        deadline = time.time() + 600
        runf = cls.hd / "run.json"
        while time.time() < deadline:
            if runf.exists():
                try:
                    d = json.loads(runf.read_text())
                    if d.get("status") in ("done", "stopped", "error"):
                        cls.rj = d
                        break
                except Exception:
                    pass
            if cls.proc.poll() is not None:
                time.sleep(1)
                try:
                    cls.rj = json.loads(runf.read_text())
                except Exception:
                    pass
                break
            time.sleep(4)
        if cls.rj is None and runf.exists():
            try:
                cls.rj = json.loads(runf.read_text())
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        for p in (getattr(cls, "proc", None), getattr(cls, "lab", None)):
            try:
                p.terminate(); p.wait(timeout=5)
            except Exception:
                try: p.kill()
                except Exception: pass

    def test_ran_unattended_to_completion(self):
        self.assertIsNotNone(self.rj, "run.json never produced")
        self.assertEqual(self.rj.get("status"), "done",
                         "deterministic autonomous run should complete unattended")

    def test_found_and_proved_real_bugs(self):
        finds = self.rj.get("findings", [])
        found = {_norm(f.get("cls")) for f in finds} & CORE_CLASSES
        self.assertGreaterEqual(len(found), 3,
                                f"expected >=3 core bug classes, got {sorted(found)}")
        proven = [f for f in finds if f.get("verdict") in ("confirmed", "likely")
                  or f.get("reco") in ("submit", "lead")]
        self.assertGreaterEqual(len(proven), 3, "expected several proven/submit-ready findings")

    def test_zero_false_positives(self):
        # nothing the engine kept should be flagged a false positive / dismissed
        for f in self.rj.get("findings", []):
            self.assertNotIn(f.get("verdict"), ("false_positive", "dismissed"),
                             f"a dismissed finding leaked into results: {f.get('title')}")

    def test_never_auto_submits(self):
        # the engine grades findings submit/lead/info but must NEVER post them.
        # no submission artifact may exist, and nothing is marked already-submitted.
        self.assertFalse((self.hd / "submitted.jsonl").exists(),
                         "engine must not auto-submit (no submitted.jsonl)")
        for f in self.rj.get("findings", []):
            self.assertNotEqual(f.get("submitted"), True, "a finding was auto-submitted")

    def test_leaves_audit_trail(self):
        # The replayable audit trail is run.json: the per-phase/decision log, the
        # coverage ledger (what was tested), and the mapped surface.
        self.assertTrue((self.hd / "run.json").exists())
        self.assertIn("coverage", self.rj)           # what was tested (the ledger)
        self.assertIn("endpoints", self.rj)          # mapped surface
        self.assertGreater(len(self.rj.get("logs", [])), 5,
                           "the run must log its phases/decisions (replayable trail)")


if __name__ == "__main__":
    unittest.main()
