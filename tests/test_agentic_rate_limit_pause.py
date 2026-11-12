"""Acceptance check for the "zero terminal required" migration, step 2: a hunt must PAUSE
(not silently cascade through every remaining agentic phase) the moment _run_phase_agent's
claude-cli subprocess reports the account's 5-hour session limit. 0-token, 0-network — the
claude-cli subprocess.run call itself is monkeypatched so this never burns real CLI quota.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _load_hunt_run():
    os.environ["HUNT_DIR"] = tempfile.mkdtemp(prefix="huntr-ratelimit-")
    os.environ["HUNT_NO_LLM"] = "1"
    saved = sys.argv
    sys.argv = ["hunt-run.py", "--target", "lab.example", "--no-llm"]
    try:
        spec = importlib.util.spec_from_file_location("hunt_run_rl", TOOLS / "hunt-run.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.argv = saved


HR = _load_hunt_run()


class FakeCompleted:
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""


class RateLimitDetection(unittest.TestCase):
    def setUp(self):
        HR._RL["hit"] = False
        HR._RL["retry_after"] = 0
        HR._RL["cost_cap"] = False
        HR.STATE.pop("rate_limit_reset", None)
        HR.STATE.pop("rate_limit_notice", None)

    def test_cli_limit_regex_matches_real_wording(self):
        self.assertTrue(HR._CLI_LIMIT_RE.search("You've hit your session limit · resets 5:10pm"))
        self.assertTrue(HR._CLI_LIMIT_RE.search("usage limit reached"))
        # the live incident: "5-hour" between "your" and "limit" slipped past a fixed literal and the
        # hunt cascaded through every phase instead of pausing. This is the regression guard.
        self.assertTrue(HR._CLI_LIMIT_RE.search("You've hit your 5-hour limit · resets 7:10pm (Africa/Cairo)"))
        self.assertTrue(HR._CLI_LIMIT_RE.search("You've hit your weekly limit"))
        self.assertTrue(HR._CLI_LIMIT_RE.search("resets 7:10pm (Africa/Cairo)"))

    def test_long_agent_output_mentioning_rate_limit_does_not_false_positive(self):
        """A real finding write-up ("no rate limit on the login endpoint...") can be long and still
        contain the keyword — only a SHORT, limit-notice-shaped output should pause the hunt (same
        length guard as llm_client.call_llm's own detection of this exact prose)."""
        long_summary = ("no rate limit on the login endpoint. " * 20)
        self.assertGreater(len(long_summary), 400)
        with mock.patch.object(HR.subprocess, "run", return_value=FakeCompleted(long_summary)):
            ok = HR._run_phase_agent("test agent", "Test (agentic)", 50, "brief", 10.0,
                                      Path(tempfile.mkdtemp()) / "nope.jsonl", lambda lines: None)
        self.assertFalse(ok)
        self.assertFalse(HR._RL["hit"])

    def test_reset_time_parses_to_future_epoch(self):
        import time
        epoch = HR._parse_cli_reset("resets 5:10pm (America/New_York)")
        self.assertIsNotNone(epoch)
        self.assertGreater(epoch, time.time() - 60)  # today-or-tomorrow, never in the past

    def test_phase_agent_raises_pause_instead_of_returning_false(self):
        """The core bug this fixes: _run_phase_agent used to just log + return False on a hit
        limit, letting main() cascade through every remaining phase on a dead account. It must
        now raise RateLimitPause so main()'s existing pause handler takes over."""
        with mock.patch.object(HR.subprocess, "run",
                                return_value=FakeCompleted("You've hit your session limit · resets 11:59pm (UTC)")):
            with self.assertRaises(HR.RateLimitPause):
                HR._run_phase_agent("test agent", "Test (agentic)", 50, "brief", 10.0,
                                     Path(tempfile.mkdtemp()) / "nope.jsonl", lambda lines: None)
        self.assertTrue(HR._RL["hit"])
        self.assertIsNotNone(HR.STATE.get("rate_limit_reset"))

    def test_normal_failure_without_limit_wording_does_not_pause(self):
        """A genuine empty/refused result (no limit text) must still just return False — this
        fix must not turn every ordinary agent miss into a hunt-wide pause."""
        with mock.patch.object(HR.subprocess, "run",
                                return_value=FakeCompleted("I won't help with this request.")):
            ok = HR._run_phase_agent("test agent", "Test (agentic)", 50, "brief", 10.0,
                                      Path(tempfile.mkdtemp()) / "nope.jsonl", lambda lines: None)
        self.assertFalse(ok)
        self.assertFalse(HR._RL["hit"])


if __name__ == "__main__":
    unittest.main()
