"""Regression tests for the CLI-subscription (HUNT_LLM_VIA_CLI=1) fallback path.

Context: under the subscription (no raw API key), `claude -p` has no native tool-calling, so
agent_core.run_agent() falls back to a JSON "propose" loop over plain call_llm(), and three new
deterministic CDP oracles were added so client-side proof doesn't need free-form browser driving.
Live-tested finding that shaped this: asking the model to "call a tool" (claim it performed a
real network/browser action) gets reliably refused ("I don't have access"); asking it to PROPOSE
a step for an external harness to run, with the harness doing the real work, is not refused. These
tests cover the pure dispatch/parsing/classification logic without making real LLM or CDP calls.
"""
import os, sys, json, unittest, importlib.util
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeLC:
    """Stand-in for the lazily-loaded llm_client module, queueing canned call_llm() replies."""
    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = []

    def call_llm(self, system, user, timeout=60, max_tokens=1600, **kw):
        self.calls.append((system, user))
        if not self._replies:
            return None, "no more replies queued"
        return self._replies.pop(0)


class ExtractUrls(unittest.TestCase):
    def setUp(self):
        import agent_core as A
        self.A = A

    def test_dedups_and_strips_trailing_punctuation(self):
        text = 'see https://x.test/a, and https://x.test/a) also https://x.test/b.'
        got = self.A._extract_urls(text, cap=5)
        self.assertEqual(got, ["https://x.test/a", "https://x.test/b"])

    def test_cap_limits_results(self):
        text = " ".join(f"https://x.test/{i}" for i in range(10))
        self.assertEqual(len(self.A._extract_urls(text, cap=3)), 3)

    def test_no_urls_returns_empty(self):
        self.assertEqual(self.A._extract_urls("no urls here", cap=3), [])


class ExtractParam(unittest.TestCase):
    def setUp(self):
        import agent_core as A
        self.A = A

    def test_finds_param_key(self):
        text = json.dumps({"cls": "xss", "param": "q", "endpoint": "https://x.test/"})
        self.assertEqual(self.A._extract_param(text), "q")

    def test_missing_param_returns_none(self):
        text = json.dumps({"cls": "xss", "endpoint": "https://x.test/"})
        self.assertIsNone(self.A._extract_param(text))


class JsonActionLoop(unittest.TestCase):
    """The propose/execute/observe loop itself — no real LLM calls, canned replies only."""

    def setUp(self):
        import agent_core as A
        self.A = A

    def tearDown(self):
        self.A._LC = None  # don't leak a fake lc() into any other test that imports agent_core

    def _patch_lc(self, replies):
        fake = FakeLC(replies)
        self.A._LC = fake
        return fake

    def test_no_tools_is_a_plain_single_completion(self):
        self._patch_lc([("plain prose answer, no JSON needed", None)])
        reply, tlog, err = self.A._json_action_loop("sys", "user", [], {}, max_rounds=3)
        self.assertEqual(reply, "plain prose answer, no JSON needed")
        self.assertEqual(tlog, [])
        self.assertIsNone(err)

    def test_propose_then_done_dispatches_and_finishes(self):
        calls = {"n": 0}
        def record_chain(inp):
            calls["n"] += 1
            return "recorded"
        tools = [{"name": "record_chain", "description": "record it",
                  "input_schema": {"type": "object", "properties": {"title": {"type": "string"}}}}]
        handlers = {"record_chain": record_chain}
        self._patch_lc([
            ('{"propose": "record_chain", "input": {"title": "X"}}', None),
            ('{"propose": "done", "text": "Chain recorded."}', None),
        ])
        reply, tlog, err = self.A._json_action_loop("sys", "user", tools, handlers, max_rounds=4)
        self.assertEqual(reply, "Chain recorded.")
        self.assertEqual(calls["n"], 1)
        self.assertEqual(len(tlog), 1)
        self.assertEqual(tlog[0]["name"], "record_chain")
        self.assertIsNone(err)

    def test_malformed_json_falls_back_to_raw_text_instead_of_looping(self):
        tools = [{"name": "record_chain", "description": "x", "input_schema": {}}]
        handlers = {"record_chain": lambda inp: "x"}
        self._patch_lc([("I don't have access to do that.", None)])
        reply, tlog, err = self.A._json_action_loop("sys", "user", tools, handlers, max_rounds=4)
        self.assertEqual(reply, "I don't have access to do that.")
        self.assertEqual(tlog, [])

    def test_unknown_proposal_name_finishes_rather_than_loops_forever(self):
        tools = [{"name": "record_chain", "description": "x", "input_schema": {}}]
        handlers = {"record_chain": lambda inp: "x"}
        self._patch_lc([('{"propose": "nonexistent_tool", "input": {}}', None)])
        reply, tlog, err = self.A._json_action_loop("sys", "user", tools, handlers, max_rounds=4)
        self.assertIsNotNone(reply)
        self.assertEqual(tlog, [])

    def test_max_rounds_without_done_reports_error_not_none_silently(self):
        tools = [{"name": "record_chain", "description": "x", "input_schema": {}}]
        handlers = {"record_chain": lambda inp: "ok"}
        self._patch_lc([
            ('{"propose": "record_chain", "input": {}}', None),
            ('{"propose": "record_chain", "input": {}}', None),
        ])
        reply, tlog, err = self.A._json_action_loop("sys", "user", tools, handlers, max_rounds=2)
        self.assertIsNone(reply)
        self.assertIsNotNone(err)
        self.assertEqual(len(tlog), 2)

    def test_http_request_is_prefetched_before_any_llm_call(self):
        fetched = []
        def http_handler(inp):
            fetched.append(inp["url"])
            return "200 OK"
        tools = [{"name": "http_request", "description": "x", "input_schema": {}}]
        handlers = {"http_request": http_handler}
        fake = self._patch_lc([('{"propose": "done", "text": "done"}', None)])
        user = json.dumps({"endpoint": "https://x.test/get?id=1"})
        reply, tlog, err = self.A._json_action_loop("sys", user, tools, handlers, max_rounds=3)
        self.assertEqual(fetched, ["https://x.test/get?id=1"])
        self.assertEqual(tlog[0]["name"], "http_request")
        # the pre-fetched evidence must have reached the model's transcript
        self.assertIn("Live evidence", fake.calls[0][1])
        # http_request must NOT be offered back to the model as something to decide on
        self.assertNotIn("http_request(", fake.calls[0][0])

    def test_browser_oracle_capped_to_one_url_unlike_http_request(self):
        seen = []
        def domxss_proof(inp):
            seen.append(inp["url"])
            return json.dumps({"proven": False})
        tools = [{"name": "domxss_proof", "description": "x", "input_schema": {}}]
        handlers = {"domxss_proof": domxss_proof}
        self._patch_lc([('{"propose": "done", "text": "done"}', None)])
        user = json.dumps({"endpoint": "https://x.test/a", "other": "https://x.test/b"})
        self.A._json_action_loop("sys", user, tools, handlers, max_rounds=3)
        self.assertEqual(len(seen), 1)


class ClientRedirectOracle(unittest.TestCase):
    """exec-cdp.py's new deterministic client-side open-redirect oracle, with eval_in_page
    monkeypatched so no real Chrome/CDP connection is needed."""

    def setUp(self):
        self.cdp = load("exec-cdp")

    def test_nobrowser_short_circuits(self):
        self.cdp.eval_in_page = lambda port, url, js, settle=3.0: {"nobrowser": True, "error": "no Chrome"}
        r = self.cdp.prove_client_redirect(9222, "https://x.test/go?url=1")
        self.assertIsNone(r["proven"])
        self.assertTrue(r.get("nobrowser"))

    def test_marker_host_detected_proves_true(self):
        def fake_eval(port, url, js, settle=3.0):
            if "huntr-marker-57005.invalid" in url:
                return {"value": "huntr-marker-57005.invalid"}
            return {"value": "x.test"}
        self.cdp.eval_in_page = fake_eval
        r = self.cdp.prove_client_redirect(9222, "https://x.test/go", param="url")
        self.assertTrue(r["proven"])
        self.assertIn("huntr-marker-57005.invalid", r["evidence"])

    def test_marker_never_reached_proves_false(self):
        self.cdp.eval_in_page = lambda port, url, js, settle=3.0: {"value": "x.test"}
        r = self.cdp.prove_client_redirect(9222, "https://x.test/go", param="url")
        self.assertFalse(r["proven"])


class CliSlotDefaults(unittest.TestCase):
    """llm_client's cross-process slot pool must default to a safe cap under CLI mode even
    when the operator hasn't set HUNTR_LLM_SLOTS, since claude -p has a hard session-limit
    wall (no 429/backoff) that an unbounded pile-up of concurrent subprocesses can exhaust."""

    def setUp(self):
        self.lc = load("llm_client")
        self._env_keys = ("HUNTR_LLM_SLOTS", "HUNTR_CLI_SLOTS", "HUNT_LLM_VIA_CLI")
        self._saved = {k: os.environ.get(k) for k in self._env_keys}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_defaults_to_zero_outside_cli_mode(self):
        os.environ.pop("HUNTR_LLM_SLOTS", None)
        os.environ.pop("HUNT_LLM_VIA_CLI", None)
        self.assertEqual(self.lc._llm_slots(), 0)

    def test_defaults_to_two_under_cli_mode_when_unset(self):
        os.environ.pop("HUNTR_LLM_SLOTS", None)
        os.environ.pop("HUNTR_CLI_SLOTS", None)
        os.environ["HUNT_LLM_VIA_CLI"] = "1"
        self.assertEqual(self.lc._llm_slots(), 2)

    def test_explicit_cli_slots_override_respected(self):
        os.environ.pop("HUNTR_LLM_SLOTS", None)
        os.environ["HUNT_LLM_VIA_CLI"] = "1"
        os.environ["HUNTR_CLI_SLOTS"] = "5"
        self.assertEqual(self.lc._llm_slots(), 5)

    def test_explicit_llm_slots_wins_even_under_cli_mode(self):
        os.environ["HUNT_LLM_VIA_CLI"] = "1"
        os.environ["HUNTR_LLM_SLOTS"] = "7"
        self.assertEqual(self.lc._llm_slots(), 7)


if __name__ == "__main__":
    unittest.main()
