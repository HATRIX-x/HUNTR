"""Regression test: HUNT_LLM_PROVIDER resolution.

A stray comma-chain like "groq,anthropic" left in the environment used to make
the engine log one provider while using another. It must now resolve to the
first *supported* provider in the chain (so account-OAuth Anthropic is used),
and never silently route elsewhere.
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _llm_client():
    spec = importlib.util.spec_from_file_location("llm_client", TOOLS / "llm_client.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class ProviderResolution(unittest.TestCase):
    def setUp(self):
        self.lc = _llm_client()
        self._saved = os.environ.get("HUNT_LLM_PROVIDER")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("HUNT_LLM_PROVIDER", None)
        else:
            os.environ["HUNT_LLM_PROVIDER"] = self._saved

    def test_comma_chain_picks_first_supported(self):
        os.environ["HUNT_LLM_PROVIDER"] = "groq,anthropic"
        self.assertEqual(self.lc.get_provider_config()["provider"], "anthropic")

    def test_unset_defaults_to_anthropic(self):
        os.environ.pop("HUNT_LLM_PROVIDER", None)
        self.assertEqual(self.lc.get_provider_config()["provider"], "anthropic")

    def test_single_supported_provider_honored(self):
        os.environ["HUNT_LLM_PROVIDER"] = "openai"
        self.assertEqual(self.lc.get_provider_config()["provider"], "openai")

    def test_all_unsupported_chain_keeps_default(self):
        os.environ["HUNT_LLM_PROVIDER"] = "groq,cohere"
        self.assertEqual(self.lc.get_provider_config()["provider"], "anthropic")


if __name__ == "__main__":
    unittest.main()
