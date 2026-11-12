"""Phase-1 regression tests: the outcome learning loop.

Verifies the funnel -> learning-store bridge and that learned priors behave:
human adjudications become labels, syncing is idempotent, a rejected-heavy class
scores low acceptance (and trips the FP pre-kill), and ranking orders by EV.
Everything runs on an isolated HUNT_CORPUS / HUNTR_FUNNEL, no network, no LLM.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
sys.path.insert(0, str(TOOLS))


class OutcomeLoop(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="huntr-outcome-")
        os.environ["HUNT_CORPUS"] = self.tmp
        os.environ["HUNTR_FUNNEL"] = str(Path(self.tmp) / "funnel.jsonl")
        # fresh import each test so module-level caches don't leak the env
        for m in ("outcome_priors", "outcome_check"):
            sys.modules.pop(m, None)
        import outcome_priors
        self.op = outcome_priors
        self.op._OC = None  # reset cached outcome-check module

    def _events(self):
        # idor keeps getting accepted/paid; cors keeps getting rejected (5 rejects)
        return [
            {"id": "F1", "class": "idor", "stage": "accepted", "target": "acme"},
            {"id": "F2", "class": "idor", "stage": "paid", "amount": 500, "target": "acme"},
            {"id": "F3", "class": "cors", "stage": "rejected", "target": "acme"},
            {"id": "F4", "class": "cors", "stage": "rejected", "target": "acme"},
            {"id": "F5", "class": "cors", "stage": "rejected", "target": "acme"},
            {"id": "F6", "class": "cors", "stage": "rejected", "target": "acme"},
            {"id": "F7", "class": "cors", "stage": "rejected", "target": "acme"},
            {"id": "F8", "class": "idor", "stage": "flagged", "target": "acme"},  # non-terminal, skipped
        ]

    def test_bridge_writes_only_terminal_events(self):
        written = self.op.sync_from_funnel(self._events())
        # F8 is non-terminal (flagged) -> not bridged; F1..F7 are terminal (7)
        self.assertEqual(len(written), 7)
        store = Path(self.tmp) / "outcomes.jsonl"
        self.assertTrue(store.exists())
        recs = [json.loads(l) for l in store.read_text().splitlines() if l.strip()]
        self.assertEqual(len(recs), 7)
        self.assertEqual({r["verdict"] for r in recs if r["cls"] == "cors"}, {"rejected"})
        paid = [r for r in recs if r["verdict"] == "paid"]
        self.assertEqual(paid[0]["reward"], 500.0)

    def test_sync_is_idempotent(self):
        self.assertEqual(len(self.op.sync_from_funnel(self._events())), 7)
        # second sync of the same events writes nothing (dedup by src_funnel_id)
        self.assertEqual(len(self.op.sync_from_funnel(self._events())), 0)

    def test_priors_reflect_labels(self):
        self.op.sync_from_funnel(self._events())
        pr = self.op.priors()
        # idor: 2/2 accepted -> high p_accept; cors: 0/5 -> low
        self.assertGreater(pr["idor"]["p_accept"], pr["cors"]["p_accept"])
        self.assertGreater(pr["idor"]["ev"], pr["cors"]["ev"])

    def test_fp_signal_holds_rejected_class_not_cold_class(self):
        self.op.sync_from_funnel(self._events())
        cors = self.op.fp_signal("cors")      # 0/5 accepted, enough history
        self.assertEqual(cors["bias"], "hold")
        self.assertIn("rejected", cors["reason"])
        idor = self.op.fp_signal("idor")      # accepted class -> no penalty
        self.assertIsNone(idor["bias"])
        # a class with no history must never be penalised
        self.assertIsNone(self.op.fp_signal("ssrf")["bias"])

    def test_rank_classes_orders_by_ev(self):
        self.op.sync_from_funnel(self._events())
        ranked = self.op.rank_classes(["cors", "idor"])
        self.assertEqual(ranked[0][0], "idor")   # higher EV first

    def test_funnel_cli_sync_outcomes(self):
        funnel = Path(os.environ["HUNTR_FUNNEL"])
        funnel.parent.mkdir(parents=True, exist_ok=True)
        funnel.write_text("\n".join(json.dumps(e) for e in self._events()) + "\n")
        env = dict(os.environ)
        r = subprocess.run([sys.executable, str(TOOLS / "funnel.py"), "--sync-outcomes", "--json"],
                           capture_output=True, text=True, env=env, cwd=str(REPO))
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertTrue(out["ok"])
        self.assertEqual(out["bridged"], 7)

    def tearDown(self):
        for k in ("HUNT_CORPUS", "HUNTR_FUNNEL"):
            os.environ.pop(k, None)


if __name__ == "__main__":
    unittest.main()
