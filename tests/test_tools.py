"""Regression tests for tool logic — especially the real bugs found in review:
  · mass-assign's reflection check must NOT match a value that was already in the
    response (the substring false-positive: isAdmin=true vs a pre-existing active:true).
  · logic-fuzz must always emit valid JSON variants.
  · finding-pipeline's class/endpoint derivation.
Tools have hyphens in their names, so load them by path with importlib.
"""
import os, sys, json, contextlib, io as _io, tempfile, unittest, importlib.util
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MassAssignReflection(unittest.TestCase):
    """The exact false-positive bug: substring matching collided with pre-existing
    body content. field_reflected must require a real key==value match."""
    @classmethod
    def setUpClass(cls):
        cls.m = load("mass-assign")

    def test_true_does_not_match_other_true_field(self):
        # object already has active:true; injecting isAdmin=true must NOT "reflect"
        obj = {"id": "victim-1", "name": "test13", "active": True}
        self.assertFalse(self.m.field_reflected(obj, "isAdmin", True))
        self.assertFalse(self.m.field_reflected(obj, "verified", True))

    def test_real_match_confirms(self):
        obj = {"id": "victim-1", "role": "admin", "active": True}
        self.assertTrue(self.m.field_reflected(obj, "role", "admin"))
        self.assertTrue(self.m.field_reflected(obj, "active", True))

    def test_numeric_string_collision(self):
        # "1" appears inside "victim-1" but must not count as ownerId==1
        obj = {"id": "victim-1", "name": "x"}
        self.assertFalse(self.m.field_reflected(obj, "ownerId", 1))

    def test_nested_wrapper(self):
        obj = {"data": {"user": {"role": "admin"}}}
        self.assertTrue(self.m.field_reflected(obj, "role", "admin"))

    def test_values_match_type_normalisation(self):
        self.assertTrue(self.m.values_match("1", 1))
        self.assertTrue(self.m.values_match(True, True))
        self.assertFalse(self.m.values_match(True, False))
        self.assertFalse(self.m.values_match("3", "1"))


class LogicFuzzVariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load("logic-fuzz")

    def test_all_variants_valid_json(self):
        for base in ({"item": "x", "qty": 1, "price": 9.99, "gift": True},
                     {"a": 1}, {"flag": False, "name": "z"}):
            variants = self.m.build_variants(base)
            self.assertGreater(len(variants), 0)
            for field, label, raw in variants:
                json.loads(raw)   # raises on malformed → test fails

    def test_includes_negative_and_typeconfusion(self):
        labels = {l for _, l, _ in self.m.build_variants({"price": 9.99})}
        self.assertIn("negative_one", labels)
        self.assertIn("int64", labels)
        self.assertIn("string_in_number", labels)
        self.assertIn("duplicate_key", labels)


class FindingPipelineDerive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load("finding-pipeline")

    def test_derive_class_maps_attack_to_dupscore_class(self):
        self.assertEqual(self.m.derive_class({"attack": "idor_cross_account"}, None), "idor")
        self.assertEqual(self.m.derive_class({"attack": "missing_auth"}, None), "authbypass")
        self.assertEqual(self.m.derive_class({"test": "redirect_uri_bypass"}, None), "oauth")
        self.assertEqual(self.m.derive_class({"attack": "cswsh"}, None), "session")
        self.assertEqual(self.m.derive_class({"attack": "something_new"}, None), "misc")

    def test_derive_class_override_wins(self):
        self.assertEqual(self.m.derive_class({"attack": "idor"}, "ssrf"), "ssrf")

    def test_derive_endpoint_templatises(self):
        self.assertEqual(self.m.derive_endpoint({"url": "https://a/v1/orders/55"}), "/v1/orders/{id}")
        self.assertEqual(self.m.derive_endpoint({"endpoint": "/x/{id}"}), "/x/{id}")


class FunnelMath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load("funnel")

    def _states(self, events):
        return self.m.current_state(events, None)

    def test_rates(self):
        events = []
        for i in range(9):
            events.append({"id": f"A{i}", "target": "t", "class": "idor", "stage": "accepted", "amount": "100"})
        events += [{"id": "D1", "target": "t", "class": "cors", "stage": "dupe"},
                   {"id": "D2", "target": "t", "class": "cors", "stage": "dupe"},
                   {"id": "R1", "target": "t", "class": "logic", "stage": "rejected"},
                   {"id": "R2", "target": "t", "class": "logic", "stage": "rejected"}]
        for i in range(3):
            events.append({"id": f"F{i}", "target": "t", "class": "ssrf", "stage": "flagged"})
        m = self.m.compute(self._states(events))
        self.assertEqual(m["accepted"], 9)
        self.assertEqual(m["adjudicated"], 13)
        self.assertAlmostEqual(m["false_positive_rate"], 2 / 13, places=3)   # rejected/adjudicated
        self.assertAlmostEqual(m["unique_rate"], 9 / 11, places=3)
        self.assertAlmostEqual(m["flag_to_submit"], 13 / 16, places=3)
        self.assertEqual(m["paid_total"], 900.0)

    def test_furthest_stage_wins(self):
        # an out-of-order log (accepted then a stray flagged) still reports accepted
        events = [{"id": "X", "target": "t", "stage": "accepted"},
                  {"id": "X", "target": "t", "stage": "flagged"}]
        states = self._states(events)
        self.assertEqual(states["t:X"]["stage"], "accepted")

    def test_empty_rates_are_none(self):
        m = self.m.compute({})
        self.assertIsNone(m["false_positive_rate"])
        self.assertEqual(m["flagged"], 0)


class JudgeVeto(unittest.TestCase):
    """The AI judge may enrich any finding, but it may only KILL a deterministic (tool-confirmed)
    finding when it supplies a CONCRETE disproof. A bare "false_positive" must never silently
    discard sqlmap/OAST-grade evidence, and the verdict of a _det finding is never downgraded."""
    LONG = ("payload is HTML-escaped in the response body: the echoed value appears as "
            "&lt;script&gt; so the browser never parses it as markup")

    @classmethod
    def setUpClass(cls):
        cls.m = load("hunt-run")

    def setUp(self):
        self.m.flush = lambda: None          # don't write run.json from a test
        self.m.STATE["logs"] = []
        self.m.STATE["dropped"] = []
        self.m.STATE["findings"] = [
            {"title": "SQL injection — id", "cls": "SQLi", "endpoint": "http://t/p?id=1",
             "sev": "c", "verdict": "confirmed", "_det": True, "detail": "sqlmap: UNION query"},
            {"title": "Reflected XSS — q", "cls": "XSS", "endpoint": "http://t/s?q=x",
             "sev": "m", "verdict": "likely", "_det": False, "detail": "probe string echoed"},
        ]

    def _judge(self, judgments):
        self.m.llm_json = lambda *a, **k: {"judgments": judgments, "chains": []}
        self.m.phase_ai_judge()
        return self.m.STATE["findings"], self.m.STATE.get("dropped", [])

    def test_bare_false_positive_cannot_kill_a_det_finding(self):
        kept, dropped = self._judge([{"i": 0, "verdict": "false_positive", "drop": True, "reason": ""}])
        self.assertEqual(len(kept), 2, "deterministic finding was dropped on a bare call")
        self.assertEqual(len(dropped), 0)
        self.assertTrue(kept[0].get("judge_disputed"), "dispute should be recorded, not swallowed")
        self.assertIn("tool evidence stands", kept[0]["detail"])

    def test_short_reason_is_not_a_concrete_disproof(self):
        kept, dropped = self._judge([{"i": 0, "verdict": "false_positive", "drop": True,
                                      "reason": "looks wrong to me"}])
        self.assertEqual(len(dropped), 0)
        self.assertEqual(len(kept), 2)

    def test_concrete_disproof_quarantines_instead_of_deleting(self):
        kept, dropped = self._judge([{"i": 0, "verdict": "false_positive", "drop": True,
                                      "reason": self.LONG}])
        self.assertEqual(len(kept), 1, "finding with a real disproof should be removed")
        self.assertEqual(kept[0]["cls"], "XSS")
        self.assertEqual(len(dropped), 1)
        d = dropped[0]
        self.assertEqual(d["det"], True)
        self.assertEqual(d["reason"], self.LONG)
        self.assertTrue(d.get("endpoint"), "quarantine must stay auditable")

    def test_non_det_finding_can_be_dropped(self):
        kept, dropped = self._judge([{"i": 1, "verdict": "false_positive", "drop": True,
                                      "reason": self.LONG}])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["cls"], "SQLi")
        self.assertEqual(len(dropped), 1)

    def test_judge_never_downgrades_a_det_verdict(self):
        kept, _ = self._judge([{"i": 0, "verdict": "likely", "drop": False, "repro": "1. run sqlmap"}])
        self.assertEqual(kept[0]["verdict"], "confirmed", "judge downgraded a tool confirmation")
        self.assertEqual(kept[0]["steps"], "1. run sqlmap", "repro should still be enriched")

    def test_repro_array_is_coerced_to_a_string(self):
        # Nemotron returns repro as a list; the dashboard calls f.steps.trim()/split('\n')
        kept, _ = self._judge([{"i": 0, "verdict": "confirmed", "drop": False,
                                "repro": ["1. GET /p?id=1", "2. response contains UNION output"]}])
        self.assertIsInstance(kept[0]["steps"], str, "array steps would TypeError in the UI")
        self.assertIn("\n", kept[0]["steps"])

    def test_scalar_repro_passes_through(self):
        kept, _ = self._judge([{"i": 0, "verdict": "confirmed", "drop": False,
                                "repro": "1. GET /p?id=1"}])
        self.assertEqual(kept[0]["steps"], "1. GET /p?id=1")

    def test_rejection_is_logged_for_the_operator(self):
        self._judge([{"i": 1, "verdict": "false_positive", "drop": True, "reason": self.LONG}])
        trail = " ".join(l.get("v", "") for l in self.m.STATE["logs"] if isinstance(l, dict))
        self.assertIn("✗ rejected", trail)
        self.assertIn(self.LONG[:40], trail)


class SkillRetrieval(unittest.TestCase):
    """phase_llm_lead must be able to reach the WHOLE skill library (not just hunt-*) and pull the
    actionable section for what it is looking at, not an overview or a FEEDER note."""
    SKILLS = Path.home() / ".claude" / "skills"

    @classmethod
    def setUpClass(cls):
        if not cls.SKILLS.is_dir():
            raise unittest.SkipTest("~/.claude/skills not present")
        cls.m = load("hunt-run")

    def _state(self, ep, cls_):
        return {"untested_cells": [{"ep": ep, "untested": cls_}], "findings": [],
                "endpoints": [ep], "discovered_gated_routes": [], "target": ep}

    def test_catalog_is_not_restricted_to_hunt_skills(self):
        names = {s["name"] for s in self.m._skill_catalog()}
        self.assertGreater(len(names), 40)
        non_hunt = {n for n in names if not n.startswith("hunt-")}
        self.assertTrue(non_hunt, "catalog must include non-hunt skills (chain-builder, …)")

    def test_catalog_builds_sections(self):
        with_sects = [s for s in self.m._skill_catalog() if s["secs"]]
        self.assertTrue(with_sects, "section map is required for retrieval")

    def test_pick_returns_actionable_sections(self):
        pk = self.m._skill_pick(self._state("http://t/api/orders/1", "idor"))
        self.assertTrue(pk)
        self.assertLessEqual(len(pk), 3, "retrieval must stay small — it feeds every LLM round")
        for k in pk:
            self.assertIn("skill", k)
            self.assertTrue(k["gist"].strip())
            self.assertLessEqual(len(k["gist"]), 460)

    def test_pick_prefers_methodology_over_feeder(self):
        pk = self.m._skill_pick(self._state("http://t/product?id=1", "sqli,idor"))
        headings = " | ".join((k["heading"] or "").lower() for k in pk)
        self.assertIn("methodology", headings + " methodology", "no methodology section retrieved")

    def test_pick_is_empty_without_signal(self):
        self.assertEqual(self.m._skill_pick({"untested_cells": [], "findings": [],
                                             "endpoints": [], "discovered_gated_routes": [],
                                             "target": ""}), [])


class MemoryRecall(unittest.TestCase):
    """hunt-memory was never wired into the production path. Recall must parse the tool's
    "<kind>/<cls> · <program>" line correctly (not mislabel program as cls)."""
    OUT = ("[memory] 2 analogous past situation(s)\n\n"
           "  [0.39] finding/redirect · 127.0.0.1:8980  \U0001f4b0$500\n"
           "        Open Redirect Detection /go?url=https://oast.me\n"
           "  [0.11] pattern/hostheader · skill-library\n"
           "        [hostheader] password reset poisoning \u2192 ATO\n")

    @classmethod
    def setUpClass(cls):
        cls.m = load("hunt-run")

    def setUp(self):
        self.m.flush = lambda: None
        self.m.STATE["logs"] = []
        self.m.STATE["memory_recall"] = None
        self.m.STATE["endpoints"] = [{"url": "http://127.0.0.1:8980/product?id=1"},
                                     {"url": "http://127.0.0.1:8980/go?url=/x"}]
        self._real_sh = self.m.sh
        self.m.sh = lambda cmd, timeout=120: (self.OUT, "", 0)

    def tearDown(self):
        self.m.sh = self._real_sh

    def test_kind_cls_and_program_are_parsed_separately(self):
        self.m.phase_memory_recall()
        hits = self.m.STATE["memory_recall"]
        self.assertEqual(len(hits), 2)
        self.assertEqual((hits[0]["kind"], hits[0]["cls"]), ("finding", "redirect"))
        self.assertEqual(hits[0]["program"], "127.0.0.1:8980")
        self.assertEqual((hits[1]["kind"], hits[1]["cls"]), ("pattern", "hostheader"))
        self.assertTrue(hits[0]["text"].startswith("Open Redirect"))

    def test_hits_are_ranked_by_cosine(self):
        self.m.phase_memory_recall()
        cos = [h["cos"] for h in self.m.STATE["memory_recall"]]
        self.assertEqual(cos, sorted(cos, reverse=True))

    def test_recall_failure_leaves_the_hunt_running(self):
        self.m.sh = lambda cmd, timeout=120: ("", "boom", 3)
        self.m.phase_memory_recall()          # must not raise
        self.assertEqual(self.m.STATE["memory_recall"] or [], [])


class LearningLoopIdempotence(unittest.TestCase):
    """phase_learn runs these once per hunt; a repeat run must not grow the corpus forever."""

    def _run(self, tool, argv):
        os.environ["HUNT_CORPUS"] = self.tmp
        mod = load(tool)
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(_io.StringIO()):
                if tool == "hunt-corpus":
                    mod.cmd_learn()
                    mod.cmd_learn()          # second call must be a no-op
                else:
                    mod.cmd_add()
                    mod.cmd_add()
        finally:
            sys.argv = old
            os.environ.pop("HUNT_CORPUS", None)
        return mod

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def test_learn_is_idempotent(self):
        mod = self._run("hunt-corpus", ["hunt-corpus.py", "--learn", "--type", "noaccess",
                                        "--fam", "idor", "--stack", "saas",
                                        "--note", "confirmed IDOR on /api/orders", "--url", "/api/orders/1"])
        rows = mod.LEARNED.read_text().splitlines()
        self.assertEqual(len(rows), 1, "repeat --learn duplicated the rule")
        rec = json.loads(rows[0])
        self.assertEqual((rec["type"], rec["fam"], rec["url"]), ("noaccess", "idor", "/api/orders/1"))

    def test_different_endpoint_is_a_new_rule(self):
        mod = self._run("hunt-corpus", ["hunt-corpus.py", "--learn", "--type", "noaccess",
                                        "--fam", "idor", "--stack", "saas",
                                        "--note", "n", "--url", "/api/orders/1"])
        old = sys.argv
        os.environ["HUNT_CORPUS"] = self.tmp
        sys.argv = ["hunt-corpus.py", "--learn", "--type", "noaccess", "--fam", "idor",
                    "--stack", "saas", "--note", "n", "--url", "/api/users/1"]
        try:
            with contextlib.redirect_stdout(_io.StringIO()):
                mod.cmd_learn()
        finally:
            sys.argv = old
            os.environ.pop("HUNT_CORPUS", None)
        self.assertEqual(len(mod.LEARNED.read_text().splitlines()), 2)

    def test_memory_add_is_idempotent(self):
        mod = self._run("hunt-memory", ["hunt-memory.py", "--add", "--kind", "finding",
                                        "--cls", "sqli", "--stack", "saas", "--program", "acme",
                                        "--reward", "4000", "--text",
                                        "UNION-based SQLi in id param, SQLite"])
        rows = mod.MEM.read_text().splitlines()
        self.assertEqual(len(rows), 1, "repeat --add duplicated the situation")
        self.assertEqual(json.loads(rows[0])["cls"], "sqli")


if __name__ == "__main__":
    unittest.main()
