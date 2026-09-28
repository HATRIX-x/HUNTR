"""Regression tests for tool logic — especially the real bugs found in review:
  · mass-assign's reflection check must NOT match a value that was already in the
    response (the substring false-positive: isAdmin=true vs a pre-existing active:true).
  · logic-fuzz must always emit valid JSON variants.
  · finding-pipeline's class/endpoint derivation.
Tools have hyphens in their names, so load them by path with importlib.
"""
import sys, json, unittest, importlib.util
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


if __name__ == "__main__":
    unittest.main()
