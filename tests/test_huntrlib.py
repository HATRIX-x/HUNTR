"""Tests for the shared core (huntrlib). Stdlib unittest, zero deps."""
import sys, os, json, unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import huntrlib as H          # noqa: E402
import mock_target            # noqa: E402


class ArgvHelpers(unittest.TestCase):
    def setUp(self):
        self._argv = sys.argv

    def tearDown(self):
        sys.argv = self._argv

    def test_arg_and_default(self):
        sys.argv = ["t", "--url", "https://x", "--json"]
        self.assertEqual(H.arg("--url"), "https://x")
        self.assertIsNone(H.arg("--missing"))
        self.assertEqual(H.arg("--missing", "d"), "d")

    def test_flag(self):
        sys.argv = ["t", "--json"]
        self.assertTrue(H.flag("--json"))
        self.assertFalse(H.flag("--verbose"))

    def test_args_multi(self):
        sys.argv = ["t", "--header", "A: 1", "--header", "B: 2"]
        self.assertEqual(H.args_multi("--header"), ["A: 1", "B: 2"])

    def test_as_int(self):
        sys.argv = ["t", "--count", "50"]
        self.assertEqual(H.as_int("--count", 10), 50)
        sys.argv = ["t", "--count", "notanint"]
        self.assertEqual(H.as_int("--count", 10), 10)
        sys.argv = ["t"]
        self.assertEqual(H.as_int("--count", 10), 10)


class Envelope(unittest.TestCase):
    def test_shape(self):
        e = H.envelope(findings=[{"a": 1}], url="u", extra="x")
        self.assertEqual(e["total"], 1)
        self.assertEqual(e["url"], "u")
        self.assertEqual(e["extra"], "x")
        self.assertIn("ts", e)
        self.assertEqual(e["findings"], [{"a": 1}])

    def test_empty(self):
        e = H.envelope()
        self.assertEqual(e["total"], 0)
        self.assertEqual(e["findings"], [])


class NormEndpoint(unittest.TestCase):
    def test_numeric_and_hash(self):
        self.assertEqual(H.norm_endpoint("/orders/1337"), "/orders/{id}")
        self.assertEqual(H.norm_endpoint("/u/deadbeefcafe0001/x"), "/u/{id}/x")
        self.assertEqual(H.norm_endpoint(""), "/")


class NormAuth(unittest.TestCase):
    def test_bearer(self):
        self.assertEqual(H.norm_auth("abc"), "Bearer abc")
        self.assertEqual(H.norm_auth("Bearer abc"), "Bearer abc")
        self.assertEqual(H.norm_auth("Basic xyz"), "Basic xyz")
        self.assertIsNone(H.norm_auth(""))


class HttpClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = mock_target.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_get_json(self):
        r = H.http(self.base + "/orders/55")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.ok)
        self.assertEqual(r.json()["owner"], "someone")
        self.assertGreater(r.size, 0)

    def test_status_passthrough(self):
        self.assertEqual(H.http(self.base + "/status/404").status, 404)
        self.assertEqual(H.http(self.base + "/status/500").status, 500)

    def test_network_error_is_resp_not_raise(self):
        r = H.http("http://127.0.0.1:1/nope", timeout=2)
        self.assertEqual(r.status, 0)
        self.assertFalse(r.ok)
        self.assertTrue(r.error)

    def test_post_dict_body_json(self):
        r = H.http(self.base + "/checkout", method="POST", body={"price": 9.99, "qty": 1})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["charged"], 9.99)

    def test_token_becomes_authorization(self):
        # /echo doesn't reflect headers, but the call must succeed with a token set
        r = H.http(self.base + "/echo?x=1", token="sometoken")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json()["query"]["x"], "1")

    def test_no_follow_exposes_location(self):
        r = H.http(self.base + "/redirect", follow=False)
        self.assertIn(r.status, (301, 302, 303, 307, 308))
        self.assertEqual(r.header("Location"), "/orders/1")

    def test_add_query(self):
        u = H.add_query(self.base + "/echo", "y", "2 3")
        r = H.http(u)
        self.assertEqual(r.json()["query"]["y"], "2 3")


if __name__ == "__main__":
    unittest.main()
