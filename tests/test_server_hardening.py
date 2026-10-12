"""Integration regression tests for the huntr-server HTTP bridge.

Locks in the input-handling fixes from the dashboard audit so they can never
regress: malformed/oversized/wrong-shape input must return a clean 4xx (never a
dropped connection or a 5xx with a traceback), and the health endpoint must
report liveness. Boots the real server as a subprocess on an isolated
HUNTR_HOME + test port so it never touches a real ~/.huntr instance.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "huntr-server.py"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _req(method, url, body=None, raw=None, timeout=10):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8", "replace") if e.fp else "")


class ServerHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.home = tempfile.mkdtemp(prefix="huntr-test-home-")
        env = dict(os.environ, HUNTR_HOME=cls.home)
        cls.proc = subprocess.Popen(
            [sys.executable, str(SERVER), "--port", str(cls.port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=str(REPO),
        )
        cls.base = f"http://127.0.0.1:{cls.port}"
        # wait for readiness
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                st, _ = _req("GET", cls.base + "/api/health", timeout=2)
                if st == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            out = cls.proc.stdout.read().decode("utf-8", "replace") if cls.proc.stdout else ""
            raise RuntimeError(f"server did not start:\n{out}")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except Exception:
            cls.proc.kill()

    def test_health_reports_liveness(self):
        st, body = _req("GET", self.base + "/api/health")
        self.assertEqual(st, 200)
        d = json.loads(body)
        self.assertTrue(d["ok"])
        self.assertIn("uptime_sec", d)
        self.assertIn("active_hunts", d)

    def test_non_object_json_body_is_400_not_crash(self):
        # A JSON array/number/string has no .get; used to crash do_POST before any response.
        for raw in (b'["a","b"]', b"42", b'"x"', b"null"):
            st, _ = _req("POST", self.base + "/api/hunt/start", raw=raw)
            self.assertEqual(st, 400, f"body {raw!r} should 400")

    def test_blank_target_is_400(self):
        st, _ = _req("POST", self.base + "/api/hunt/start", body={"target": "   "})
        self.assertEqual(st, 400)

    def test_bad_base64_upload_is_400(self):
        st, _ = _req("POST", self.base + "/api/mobile/upload",
                     body={"filename": "x.apk", "data_b64": "@@@not base64@@@"})
        self.assertEqual(st, 400)

    def test_slow_get_without_target_is_400_fast(self):
        start = time.time()
        st, _ = _req("GET", self.base + "/api/hunt/kgraph", timeout=8)
        self.assertEqual(st, 400)
        self.assertLess(time.time() - start, 5, "should reject immediately, not shell out")

    def test_oversized_get_query_is_handled(self):
        st, _ = _req("GET", self.base + "/api/hunt/status?target=" + ("A" * 100_000))
        self.assertGreaterEqual(st, 400)   # 414 from stdlib; must not be a crash/5xx
        self.assertLess(st, 500)

    def test_no_server_traceback_leaked(self):
        # After all the malformed probes above run in the suite, a 400 body must be a
        # clean JSON error, never a Python traceback dumped to the client.
        st, body = _req("POST", self.base + "/api/hunt/start", raw=b'["x"]')
        self.assertEqual(st, 400)
        self.assertNotIn("Traceback", body)


if __name__ == "__main__":
    unittest.main()
