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
        # Disable LLM creds so /api/scope/parse stays deterministic + fast in tests
        # (no live model call / no rate-limit dependency).
        env = dict(os.environ, HUNTR_HOME=cls.home, HUNT_CLAUDE_CREDS="/nonexistent/creds.json")
        env.pop("ANTHROPIC_API_KEY", None)
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

    def test_raw_program_page_with_no_extractable_targets_is_refused(self):
        # Real incident (2026-10-15): a full HackerOne program page, pasted as `target` before the
        # client had a Haiku-classified scope_obj, fell through the deterministic-fallback-found-0-
        # targets branch with `t` never reset — so the ENTIRE RAW PAGE became hunt-run.py's literal
        # --target. Confirmed live: a `ps aux` showing `hunt-run.py --target Skip to main content >
        # ...` as an actual running process, which then whitespace/comma-split the prose into bogus
        # "hosts" (English words lifted out of scope-exclusion sentences) and produced false-positive
        # findings. This must always be refused with a clean 400, never silently started.
        page = ("Scope exclusions\nCore Ineligible Findings are out of scope. Learn more.\n\n"
                "Overview\nAcme is a wallet. DO NOT test Acme Exchange hosts.\n\n"
                "Known Findings but not limited to:\nAsset\tOut of scope finding class\n"
                "fiat.a.acme.io\tUnauthenticated signing oracle, including message read, write, "
                "delete, interception and credential ID or wallet UUID lookup\n")
        st, body = _req("POST", self.base + "/api/hunt/start", body={"target": page})
        self.assertEqual(st, 400)
        self.assertIn("couldn't find any in-scope targets", json.loads(body)["error"])

    def test_scope_obj_from_client_is_trusted_and_used_as_target(self):
        # The companion success path: when the client already ran Haiku classification (the live
        # preview) and sends scope_obj, the server must use ITS targets, not re-derive (and
        # potentially regress) with the fast/no-LLM fallback.
        target = "pidreuse-test-scopeobj.invalid"   # .invalid never resolves — DNS fails fast, no flakiness
        try:
            st, body = _req("POST", self.base + "/api/hunt/start", body={
                "target": "ignored raw page text that would otherwise fail extraction",
                "scope_obj": {"targets": [target], "allow": [target], "deny": []},
            })
            self.assertEqual(st, 200)
            self.assertEqual(json.loads(body)["target"], target)
        finally:
            subprocess.run(["pkill", "-9", "-f", f"hunt-run.py --target {target}"])

    def test_stale_non_hunt_pid_does_not_falsely_report_already_running(self):
        # A PID can be reused by the OS after the original hunt-run.py exits. The old check was a
        # bare `os.kill(pid, 0)` — alive-or-not only — so a stale run.pid left by a crashed hunt
        # could point at any unrelated live process and this would falsely claim
        # "already_running": true, leaving the operator believing a hunt is running when nothing is.
        target = "pidreuse-test-stale.invalid"
        hd = Path(self.home) / "targets" / target / ".hunt"
        hd.mkdir(parents=True, exist_ok=True)
        (hd / "run.pid").write_text(str(os.getpid()))   # this TEST process: alive, definitely not hunt-run.py
        try:
            st, body = _req("POST", self.base + "/api/hunt/start", body={"target": target})
            self.assertEqual(st, 200)
            self.assertNotIn("already_running", json.loads(body))
        finally:
            subprocess.run(["pkill", "-9", "-f", f"hunt-run.py --target {target}"])

    def test_credentials_file_created_with_restrictive_permissions(self):
        # creds.json holds session tokens/cookies in the clear. The old write_text()-then-chmod()
        # sequence had a real window where the file existed at the default umask (often group/world
        # readable) before chmod narrowed it. Must be 0600 from the moment it exists.
        target = "pidreuse-test-creds.invalid"
        try:
            st, _ = _req("POST", self.base + "/api/hunt/start",
                         body={"target": target, "session_token": "Bearer sekrit-token-value"})
            self.assertEqual(st, 200)
            cf = Path(self.home) / "targets" / target / ".hunt" / "creds.json"
            deadline = time.time() + 5
            while not cf.exists() and time.time() < deadline:
                time.sleep(0.1)
            self.assertTrue(cf.exists(), "creds.json was never written")
            self.assertEqual(oct(cf.stat().st_mode & 0o777), "0o600")
        finally:
            subprocess.run(["pkill", "-9", "-f", f"hunt-run.py --target {target}"])

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

    def test_scope_parse_extracts_assets_deterministically(self):
        page = ("In scope:\n*.acme.com\napi.acme.com\n\n"
                "Out of scope:\nlegacy.acme.com\nRewards: Critical $5000. PoC required.")
        st, body = _req("POST", self.base + "/api/scope/parse", body={"text": page})
        self.assertEqual(st, 200)
        sc = json.loads(body)["scope"]
        in_assets = {a["asset"] for a in sc["in_scope"]}
        self.assertIn("*.acme.com", in_assets)
        self.assertIn("api.acme.com", in_assets)
        self.assertIn("legacy.acme.com", {o["asset"] for o in sc["out_of_scope"]})
        # prose never becomes scope
        self.assertFalse(any("critical" in a for a in in_assets))

    def test_no_server_traceback_leaked(self):
        # After all the malformed probes above run in the suite, a 400 body must be a
        # clean JSON error, never a Python traceback dumped to the client.
        st, body = _req("POST", self.base + "/api/hunt/start", raw=b'["x"]')
        self.assertEqual(st, 400)
        self.assertNotIn("Traceback", body)


if __name__ == "__main__":
    unittest.main()
