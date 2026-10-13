"""Bet #3 regression test: one-click, triager-trustable reproduction.

Every finding ships a deterministic command that reproduces it + the exact signal
to look for. This locks (a) the command is well-formed and injects the right
payload/header per class, and (b) — gated, live — the generated command actually
reproduces the planted bug against the lab. The trust layer: run one line, see
the signal, it's real.
"""
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
sys.path.insert(0, str(TOOLS))

import proof_repro as pr  # noqa: E402


class ReproShape(unittest.TestCase):
    def _r(self, cls, endpoint, **kw):
        return pr.repro_for({"cls": cls, "endpoint": endpoint, **kw})

    def test_each_class_yields_cmd_expect_note(self):
        for cls, ep in (("sqli", "http://x/p?id=1"), ("xss", "http://x/s?q=1"),
                        ("ssti", "http://x/g?name=1"), ("ssrf", "http://x/f?url=1"),
                        ("lfi", "http://x/d?file=1"), ("cors", "http://x/api/data"),
                        ("idor", "http://x/a?uid=1"), ("redirect", "http://x/go?url=1")):
            r = self._r(cls, ep)
            self.assertIsNotNone(r, cls)
            self.assertTrue(r["cmd"].startswith("curl "), cls)
            self.assertTrue(r["expect"] and r["note"], cls)

    def test_payload_injected_into_right_param(self):
        self.assertIn("id=1%27", self._r("sqli", "http://x/p?id=1", param="id")["cmd"])
        self.assertIn("9359", "".join(pr._PAYLOADS["ssti"]))           # payload yields the signal
        self.assertIn("169.254.169.254", self._r("ssrf", "http://x/f?url=z", param="url")["cmd"])
        self.assertIn("etc", self._r("lfi", "http://x/d?file=z", param="file")["cmd"])

    def test_cors_uses_attacker_origin_header(self):
        r = self._r("cors", "http://x/api/data")
        self.assertIn("Origin: https://evil.example", r["cmd"])
        self.assertIn("-I", r["cmd"])

    def test_unmappable_without_endpoint_is_none(self):
        self.assertIsNone(pr.repro_for({"cls": "sqli"}))


@unittest.skipUnless(os.environ.get("HUNT_RUN_SLOW") == "1",
                     "live repro check — set HUNT_RUN_SLOW=1")
class ReproReproducesLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import socket
        s = socket.socket(); s.bind(("127.0.0.1", 0)); cls.port = s.getsockname()[1]; s.close()
        cls.lab = subprocess.Popen([sys.executable, str(REPO / "bench" / "labs.py"), "--port", str(cls.port)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import urllib.request
        for _ in range(40):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/", timeout=1); break
            except Exception:
                time.sleep(0.25)

    @classmethod
    def tearDownClass(cls):
        try: cls.lab.terminate(); cls.lab.wait(timeout=5)
        except Exception:
            try: cls.lab.kill()
            except Exception: pass

    def _run(self, cls, path, param, signals):
        ep = f"http://127.0.0.1:{self.port}{path}"
        r = pr.repro_for({"cls": cls, "endpoint": ep, "param": param})
        out = subprocess.run(r["cmd"], shell=True, capture_output=True, text=True, timeout=30).stdout
        self.assertTrue(any(s.lower() in out.lower() for s in signals),
                        f"{cls} repro did not reproduce: {r['cmd']}")

    def test_sqli_repro_reproduces(self):  self._run("sqli", "/product?id=1", "id", ["error", "sqlite", "syntax", "unrecognized"])
    def test_xss_repro_reproduces(self):   self._run("xss", "/search?q=hi", "q", ["<script>alert(1)"])
    def test_ssti_repro_reproduces(self):  self._run("ssti", "/greet?name=x", "name", ["9359"])
    def test_lfi_repro_reproduces(self):   self._run("lfi", "/download?file=readme.txt", "file", ["root:"])
    def test_cors_repro_reproduces(self):  self._run("cors", "/api/data", None, ["evil.example"])


if __name__ == "__main__":
    unittest.main()
