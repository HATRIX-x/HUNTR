"""Reusable in-process mock target for HUNTR tests.

start() spins up a ThreadingHTTPServer on an ephemeral port and returns
(server, base_url). It models the behaviours the probes care about:
  GET  /orders/<id>       → 200 {"order","owner"}          (IDOR surface)
  GET  /echo?<qs>         → 200 {"method","query"}         (param reflection)
  GET  /status/<code>     → returns <code>
  GET  /admin/users       → 200 (no real auth)             (auth-bypass surface)
  GET  /redirect          → 302 Location: /orders/1        (no-follow test)
  POST /checkout          → 200 echoes body                (logic-fuzz surface)
  PUT  /user/update       → 204, stores ANY field          (mass-assign permissive)
  PUT  /strict/update     → 204, stores only whitelist     (mass-assign strict)
  GET  /user/<id>         → 200 stored object
"""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_DB = {"victim-1": {"id": "victim-1", "name": "test13", "type": "3", "active": True}}
_ALLOWED = {"name", "firstName", "lastName"}


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj=b""):
        body = obj.encode() if isinstance(obj, str) else obj
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, to):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        p = u.path
        if p == "/redirect":
            return self._redirect("/orders/1")
        if p.startswith("/status/"):
            try:
                return self._send(int(p.split("/")[-1]), "{}")
            except ValueError:
                return self._send(400, "{}")
        if p.startswith("/orders/"):
            oid = p.split("/")[-1]
            return self._send(200, json.dumps({"order": oid, "owner": "someone"}))
        if p.startswith("/user/"):
            oid = p.split("/")[-1]
            return self._send(200, json.dumps(_DB[oid])) if oid in _DB else self._send(404, "{}")
        if p == "/admin/users":
            return self._send(200, json.dumps({"users": ["a", "b"]}))
        if p == "/echo":
            return self._send(200, json.dumps({"method": "GET",
                                               "query": {k: v[0] for k, v in parse_qs(u.query).items()}}))
        return self._send(404, "{}")

    def _read_json(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def do_POST(self):
        if self.path.startswith("/checkout"):
            b = self._read_json()
            return self._send(200, json.dumps({"ok": True, "charged": b.get("price"), "qty": b.get("qty")}))
        return self._send(404, "{}")

    def do_PUT(self):
        b = self._read_json()
        oid = b.get("id")
        if self.path.startswith("/strict/update"):
            if oid in _DB:
                for k, v in b.items():
                    if k in _ALLOWED:
                        _DB[oid][k] = v
                return self._send(204)
            return self._send(404, "{}")
        if self.path.startswith("/user/update"):
            if oid in _DB:
                for k, v in b.items():
                    if k != "id":
                        _DB[oid][k] = v
                return self._send(204)
            return self._send(404, "{}")
        return self._send(404, "{}")


def reset_db():
    _DB.clear()
    _DB["victim-1"] = {"id": "victim-1", "name": "test13", "type": "3", "active": True}


def start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    return srv, f"http://127.0.0.1:{port}"
