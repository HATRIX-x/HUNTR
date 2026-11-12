#!/usr/bin/env python3
"""
js-api-harvest — mine a JS SPA's REAL API surface from its bundles over CDP.

katana only follows linked HTML, and passive XHR capture (browser-capture.py) records only the calls
the app happens to FIRE during a bare navigation — a server-rendered SPA fires almost none without clicks,
so both miss the authenticated API entirely. This tool drives the already-running debug Chrome, fetches
every loaded same-origin .js bundle IN-PAGE (so it carries the live session + passes the bot manager),
and regex-extracts the API path literals (/v1/.., /api/.., /v2/.., /v3/..) that the app's code declares.
On the CoinTR grey hunt this turned 0 discovered API endpoints into 530.

Usage:
  js-api-harvest.py --cdp-port 9222 --origin https://www.cointr.com [--nav] [--json]

Output (--json): {"origin":..., "scripts":N, "paths":[...], "urls":[...]}  (urls = origin + path)
Exit 0 always (harvest is best-effort); empty paths on failure.
"""
import json, sys, socket, base64, struct, os, urllib.request, time, re

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv

def ws_connect(url):
    assert url.startswith("ws://")
    hostport, path = url[5:].split("/", 1); path = "/" + path
    host, port = hostport.split(":"); port = int(port)
    s = socket.create_connection((host, port), timeout=15)
    key = base64.b64encode(os.urandom(16)).decode()
    s.send((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s

def ws_send(s, obj):
    data = json.dumps(obj).encode()
    hdr = bytearray([0x81]); mask = os.urandom(4); ln = len(data)
    if ln < 126: hdr.append(0x80 | ln)
    elif ln < 65536: hdr.append(0x80 | 126); hdr += struct.pack(">H", ln)
    else: hdr.append(0x80 | 127); hdr += struct.pack(">Q", ln)
    hdr += mask
    s.send(bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

def ws_recv(s):
    b1 = s.recv(1)
    if not b1: return None
    ln = s.recv(1)[0] & 0x7f
    if ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
    elif ln == 127: ln = struct.unpack(">Q", s.recv(8))[0]
    data = b""
    while len(data) < ln:
        chunk = s.recv(ln - len(data))
        if not chunk: break
        data += chunk
    try: return json.loads(data.decode())
    except Exception: return None

def cmd(s, i, method, params=None, tries=400):
    ws_send(s, {"id": i, "method": method, "params": params or {}})
    for _ in range(tries):
        m = ws_recv(s)
        if m and m.get("id") == i:
            return m
    return None

def main():
    port = arg("--cdp-port", "9222")
    origin = (arg("--origin") or "").rstrip("/")
    result = {"origin": origin, "scripts": 0, "paths": [], "urls": [], "ws": []}
    try:
        targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=5))
        pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
        if not pages:
            print(json.dumps({**result, "error": "no page target"})); return
        s = ws_connect(pages[0]["webSocketDebuggerUrl"])
        cmd(s, 1, "Runtime.enable")
        if flag("--nav") and origin:
            cmd(s, 2, "Page.enable")
            cmd(s, 3, "Page.navigate", {"url": origin + "/"})
            time.sleep(6)
        host = re.sub(r"^https?://", "", origin).split("/")[0]
        # in-page: fetch every loaded same-origin .js, extract API path literals
        expr = r"""
        (async () => {
          const host = %s;
          const res = performance.getEntriesByType('resource').map(e=>e.name)
                       .filter(u=>/\.js(\?|$)/.test(u) && u.includes(host));
          const uniq = [...new Set(res)];
          const paths = new Set(), ws = new Set();
          const RE = /["'`](\/(?:v\d+|api|rest|gateway|service)\/[a-zA-Z0-9_\/\-{}:.]{2,120})["'`]/g;
          const WS = /["'`](wss?:\/\/[a-zA-Z0-9_.\-\/:{}]{4,160}|\/(?:ws|websocket|socket|stream|stomp|hub|cable|sockjs)[a-zA-Z0-9_\/\-]{0,80})["'`]/g;
          for (const u of uniq) {
            try {
              const t = await (await fetch(u,{credentials:'include'})).text();
              let m; while ((m = RE.exec(t))) paths.add(m[1]);
              let w; while ((w = WS.exec(t))) ws.add(w[1]);
            } catch(e){}
          }
          return JSON.stringify({scripts: uniq.length, paths: [...paths].sort(), ws: [...ws].sort()});
        })()
        """ % json.dumps(host)
        r = cmd(s, 10, "Runtime.evaluate", {"expression": expr, "awaitPromise": True, "returnByValue": True})
        val = (((r or {}).get("result") or {}).get("result") or {}).get("value")
        if val:
            o = json.loads(val)
            result["scripts"] = o.get("scripts", 0)
            result["paths"] = o.get("paths", [])
            result["ws"] = o.get("ws", [])
            result["urls"] = [origin + p for p in result["paths"]]
    except Exception as e:
        result["error"] = str(e)[:160]
    if flag("--json"):
        print(json.dumps(result))
    else:
        print(f"origin {origin} · {result['scripts']} bundles · {len(result['paths'])} API paths")
        for p in result["paths"]:
            print(" ", p)

if __name__ == "__main__":
    main()
