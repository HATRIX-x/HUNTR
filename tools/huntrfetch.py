"""
huntrfetch — one HTTP call that survives the WAF.

The deterministic scanners (param-fuzz / idor-chain / auth-bypass / …) fetch with urllib + the session
cookie. On a Cloudflare/Akamai target that works until __cf_bm expires, then every request is challenged
(403/JS interstitial) and the scanner goes blind — only the CDP exploit-agent survives. This shim lets a
scanner route the SAME request through the already-running debug Chrome (in-page fetch, same-origin, live
session, passes the bot manager) WHEN `HUNT_CDP_PORT` is set, and otherwise behaves exactly like urllib.

Contract (drop-in, never raises for a network error — returns status 0):
    http(method, url, headers=None, data=None, timeout=12) -> (status:int, body:str)

Design guarantees (so it cannot break a working scanner):
  • No HUNT_CDP_PORT  → `cdp_available()` is False; callers keep their existing urllib path untouched.
  • CDP set but the fetch fails for any reason → raises, so the caller's try/except falls back to urllib.
  • Same-origin only (in-page fetch); cross-origin is left to urllib. Scanners test the target origin.
Only used for sequential scanners; race-fire keeps raw sockets (CDP would serialize and kill the race).
"""
import os, json, socket, base64, struct, threading, urllib.request, urllib.parse, ssl

_LOCK = threading.Lock()
_WS = None          # cached CDP websocket
_WS_PORT = None
_ID = [0]

def cdp_available():
    return bool(os.environ.get("HUNT_CDP_PORT"))

# ── CDP websocket (minimal, stdlib) ──────────────────────────────────────────────────────────────
def _ws_open(port):
    tr = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=5))
    pages = [t for t in tr if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    if not pages:
        raise RuntimeError("no CDP page target")
    url = pages[0]["webSocketDebuggerUrl"]
    hostport, path = url[5:].split("/", 1); path = "/" + path
    host, p = hostport.split(":")
    s = socket.create_connection((host, int(p)), timeout=20)
    key = base64.b64encode(os.urandom(16)).decode()
    s.send((f"GET {path} HTTP/1.1\r\nHost: {host}:{p}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s

def _ws_send(s, obj):
    data = json.dumps(obj).encode()
    hdr = bytearray([0x81]); mask = os.urandom(4); ln = len(data)
    if ln < 126: hdr.append(0x80 | ln)
    elif ln < 65536: hdr.append(0x80 | 126); hdr += struct.pack(">H", ln)
    else: hdr.append(0x80 | 127); hdr += struct.pack(">Q", ln)
    hdr += mask
    s.send(bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

def _ws_recv(s):
    b1 = s.recv(1)
    if not b1: return None
    ln = s.recv(1)[0] & 0x7f
    if ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
    elif ln == 127: ln = struct.unpack(">Q", s.recv(8))[0]
    d = b""
    while len(d) < ln:
        c = s.recv(ln - len(d))
        if not c: break
        d += c
    try: return json.loads(d.decode())
    except Exception: return None

def _cdp_cmd(s, method, params, tries=600):
    _ID[0] += 1; i = _ID[0]
    _ws_send(s, {"id": i, "method": method, "params": params or {}})
    for _ in range(tries):
        m = _ws_recv(s)
        if m and m.get("id") == i:
            return m
    return None

def _cdp_http(method, url, headers, data, timeout):
    global _WS, _WS_PORT
    port = os.environ.get("HUNT_CDP_PORT")
    with _LOCK:
        if _WS is None or _WS_PORT != port:
            _WS = _ws_open(port); _WS_PORT = port
            _cdp_cmd(_WS, "Runtime.enable", {})
        # headers minus ones the browser forbids setting on fetch()
        hdrs = {k: v for k, v in (headers or {}).items()
                if k.lower() not in ("host", "cookie", "content-length", "connection", "accept-encoding")}
        body = data.decode("utf-8", "ignore") if isinstance(data, (bytes, bytearray)) else (data or "")
        opts = {"method": method.upper(), "credentials": "include",
                "headers": hdrs}
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE") and body:
            opts["body"] = body
        expr = ("(async()=>{try{const r=await fetch(" + json.dumps(url) + "," + json.dumps(opts) + ");"
                "const t=await r.text();return JSON.stringify({s:r.status,b:t.slice(0,65536)});}"
                "catch(e){return JSON.stringify({s:0,b:'cdp-fetch-err:'+e});}})()")
        r = _cdp_cmd(_WS, "Runtime.evaluate",
                     {"expression": expr, "awaitPromise": True, "returnByValue": True, "timeout": timeout * 1000})
        val = (((r or {}).get("result") or {}).get("result") or {}).get("value")
        if val is None:
            # context may have been torn down (navigation) — drop the cached ws so next call reopens
            _WS = None
            raise RuntimeError("cdp no result")
        o = json.loads(val)
        return int(o.get("s", 0)), o.get("b", "")

def _urllib_http(method, url, headers, data, timeout):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPHandler())
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(65536).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try: b = e.read(8192).decode("utf-8", "ignore")
        except Exception: b = ""
        return e.code, b
    except Exception as ex:
        return 0, str(ex)[:200]

def http(method, url, headers=None, data=None, timeout=12):
    """Route through CDP when HUNT_CDP_PORT is set (WAF-surviving), else urllib. Returns (status, body)."""
    # Merge program auth header(s) (e.g. Files.com's X-FilesAPI-Auth) — the browser's in-page fetch does
    # NOT add them automatically (the app's JS does), so inject them on every request. Explicit headers win.
    merged = {}
    try:
        merged.update(json.loads(os.environ.get("HUNT_AUTH_HEADERS", "") or "{}") or {})
    except Exception:
        pass
    merged.update(headers or {})
    headers = merged or None
    if cdp_available():
        return _cdp_http(method, url, headers, data, timeout)   # may raise → caller falls back to urllib
    return _urllib_http(method, url, headers, data, timeout)
