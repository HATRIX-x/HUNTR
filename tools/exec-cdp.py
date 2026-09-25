#!/usr/bin/env python3
"""
exec-cdp — fire requests from your REAL logged-in Chrome (DevTools Protocol), not curl.

Bot managers (Akamai, Cloudflare, PerimeterX) and JS-heavy apps defeat curl. This drives a real Chrome
over CDP: it navigates to the target's origin (so the fetch is same-origin + carries the live session)
and runs an in-page fetch — the request is indistinguishable from the browser's own traffic. Still
scope-gated (scope-guard --check refuses out-of-scope before anything fires) and evidence-bound.

One-time: launch Chrome with a debugging port, ideally your normal logged-in profile:
  google-chrome --remote-debugging-port=9222 --user-data-dir="$HOME/.config/google-chrome"
  # (or chromium / brave; Kali: chromium --remote-debugging-port=9222)
Then keep a tab open on the target and:

Usage:
  exec-cdp.py --url https://api.acme.com/api/v1/orders/1337 [--port 9222] [--no-nav] [--method GET] [--approve]
Exit: 0 ok · 2 scope/refused · 5 no browser.
"""
import sys, os, re, json, socket, base64, struct, time, urllib.request, subprocess
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
EV = HUNT / "evidence"
TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


# ── minimal CDP-over-WebSocket client (stdlib only) ─────────────────────────
class WS:
    def __init__(s, url, timeout=8):
        m = re.match(r"ws://([^:/]+):(\d+)(/.*)", url)
        if not m:
            raise ValueError("bad ws url")
        host, port, path = m.group(1), int(m.group(2)), m.group(3)
        s.sock = socket.create_connection((host, port), timeout=timeout)
        s.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        s.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.sock.recv(1024)
        if b"101" not in buf.split(b"\r\n", 1)[0]:
            raise ConnectionError("CDP websocket upgrade failed")
        s.buf = buf.split(b"\r\n\r\n", 1)[1]

    def send(s, obj):
        payload = json.dumps(obj).encode()
        hdr = bytearray([0x81])
        n = len(payload)
        mask = os.urandom(4)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127); hdr += struct.pack(">Q", n)
        hdr += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        s.sock.sendall(bytes(hdr) + masked)

    def _read(s, n):
        while len(s.buf) < n:
            chunk = s.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed")
            s.buf += chunk
        out, s.buf = s.buf[:n], s.buf[n:]
        return out

    def recv(s):
        b0, b1 = s._read(2)
        op = b0 & 0x0F
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", s._read(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", s._read(8))[0]
        data = s._read(ln) if ln else b""
        if op == 0x8:
            raise ConnectionError("ws close")
        if op == 0x9:  # ping → ignore
            return None
        return data.decode("utf-8", "replace")

    def cmd(s, mid, method, params=None, wait=True, deadline=10):
        s.send({"id": mid, "method": method, "params": params or {}})
        if not wait:
            return None
        end = time.time() + deadline
        while time.time() < end:
            try:
                msg = s.recv()
            except socket.timeout:
                continue
            if not msg:
                continue
            try:
                j = json.loads(msg)
            except Exception:
                continue
            if j.get("id") == mid:
                return j
        return None

    def close(s):
        try:
            s.sock.close()
        except Exception:
            pass


def pages(port):
    try:
        raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=4).read()
        return json.loads(raw)
    except Exception:
        return None


def next_ev():
    EV.mkdir(parents=True, exist_ok=True)
    n = 1
    while (EV / f"e{n}").exists():
        n += 1
    return EV / f"e{n}"


def scope_ok(url):
    g = subprocess.run([sys.executable, str(TOOLS / "scope-guard.py"), "--check", url], capture_output=True, text=True)
    return g.returncode == 0, (g.stdout or g.stderr).strip()


def fetch_via(port, url, method="GET", nav=True):
    """Run an in-page fetch from the real Chrome on <port>. Returns data dict or {'error':..}."""
    ps = pages(port)
    if ps is None:
        return {"error": f"no Chrome DevTools on :{port}", "nobrowser": True}
    page = next((p for p in ps if p.get("type") == "page" and p.get("webSocketDebuggerUrl")), None)
    if not page:
        return {"error": f"no open tab on :{port}", "nobrowser": True}
    m = re.match(r"(https?://[^/]+)", url)
    origin = m.group(1) if m else url
    try:
        ws = WS(page["webSocketDebuggerUrl"])
    except Exception as e:
        return {"error": f"attach failed on :{port}: {e}", "nobrowser": True}
    try:
        if nav:
            ws.cmd(1, "Page.enable")
            ws.cmd(2, "Page.navigate", {"url": origin})
            time.sleep(2.2)
        expr = ("(async()=>{try{const r=await fetch(%s,{credentials:'include',method:%s});"
                "const t=await r.text();return JSON.stringify({status:r.status,len:t.length,"
                "body:t.slice(0,4000)});}catch(e){return JSON.stringify({error:String(e)});}})()"
                % (json.dumps(url), json.dumps(method)))
        res = ws.cmd(3, "Runtime.evaluate", {"expression": expr, "awaitPromise": True, "returnByValue": True}, deadline=25)
    finally:
        ws.close()
    if not res or "result" not in res:
        return {"error": "no result (navigation blocked or timed out)"}
    val = res["result"].get("result", {}).get("value")
    try:
        return json.loads(val) if isinstance(val, str) else (val or {})
    except Exception:
        return {"raw": val}


def save(url, port, method, data, label=""):
    d = next_ev(); d.mkdir(parents=True, exist_ok=True)
    (d / "request.txt").write_text(f"{method} {url}\n(via real Chrome @ CDP :{port}{', '+label if label else ''}, credentials:include)\n")
    (d / "response.txt").write_text(f"HTTP {data.get('status','?')}\nlen={data.get('len','?')}\n\n{data.get('body','')}")
    return d


def waf_variants(p):
    import urllib.parse as up
    return {"url-encode": up.quote(p), "double-encode": up.quote(up.quote(p)),
            "case-flip": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
            "inline-comment": re.sub(r"\s+", "/**/", p), "trailing-null": p + "%00"}


def main():
    url = arg("--url")
    if not url:
        sys.exit("usage: exec-cdp.py --url <URL> [--port 9222] [--diff --port2 9223] [--waf PAYLOAD] [--no-nav] [--method GET] [--approve]")
    port = int(arg("--port", "9222") or 9222)
    method = (arg("--method", "GET") or "GET").upper()
    nav = not flag("--no-nav")

    ok, why = scope_ok(url)
    if not ok:
        print("[cdp] ⛔ " + why); sys.exit(2)
    if method not in ("GET", "HEAD") and not flag("--approve"):
        print(f"[cdp] ⛔ {method} is state-changing — re-run with --approve."); sys.exit(2)

    # ── two-identity DIFF across two Chrome profiles (admin :port, low-priv :port2) ──
    if flag("--diff"):
        port2 = int(arg("--port2", str(port + 1)) or port + 1)
        A = fetch_via(port, url, method, nav)
        B = fetch_via(port2, url, method, nav)
        if A.get("nobrowser") or B.get("nobrowser"):
            print(f"[cdp] ✗ need TWO debugged Chrome profiles: admin on :{port}, low-priv on :{port2}.\n"
                  f"      launch each with a different --user-data-dir and --remote-debugging-port.")
            sys.exit(5)
        dA = save(url, port, method, A, "identity A"); dB = save(url, port2, method, B, "identity B")
        r = subprocess.run([sys.executable, str(TOOLS / "diff-oracle.py"), "--a", str(dA / "response.txt"),
                            "--b", str(dB / "response.txt"), "--a-owner", "browser-A", "--b-owner", "browser-B",
                            "--expect", arg("--expect", "deny")], text=True)
        sys.exit(r.returncode)

    # ── WAF-bypass: baseline, then variants if blocked ──
    if arg("--waf"):
        payload = arg("--waf")
        base = fetch_via(port, url, method, nav)
        if base.get("nobrowser"):
            print(f"[cdp] ✗ {base['error']} — launch Chrome with --remote-debugging-port={port}"); sys.exit(5)
        st = base.get("status")
        if st not in (403, 406, 429, 501):
            print(f"[cdp] baseline not blocked (status {st}) — no WAF bypass needed."); sys.exit(0)
        print(f"[cdp] baseline BLOCKED ({st}); trying {len(waf_variants(payload))} variants via real browser:")
        wins = []
        import urllib.parse as up
        for name, v in waf_variants(payload).items():
            vurl = url.replace(up.quote(payload), up.quote(v)) if up.quote(payload) in url else \
                   (url.replace(payload, v) if payload in url else url + ("&" if "?" in url else "?") + "p=" + up.quote(v))
            d = fetch_via(port, vurl, method, nav=False)
            s = d.get("status")
            print(f"    {name:<16} → {s}")
            if s and s not in (403, 406, 429, 501):
                wins.append((name, s, save(vurl, port, method, d, "waf:" + name)))
        print("\n" + ("  ✓ BYPASS: " + ", ".join(f"{n} ({s})" for n, s, _ in wins) if wins else "  ✗ no variant bypassed."))
        sys.exit(0)

    # ── single request ──
    data = fetch_via(port, url, method, nav)
    if data.get("nobrowser"):
        print(f"[cdp] ✗ {data['error']}.\n"
              f"      launch:  google-chrome --remote-debugging-port={port} --user-data-dir=\"$HOME/.config/google-chrome\"\n"
              f"      then open a tab on the target and retry.")
        sys.exit(5)
    if data.get("error"):
        print(f"[cdp] fetch error in-page: {data['error']}"); sys.exit(1)
    d = save(url, port, method, data)
    print(f"[cdp] {method} {url}  → status {data.get('status','?')}  ({data.get('len','?')} bytes)  saved {d}")
    print("      fired from your real logged-in Chrome — bot-manager & JS gates bypassed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
