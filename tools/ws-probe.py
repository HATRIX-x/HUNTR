#!/usr/bin/env python3
"""
ws-probe — WebSocket / GraphQL-subscription security probe (stdlib only).

Modern apps push auth, chat, trading and GraphQL subscriptions over WebSockets,
and most scanners never touch them. This does the RFC6455 handshake itself and
tests the classic WS bugs:

  · missing auth            — handshake succeeds with NO credentials → 101
  · CSWSH                   — handshake succeeds with a foreign Origin (cross-site
                              WebSocket hijacking; the session rides along)
  · origin-reflection       — server echoes/accepts arbitrary Origin
  · message injection/IDOR  — send --message and capture the reply for triage
  · graphql-ws              — connection_init + a subscribe, see if it streams

Usage:
  ws-probe.py --url wss://api.acme.com/socket [--token JWT] [--origin https://acme.com] \
              [--message '{"type":"subscribe","id":"1","payload":{...}}'] \
              [--graphql-sub '{ me { id email } }'] [--json]
Authorized targets only.
Exit: 0 clean · 1 findings.
"""
import sys, os, re, json, time, ssl, socket, base64, struct
from urllib.parse import urlparse


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ws_connect(url, origin=None, token=None, extra=None, timeout=8):
    """Do a WS handshake. Returns (status_code, resp_headers, sock) or (0, err, None)."""
    u = urlparse(url)
    secure = u.scheme == "wss"
    host = u.hostname
    port = u.port or (443 if secure else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if secure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [f"GET {path} HTTP/1.1", f"Host: {host}:{port}",
                 "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
                 "User-Agent: Mozilla/5.0"]
        if origin:
            lines.append(f"Origin: {origin}")
        if token:
            lines.append(f"Authorization: {token if ' ' in token else 'Bearer ' + token}")
        for k, v in (extra or {}).items():
            lines.append(f"{k}: {v}")
        raw.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        raw.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = raw.recv(1024)
            if not chunk:
                break
            buf += chunk
        head = buf.decode("utf-8", "ignore")
        m = re.match(r"HTTP/1\.\d (\d+)", head)
        status = int(m.group(1)) if m else 0
        headers = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, raw
    except Exception as ex:
        return 0, {"error": str(ex)[:150]}, None


def ws_send(sock, text):
    payload = text.encode()
    header = bytearray([0x81])  # FIN + text
    n = len(payload)
    mask = os.urandom(4)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126); header += struct.pack(">H", n)
    else:
        header.append(0x80 | 127); header += struct.pack(">Q", n)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def ws_recv(sock, timeout=5):
    sock.settimeout(timeout)
    try:
        first = sock.recv(2)
        if len(first) < 2:
            return None
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        data = b""
        while len(data) < length and length < 1 << 20:
            chunk = sock.recv(min(4096, length - len(data)))
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "ignore")
    except Exception:
        return None


def main():
    url = arg("--url")
    token = arg("--token")
    origin = arg("--origin")
    message = arg("--message")
    gql_sub = arg("--graphql-sub")

    if not url:
        print(__doc__)
        sys.exit(0)

    u = urlparse(url)
    legit_origin = origin or f"https://{u.hostname}"
    findings = []
    print(f"[ws-probe] {url}", file=sys.stderr)

    # baseline: authed handshake
    st_auth, h_auth, s_auth = ws_connect(url, origin=legit_origin, token=token)
    if s_auth:
        try:
            s_auth.close()
        except Exception:
            pass
    print(f"[ws-probe] authed handshake HTTP {st_auth}", file=sys.stderr)

    # missing auth
    if token:
        st_noauth, _, s_noauth = ws_connect(url, origin=legit_origin, token=None)
        if s_noauth:
            s_noauth.close()
        if st_noauth == 101:
            findings.append({
                "attack": "missing_auth", "severity": "high", "status": st_noauth,
                "note": "handshake succeeded with no Authorization header — WS accepts "
                        "unauthenticated clients.",
            })
            print("  ✓ accepts unauthenticated handshake", file=sys.stderr)

    # CSWSH: foreign origin
    evil = "https://evil.example"
    st_cs, h_cs, s_cs = ws_connect(url, origin=evil, token=token)
    if s_cs:
        s_cs.close()
    if st_cs == 101:
        findings.append({
            "attack": "cswsh", "severity": "high", "status": st_cs, "origin": evil,
            "note": "handshake accepted with a cross-site Origin — Cross-Site WebSocket "
                    "Hijacking: a malicious page can open an authenticated socket.",
        })
        print("  ✓ CSWSH: foreign Origin accepted", file=sys.stderr)
    if h_cs.get("access-control-allow-origin") in (evil, "*"):
        findings.append({
            "attack": "origin_reflection", "severity": "medium",
            "note": f"server reflected Origin in ACAO ({h_cs.get('access-control-allow-origin')}).",
        })

    # message injection / capture
    if message and st_auth == 101:
        st_m, _, s_m = ws_connect(url, origin=legit_origin, token=token)
        if s_m:
            ws_send(s_m, message)
            reply = ws_recv(s_m)
            s_m.close()
            findings.append({
                "attack": "message_probe", "severity": "info",
                "sent": message[:120], "reply_snippet": (reply or "")[:200],
                "note": "sent probe message; inspect the reply for IDOR / injection / data leak.",
            })

    # graphql-ws subscription
    if gql_sub:
        st_g, _, s_g = ws_connect(url, origin=legit_origin, token=token,
                                  extra={"Sec-WebSocket-Protocol": "graphql-transport-ws"})
        if s_g:
            ws_send(s_g, json.dumps({"type": "connection_init", "payload": {}}))
            _ = ws_recv(s_g)
            ws_send(s_g, json.dumps({"id": "1", "type": "subscribe",
                                     "payload": {"query": "subscription " + gql_sub
                                                 if not gql_sub.strip().startswith("subscription")
                                                 else gql_sub}}))
            reply = ws_recv(s_g)
            s_g.close()
            got = bool(reply and ("data" in reply or "next" in reply))
            findings.append({
                "attack": "graphql_ws", "severity": "info" if not got else "medium",
                "reply_snippet": (reply or "")[:200],
                "note": "graphql-ws subscription " + ("streamed data — check authz on the "
                        "subscription root." if got else "connected; refine the query."),
            })

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"), "url": url,
        "authed_handshake": st_auth,
        "total": len(findings),
        "findings": findings,
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== ws-probe · {url} ==")
    print(f"  authed handshake: HTTP {st_auth} · {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {f['attack']}  {f['note'][:90]}")
    if not findings:
        print("  no WS issues with tested vectors.")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
