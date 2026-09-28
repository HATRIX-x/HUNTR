#!/usr/bin/env python3
"""
huntrlib — the shared core every HUNTR tool duplicates: arg parsing, one HTTP
client (SSL, auth, headers, timeout, size cap, uniform error handling), and the
JSON output envelope. Import it instead of re-implementing; a fix here lands once
across the whole engine.

Sibling tools import it directly (the script's own dir is on sys.path):
    import huntrlib as H
    url = H.arg("--url"); token = H.arg("--token")
    r = H.http(url, token=token)          # r.status, r.size, r.text, r.headers
    H.emit(H.envelope(url=url, findings=findings))   # prints JSON or a human line

Stdlib only. No network side effects on import.
"""
import sys, os, json, ssl, time, re
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler, HTTPRedirectHandler
from urllib.error import HTTPError
import urllib.parse

DEFAULT_UA = "Mozilla/5.0 (HUNTR)"
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_READ = 65536


# ── argv helpers ────────────────────────────────────────────────────────
def arg(name, default=None):
    """Value after `name` in argv, or default."""
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def flag(name):
    return name in sys.argv


def args_multi(name):
    """Every value that follows a repeated `name` flag."""
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv)
            if a == name and i + 1 < len(sys.argv)]


def as_int(name, default):
    try:
        return int(arg(name, default))
    except (TypeError, ValueError):
        return default


# ── HTTP ────────────────────────────────────────────────────────────────
def ssl_ctx(verify=False):
    c = ssl.create_default_context()
    if not verify:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Resp:
    """A finished HTTP response. status 0 means the request never completed."""
    __slots__ = ("status", "size", "text", "headers", "final_url", "error")

    def __init__(self, status=0, size=0, text="", headers=None, final_url="", error=""):
        self.status = status
        self.size = size
        self.text = text
        self.headers = headers or {}
        self.final_url = final_url
        self.error = error

    @property
    def ok(self):
        return 200 <= self.status < 300

    def json(self, default=None):
        try:
            return json.loads(self.text)
        except Exception:
            return default

    def header(self, name):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


def norm_auth(token):
    if not token:
        return None
    return token if " " in token else f"Bearer {token}"


def http(url, method="GET", headers=None, body=None, token=None,
         timeout=DEFAULT_TIMEOUT, max_read=DEFAULT_MAX_READ, follow=True,
         verify=False):
    """One HTTP call. Never raises for HTTP/network errors — returns a Resp.

    body: str | bytes | dict (dict is JSON-encoded with a JSON content-type).
    token: raw or 'Bearer x' — added as Authorization unless already in headers.
    follow=False disables redirect following (Location is on the Resp headers).
    """
    h = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    elif isinstance(body, str):
        body = body.encode()
    for k, v in (headers or {}).items():
        h[k] = v
    if token and not any(k.lower() == "authorization" for k in h):
        h["Authorization"] = norm_auth(token)

    handlers = [HTTPSHandler(context=ssl_ctx(verify)), HTTPHandler()]
    if not follow:
        handlers.append(_NoRedirect())
    opener = build_opener(*handlers)
    req = Request(url, data=body, headers=h, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(max_read)
            return Resp(r.status, len(raw), raw.decode("utf-8", "ignore"),
                        dict(r.headers), str(r.url))
    except HTTPError as e:
        try:
            raw = e.read(max_read)
        except Exception:
            raw = b""
        return Resp(e.code, len(raw), raw.decode("utf-8", "ignore"),
                    dict(e.headers or {}), url)
    except Exception as ex:
        return Resp(0, 0, "", {}, "", f"{type(ex).__name__}: {str(ex)[:200]}")


def add_query(url, key, value):
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urllib.parse.quote(key)}={urllib.parse.quote(str(value), safe='')}"


# ── output ──────────────────────────────────────────────────────────────
def envelope(findings=None, **extra):
    """Standard result envelope: ts + total + findings + whatever else."""
    findings = findings or []
    out = {"ts": time.strftime("%Y-%m-%d %H:%M"), "total": len(findings)}
    out.update(extra)
    out["findings"] = findings
    return out


def emit(result, human=None, code=None):
    """Print JSON when --json is set, else the human string (or JSON fallback).
    Exits with `code` when given (else 1 if findings present, 0 otherwise)."""
    if flag("--json"):
        print(json.dumps(result))
    elif human is not None:
        print(human)
    else:
        print(json.dumps(result, indent=2))
    if code is None:
        code = 1 if result.get("findings") else 0
    sys.exit(code)


# ── misc shared helpers ─────────────────────────────────────────────────
def norm_endpoint(path):
    """Collapse ids to a template: /orders/123 -> /orders/{id}."""
    path = re.sub(r"/\d+", "/{id}", path or "/")
    return re.sub(r"/[0-9a-f]{8,}", "/{id}", path)


def hunt_dir():
    from pathlib import Path
    return Path(os.environ.get("HUNT_DIR", "./.hunt"))
