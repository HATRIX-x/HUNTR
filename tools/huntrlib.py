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


def auth_headers_env():
    """Custom program auth header(s) the operator supplied (e.g. Files.com's `X-FilesAPI-Auth: <token>`,
    where auth is NOT a Bearer token or cookie). hunt-run exports them as HUNT_AUTH_HEADERS (JSON dict);
    every scanner subprocess inherits the env and merges these into its request headers so the
    authenticated surface is actually reached. Returns {} when none set."""
    try:
        return json.loads(os.environ.get("HUNT_AUTH_HEADERS", "") or "{}") or {}
    except Exception:
        return {}


def parse_auth_header(raw):
    """Parse an operator-pasted auth-header string into a {name: value} dict. Accepts one or many
    'Name: value' lines; a bare token with no colon is ignored (ambiguous — needs a header name)."""
    out = {}
    for ln in str(raw or "").replace("\\n", "\n").splitlines():
        ln = ln.strip()
        if not ln or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k, v = k.strip(), v.strip()
        if k and v:
            out[k] = v
    return out


def normalize_cookie(raw):
    """CRITICAL (2026-10-21, caught live): an operator-pasted creds.cookie is sometimes a raw
    Netscape cookie-jar FILE — the tab-separated `domain\tflag\tpath\tsecure\texpiry\tname\tvalue`
    format curl -c / most browser "export cookies" extensions produce, often prefixed
    '# Netscape HTTP Cookie File' — instead of an actual browser Cookie-HEADER string
    ('name=value; name2=value2'). Every consumer that sends this value verbatim as a literal
    `Cookie:` header (hunt-run.py's authed scan loop, browser-capture.py's SPA capture,
    creds-test.py's own verification probe) was silently running fully anonymous — pasted
    Netscape-file text is not valid cookie syntax at all, so the real auth cookie was present in
    the string somewhere but never actually sent in a form any server could parse, with no error
    anywhere to surface it. THE canonical place to fix this: call it once wherever a raw
    creds.cookie value first enters a tool, instead of duplicating the parser per caller.
    Handles both normal multi-line Netscape text and a pathological but observed case: the paste
    flattened real newlines into spaces, so a record's value has the next record's domain glued
    onto its end with no delimiter but a space — the non-greedy lookahead stops exactly at that
    glue point instead of swallowing it into the value."""
    raw = (raw or "").strip()
    if not raw or ("Netscape HTTP Cookie File" not in raw and "\t" not in raw):
        return raw  # already an ordinary Cookie-header string (or empty) — leave it alone
    pat = re.compile(r'\t(?:TRUE|FALSE)\t[^\t]*\t(?:TRUE|FALSE)\t\d+\t([^\t]+)\t(.*?)(?=\s+\S*\t(?:TRUE|FALSE)\t|$)', re.S)
    pairs = [(n, v) for n, v in pat.findall(raw) if n and not n.startswith("#")]
    return "; ".join(n + "=" + v for n, v in pairs) if pairs else raw


def spine(url, method="GET", data=None, identity=None, headers=None, timeout=45):
    """THE canonical HTTP spine for the whole engine: every request through scope-guard,
    every response saved as evidence. This is a thin, importable wrapper over exec-http.py so
    agents, hunt-run, and tools share ONE disciplined path (scope + write-approval + circuit
    breaker + evidence capture) instead of each re-implementing raw urllib.

    Returns {"ok", "status", "headers" (full header block str), "body", "evidence_dir", "raw"}.
    New tools should call this instead of http(); http() stays for legacy/stdlib-only callers.
    """
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    a = ["--url", url, "--method", (method or "GET").upper()]
    if data:
        a += ["--data", data if isinstance(data, str) else json.dumps(data)]
    if identity:
        a += ["--identity", identity]
    merged = dict(auth_headers_env())          # program-supplied auth header(s), e.g. X-FilesAPI-Auth
    merged.update(headers or {})               # explicit per-call headers win
    for k, v in merged.items():
        a += ["--header", f"{k}: {v}"]
    try:
        r = subprocess.run([sys.executable, os.path.join(here, "exec-http.py")] + a,
                           capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ))
    except Exception as e:
        return {"ok": False, "status": 0, "headers": "", "body": "", "evidence_dir": "", "raw": str(e)[:200]}
    summary = (r.stdout or r.stderr or "").strip()
    ev, status, heads, body = "", 0, "", ""
    m = re.search(r"\(([^)]*evidence[^)]*)\)", summary)
    if m:
        ev = m.group(1).strip()
        rp = os.path.join(ev, "response.txt")
        if os.path.exists(rp):
            with open(rp, errors="ignore") as fh:
                full = fh.read()
            parts = full.split("\n\n", 1)
            heads = parts[0]
            body = parts[1] if len(parts) > 1 else ""
            sm = re.search(r"\b(\d{3})\b", heads.split("\n", 1)[0])
            status = int(sm.group(1)) if sm else 0
    return {"ok": "⛔" not in summary, "status": status, "headers": heads,
            "body": body, "evidence_dir": ev, "raw": summary}


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
