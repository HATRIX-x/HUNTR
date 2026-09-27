#!/usr/bin/env python3
"""
idor-chain — cross-account IDOR / broken-object-level-authorization tester.

Fires each object id as account A (the owner), then replays the identical
request as account B (a second account you control). If B gets 200 with the
same body as A, B can read A's objects → IDOR.

Also flags:
  · numeric enumeration    (ids walk 1,2,3… — predictable object space)
  · sequential GUID        (v1/ordered UUIDs leak creation order → guessable)
  · hashed-id bypass       (md5/sha1(int) accepted where a raw int is expected)

Id injection (first that matches):
  · "{id}" placeholder anywhere in --base-url or --data  → substituted
  · GET  → appended as ?<id-field>=<id>
  · POST/PUT/PATCH → set <id-field> in the JSON --data body

Usage:
  idor-chain.py --base-url https://api.acme.com/v1/orders/{id} \
                --token A_JWT --token2 B_JWT \
                --id-field id --id-range 1000-1100 \
                [--method GET] [--data '{}'] [--json] [--out r.json]

Only run against objects in accounts you own on an in-scope program.
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, ssl, hashlib
from pathlib import Path
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError
import urllib.parse


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def parse_range(s):
    if not s:
        return []
    s = s.strip()
    if "-" in s:
        a, b = s.split("-", 1)
        try:
            lo, hi = int(a), int(b)
        except ValueError:
            return [x.strip() for x in s.split(",") if x.strip()]
        if hi - lo > 5000:
            hi = lo + 5000
        return list(range(lo, hi + 1))
    if "," in s:
        return [x.strip() for x in s.split(",") if x.strip()]
    return [s]


def build_request(base_url, id_field, id_val, method, data_tpl):
    url = base_url
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    body = None
    sid = str(id_val)

    if "{id}" in base_url or (data_tpl and "{id}" in data_tpl):
        url = base_url.replace("{id}", urllib.parse.quote(sid, safe=""))
        if data_tpl:
            body = data_tpl.replace("{id}", sid).encode()
            headers["Content-Type"] = "application/json"
    elif method.upper() == "GET":
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urllib.parse.quote(id_field)}={urllib.parse.quote(sid, safe='')}"
    else:
        try:
            obj = json.loads(data_tpl or "{}")
        except Exception:
            obj = {}
        obj[id_field] = id_val
        body = json.dumps(obj).encode()
        headers["Content-Type"] = "application/json"
    return url, body, headers


def send(url, body, headers, method, token, timeout=8):
    h = dict(headers)
    if token:
        h["Authorization"] = token if " " in token else f"Bearer {token}"
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    req = Request(url, data=body, headers=h, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            data = r.read(65536)
            return r.status, len(data), data.decode("utf-8", "ignore")
    except HTTPError as e:
        try:
            data = e.read(8192)
        except Exception:
            data = b""
        return e.code, len(data), data.decode("utf-8", "ignore")
    except Exception as ex:
        return 0, 0, str(ex)[:200]


def similar(a, b):
    if a == 0 or b == 0:
        return False
    lo, hi = (a, b) if a < b else (b, a)
    return lo / hi >= 0.90


def looks_uuid(s):
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                             r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", str(s)))


def main():
    base_url = arg("--base-url")
    token_a = arg("--token")
    token_b = arg("--token2")
    id_field = arg("--id-field", "id")
    id_range = arg("--id-range", "")
    method = arg("--method", "GET")
    data_tpl = arg("--data")
    out_file = arg("--out")

    if not base_url:
        print(__doc__)
        sys.exit(0)

    ids = parse_range(id_range)
    findings = []
    numeric_ok = 0
    tested = 0

    print(f"[idor-chain] base={base_url} field={id_field} ids={len(ids)} "
          f"A={'set' if token_a else 'none'} B={'set' if token_b else 'none'}",
          file=sys.stderr)

    for idv in ids:
        tested += 1
        url, body, headers = build_request(base_url, id_field, idv, method, data_tpl)
        sa, za, _ = send(url, body, headers, method, token_a)
        if token_b is not None:
            sb, zb, _ = send(url, body, headers, method, token_b)
        else:
            sb, zb = 0, 0

        owner_ok = sa == 200 and za > 0
        if owner_ok:
            numeric_ok += 1
        cross = token_b is not None and sb == 200 and similar(za, zb)
        verdict = "IDOR" if (owner_ok and cross) else ("owner-only" if owner_ok else "no-object")

        if verdict == "IDOR":
            findings.append({
                "attack": "idor_cross_account",
                "id": idv, "id_field": id_field,
                "status_a": sa, "status_b": sb,
                "size_a": za, "size_b": zb,
                "severity": "high",
                "verdict": verdict,
                "note": f"account B read object {idv} owned via account A "
                        f"(A:{sa}/{za}b  B:{sb}/{zb}b)",
            })
            print(f"  ✓ IDOR id={idv}  A:{sa}/{za}  B:{sb}/{zb}", file=sys.stderr)

    numeric_pred = None
    int_ids = [i for i in ids if isinstance(i, int)]
    if len(int_ids) >= 3 and numeric_ok >= max(2, int(0.5 * len(int_ids))):
        numeric_pred = {
            "attack": "numeric_enumeration",
            "severity": "medium",
            "hit_ratio": round(numeric_ok / max(1, tested), 2),
            "note": f"{numeric_ok}/{tested} sequential integer ids resolved to live "
                    f"objects — object space is enumerable; pair with authz gaps.",
        }
        findings.append(numeric_pred)

    if looks_uuid(id_field) is False and ids and looks_uuid(ids[0]):
        findings.append({
            "attack": "sequential_guid",
            "severity": "low",
            "note": "sample id is a UUID — if v1/ordered, creation order leaks and "
                    "neighbours are guessable; confirm version byte.",
        })

    hashed = []
    for idv in int_ids[:3]:
        for algo in ("md5", "sha1"):
            hv = getattr(hashlib, algo)(str(idv).encode()).hexdigest()
            url, body, headers = build_request(base_url, id_field, hv, method, data_tpl)
            s, z, _ = send(url, body, headers, method, token_b if token_b is not None else token_a)
            if s == 200 and z > 0:
                hashed.append({
                    "attack": "hashed_id_bypass",
                    "id": idv, "algo": algo, "hashed": hv,
                    "status": s, "size": z,
                    "severity": "high",
                    "note": f"{algo}(int {idv}) accepted as object key → predictable "
                            f"hashed id, no real authz on the object.",
                })
                print(f"  ✓ hashed-id {algo}({idv}) accepted", file=sys.stderr)
    findings += hashed

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "base_url": base_url, "id_field": id_field,
        "tested": tested,
        "total": len(findings),
        "idor": sum(1 for f in findings if f.get("attack") == "idor_cross_account"),
        "findings": findings,
    }
    if out_file:
        Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== IDOR chain · {base_url} ==")
    print(f"  tested {tested} ids · {result['idor']} cross-account IDOR · "
          f"{len(findings)} total findings")
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {f['attack']}  {f.get('note','')[:90]}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
