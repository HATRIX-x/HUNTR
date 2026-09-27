#!/usr/bin/env python3
"""
rate-limit — detect whether an endpoint is rate-limited, and whether the limit
is bypassable by trivial header/routing tricks.

Phase 1 (detect): fire --count requests (default 50) across --threads workers,
tally status codes + any X-RateLimit-* / Retry-After headers. If nothing 429s,
the endpoint has no visible throttle.

Phase 2 (bypass, only if a 429 was seen): re-fire small bursts while rotating
one spoofable signal at a time — X-Forwarded-For / X-Real-IP / CF-Connecting-IP
random IPs, null Origin, rotating User-Agent, path case mutation. If a vector
turns 429s back into 200s, the limiter keys on a client-controlled value.

Keep --count modest; this is a limiter probe, not a load test. Authorized
targets only.

Usage:
  rate-limit.py --url https://api.acme.com/v1/login \
                [--method POST] [--data '{}'] [--token JWT] \
                [--count 50] [--threads 10] [--json]
Exit: 0 solid limit / no data · 1 no-limit or bypass found.
"""
import sys, json, time, ssl, random, threading
from collections import Counter
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


def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
]


def fire(url, method, headers, data, timeout=10):
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    body = data.encode() if isinstance(data, str) else data
    req = Request(url, data=body, headers=headers, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            r.read(2048)
            rl = {k: v for k, v in r.headers.items()
                  if k.lower().startswith("x-ratelimit") or k.lower() in ("retry-after", "ratelimit-remaining")}
            return r.status, rl
    except HTTPError as e:
        rl = {k: v for k, v in (e.headers or {}).items()
              if k.lower().startswith("x-ratelimit") or k.lower() in ("retry-after", "ratelimit-remaining")}
        return e.code, rl
    except Exception:
        return 0, {}


def burst(url, method, base_headers, data, n, threads):
    codes = Counter()
    rl_seen = {}
    lock = threading.Lock()
    idx = {"i": 0}

    def worker():
        while True:
            with lock:
                if idx["i"] >= n:
                    return
                idx["i"] += 1
            s, rl = fire(url, method, dict(base_headers), data)
            with lock:
                codes[s] += 1
                if rl:
                    rl_seen.update(rl)

    ts = [threading.Thread(target=worker) for _ in range(max(1, threads))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return codes, rl_seen


def main():
    url = arg("--url")
    method = arg("--method", "GET")
    data = arg("--data")
    token = arg("--token")
    count = int(arg("--count", "50"))
    threads = int(arg("--threads", "10"))

    if not url:
        print(__doc__)
        sys.exit(0)

    count = min(count, 300)
    base_h = {"User-Agent": UAS[0], "Accept": "*/*"}
    if data:
        base_h["Content-Type"] = "application/json"
    if token:
        base_h["Authorization"] = token if " " in token else f"Bearer {token}"

    print(f"[rate-limit] detect: {count} reqs × {threads} threads → {url}", file=sys.stderr)
    codes, rl = burst(url, method, base_h, data, count, threads)
    limited = codes.get(429, 0) > 0
    ok = codes.get(200, 0) + codes.get(201, 0) + codes.get(204, 0)

    findings = []
    bypass_found = False

    if not limited:
        findings.append({
            "attack": "no_rate_limit",
            "severity": "medium",
            "codes": dict(codes),
            "note": f"{ok}/{count} requests succeeded with no 429 — endpoint shows no "
                    f"rate limiting; abuse-prone (credential stuffing, OTP brute, scraping).",
        })
        print(f"[rate-limit] no 429 seen ({dict(codes)})", file=sys.stderr)

    if limited:
        print(f"[rate-limit] limiter present ({dict(codes)}) — testing bypass vectors",
              file=sys.stderr)
        vectors = [
            ("x_forwarded_for", lambda h: h.update({"X-Forwarded-For": rand_ip()})),
            ("x_real_ip", lambda h: h.update({"X-Real-IP": rand_ip()})),
            ("cf_connecting_ip", lambda h: h.update({"CF-Connecting-IP": rand_ip()})),
            ("forwarded_header", lambda h: h.update({"Forwarded": f"for={rand_ip()}"})),
            ("null_origin", lambda h: h.update({"Origin": "null"})),
            ("rotate_ua", lambda h: h.update({"User-Agent": random.choice(UAS)})),
        ]
        vurl_case = None
        p = urlparse(url)
        if p.path and p.path != "/":
            seg = p.path.rsplit("/", 1)[-1]
            if seg and seg[0].isalpha():
                vurl_case = urlunparse(p._replace(
                    path=p.path[: -len(seg)] + seg[0].upper() + seg[1:]))

        for name, mut in vectors:
            def hdr_factory(_mut=mut):
                h = dict(base_h)
                _mut(h)
                return h
            # each request gets a freshly-mutated header (new random IP etc.)
            c2 = Counter()
            for _ in range(min(20, count)):
                s, _rl = fire(url, method, hdr_factory(), data)
                c2[s] += 1
            recovered = c2.get(200, 0) + c2.get(201, 0) + c2.get(204, 0)
            if recovered > 0 and c2.get(429, 0) == 0:
                bypass_found = True
                findings.append({
                    "attack": "rate_limit_bypass",
                    "vector": name,
                    "severity": "high",
                    "codes": dict(c2),
                    "note": f"limiter keys on client-controlled '{name}': rotating it "
                            f"restored {recovered}/{sum(c2.values())} to 2xx with zero 429.",
                })
                print(f"  ✓ bypass via {name}  {dict(c2)}", file=sys.stderr)

        if vurl_case:
            c2 = Counter()
            for _ in range(min(20, count)):
                s, _rl = fire(vurl_case, method, dict(base_h), data)
                c2[s] += 1
            if (c2.get(200, 0) + c2.get(201, 0)) > 0 and c2.get(429, 0) == 0:
                bypass_found = True
                findings.append({
                    "attack": "rate_limit_bypass",
                    "vector": "path_case_mutation",
                    "severity": "high",
                    "codes": dict(c2),
                    "note": "limiter buckets per exact path — case-mutated path is a "
                            "separate bucket, resetting the counter.",
                })

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url,
        "count": count, "threads": threads,
        "limit_detected": limited,
        "bypass_found": bypass_found,
        "detect_codes": dict(codes),
        "ratelimit_headers": rl,
        "total": len(findings),
        "findings": findings,
    }

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== rate-limit · {url} ==")
    print(f"  detect: {dict(codes)}  headers={rl or '-'}")
    print(f"  limit_detected={limited}  bypass_found={bypass_found}")
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {f['attack']}"
              + (f"/{f.get('vector')}" if f.get('vector') else "")
              + f"  {f['note'][:80]}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
