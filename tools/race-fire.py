#!/usr/bin/env python3
"""
race-fire — race condition tester for bug bounty.

Fires N identical requests simultaneously using threads with a gate
(all threads ready → release together). Detects:
  • Duplicate resource creation (201 count > 1)
  • Balance/counter inconsistency (different numeric values in responses)
  • TOCTOU window (some success + some 409/429/403 in same window)
  • Idempotency failure (POST fires multiple times, non-idempotent result)

Usage:
  race-fire.py --url https://api.acme.com/v1/redeem
               [--method POST] [--data '{"code":"SAVE10"}']
               [--token Bearer_xxx] [--header X-Foo:bar]
               [--count 25] [--warmup 5] [--json] [--out results.json]

  --count   parallel requests (default 25)
  --warmup  send N single requests first to warm connection pool (default 5)
Exit: 0 clean · 1 race condition found.
"""
import sys, re, json, time, ssl, threading
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
def args_multi(n):
    vals = []
    for i,a in enumerate(sys.argv):
        if a == n and i+1 < len(sys.argv): vals.append(sys.argv[i+1])
    return vals
def flag(n): return n in sys.argv

def build_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    return ctx

def do_request(url, method, headers, data, timeout=10):
    import urllib.request
    ctx = build_ctx()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    req = Request(url, data=data, headers=headers, method=method)
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(2048).decode("utf-8","ignore")
            return {"status": r.status, "body": body, "ms": int((time.time()-t0)*1000)}
    except HTTPError as e:
        try: body = e.read(1024).decode("utf-8","ignore")
        except: body = ""
        return {"status": e.code, "body": body, "ms": int((time.time()-t0)*1000)}
    except Exception as ex:
        return {"status": 0, "body": str(ex)[:100], "ms": int((time.time()-t0)*1000)}

def fire_race(url, method, headers, data, count, gate_event):
    results = []
    lock = threading.Lock()
    def worker():
        gate_event.wait()  # all threads block here until gate opens
        r = do_request(url, method, headers, data)
        with lock: results.append(r)
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(count)]
    for t in threads: t.start()
    time.sleep(0.05)  # let all threads reach the gate
    gate_event.set()  # release all at once
    for t in threads: t.join(timeout=30)
    return results

# Many APIs return HTTP 200 with an error CODE in the body — such a response is NOT a successful
# state-change and must be excluded from all race signals (else identical error bodies look like a race).
_ERR_BODY = re.compile(r'"code"\s*:\s*"?(?:[1-9]\d{3,}|[45]\d\d)'
                       r'|"(?:status|ret|errno)"\s*:\s*(?:[45]\d\d|[1-9]\d{3,})'
                       r'|unauthor|forbidden|verification\s*failed|not\s*login|invalid|参数|请登录', re.I)

def _is_err(body):
    return bool(body) and bool(_ERR_BODY.search(body[:600]))

def analyze(results):
    statuses = [r["status"] for r in results]
    bodies = [r["body"] for r in results]
    counts = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    success = sum(1 for s in statuses if 200 <= s < 300)
    created = sum(1 for s in statuses if s == 201)
    errors  = [s for s in statuses if s >= 400]

    # ONLY genuine successful, non-error responses can evidence a state-change race. An error body (incl.
    # HTTP-200-wrapped errors) or a read returning the same payload is not a race. (Killed 5 FPs on cointr:
    # identical error bodies read as "duplicate_id", rate-limit 429 read as "toctou".)
    ok_bodies = [r["body"] for r in results if 200 <= r["status"] < 300 and not _is_err(r["body"])]
    distinct_ok = len(set(ok_bodies))

    findings = []
    # If there is no real multi-success, or every success is byte-identical (idempotent read / cached /
    # same error), there is nothing to race — return a LEAD at most, never a confirmed finding.
    if len(ok_bodies) < 2 or distinct_ok < 1:
        return findings, counts, success

    # resource-id duplication — only across DISTINCT successful creates (not identical responses, no `code`)
    # BUG FIX (2026-10-19): the old version pooled every matched id from every response into one FLAT
    # list and checked that whole pool for a duplicate. A perfectly normal, single, non-racing
    # response that echoes the same resource id in two places — a wrapper field plus a nested object,
    # e.g. {"id":"X","order":{"id":"X",...}} — is a common REST pattern and produces a "duplicate"
    # within that ONE response alone, with no second request involved at all. Dedup ids PER RESPONSE
    # first (a set, not a list) so only an id appearing in TWO OR MORE DIFFERENT successful responses
    # — the actual race-collision signal — counts.
    per_body_ids = []
    for body in ok_bodies:
        per_body_ids.append(set(
            m.group(1) for m in re.finditer(
                r'"(?:id|order_id|orderId|transaction_id|txId|coupon_id)"\s*:\s*"?(\w{4,})"?', body, re.I)
        ))
    id_counts = {}
    for s in per_body_ids:
        for idv in s:
            id_counts[idv] = id_counts.get(idv, 0) + 1
    id_dupes = any(c >= 2 for c in id_counts.values()) and distinct_ok > 1

    # numeric divergence (double-spend) among successful responses
    nums = []
    for body in ok_bodies:
        for m in re.finditer(r'"(?:balance|amount|credits?|points?|remaining|count|uses_remaining)"\s*:\s*([\d.]+)', body, re.I):
            nums.append(float(m.group(1)))
    num_diverge = len(set(nums)) > 1

    if created > 1:
        findings.append({"type": "duplicate_creation", "severity": "high",
            "note": f"{created}/{len(results)} requests returned 201 Created — resource created multiple times in race window",
            "statuses": counts})
    if id_dupes:
        findings.append({"type": "duplicate_id", "severity": "critical",
            "note": "Same resource ID across multiple DISTINCT successful parallel creates — duplicate creation in the race window",
            "statuses": counts})
    if num_diverge:
        findings.append({"type": "balance_diverge", "severity": "high",
            "note": f"Numeric value diverged across successful parallel responses: {sorted(set(nums))[:5]} — potential double-spend",
            "statuses": counts})
    # TOCTOU: a genuine check-then-act conflict (409 Conflict / 423 Locked) alongside real successes.
    # 429 (rate-limit) is NOT a race signal and is excluded.
    if success > 1 and any(s in (409, 423) for s in errors):
        findings.append({"type": "toctou_window", "severity": "medium",
            "note": f"{success} success + {sum(1 for s in errors if s in (409,423))} 409/423 conflict in same window — TOCTOU race",
            "statuses": counts})
    elif distinct_ok > 1 and not findings:
        # DISTINCT successful responses (not identical) with no concrete divergence proof → info lead only.
        # Identical successes = idempotent read → no finding at all (no noise).
        findings.append({"type": "non_idempotent", "severity": "info",
            "note": f"{len(ok_bodies)}/{len(results)} genuine successes in parallel, {distinct_ok} distinct — possibly non-idempotent (LEAD; prove a state effect)",
            "statuses": counts})
    return findings, counts, success

def main():
    url     = arg("--url")
    method  = arg("--method","POST").upper()
    token   = arg("--token")
    extra_h = args_multi("--header")
    body    = arg("--data")
    count   = int(arg("--count","25"))
    warmup  = int(arg("--warmup","5"))
    out_file= arg("--out")

    if not url: print(__doc__); sys.exit(0)

    headers = {"User-Agent":"Mozilla/5.0","Accept":"application/json"}
    if token: headers["Authorization"] = token if " " in token else f"Bearer {token}"
    if method in ("POST","PUT","PATCH") and body:
        headers["Content-Type"] = "application/json"
    for h in extra_h:
        if ":" in h:
            k,v = h.split(":",1); headers[k.strip()] = v.strip()
    data = body.encode() if body else None

    print(f"[race-fire] {method} {url} × {count} simultaneous", file=sys.stderr)

    # warmup (establish connections, avoid cold-start noise)
    if warmup > 0:
        print(f"[race-fire] warming up with {warmup} serial requests …", file=sys.stderr)
        for _ in range(warmup):
            do_request(url, method, headers, data, timeout=8)
        time.sleep(0.2)

    # race
    gate = threading.Event()
    t0 = time.time()
    print(f"[race-fire] releasing {count} threads simultaneously …", file=sys.stderr)
    results = fire_race(url, method, headers, data, count, gate)
    elapsed = int((time.time()-t0)*1000)

    findings, status_counts, success = analyze(results)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url, "method": method, "threads": count,
        "elapsed_ms": elapsed,
        "status_counts": status_counts,
        "success_count": success,
        "total_findings": len(findings),
        "findings": findings,
        "raw_results": [{"status": r["status"], "ms": r["ms"]} for r in results],
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if findings else 0)

    print(f"\n══ Race condition · {url} ══════════════════════════")
    print(f"  Threads: {count}  Elapsed: {elapsed}ms")
    print(f"  Status distribution: {dict(sorted(status_counts.items()))}")
    print(f"  Successes: {success}/{count}")
    if findings:
        print()
        for f in findings:
            print(f"  [{f['severity'].upper():<8}] {f['type']}")
            print(f"             {f['note']}")
    else:
        print("  No race condition detected. Endpoint appears idempotent.")

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
