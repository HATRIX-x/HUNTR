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

def analyze(results):
    statuses = [r["status"] for r in results]
    bodies = [r["body"] for r in results]
    counts = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    # success count
    success = sum(1 for s in statuses if 200 <= s < 300)
    created = sum(1 for s in statuses if s == 201)
    errors  = [s for s in statuses if s >= 400]
    # check for duplicate IDs in bodies
    ids = []
    for body in bodies:
        for m in re.finditer(r'"(?:id|order_id|transaction_id|coupon_id|code)"\s*:\s*"?(\w{4,})"?', body, re.I):
            ids.append(m.group(1))
    id_dupes = len(ids) != len(set(ids))
    # numeric value divergence (balance, amount, credits)
    nums = []
    for body in bodies:
        for m in re.finditer(r'"(?:balance|amount|credits?|points?|remaining|count|uses_remaining)"\s*:\s*([\d.]+)', body, re.I):
            nums.append(float(m.group(1)))
    num_diverge = len(set(nums)) > 1

    findings = []
    if created > 1:
        findings.append({
            "type": "duplicate_creation",
            "severity": "high",
            "note": f"{created}/{len(results)} requests returned 201 Created — resource created multiple times in race window",
            "statuses": counts,
        })
    if id_dupes:
        findings.append({
            "type": "duplicate_id",
            "severity": "critical",
            "note": f"Same resource ID returned in multiple parallel responses — likely duplicate creation",
            "statuses": counts,
        })
    if num_diverge:
        unique_vals = sorted(set(nums))
        findings.append({
            "type": "balance_diverge",
            "severity": "high",
            "note": f"Numeric value diverged across parallel responses: {unique_vals[:5]} — potential double-spend",
            "statuses": counts,
        })
    if success > 1 and errors and any(s in (409, 429, 423) for s in errors):
        findings.append({
            "type": "toctou_window",
            "severity": "medium",
            "note": f"{success} success + {len(errors)} 409/429/423 in same window — TOCTOU race condition likely",
            "statuses": counts,
        })
    elif success > 1 and not findings:
        findings.append({
            "type": "non_idempotent",
            "severity": "medium",
            "note": f"{success}/{len(results)} requests succeeded simultaneously — endpoint may not be idempotent",
            "statuses": counts,
        })
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
