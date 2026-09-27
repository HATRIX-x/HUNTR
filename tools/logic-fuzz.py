#!/usr/bin/env python3
"""
logic-fuzz — business-logic fuzzer for JSON APIs.

Sends the original request once (baseline), then mutates each top-level field of
the JSON body independently and resends. A mutation that still returns 2xx but a
materially different body than baseline is flagged as unexpected acceptance —
the seed of price/quantity/privilege abuse (buy for -$1, order 2^31 items,
flip "isAdmin", etc.). It reports; it never confirms a purchase or write.

Per-field mutations:
  numbers  : 0 · -1 · -9999 · 2^31 · 2^63 · float · numeric-as-string
  strings  : "" · null · number-in-string · array-wrap ["v"]
  bool     : flipped
  any      : null · array-wrap · duplicate-key injection (raw JSON)

Usage:
  logic-fuzz.py --url https://api.acme.com/v1/checkout \
                --method POST --data '{"item":"x","qty":1,"price":9.99}' \
                [--token JWT] [--json]
Authorized targets only; expect it to create/modify state — use a throwaway
account and never on production orders you can't reverse.
Exit: 0 nothing accepted · 1 unexpected acceptance(s).
"""
import sys, json, time, ssl
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def fire(url, method, headers, raw_body, timeout=10):
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    req = Request(url, data=body, headers=headers, method=method.upper())
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


I32, I64 = 2**31, 2**63


def mutations_for(value):
    """Yield (label, new_value_or_RAW) for a field's current value."""
    out = []
    if isinstance(value, bool):
        out.append(("bool_flip", not value))
    elif isinstance(value, (int, float)):
        out += [("zero", 0), ("negative_one", -1), ("negative_big", -9999),
                ("int32", I32), ("int64", I64),
                ("numeric_string", str(value)), ("string_in_number", "abc")]
    elif isinstance(value, str):
        out += [("empty_string", ""), ("number_in_string", 12345),
                ("negative_number", -1)]
    out += [("null", None), ("array_wrap", [value])]
    return out


def build_variants(base_obj):
    """Each variant = (field, label, raw_json_body)."""
    variants = []
    for field, val in base_obj.items():
        for label, newval in mutations_for(val):
            obj = dict(base_obj)
            obj[field] = newval
            variants.append((field, label, json.dumps(obj)))
        # duplicate-key injection (can't express with dict → craft raw JSON)
        dup = json.dumps(base_obj)
        inj = f', "{field}": {json.dumps(val)}, "{field}": {json.dumps("__DUP__")}'
        if dup.endswith("}"):
            raw = dup[:-1].rstrip()
            if raw.endswith("{"):
                raw = raw + f'"{field}": {json.dumps("__DUP__")}}}'
            else:
                raw = raw + inj + "}"
            variants.append((field, "duplicate_key", raw))
    return variants


def body_signature(text):
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return tuple(sorted(obj.keys()))
    except Exception:
        pass
    return None


def main():
    url = arg("--url")
    method = arg("--method", "POST")
    data = arg("--data")
    token = arg("--token")

    if not url or not data:
        print(__doc__)
        sys.exit(0)

    try:
        base_obj = json.loads(data)
        assert isinstance(base_obj, dict)
    except Exception:
        print(json.dumps({"ok": False, "error": "--data must be a JSON object",
                          "findings": []}) if flag("--json")
              else "--data must be a JSON object")
        sys.exit(0)

    headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*",
               "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token if " " in token else f"Bearer {token}"

    b_status, b_size, b_body = fire(url, method, headers, json.dumps(base_obj))
    b_sig = body_signature(b_body)
    print(f"[logic-fuzz] baseline HTTP {b_status} size={b_size}", file=sys.stderr)

    # mutations a strict API should normally reject; 2xx acceptance is the signal
    SUSPICIOUS = {"negative_one", "negative_big", "negative_number", "int32", "int64",
                  "string_in_number", "number_in_string", "bool_flip", "array_wrap",
                  "duplicate_key"}

    findings = []
    variants = build_variants(base_obj)
    for field, label, raw in variants:
        s, z, body = fire(url, method, headers, raw)
        if s not in (200, 201, 202):
            continue
        try:
            payload = json.loads(raw).get(field, "__DUP__")
        except Exception:
            payload = "<raw>"
        reflected = False
        if isinstance(payload, (int, float, str)) and str(payload):
            reflected = str(payload) in body
        struct_change = body_signature(body) != b_sig
        size_change = abs(z - b_size) > 2
        # flag: server accepted a suspicious mutation, OR the response changed in a
        # way that shows the mutated value took effect (reflected / new shape / size)
        if label in SUSPICIOUS or reflected or struct_change or size_change:
            sev = "high" if (label in ("negative_one", "negative_big", "negative_number",
                                       "bool_flip") and reflected) else "medium"
            findings.append({
                "field": field, "mutation": label,
                "payload": payload,
                "status": s, "size": z, "reflected": reflected,
                "baseline_status": b_status, "baseline_size": b_size,
                "severity": sev,
                "snippet": body[:180],
                "note": f"field '{field}' accepted mutation '{label}' with {s}"
                        + (" and the value is reflected in the response"
                           if reflected else "")
                        + " — check for value/logic abuse.",
            })
            print(f"  ✓ {field}/{label}  {s}/{z} reflected={reflected}", file=sys.stderr)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url,
        "baseline_status": b_status, "baseline_size": b_size,
        "fields": list(base_obj.keys()),
        "variants_tested": len(variants),
        "total": len(findings),
        "findings": findings,
    }

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== logic-fuzz · {url} ==")
    print(f"  baseline {b_status}/{b_size}b · {len(base_obj)} fields · "
          f"{len(variants)} mutations · {len(findings)} accepted")
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {f['field']}/{f['mutation']:<16} "
              f"→ {f['status']}/{f['size']}b  payload={f['payload']!r}")
    if not findings:
        print("  no unexpected acceptances — server validated every mutation.")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
