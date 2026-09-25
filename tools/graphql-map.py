#!/usr/bin/env python3
"""
graphql-map — introspect a GraphQL endpoint and map the full attack surface.

Fires an introspection query, maps every query/mutation/subscription to a vuln
class (IDOR, injection, upload, rate-limit bypass, authz), and seeds
coverage.tsv cells ready to probe. Detects batch-query support (rate-limit
bypass), user/account/admin fields (IDOR candidates), file upload mutations
(RCE/path traversal), and dangerous scalar types.

Usage:
  graphql-map.py --url https://api.acme.com/graphql [--token Bearer:xxx]
                 [--json] [--out report.json] [--seed-coverage]
  graphql-map.py --url https://api.acme.com/graphql --batch-test
Exit: 0.
"""
import sys, re, json, os
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

HUNT_DIR = Path(os.environ.get("HUNT_DIR", "."))

INTROSPECT_Q = """{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields(includeDeprecated:true){name description type{name kind ofType{name kind ofType{name kind}}}args{name type{name kind ofType{name kind}}}}inputFields{name type{name kind ofType{name kind}}}}}}" }"""

IDOR_HINTS = re.compile(r"(?i)(?:id|userId|accountId|orderId|customerId|resourceId|objectId|ownerId|memberId|tenantId|orgId)")
ADMIN_HINTS = re.compile(r"(?i)(?:admin|internal|superuser|staff|manage|sudo|root|privilege|elevated|system)")
UPLOAD_HINTS = re.compile(r"(?i)(?:upload|file|attachment|image|document|media|blob|multipart)")
INJECT_HINTS = re.compile(r"(?i)(?:query|search|filter|where|expression|formula|template|eval|exec|command|script|raw)")
AUTH_HINTS   = re.compile(r"(?i)(?:login|logout|register|signup|token|refresh|auth|password|reset|verify|otp|mfa|session)")
PII_HINTS    = re.compile(r"(?i)(?:email|phone|ssn|dob|address|passport|credit|card|bank|salary|secret|private)")
RATE_HINTS   = re.compile(r"(?i)(?:send|submit|verify|confirm|resend|request|initiat|create|transact|pay|charge|transfer)")


def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def flag(n): return n in sys.argv

def gql_request(url, payload, headers=None, timeout=20):
    h = {"Content-Type":"application/json","Accept":"application/json",
         "User-Agent":"Mozilla/5.0"}
    if headers: h.update(headers)
    req = Request(url, data=payload.encode() if isinstance(payload,str) else payload,
                  headers=h, method="POST")
    try:
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8","ignore"))
    except Exception as e:
        return {"error": str(e)}

def build_headers(token):
    if not token: return {}
    if token.startswith("Bearer:"): return {"Authorization": f"Bearer {token[7:]}"}
    if token.startswith("Basic:"):  return {"Authorization": f"Basic {token[6:]}"}
    if ":" in token:
        k,v = token.split(":",1); return {k: v}
    return {"Authorization": f"Bearer {token}"}

def resolve_type(t):
    """Unwrap NON_NULL / LIST wrappers to get the base type name."""
    if not t: return "?"
    if t.get("name"): return t["name"]
    return resolve_type(t.get("ofType"))

def classify_field(name, type_name=""):
    combined = f"{name} {type_name}".lower()
    cats = []
    if IDOR_HINTS.search(combined): cats.append("IDOR")
    if ADMIN_HINTS.search(combined): cats.append("AUTHZ")
    if UPLOAD_HINTS.search(combined): cats.append("UPLOAD")
    if INJECT_HINTS.search(combined): cats.append("INJECT")
    if AUTH_HINTS.search(combined):   cats.append("AUTH")
    if PII_HINTS.search(combined):    cats.append("PII")
    if RATE_HINTS.search(combined):   cats.append("RATE-LIMIT")
    return cats or ["MISC"]

def classify_op(name, op_type, args):
    """Return (vuln_class, priority, reason)."""
    arg_names = " ".join(a.get("name","") for a in (args or []))
    combined  = f"{name} {arg_names}"
    cats = classify_field(combined)
    # mutations are higher priority than queries
    base_pri = 2 if op_type == "mutation" else (3 if op_type == "subscription" else 4)
    if "IDOR" in cats or "AUTHZ" in cats: base_pri = min(base_pri, 1)
    if "UPLOAD" in cats or "INJECT" in cats: base_pri = min(base_pri, 1)
    if "AUTH" in cats: base_pri = min(base_pri, 2)
    return cats, base_pri

def test_batch(url, headers):
    """Check if server accepts array batching (rate-limit bypass)."""
    payload = json.dumps([{"query":"{__typename}"},{"query":"{__typename}"}])
    r = gql_request(url, payload, headers)
    return isinstance(r, list)

def introspect(url, headers):
    r = gql_request(url, INTROSPECT_Q, headers)
    if "error" in r:
        # try GET introspection (some endpoints)
        try:
            from urllib.request import urlopen, Request
            from urllib.parse import quote
            q = quote('{"query":"{__schema{queryType{name}}}"}')
            req2 = Request(f"{url}?query={{{quote('__typename')}}}", headers={**headers,"Accept":"application/json"})
            with urlopen(req2,timeout=10) as resp:
                return json.loads(resp.read().decode()), True
        except Exception:
            pass
        return None, False
    schema = r.get("data",{}).get("__schema") or {}
    return schema, bool(schema)

def map_operations(schema):
    types_by_name = {t["name"]: t for t in (schema.get("types") or [])}
    ops = []
    for kind, root_key in [("query","queryType"),("mutation","mutationType"),("subscription","subscriptionType")]:
        root = schema.get(root_key) or {}
        root_name = root.get("name")
        if not root_name or root_name not in types_by_name: continue
        root_type = types_by_name[root_name]
        for field in (root_type.get("fields") or []):
            name = field.get("name","")
            rtype = resolve_type(field.get("type"))
            args = field.get("args") or []
            cats, pri = classify_op(name, kind, args)
            # check return type fields for IDOR/PII
            ret_type = types_by_name.get(rtype,{})
            ret_fields = [f.get("name","") for f in (ret_type.get("fields") or [])]
            extra = classify_field(" ".join(ret_fields))
            for c in extra:
                if c not in cats: cats.append(c)
            ops.append({
                "op": kind, "name": name, "return_type": rtype,
                "args": [{"name":a["name"],"type":resolve_type(a.get("type"))} for a in args],
                "classes": cats, "priority": pri,
                "description": (field.get("description") or "")[:120],
            })
    return sorted(ops, key=lambda o: (o["priority"], o["op"], o["name"]))

def seed_coverage(ops, url):
    cov = HUNT_DIR / "coverage.tsv"
    lines = cov.read_text().splitlines() if cov.exists() else []
    header = lines[0] if lines else "endpoint\tclass\tstatus\tdepth\tnotes"
    existing = {l.split("\t")[0] for l in lines[1:]}
    new_lines = []
    for op in ops:
        for cls in op["classes"]:
            key = f"GraphQL:{op['op']}:{op['name']}"
            if key not in existing:
                args = ",".join(a["name"] for a in op.get("args",[])[:4])
                note = f"→{op['return_type']} args:[{args}]"
                new_lines.append(f"{key}\t{cls}\tTODO\tT0\t{note}")
                existing.add(key)
    if new_lines:
        cov.write_text(header + "\n" + "\n".join(lines[1:]) + "\n" + "\n".join(new_lines) + "\n")
        print(f"[graphql-map] seeded {len(new_lines)} cells → {cov}", file=sys.stderr)
    return len(new_lines)

def main():
    url = arg("--url")
    if not url: print(__doc__); sys.exit(0)

    token = arg("--token")
    headers = build_headers(token)
    print(f"[graphql-map] introspecting {url} …", file=sys.stderr)

    schema, ok = introspect(url, headers)
    if not ok:
        # introspection disabled — try common field probes
        print("[graphql-map] introspection disabled. Trying field probes…", file=sys.stderr)
        probes = ["{me{id email}}", "{user(id:1){id}}","  {users{id email}}", "{viewer{id}}"]
        result = {"introspection": False, "url": url, "probes": []}
        for p in probes:
            r = gql_request(url, json.dumps({"query":p}), headers)
            if "data" in r and r["data"]:
                result["probes"].append({"query":p,"response":str(r["data"])[:200]})
        result["operations"] = []
        result["batch_support"] = False
        result["notes"] = ["Introspection disabled — manual field enumeration required","Probe results attached"]
        if flag("--json"): print(json.dumps(result)); return
        print("[graphql-map] introspection disabled. Try --token or field probing manually."); return

    ops = map_operations(schema)
    batch = test_batch(url, headers)

    # summary counts
    mutations  = [o for o in ops if o["op"]=="mutation"]
    queries    = [o for o in ops if o["op"]=="query"]
    subs       = [o for o in ops if o["op"]=="subscription"]
    idor_ops   = [o for o in ops if "IDOR" in o["classes"]]
    upload_ops = [o for o in ops if "UPLOAD" in o["classes"]]
    admin_ops  = [o for o in ops if "AUTHZ" in o["classes"]]
    auth_ops   = [o for o in ops if "AUTH" in o["classes"]]

    notes = []
    if batch: notes.append("✓ Batch queries accepted — rate-limit bypass possible (send 100 login attempts in one request)")
    if upload_ops: notes.append(f"⚠ {len(upload_ops)} upload mutation(s) — test for unrestricted file upload / path traversal")
    if admin_ops:  notes.append(f"⚠ {len(admin_ops)} admin/elevated operation(s) — test BFLA / privilege escalation")
    if idor_ops:   notes.append(f"⚠ {len(idor_ops)} IDOR-candidate operation(s) — test cross-user access")
    if subs:       notes.append(f"✓ {len(subs)} subscription(s) — test for unauth real-time data leak")

    result = {
        "url": url, "introspection": True, "batch_support": batch,
        "counts": {"queries":len(queries),"mutations":len(mutations),"subscriptions":len(subs),"total":len(ops)},
        "priority_ops": [o for o in ops if o["priority"]<=2][:40],
        "operations": ops,
        "notes": notes,
    }

    out_file = arg("--out")
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--seed-coverage"):
        seeded = seed_coverage(ops, url)
        result["seeded_cells"] = seeded

    if flag("--json"):
        print(json.dumps(result)); return

    # human report
    print(f"\n══ GraphQL surface · {url} ════════════════════════════")
    print(f"  Queries: {len(queries)}  Mutations: {len(mutations)}  Subscriptions: {len(subs)}")
    print(f"  Batch: {'✓ YES — rate-limit bypass' if batch else '✗ no'}\n")
    print(f"  Priority operations (IDOR/AUTHZ/UPLOAD first):")
    for o in [op for op in ops if op["priority"]<=2][:20]:
        args = ", ".join(f"{a['name']}:{a['type']}" for a in o["args"][:3])
        print(f"    [{o['op'].upper():<8}] {o['name']:<32} {', '.join(o['classes'])} → {o['return_type']}")
        if args: print(f"             args: {args}")
    if notes:
        print("\n  Notes:")
        for n in notes: print(f"    → {n}")

if __name__ == "__main__":
    main()
