#!/usr/bin/env python3
"""
invariant-mine — derive candidate invariants + capability edges from the app's own artifacts,
so you don't rely on the model to *imagine* the rules. Most invariants are latent in the spec,
the client JS, or observed traffic — extract them, then invariant-check.py asserts them.

Inputs (auto-detected): OpenAPI/Swagger JSON · GraphQL SDL · client JS/TS bundle · HAR capture.
Outputs (appended, de-duped): ./.hunt/invariants.tsv  and  ./.hunt/capabilities.tsv
Each row is a CANDIDATE tagged source=mined — you confirm the identity/marker, then run it.

Usage:
  invariant-mine.py <file> [--host https://api.acme.com] [--out ./.hunt/invariants.tsv]
                          [--edges ./.hunt/capabilities.tsv] [--dry]
"""
import sys, os, re, json
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
def arg(n, d=None): return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
HOST = (arg("--host", "") or "").rstrip("/")
OUT = Path(arg("--out", str(HUNT / "invariants.tsv")))
EDG = Path(arg("--edges", str(HUNT / "capabilities.tsv")))
DRY = "--dry" in sys.argv

ONCE = re.compile(r"coupon|redeem|apply|voucher|promo|transfer|withdraw|invite|referral|vote|claim|checkout|refund", re.I)
ADMIN = re.compile(r"/admin|/internal|/manage|/superuser|/console", re.I)
MONEY = re.compile(r"amount|price|qty|quantity|balance|total|cost|credit|points|stock", re.I)
IDPARAM = re.compile(r"\{[^}]*(id|uuid|key|ref|no|num)\}", re.I)


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        print(__doc__); sys.exit(2)
    f = Path(sys.argv[1])
    if not f.exists():
        sys.exit(f"[mine] no such file: {f}")
    raw = f.read_text(errors="replace")
    kind = detect(f, raw)
    invs, edges = [], []
    if kind == "openapi":
        mine_openapi(json.loads(raw), invs, edges)
    elif kind == "har":
        mine_har(json.loads(raw), invs, edges)
    elif kind == "graphql":
        mine_graphql(raw, invs, edges)
    else:
        mine_js(raw, invs, edges)
    write(invs, edges, kind)


def detect(f, raw):
    s = f.suffix.lower()
    if s in (".graphql", ".gql") or re.search(r"\btype\s+Query\b", raw):
        return "graphql"
    if s == ".har" or '"log"' in raw[:400] and '"entries"' in raw[:2000]:
        return "har"
    if s == ".json":
        try:
            j = json.loads(raw)
            if isinstance(j, dict) and ("openapi" in j or "swagger" in j):
                return "openapi"
            if isinstance(j, dict) and "log" in j:
                return "har"
        except Exception:
            pass
    return "js"


def add(invs, t, method, path, marker, note):
    url = (HOST + path) if HOST and path.startswith("/") else path
    invs.append([t, method, url, marker, note])


def mine_openapi(spec, invs, edges):
    base = ""
    if spec.get("servers"):
        base = (spec["servers"][0].get("url", "") or "").rstrip("/")
    for path, item in (spec.get("paths") or {}).items():
        full = (HOST or base) + path
        for method, op in (item or {}).items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            m = method.upper()
            if m == "GET" and IDPARAM.search(path):
                add(invs, "noaccess", "GET", full, "<VICTIM_MARKER>", f"BOLA: {path} takes an id — test cross-user read")
            if ADMIN.search(path):
                add(invs, "deny", m, full, "", f"BFLA: {path} looks admin-only — test as low-priv role")
            if m in ("POST", "PUT", "PATCH") and ONCE.search(path):
                add(invs, "once", m, full, "", f"idempotency: {path} is a once-only action — test replay/race")
            # money/limit params → rejects (negative / over-limit)
            fields = json.dumps(op.get("parameters", [])) + json.dumps(op.get("requestBody", {}))
            if MONEY.search(fields) and m != "GET":
                add(invs, "rejects", m, full, "", f"value integrity: {path} takes a money/qty field — test negative/over-limit")
            # capability edge: auth/token endpoints
            if re.search(r"login|token|oauth|session|auth", path, re.I):
                edges.append(["anon", f"auth:{path}", "session", "unproven", "-", ""])


def mine_har(har, invs, edges):
    seen = set()
    for e in (har.get("log", {}).get("entries") or []):
        req = e.get("request", {})
        url = req.get("url", ""); m = (req.get("method", "GET")).upper()
        if not url or url in seen:
            continue
        seen.add(url)
        path = re.sub(r"https?://[^/]+", "", url)
        if m == "GET" and re.search(r"/\d{2,}(/|$|\?)", path):
            add(invs, "noaccess", "GET", url.split("?")[0], "<VICTIM_MARKER>", "BOLA: numeric id in observed request — test cross-user")
        if m in ("POST", "PUT", "PATCH") and ONCE.search(path):
            add(invs, "once", m, url.split("?")[0], "", "idempotency: once-only action seen in traffic")
        if ADMIN.search(path):
            add(invs, "deny", m, url.split("?")[0], "", "BFLA: admin path seen in traffic — test low-priv")


def mine_graphql(sdl, invs, edges):
    for mut in re.findall(r"\b(\w+)\s*\([^)]*\)\s*:\s*\w+", sdl):
        if ONCE.search(mut):
            add(invs, "once", "POST", "/graphql", "", f"idempotency: mutation {mut} — test replay")
        if MONEY.search(mut):
            add(invs, "rejects", "POST", "/graphql", "", f"value integrity: mutation {mut} — test negative/over-limit")
    if re.search(r"ownerId|userId|tenantId|accountId", sdl):
        add(invs, "noaccess", "POST", "/graphql", "<VICTIM_MARKER>", "BOLA: type has owner/tenant id — test cross-user query")


def mine_js(js, invs, edges):
    eps = set(re.findall(r"['\"](/(?:api|v\d|graphql)[^'\"?\s]{0,80})['\"]", js))
    for ep in sorted(eps):
        if IDPARAM.search(ep) or re.search(r"/\$\{|/:", ep):
            add(invs, "noaccess", "GET", (HOST + ep) if HOST else ep, "<VICTIM_MARKER>", "BOLA: id-bearing endpoint referenced in JS")
        if ONCE.search(ep):
            add(invs, "once", "POST", (HOST + ep) if HOST else ep, "", "idempotency: once-only endpoint in JS")
    if re.search(r"isAdmin|role\s*===|hasRole|isSuperuser|can(Edit|Delete|Admin)", js):
        add(invs, "deny", "GET", HOST or "<admin endpoint>", "", "client enforces a ROLE gate — verify the server enforces it too (BFLA)")
    if re.search(r"max(Uses|Redemptions|Amount|Quantity)|\blimit\b|quota", js):
        add(invs, "once", "POST", HOST or "<limited action>", "", "client enforces a LIMIT (maxUses/quota) — verify server-side (idempotency/over-limit)")
    if re.search(r"price|subtotal|discount|total", js) and re.search(r"[-+*]", js):
        add(invs, "rejects", "POST", HOST or "<price/checkout>", "", "client computes price/total — test server-side price tampering / negative")
    for tok in set(re.findall(r"(/(?:api|v\d)[^'\"?\s]*(?:token|secret|key|hash|cred)[^'\"?\s]*)", js, re.I)):
        edges.append(["anon", f"leak:{tok}", "secret_or_token", "unproven", "-", ""])


def write(invs, edges, kind):
    # de-dup by (type,url)
    def existing(p, keyidx):
        s = set()
        if p.exists():
            for ln in p.read_text().splitlines():
                if ln.strip() and not ln.startswith("#"):
                    c = ln.split("\t")
                    if len(c) > max(keyidx):
                        s.add(tuple(c[i] for i in keyidx))
        return s
    print(f"[mine] source={kind}  candidates: {len(invs)} invariants, {len(edges)} edges")
    if DRY:
        for r in invs[:40]:
            print("  INV " + " | ".join(r))
        for e in edges[:20]:
            print("  EDGE " + " | ".join(e))
        return
    HUNT.mkdir(parents=True, exist_ok=True)
    # invariants.tsv  columns: id type method url header marker note
    ex = existing(OUT, (1, 3))  # type,url
    if not OUT.exists():
        OUT.write_text("# id\ttype\tmethod\turl\theader\tmarker\tnote\n")
    n = sum(1 for ln in OUT.read_text().splitlines() if ln.strip() and not ln.startswith("#"))
    added = 0
    with OUT.open("a") as fh:
        for t, method, url, marker, note in invs:
            if (t, url) in ex:
                continue
            n += 1; added += 1
            fh.write(f"MINE-{n}\t{t}\t{method}\t{url}\t\t{marker}\t{note} [source=mined]\n")
    exe = existing(EDG, (0, 1, 2))
    eadd = 0
    if edges:
        if not EDG.exists():
            EDG.write_text("# from\tprimitive\tto\tstatus\timpact\tevidence\n")
        with EDG.open("a") as fh:
            for row in edges:
                if tuple(row[:3]) in exe:
                    continue
                eadd += 1
                fh.write("\t".join(row) + "\n")
    print(f"[mine] wrote {added} new invariant candidates → {OUT}")
    if eadd:
        print(f"[mine] wrote {eadd} new capability edges → {EDG}")
    print("  Next: fill in identities/markers, then: invariant-check.py --run", OUT)


if __name__ == "__main__":
    main()
