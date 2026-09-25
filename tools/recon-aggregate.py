#!/usr/bin/env python3
"""
recon-aggregate — fuse recon output into one signal map the whole engine reads.

The engine is only as smart as its surface map. This ingests whatever recon you have — URL dumps
(gau/wayback/katana), JS files, an OpenAPI/Swagger spec, a HAR, a subdomain list, or raw text — and
merges it (deduped) into ./.hunt/signals.json (feeds hunt-hypothesize) plus ./.hunt/surface.txt
(feeds hunt-monitor's baseline). Run it repeatedly; it MERGES, never clobbers.

Extracts: hosts · endpoints (paths) · params/fields · tech/versions · exposed secrets.

Usage (any combination):
  recon-aggregate.py --urls gau.txt --js app.js,vendor.js --openapi swagger.json \
                     --har traffic.har --subs subs.txt [--raw notes.txt] [--stack saas]
  cat urls.txt | recon-aggregate.py --urls -           # '-' = stdin
Exit: 0 ok.
"""
import sys, os, re, json
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
SIG = HUNT / "signals.json"
SURFACE = HUNT / "surface.txt"

SECRET_RE = re.compile(
    r"(sk_[a-z0-9_]{6,}|akia[0-9a-z]{10,}|ghp_[a-z0-9]{20,}|xox[baprs]-[a-z0-9-]+|-----begin[ a-z]+private key|"
    r"(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret)\s*[=:]\s*['\"]?[a-z0-9_\-]{8,}|"
    r"ey[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{6,})", re.I)
PATH_IN_JS = re.compile(r"""['"`](/[a-zA-Z0-9_][a-zA-Z0-9_/{}.\-]{2,})['"`]""")
TECH_HDR = re.compile(r"^(server|x-powered-by|x-generator|via)\s*:\s*(.+)$", re.I)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def read(spec):
    if spec == "-":
        return sys.stdin.read()
    return Path(spec).read_text(errors="replace")


def norm_path(u):
    u = u.split("#")[0]
    p = re.sub(r"^https?://[^/]+", "", u)
    return p or "/"


class Bag:
    def __init__(s):
        s.hosts, s.endpoints, s.params, s.tech, s.secrets = set(), set(), set(), set(), set()

    def url(s, u):
        u = u.strip()
        if not u:
            return
        m = re.match(r"^https?://([^/:]+)", u)
        if m:
            s.hosts.add(m.group(1).lower())
        p = norm_path(u)
        if "?" in p:
            base, q = p.split("?", 1)
            s.endpoints.add(base)
            for kv in re.split(r"[&;]", q):
                k = kv.split("=", 1)[0]
                if k:
                    s.params.add(k)
        elif p and p != "/":
            s.endpoints.add(p)
        if SECRET_RE.search(u):
            s.secrets.add(u[:120])


def ingest_urls(bag, spec):
    for ln in read(spec).splitlines():
        bag.url(ln.strip())


def ingest_js(bag, spec):
    for f in spec.split(","):
        f = f.strip()
        if not f:
            continue
        paths = [f]
        if Path(f).is_dir():
            paths = [str(p) for p in Path(f).rglob("*.js")]
        for p in paths:
            try:
                txt = read(p)
            except Exception:
                continue
            for m in PATH_IN_JS.finditer(txt):
                bag.endpoints.add(m.group(1))
            for m in SECRET_RE.finditer(txt):
                bag.secrets.add(f"{Path(p).name}: {m.group(0)[:80]}")


def ingest_openapi(bag, spec):
    try:
        doc = json.loads(read(spec))
    except Exception as e:
        sys.stderr.write(f"[recon] openapi parse failed: {e}\n")
        return
    for srv in doc.get("servers", []):
        u = srv.get("url", "")
        m = re.match(r"^https?://([^/]+)", u)
        if m:
            bag.hosts.add(m.group(1).lower())
    for path, item in (doc.get("paths", {}) or {}).items():
        bag.endpoints.add(path)
        if not isinstance(item, dict):
            continue
        for meth, op in item.items():
            if not isinstance(op, dict):
                continue
            for pr in op.get("parameters", []) or []:
                if isinstance(pr, dict) and pr.get("name"):
                    bag.params.add(pr["name"])
            body = (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema") or {}
            for prop in (body.get("properties") or {}):
                bag.params.add(prop)


def ingest_har(bag, spec):
    try:
        doc = json.loads(read(spec))
    except Exception as e:
        sys.stderr.write(f"[recon] har parse failed: {e}\n")
        return
    for ent in (doc.get("log", {}).get("entries", []) or []):
        req = ent.get("request", {})
        bag.url(req.get("url", ""))
        for h in req.get("headers", []) or []:
            nm = (h.get("name") or "").lower()
            if nm in ("authorization", "cookie") or nm.startswith("x-"):
                bag.tech.add(f"auth-header:{nm}")
        for pp in req.get("postData", {}).get("params", []) or []:
            if pp.get("name"):
                bag.params.add(pp["name"])
        for h in ent.get("response", {}).get("headers", []) or []:
            m = TECH_HDR.match(f"{h.get('name','')}: {h.get('value','')}")
            if m:
                bag.tech.add(m.group(2).strip()[:40])


def ingest_subs(bag, spec):
    for ln in read(spec).splitlines():
        h = re.sub(r"^https?://", "", ln.strip()).split("/")[0].lower()
        if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", h):
            bag.hosts.add(h)


def ingest_raw(bag, spec):
    txt = read(spec)
    for m in re.finditer(r"https?://[^\s)>\]]+", txt):
        bag.url(m.group(0))
    for m in re.finditer(r"(?<![\w.@/])((?:[a-z0-9-]+\.)+[a-z]{2,})", txt, re.I):
        if m.group(1).rsplit(".", 1)[-1] not in ("js", "json", "css", "html", "png", "md", "txt"):
            bag.hosts.add(m.group(1).lower())
    for m in SECRET_RE.finditer(txt):
        bag.secrets.add(m.group(0)[:100])


def merge_list(old, new):
    return sorted(set(old or []) | set(new))


def main():
    bag = Bag()
    did = []
    for opt, fn in [("--urls", ingest_urls), ("--js", ingest_js), ("--openapi", ingest_openapi),
                    ("--har", ingest_har), ("--subs", ingest_subs), ("--raw", ingest_raw)]:
        if opt in sys.argv:
            fn(bag, arg(opt))
            did.append(opt[2:])
    if not did:
        sys.exit("nothing to ingest. pass --urls/--js/--openapi/--har/--subs/--raw (any combo).")

    HUNT.mkdir(parents=True, exist_ok=True)
    sig = {}
    if SIG.exists():
        try:
            sig = json.loads(SIG.read_text())
        except Exception:
            pass
    sig["tech"] = merge_list(sig.get("tech"), bag.tech)
    sig["endpoints"] = merge_list(sig.get("endpoints"), bag.endpoints)
    sig["fields"] = merge_list(sig.get("fields"), bag.params)
    sig["hosts"] = merge_list(sig.get("hosts"), bag.hosts)
    sig["secrets"] = merge_list(sig.get("secrets"), bag.secrets)
    sig.setdefault("roles", [])
    stack = arg("--stack")
    note = sig.get("notes", "")
    if stack and f"stacks={stack}" not in note:
        note = (note + f"; stacks={stack}").strip("; ")
    sig["notes"] = note
    SIG.write_text(json.dumps(sig, indent=2))

    # surface.txt for the monitor (hosts, endpoints, params-as-query, secrets, tech)
    lines = sorted(sig["hosts"]) + sorted(sig["endpoints"]) + \
        [f"{e}?{p}=" for e in sorted(sig["endpoints"])[:1] for p in sorted(sig["fields"])[:0]] + \
        [f"param:{p}" for p in sorted(sig["fields"])] + \
        sorted(sig["secrets"]) + [f"tech: {t}" for t in sorted(sig["tech"])]
    SURFACE.write_text("\n".join(lines) + ("\n" if lines else ""))

    print(f"[recon] ingested {', '.join(did)} → merged into {SIG}\n")
    print(f"  hosts:     {len(sig['hosts'])}")
    print(f"  endpoints: {len(sig['endpoints'])}")
    print(f"  params:    {len(sig['fields'])}")
    print(f"  tech:      {len(sig['tech'])}  {', '.join(sig['tech'][:6])}")
    print(f"  secrets:   {len(sig['secrets'])}" + ("  ⚠ verify + report the live ones" if sig["secrets"] else ""))
    print(f"\n  → surface.txt written ({len(lines)} items) for: hunt-monitor.py --target <t> --surface {SURFACE} --snapshot")
    print(f"  → then: hunt-hypothesize.py --signals {SIG}" + (f" --stack {stack}" if stack else ""))


if __name__ == "__main__":
    main()
