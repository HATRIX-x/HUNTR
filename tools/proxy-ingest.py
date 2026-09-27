#!/usr/bin/env python3
"""
proxy-ingest — import an existing proxy history into HUNTR's attack surface, so a
hunter who lives in Burp/Caido doesn't re-crawl. Meets them where they work.

Accepts (auto-detected by content):
  · Burp Suite XML export           (<items><item>…</item></items>, base64 requests)
  · HAR 1.2                         (Burp "Save as HAR", Caido export, DevTools)
  · plain URL list                  (one URL per line)

Extracts per endpoint: method, normalised URL, query + body params, host.
De-dupes by (method, path-template). Writes:
  · <HUNT_DIR>/endpoints.json       merged endpoint inventory
  · <HUNT_DIR>/coverage.tsv         appends "method\turl\tparams" rows (untested)

Usage:
  proxy-ingest.py --file history.xml [--scope acme.com] [--in-scope-only] [--json]
Exit: 0 ok.
"""
import sys, os, re, json, time, base64
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def norm_path(p):
    p = re.sub(r"/\d+", "/{id}", p or "/")
    return re.sub(r"/[0-9a-f]{8,}", "/{id}", p)


def body_params(body, ctype):
    params = []
    if not body:
        return params
    if "json" in (ctype or "").lower():
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                params = list(obj.keys())
        except Exception:
            pass
    elif "=" in body:
        params = [kv.split("=", 1)[0] for kv in body.split("&") if "=" in kv]
    return params


def add(endpoints, method, url, body="", ctype=""):
    if not url:
        return
    u = urlparse(url)
    if not u.scheme:
        return
    key = f"{method} {u.netloc}{norm_path(u.path)}"
    rec = endpoints.setdefault(key, {
        "method": method, "host": u.netloc,
        "url": f"{u.scheme}://{u.netloc}{u.path}",
        "path_template": norm_path(u.path),
        "params": set(), "seen": 0,
    })
    rec["seen"] += 1
    for k in parse_qs(u.query):
        rec["params"].add(k)
    for k in body_params(body, ctype):
        rec["params"].add(k)


def parse_burp_xml(text, endpoints):
    root = ET.fromstring(text)
    for item in root.findall(".//item"):
        method = (item.findtext("method") or "GET").strip()
        url = (item.findtext("url") or "").strip()
        req_el = item.find("request")
        body, ctype = "", ""
        if req_el is not None and (req_el.text or ""):
            raw = req_el.text
            if req_el.get("base64") == "true":
                try:
                    raw = base64.b64decode(raw).decode("utf-8", "ignore")
                except Exception:
                    raw = ""
            m = re.search(r"content-type:\s*([^\r\n]+)", raw, re.I)
            ctype = m.group(1) if m else ""
            parts = re.split(r"\r?\n\r?\n", raw, 1)
            body = parts[1] if len(parts) > 1 else ""
        add(endpoints, method, url, body, ctype)


def parse_har(text, endpoints):
    obj = json.loads(text)
    for e in (obj.get("log", {}).get("entries", []) or []):
        req = e.get("request", {})
        method = req.get("method", "GET")
        url = req.get("url", "")
        post = req.get("postData", {}) or {}
        body = post.get("text", "")
        ctype = post.get("mimeType", "")
        if not body and post.get("params"):
            body = "&".join(f"{p.get('name')}={p.get('value','')}" for p in post["params"])
            ctype = "application/x-www-form-urlencoded"
        add(endpoints, method, url, body, ctype)


def parse_urls(text, endpoints):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("http"):
            add(endpoints, "GET", line)


def main():
    fpath = arg("--file")
    scope = arg("--scope")
    in_scope_only = flag("--in-scope-only")

    if not fpath or not Path(fpath).exists():
        print(__doc__)
        sys.exit(0)

    text = Path(fpath).read_text(errors="ignore")
    endpoints = {}
    kind = "unknown"
    head = text.lstrip()[:200].lower()
    try:
        if head.startswith("<?xml") or "<items" in head:
            kind = "burp-xml"; parse_burp_xml(text, endpoints)
        elif head.startswith("{") and '"log"' in text[:2000]:
            kind = "har"; parse_har(text, endpoints)
        else:
            kind = "urls"; parse_urls(text, endpoints)
    except Exception as ex:
        print(json.dumps({"ok": False, "error": f"{kind} parse failed: {ex}"}) if flag("--json")
              else f"parse failed ({kind}): {ex}")
        sys.exit(0)

    recs = []
    for rec in endpoints.values():
        if in_scope_only and scope and scope not in rec["host"]:
            continue
        rec["params"] = sorted(rec["params"])
        recs.append(rec)
    recs.sort(key=lambda r: (-r["seen"], r["url"]))

    HUNT.mkdir(parents=True, exist_ok=True)
    (HUNT / "endpoints.json").write_text(json.dumps(recs, indent=2))
    with (HUNT / "coverage.tsv").open("a") as f:
        for r in recs:
            f.write(f"{r['method']}\t{r['url']}\t{','.join(r['params'])}\n")

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "source_kind": kind, "endpoints": len(recs),
        "with_params": sum(1 for r in recs if r["params"]),
        "hosts": sorted({r["host"] for r in recs}),
        "out": str(HUNT / "endpoints.json"),
        "top": recs[:15],
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"\n== proxy-ingest · {kind} ==")
    print(f"  {len(recs)} endpoints ({result['with_params']} with params) across "
          f"{len(result['hosts'])} host(s)")
    for r in recs[:15]:
        print(f"  {r['method']:<6} {r['url']}  [{','.join(r['params'][:6])}]")
    print(f"  → {HUNT / 'endpoints.json'}")
    sys.exit(0)


if __name__ == "__main__":
    main()
