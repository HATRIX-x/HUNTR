#!/usr/bin/env python3
"""
disclosed-index — pull PUBLICLY disclosed reports into the local dedup corpus so
dup-score / dedup-check score a finding against the real world, not just your own
history.

Sources (public, best-effort; each degrades gracefully if unreachable/blocked):
  · HackerOne hacktivity GraphQL   (disclosed reports, titles + weakness + severity)
  · a --seed-file of {title, url, weakness} objects you paste in yourself

Writes/merges:
  · <corpus>/disclosed.jsonl        one record per disclosed report (deduped by url)
  · <HUNT_DIR>/known.md             appends titles for the current program so
                                    dedup-check picks them up

corpus = $HUNT_CORPUS or ~/.claude/hunt-corpus

Usage:
  disclosed-index.py --program shopify [--handle shopify] [--limit 100] \
                     [--weakness idor] [--seed-file more.json] [--json]
Exit: 0 ok.
"""
import sys, os, re, json, time, ssl
from pathlib import Path
from urllib.request import Request, urlopen

CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
H1_GQL = "https://hackerone.com/graphql"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def h1_hacktivity(handle, limit):
    """Query HackerOne public hacktivity for disclosed reports on a program handle."""
    query = {
        "operationName": "HacktivityPageQuery",
        "variables": {
            "querystring": f"disclosed:true program:{handle}",
            "first": min(limit, 100), "orderBy": None,
            "secureOrderBy": {"latest_disclosable_activity_at": {"_direction": "DESC"}},
        },
        "query": (
            "query HacktivityPageQuery($querystring: String!, $first: Int, "
            "$secureOrderBy: FiltersHacktivityItemFilterOrder) {"
            " search(index: CompleteHacktivityReportIndex, query_string: $querystring,"
            " first: $first, secure_order_by: $secureOrderBy) { nodes {"
            " ... on HacktivityDocument { report { title url severity_rating "
            " weakness { name } } } } } }"
        ),
    }
    req = Request(H1_GQL, data=json.dumps(query).encode(), headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "Mozilla/5.0",
    }, method="POST")
    ctx = ssl.create_default_context()
    with urlopen(req, timeout=20, context=ctx) as r:
        data = json.loads(r.read())
    out = []
    nodes = (((data.get("data") or {}).get("search") or {}).get("nodes")) or []
    for n in nodes:
        rep = (n or {}).get("report") or {}
        if not rep.get("title"):
            continue
        out.append({
            "title": rep.get("title", ""),
            "url": rep.get("url", ""),
            "severity": rep.get("severity_rating", ""),
            "weakness": ((rep.get("weakness") or {}).get("name") or ""),
            "source": "hackerone",
        })
    return out


def load_seed(path):
    if not path or not Path(path).exists():
        return []
    try:
        obj = json.loads(Path(path).read_text())
    except Exception:
        return []
    recs = obj.get("reports", obj) if isinstance(obj, dict) else obj
    out = []
    for r in recs if isinstance(recs, list) else []:
        if isinstance(r, dict) and r.get("title"):
            out.append({"title": r["title"], "url": r.get("url", ""),
                        "severity": r.get("severity", ""),
                        "weakness": r.get("weakness", ""), "source": "seed"})
    return out


def main():
    program = arg("--program", "")
    handle = arg("--handle", program)
    limit = int(arg("--limit", "100"))
    weakness = (arg("--weakness", "") or "").lower()
    seed_file = arg("--seed-file")

    CORPUS.mkdir(parents=True, exist_ok=True)
    HUNT.mkdir(parents=True, exist_ok=True)
    index_file = CORPUS / "disclosed.jsonl"

    existing = {}
    if index_file.exists():
        for line in index_file.read_text().splitlines():
            try:
                rec = json.loads(line)
                existing[rec.get("url") or rec.get("title")] = rec
            except Exception:
                pass

    fetched, errors = [], []
    if handle:
        try:
            fetched += h1_hacktivity(handle, limit)
        except Exception as ex:
            errors.append(f"hackerone: {type(ex).__name__}: {str(ex)[:120]}")
    fetched += load_seed(seed_file)

    added = 0
    for rec in fetched:
        if weakness and weakness not in (rec.get("weakness", "") + rec.get("title", "")).lower():
            continue
        key = rec.get("url") or rec.get("title")
        if key and key not in existing:
            existing[key] = rec
            added += 1

    with index_file.open("w") as f:
        for rec in existing.values():
            f.write(json.dumps(rec) + "\n")

    known = HUNT / "known.md"
    titles = [r["title"] for r in existing.values() if r.get("title")]
    if titles:
        header = f"\n<!-- disclosed-index {program} {time.strftime('%Y-%m-%d')} -->\n"
        body = "\n".join(f"- {t}" for t in titles[:limit])
        prev = known.read_text() if known.exists() else ""
        known.write_text(prev + header + body + "\n")

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "program": program, "handle": handle,
        "fetched": len(fetched), "added": added,
        "index_total": len(existing),
        "index_file": str(index_file), "known_file": str(known),
        "errors": errors,
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"\n== disclosed-index · {program} ==")
    print(f"  fetched {len(fetched)} · added {added} new · corpus now {len(existing)} reports")
    if errors:
        for e in errors:
            print(f"  ! {e}")
    print(f"  → {index_file}")
    print(f"  → {known} (dedup-check reads this)")
    sys.exit(0)


if __name__ == "__main__":
    main()
