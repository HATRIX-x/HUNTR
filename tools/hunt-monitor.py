#!/usr/bin/env python3
"""
hunt-monitor — watch a target's attack surface and turn NEW surface into ranked leads automatically.

New surface is where first-to-report bounties live. This snapshots what exists, diffs it on the
next scan, and — the wiring — feeds every new item straight into the hypothesis engine so you get
"here's what appeared AND here's the bug to test for it," ordered by your paid history (outcome EV).

Surface items (one per line; type is inferred, or prefix `tech:`/`param:`):
  api.acme.com                      → subdomain/host
  /api/v2/internal/exports          → endpoint
  /api/v1/orders?includeInternal=   → param
  main.9f3c.js :: sk_test_51Q...    → secret
  tech: nginx 1.27.0                → tech/version

Snapshots persist at ~/.claude/hunt-monitor/<target>.json (survives sessions).

Usage:
  hunt-monitor.py --target api.acme.com --surface surface.txt [--snapshot]     # set/replace baseline
  hunt-monitor.py --target api.acme.com --surface new.txt [--stack saas] \
      [--roles admin,low-priv] [--emit ./.hunt/hypotheses.tsv]                  # diff → new leads
  echo "/api/v2/fetch?url=" | hunt-monitor.py --target api.acme.com --stack saas
Exit: 0 no new surface · 1 new surface found (leads printed).
"""
import sys, os, re, json, time, importlib.util
from pathlib import Path

STORE = Path(os.environ.get("HUNT_MONITOR", str(Path.home() / ".claude" / "hunt-monitor")))
TOOLS = Path(__file__).parent
SECRET_RE = re.compile(
    r"(sk_[a-z0-9_]{6,}|akia[0-9a-z]{10,}|-----begin|xox[baprs]-|ghp_[a-z0-9]{20,}|"
    r"aws_secret|api[_-]?key|client_secret|password\s*[=:]|bearer\s+ey[a-z0-9]|ey[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.)",
    re.I)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


def _load(fname):
    p = TOOLS / fname
    if not p.exists():
        return None
    spec = importlib.util.spec_from_file_location(fname.replace("-", "_").replace(".py", ""), p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def safe(t):
    return re.sub(r"[^a-z0-9._-]+", "_", t.lower())


def read_surface():
    s = arg("--surface")
    if s:
        return [l.strip() for l in Path(s).read_text().splitlines() if l.strip()]
    if not sys.stdin.isatty():
        return [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    return []


def classify(item):
    s = item.strip()
    if s.lower().startswith("tech:"):
        return "tech", s.split(":", 1)[1].strip()
    if s.lower().startswith("param:"):
        return "param", s.split(":", 1)[1].strip()
    if SECRET_RE.search(s):
        return "secret", s
    path = re.sub(r"^https?://[^/]+", "", s)
    if ("?" in s and "=" in s):
        return "param", s
    if s.startswith("/") or (path and path != s and path not in ("", "/")):
        return "endpoint", s
    if re.match(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}/?$", s, re.I):
        return "subdomain", s
    return "endpoint", s


def leads_for(kind, value, stack, roles, hyp, oc):
    """Return list of {cls,why,test,score,prior_ev} leads for one new surface item."""
    if kind == "secret":
        return [{"cls": "secret", "why": "exposed credential/secret in new surface", "score": 2.0,
                 "prior_ev": 0, "test": "verify the key is LIVE and its scope (make one benign authenticated call); "
                 "if valid → report as exposed secret; rotate advice in remediation"}]
    if kind == "subdomain":
        host = re.sub(r"^https?://", "", value).rstrip("/")
        return [{"cls": "recon", "why": "brand-new host — untested surface", "score": 1.5, "prior_ev": 0,
                 "test": f"scope-guard then full pipeline: /autohunt {host}  (fresh assets = first-to-report)"}]
    if kind == "tech":
        return [{"cls": "cve", "why": f"tech/version change: {value}", "score": 1.2, "prior_ev": 0,
                 "test": "map the new version to known CVEs (scan-cves / hunt-program-intel); test any that apply"}]
    # endpoint / param → real hypotheses
    sig = {"endpoints": [value], "fields": [value] if kind == "param" else [], "roles": roles, "notes": ""}
    hs = hyp.hypotheses(sig, stack, oc) if hyp else []
    return hs[:3] if hs else [{"cls": "misc", "why": "new endpoint", "score": 0.5, "prior_ev": 0,
                              "test": "enumerate methods/params; run the applicable hunt-<class> matrix"}]


def main():
    target = arg("--target")
    if not target:
        sys.exit("usage: hunt-monitor.py --target <t> --surface <file> [--snapshot] [--stack ..] [--roles ..] [--emit ..]")
    STORE.mkdir(parents=True, exist_ok=True)
    snap_path = STORE / (safe(target) + ".json")
    log_path = STORE / (safe(target) + ".changes.jsonl")
    surface = read_surface()
    if not surface:
        sys.exit("no surface items provided (--surface FILE or stdin)")

    prev = set()
    if snap_path.exists():
        try:
            prev = set(json.loads(snap_path.read_text()).get("surface", []))
        except Exception:
            pass

    if flag("--snapshot") or not prev:
        snap_path.write_text(json.dumps({"target": target, "surface": sorted(set(surface)),
                                         "ts": time.strftime("%Y-%m-%d %H:%M")}, indent=2))
        print(f"[monitor] baseline set for {target}: {len(set(surface))} surface items → {snap_path}")
        if not flag("--snapshot"):
            print("          (first run = baseline; next run with --surface diffs it into new leads)")
        return

    new = [x for x in surface if x not in prev]
    # persist: never re-alert on something already seen
    snap_path.write_text(json.dumps({"target": target, "surface": sorted(prev | set(surface)),
                                     "ts": time.strftime("%Y-%m-%d %H:%M")}, indent=2))
    if not new:
        print(f"[monitor] {target}: no new surface since last scan ({len(prev)} known).")
        sys.exit(0)

    stack = arg("--stack")
    roles = [r.strip() for r in (arg("--roles") or "").split(",") if r.strip()]
    hyp = _load("hunt-hypothesize.py")
    oc = _load("outcome-check.py")

    items = []
    for it in new:
        kind, val = classify(it)
        leads = leads_for(kind, val, stack, roles, hyp, oc)
        top = leads[0] if leads else None
        pr = top["score"] if top else 0
        items.append((pr, kind, val, leads))
        with log_path.open("a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M"), "kind": kind, "value": val,
                                "top_lead": (top or {}).get("cls")}) + "\n")
    items.sort(key=lambda x: -x[0])

    hv = sum(1 for pr, *_ in items if pr >= 0.9)
    print(f"[monitor] {target}: {len(new)} NEW surface item(s) since last scan "
          f"({hv} high-value)  — auto-hypothesised, ranked by paid history\n")
    emit = arg("--emit")
    emit_rows = []
    for pr, kind, val, leads in items:
        star = "★" if pr >= 0.9 else " "
        print(f" {star} NEW {kind:<9} {val}")
        for h in leads:
            ev = f" EV≈${h['prior_ev']:.0f}" if h.get("prior_ev") else ""
            print(f"      ⇒ hunt-{h['cls']:<10}{ev}  {h['why']}\n         → {h['test']}")
            emit_rows.append((kind, val, h))
        print()

    if emit:
        p = Path(emit)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("# id\tclass\tscore\tprior_ev\tstatus\twhy\ttest\n")
        n = sum(1 for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#"))
        with p.open("a") as f:
            for kind, val, h in emit_rows:
                n += 1
                f.write(f"MON-{n}\t{h['cls']}\t{h.get('score',0)}\t{h.get('prior_ev',0):.0f}\topen\t"
                        f"[new {kind}] {h['why']}\t{h['test']}  (surface: {val})\n")
        print(f"[monitor] appended {len(emit_rows)} lead(s) → {p}")
    print("  → hunt the ★ high-value items first; new surface + a ready hypothesis = first-to-report.")
    sys.exit(1)


if __name__ == "__main__":
    main()
