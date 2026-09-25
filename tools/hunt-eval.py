#!/usr/bin/env python3
"""
hunt-eval — measure whether the engine is actually getting smarter.

You cannot optimize what you don't measure. This scores the engine's *prioritisation* against
ground-truth cases (real past hunts + known-vuln apps): given a target's stack + recon signals,
does the engine rank the bug classes that were genuinely present near the TOP — before it has
seen that target? It also scores the hypothesis engine when one is installed.

Cases live in  ~/.claude/hunt-eval/cases/*.json :
  {"name":"..", "stack":"saas", "signals":{...}, "expect":["authz","idor"]}
    expect = bug classes truly present/paid on that target (the answer key)

Metrics (higher is better):
  recall@k   fraction of expected classes appearing in the engine's top-k ranked classes
  MRR        1 / rank of the first expected class the engine surfaces
  hyp_recall (if hunt-hypothesize.py present) expected classes covered by generated hypotheses

Usage:
  hunt-eval.py                 # run all cases, print scorecard, compare to last run
  hunt-eval.py --k 5 --save    # set top-k, persist this run as the new baseline
  hunt-eval.py --seed          # write the starter case set (idempotent) then exit
Exit: 0 ok / no regression · 1 regression vs baseline (for CI).
"""
import sys, os, json, importlib.util
from pathlib import Path

EVAL = Path(os.environ.get("HUNT_EVAL", str(Path.home() / ".claude" / "hunt-eval")))
CASES = EVAL / "cases"
LAST = EVAL / "last.json"
TOOLS = Path(__file__).parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def _load_tool(fname):
    p = TOOLS / fname
    if not p.exists():
        return None
    spec = importlib.util.spec_from_file_location(fname.replace("-", "_").replace(".py", ""), p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def norm(c):
    return (c or "").lower().strip().replace(" ", "").replace("-", "").replace("_", "")


SEED_CASES = [
    {"name": "jamf-global-settings-authz", "stack": "saas",
     "signals": {"tech": ["jamf", "tomcat", "bearer token"],
                 "endpoints": ["/api/v1/settings", "/api/v1/inventory-collection-settings", "/auth/keep-alive"],
                 "roles": ["admin", "low-priv"], "notes": "global (non-id-scoped) settings; token auth; two account tiers"},
     "expect": ["authz", "session"]},
    {"name": "fintech-giftcard-race", "stack": "fintech",
     "signals": {"endpoints": ["/redeem", "/wallet/topup", "/transfer"], "fields": ["amount", "code"],
                 "notes": "single-use gift codes, wallet balance"},
     "expect": ["race", "logic"]},
    {"name": "ecommerce-coupon-and-price", "stack": "ecommerce",
     "signals": {"endpoints": ["/cart", "/checkout", "/coupon"], "fields": ["price", "qty", "promo"],
                 "notes": "client posts price; single-use promo"},
     "expect": ["logic", "race"]},
    {"name": "nextjs-middleware-authbypass", "stack": "saas",
     "signals": {"tech": ["next.js 13", "middleware"], "endpoints": ["/dashboard", "/api/admin"],
                 "notes": "middleware-gated routes; CVE-2025-29927 surface"},
     "expect": ["authbypass", "authz"]},
    {"name": "saas-tenant-isolation-idor", "stack": "saas",
     "signals": {"endpoints": ["/api/orgs/{id}", "/api/orgs/{id}/members", "/export"],
                 "roles": ["tenant-A", "tenant-B"], "notes": "org-scoped objects, two tenants"},
     "expect": ["idor", "authz"]},
]


def cmd_seed():
    CASES.mkdir(parents=True, exist_ok=True)
    n = 0
    for c in SEED_CASES:
        p = CASES / (c["name"] + ".json")
        if not p.exists():
            p.write_text(json.dumps(c, indent=2))
            n += 1
    print(f"[eval] seeded {n} new case(s) → {CASES}  ({len(list(CASES.glob('*.json')))} total)")


def load_cases():
    if not CASES.exists():
        return []
    out = []
    for p in sorted(CASES.glob("*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except Exception as e:
            sys.stderr.write(f"[eval] skip {p.name}: {e}\n")
    return out


def ranked_classes(oc, stack):
    """Engine's class priority for a stack, as a list, best-first."""
    agg = oc.all_classes_with_priors(oc.score(oc.load(oc.GLOBAL), [stack] if stack else None))
    return [c for c, _ in sorted(agg.items(), key=lambda kv: -kv[1]["ev"])]


def run():
    k = int(arg("--k", "5") or 5)
    oc = _load_tool("outcome-check.py")
    if not oc:
        sys.exit("[eval] outcome-check.py not found — build #1 first.")
    hyp = _load_tool("hunt-hypothesize.py")   # #2, optional
    cases = load_cases()
    if not cases:
        sys.exit("[eval] no cases. run: hunt-eval.py --seed")

    tot_recall = tot_mrr = tot_hyp = 0.0
    hyp_cases = 0
    print(f"[eval] {len(cases)} cases · top-k={k}"
          f"{' · hypothesis engine: ON' if hyp else ''}\n")
    print(f"{'CASE':<34}{'stack':<11}{'recall@k':>9}{'MRR':>6}" + ("  hyp" if hyp else ""))
    rows = []
    for c in cases:
        exp = [norm(x) for x in c.get("expect", [])]
        ranks = ranked_classes(oc, c.get("stack"))
        topk = ranks[:k]
        hit = [e for e in exp if e in topk]
        recall = len(hit) / len(exp) if exp else 0.0
        firsts = [ranks.index(e) + 1 for e in exp if e in ranks]
        mrr = 1.0 / min(firsts) if firsts else 0.0
        line = f"{c['name'][:33]:<34}{c.get('stack',''):<11}{recall:>9.2f}{mrr:>6.2f}"
        hval = None
        if hyp:
            gen = hyp.hypotheses(c.get("signals", {}), c.get("stack"), oc)
            gcls = {norm(h["cls"]) for h in gen}
            hval = len([e for e in exp if e in gcls]) / len(exp) if exp else 0.0
            tot_hyp += hval
            hyp_cases += 1
            line += f"{hval:>5.2f}"
        print(line)
        rows.append({"name": c["name"], "recall": recall, "mrr": mrr, "hyp": hval})
        tot_recall += recall
        tot_mrr += mrr

    n = len(cases)
    summary = {"cases": n, "k": k,
               "recall@k": round(tot_recall / n, 3), "MRR": round(tot_mrr / n, 3),
               "hyp_recall": round(tot_hyp / hyp_cases, 3) if hyp_cases else None}
    print("\n" + "─" * 58)
    print(f"  mean recall@{k} = {summary['recall@k']:.3f}   mean MRR = {summary['MRR']:.3f}"
          + (f"   hyp_recall = {summary['hyp_recall']:.3f}" if summary["hyp_recall"] is not None else ""))

    regressed = False
    if LAST.exists():
        try:
            prev = json.loads(LAST.read_text())
            def delta(key):
                a, b = summary.get(key), prev.get(key)
                if a is None or b is None:
                    return ""
                d = a - b
                mark = "▲" if d > 0.001 else ("▼" if d < -0.001 else "=")
                return f"  {key}: {mark}{d:+.3f} (was {b:.3f})"
            print("  vs baseline:" + "".join(delta(k2) for k2 in ("recall@k", "MRR", "hyp_recall")))
            if (prev.get("recall@k") or 0) - summary["recall@k"] > 0.02:
                regressed = True
        except Exception:
            pass
    else:
        print("  (no baseline yet — run with --save to set one)")

    if "--save" in sys.argv:
        EVAL.mkdir(parents=True, exist_ok=True)
        LAST.write_text(json.dumps({**summary, "rows": rows}, indent=2))
        print(f"  saved baseline → {LAST}")

    if regressed:
        print("\n  ✗ REGRESSION: recall dropped >0.02 vs baseline.")
        sys.exit(1)
    sys.exit(0)


def main():
    if "--seed" in sys.argv:
        return cmd_seed()
    run()


if __name__ == "__main__":
    main()
