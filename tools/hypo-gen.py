#!/usr/bin/env python3
"""
hypo-gen — hypothesis generator. Given the endpoints already mapped and the
findings so far, ask the configured LLM for the highest-ROI attack hypotheses
NOT yet tested, each with a concrete HUNTR command to run next.

Reads HUNT_LLM_API_KEY from env (or --api-key). Uses llm_client for provider abstraction.
Zero deps beyond stdlib.

Usage:
  hypo-gen.py --endpoints-file eps.json --findings-file finds.json \
              [--program acme] [--model nvidia/nemotron-3-ultra-550b-a55b] [--max 5] [--json]

  eps.json    : ["https://api.acme.com/v1/orders", ...]  (or {"endpoints":[...]})
  finds.json  : [ {finding}, ... ]                       (or {"findings":[...]})

Output: {ok, hypotheses:[{title, attack_class, target_endpoint, why_likely,
          test_command, estimated_severity}]}
"""
import sys, os, json, time
from pathlib import Path

# Use the unified LLM client
sys.path.insert(0, os.path.dirname(__file__))
import llm_client


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


def load_list(path, key):
    if not path:
        return []
    try:
        obj = json.loads(Path(path).read_text())
    except Exception:
        return []
    if isinstance(obj, dict):
        return obj.get(key, [])
    return obj if isinstance(obj, list) else []


def extract_json(text):
    if not text:
        return None
    a, b = text.find("["), text.rfind("]")
    if a >= 0 and b > a:
        try:
            return json.loads(text[a:b + 1])
        except Exception:
            pass
    a, b = text.find("{"), text.rfind("}")
    if a >= 0 and b > a:
        try:
            obj = json.loads(text[a:b + 1])
            return obj.get("hypotheses", obj) if isinstance(obj, dict) else obj
        except Exception:
            pass
    return None


SYSTEM = (
    "You are a senior bug-bounty strategist working ONLY on programs the operator "
    "is authorized to test. Given mapped endpoints and findings so far, propose the "
    "highest-ROI attack HYPOTHESES that have NOT yet been tested. Prefer high-impact, "
    "in-scope, non-destructive tests. Return ONLY a JSON array; each item has keys: "
    "title, attack_class, target_endpoint, why_likely, test_command, estimated_severity. "
    "test_command must be a real shell command invoking one HUNTR tool "
    "(idor-chain.py, auth-bypass.py, rate-limit.py, oauth-probe.py, logic-fuzz.py, "
    "ssrf-probe.py, ssti-probe.py, race-fire.py, open-redirect.py, cors-test.py, "
    "jwt-test.py, param-fuzz.py, graphql-map.py) with realistic flags. "
    "estimated_severity ∈ {critical,high,medium,low}."
)


def main():
    eps = load_list(arg("--endpoints-file"), "endpoints")
    finds = load_list(arg("--findings-file"), "findings")
    program = arg("--program", "target")
    model = arg("--model")
    max_n = int(arg("--max", "5"))
    api_key = arg("--api-key")

    if not eps and not finds:
        print(__doc__)
        sys.exit(0)

    user = json.dumps({
        "program": program,
        "endpoints": eps[:120],
        "findings": finds[:60],
        "want": f"the {max_n} highest-ROI untested hypotheses",
    }, indent=2)

    print(f"[hypo-gen] model={model or llm_client.get_provider_config()['model']} endpoints={len(eps)} findings={len(finds)}",
          file=sys.stderr)
    text, err = llm_client.call_llm(SYSTEM, user, model=model, api_key=api_key, max_tokens=2500)

    if err:
        out = {"ok": False, "error": err, "hypotheses": []}
        print(json.dumps(out) if flag("--json") else f"[hypo-gen] error: {err}")
        sys.exit(2)

    hyps = extract_json(text) or []
    if isinstance(hyps, dict):
        hyps = hyps.get("hypotheses", hyps)

    # Rank by the learned expected value of each hypothesis's attack class, so the
    # highest-ROI (historically-paid) classes surface first instead of raw LLM
    # order. Degrades to the LLM order if no history / the helper is unavailable.
    try:
        import outcome_priors
        stacks = (arg("--stack") or "").split(",") if arg("--stack") else None
        pr = outcome_priors.priors(stacks)
        for h in hyps:
            a = pr.get(outcome_priors.norm_cls(h.get("attack_class", "")))
            h["ev_prior"] = round(a["ev"], 1) if a else 0.0
        hyps.sort(key=lambda h: -h.get("ev_prior", 0.0))
    except Exception as e:
        print(f"[hypo-gen] prior ranking skipped: {e}", file=sys.stderr)

    result = {"ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"), "model": model or "auto",
              "hypotheses": hyps[:max_n]}

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    for i, h in enumerate(hyps[:max_n], 1):
        print(f"\n  {i}. [{h.get('estimated_severity','?').upper()}] {h.get('title','')}")
        print(f"     class: {h.get('attack_class','?')}  endpoint: {h.get('target_endpoint','?')}  EV≈${h.get('ev_prior',0)}")
        print(f"     why: {h.get('why_likely','')[:120]}")
        print(f"     cmd: {h.get('test_command','')}")
    if not hyps:
        print("  no new hypotheses.")
    sys.exit(0)


if __name__ == "__main__":
    import time
    main()