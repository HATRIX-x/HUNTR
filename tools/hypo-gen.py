#!/usr/bin/env python3
"""
hypo-gen — hypothesis generator. Given the endpoints already mapped and the
findings so far, ask Claude for the highest-ROI attack hypotheses NOT yet tested,
each with a concrete HUNTR command to run next.

Reads ANTHROPIC_API_KEY from env (or --api-key). Zero deps beyond urllib.

Usage:
  hypo-gen.py --endpoints-file eps.json --findings-file finds.json \
              [--program acme] [--model claude-opus-4-8] [--max 5] [--json]

  eps.json    : ["https://api.acme.com/v1/orders", ...]  (or {"endpoints":[...]})
  finds.json  : [ {finding}, ... ]                       (or {"findings":[...]})

Output: {ok, hypotheses:[{title, attack_class, target_endpoint, why_likely,
         test_command, estimated_severity}]}
"""
import sys, os, json, time, ssl
from pathlib import Path
from urllib.request import Request, urlopen

MODELS = {"strong": "claude-opus-4-8", "mid": "claude-sonnet-4-6",
          "cheap": "claude-haiku-4-5-20251001"}


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


def call_claude(model, system, user, api_key, max_tokens=2000):
    if not api_key:
        return None, "no ANTHROPIC_API_KEY set (export it or pass --api-key)"
    payload = json.dumps({
        "model": model, "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode()
    req = Request("https://api.anthropic.com/v1/messages", data=payload, headers={
        "content-type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }, method="POST")
    try:
        with urlopen(req, timeout=90, context=ssl.create_default_context()) as r:
            data = json.loads(r.read())
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        return "".join(parts).strip(), None
    except Exception as ex:
        detail = ""
        try:
            detail = ex.read().decode("utf-8", "ignore")[:300]
        except Exception:
            pass
        return None, f"{type(ex).__name__}: {ex} {detail}".strip()


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
    model = arg("--model", MODELS["strong"])
    model = MODELS.get(model, model)
    max_n = int(arg("--max", "5"))
    api_key = arg("--api-key") or os.environ.get("ANTHROPIC_API_KEY")

    if not eps and not finds:
        print(__doc__)
        sys.exit(0)

    user = json.dumps({
        "program": program,
        "endpoints": eps[:120],
        "findings": finds[:60],
        "want": f"the {max_n} highest-ROI untested hypotheses",
    }, indent=2)

    print(f"[hypo-gen] model={model} endpoints={len(eps)} findings={len(finds)}",
          file=sys.stderr)
    text, err = call_claude(model, SYSTEM, user, api_key, max_tokens=2500)

    if err:
        out = {"ok": False, "error": err, "hypotheses": []}
        print(json.dumps(out) if flag("--json") else f"[hypo-gen] error: {err}")
        sys.exit(2)

    hyps = extract_json(text) or []
    if isinstance(hyps, dict):
        hyps = hyps.get("hypotheses", [])
    hyps = hyps[:max_n]

    result = {"ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
              "program": program, "model": model,
              "count": len(hyps), "hypotheses": hyps}

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"\n== hypotheses · {program} ({len(hyps)}) ==")
    for i, h in enumerate(hyps, 1):
        print(f"\n  {i}. [{str(h.get('estimated_severity','?')).upper()}] "
              f"{h.get('title','')}")
        print(f"     class:  {h.get('attack_class','')}")
        print(f"     target: {h.get('target_endpoint','')}")
        print(f"     why:    {str(h.get('why_likely',''))[:120]}")
        print(f"     run:    {h.get('test_command','')}")
    sys.exit(0)


if __name__ == "__main__":
    main()
