#!/usr/bin/env python3
"""
chain-builder — turn a pile of confirmed findings into exploit CHAINS. Sends the
findings to the configured LLM and asks which ones combine into a higher-severity
attack path (e.g. open-redirect → OAuth token theft; IDOR + SSRF → internal pivot).

Reads HUNT_LLM_API_KEY from env (or --api-key). Uses llm_client for provider abstraction.
Zero deps beyond stdlib.

Usage:
  chain-builder.py --findings-file finds.json \
                   [--model nvidia/nemotron-3-ultra-550b-a55b] [--json]

Output: {ok, chains:[{title, steps:[{finding_id, role}], combined_severity,
          cvss, description}]}
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


def load_findings(path):
    if not path:
        return []
    try:
        obj = json.loads(Path(path).read_text())
    except Exception:
        return []
    if isinstance(obj, dict):
        obj = obj.get("findings", [])
    out = []
    for i, f in enumerate(obj if isinstance(obj, list) else []):
        if isinstance(f, dict):
            f = dict(f)
            f.setdefault("finding_id", f.get("id", f"F{i+1}"))
            out.append(f)
    return out


def cluster_findings(finds):
    """Collapse findings that share identical (cls, detail) into one digest row.

    Without this, 25 findings that are the SAME root cause probed at 25 different
    paths (e.g. one load-balancer/gateway control hit via /forgot, /oauth/token,
    /verify, ...) look to the LLM like 25 independent app-level bugs, and it invents
    a separate business-logic narrative (password reset, OAuth, email verification)
    for each one — narratives nothing here ever tested. Collapsing to one row per
    unique evidence signature, with the member count and endpoint list attached,
    keeps the model from building N speculative chains out of 1 real bug.
    """
    groups = {}
    order = []
    for f in finds:
        key = (str(f.get("cls", "")).lower(), (f.get("detail") or "").strip())
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    rows = []
    for key in order:
        members = groups[key]
        rep = dict(members[0])
        rep["cluster_size"] = len(members)
        if len(members) > 1:
            rep["cluster_endpoints"] = [m.get("endpoint") for m in members[:10]]
        rows.append(rep)
    return rows


def extract_json(text):
    if not text:
        return None
    for lo, hi in (("[", "]"), ("{", "}")):
        a, b = text.find(lo), text.rfind(hi)
        if a >= 0 and b > a:
            try:
                obj = json.loads(text[a:b + 1])
                if isinstance(obj, dict):
                    return obj.get("chains", obj)
                return obj
            except Exception:
                continue
    return None


SYSTEM = (
    "You are an exploit-chaining analyst for authorized bug-bounty work. Given a list "
    "of CONFIRMED findings (each with finding_id), identify combinations that chain into "
    "a materially higher-severity attack path. Only chain findings that plausibly connect. "
    "You cannot make any live requests from here — every chain you propose is an UNTESTED "
    "hypothesis for a human to verify, never a demonstrated exploit. Do not write as if the "
    "chain has been observed to work.\n\n"
    "Some entries carry a 'cluster_size' > 1 and a 'cluster_endpoints' list: that means MANY "
    "findings share byte-identical evidence/detail text across different paths — almost always "
    "one root cause hit from many angles (e.g. a load-balancer or gateway-level control), not "
    "independent per-endpoint application bugs. Treat a clustered entry as ONE finding. Never "
    "invent a separate business-logic narrative (password reset email, OAuth token issuance, "
    "email verification, etc.) for individual endpoints inside the same cluster unless the "
    "finding's own evidence text actually demonstrates that specific mechanism — a generic "
    "redirect/auth-wall response proves nothing about what code runs behind it.\n\n"
    "Return ONLY a JSON array; each item: title, steps (array of {finding_id, role}), "
    "combined_severity (critical|high|medium|low), cvss (0-10 number), description "
    "(how the chain works and its real-world impact — note explicitly which parts are "
    "confirmed by the findings' own evidence vs. which parts are your unverified assumption). "
    "If nothing chains, return []."
)


def main():
    finds = load_findings(arg("--findings-file"))
    model = arg("--model")
    api_key = arg("--api-key")

    if not finds:
        print(__doc__)
        sys.exit(0)

    clustered = cluster_findings(finds)
    user = json.dumps({"findings": clustered[:80],
                       "want": "exploit chains across these findings"}, indent=2)
    print(f"[chain-builder] model={model or llm_client.get_provider_config()['model']} "
          f"findings={len(finds)} clustered={len(clustered)}", file=sys.stderr)
    text, err = llm_client.call_llm(SYSTEM, user, model=model, api_key=api_key)

    if err:
        out = {"ok": False, "error": err, "chains": []}
        print(json.dumps(out) if flag("--json") else f"[chain-builder] error: {err}")
        sys.exit(2)

    chains = extract_json(text) or []
    if isinstance(chains, dict):
        chains = chains.get("chains", [])
    for c in chains:
        if isinstance(c, dict):
            c["verified"] = False  # this tool never makes a live request — always a hypothesis

    result = {"ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"), "model": model or "auto",
              "count": len(chains), "chains": chains}

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(f"\n== exploit chains ({len(chains)}) ==")
    for i, c in enumerate(chains, 1):
        print(f"\n  {i}. [{str(c.get('combined_severity','?')).upper()} "
              f"cvss {c.get('cvss','?')}] {c.get('title','')}")
        for s in c.get("steps", []):
            print(f"       · {s.get('finding_id','?')}: {s.get('role','')}")
        print(f"     {str(c.get('description',''))[:160]}")
    if not chains:
        print("  no chains identified across the current findings.")
    sys.exit(0)


if __name__ == "__main__":
    import time
    main()