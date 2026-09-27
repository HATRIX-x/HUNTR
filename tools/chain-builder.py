#!/usr/bin/env python3
"""
chain-builder — turn a pile of confirmed findings into exploit CHAINS. Sends the
findings to Claude and asks which ones combine into a higher-severity attack path
(e.g. open-redirect → OAuth token theft; IDOR + SSRF → internal pivot).

Reads ANTHROPIC_API_KEY from env (or --api-key). Zero deps beyond urllib.

Usage:
  chain-builder.py --findings-file finds.json \
                   [--model claude-opus-4-8] [--json]

Output: {ok, chains:[{title, steps:[{finding_id, role}], combined_severity,
         cvss, description}]}
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


def call_claude(model, system, user, api_key, max_tokens=2500):
    if not api_key:
        return None, "no ANTHROPIC_API_KEY set (export it or pass --api-key)"
    payload = json.dumps({
        "model": model, "max_tokens": max_tokens, "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode()
    req = Request("https://api.anthropic.com/v1/messages", data=payload, headers={
        "content-type": "application/json", "x-api-key": api_key,
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
    "Return ONLY a JSON array; each item: title, steps (array of {finding_id, role}), "
    "combined_severity (critical|high|medium|low), cvss (0-10 number), description "
    "(how the chain works and its real-world impact). If nothing chains, return []."
)


def main():
    finds = load_findings(arg("--findings-file"))
    model = arg("--model", MODELS["strong"])
    model = MODELS.get(model, model)
    api_key = arg("--api-key") or os.environ.get("ANTHROPIC_API_KEY")

    if not finds:
        print(__doc__)
        sys.exit(0)

    user = json.dumps({"findings": finds[:80],
                       "want": "exploit chains across these findings"}, indent=2)
    print(f"[chain-builder] model={model} findings={len(finds)}", file=sys.stderr)
    text, err = call_claude(model, SYSTEM, user, api_key)

    if err:
        out = {"ok": False, "error": err, "chains": []}
        print(json.dumps(out) if flag("--json") else f"[chain-builder] error: {err}")
        sys.exit(2)

    chains = extract_json(text) or []
    if isinstance(chains, dict):
        chains = chains.get("chains", [])

    result = {"ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"), "model": model,
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
    main()
