#!/usr/bin/env python3
"""
scope-parse.py — turn a pasted bug-bounty PROGRAM PAGE into a clean, structured scope with the LLM.

Paste the whole program (scope table, out-of-scope, rewards, rules, UA requirement, …) and this extracts:
  • in_scope assets, each classified web | api | mobile | source | other
  • out_of_scope assets (→ deny list, so the hunt STICKS to scope)
  • rewards summary, any required User-Agent, and a one-line rules note
So the operator pastes once and the engine is pointed at exactly the right assets, nothing out of scope.

Usage:  scope-parse.py --text "<program page>"   (or pipe text on stdin)   [--json]
Emits:  {"in_scope":[{"asset","type"}], "out_of_scope":[..], "rewards":"", "ua_required":"", "notes":""}
"""
import sys, os, re, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

TEXT = arg("--text") or (sys.stdin.read() if not sys.stdin.isatty() else "")
MODELS = ["claude-haiku-4-5"] if os.environ.get("HUNT_LLM") == "haiku" else \
         ["claude-sonnet-4-6", "claude-sonnet-4-5", "claude-haiku-4-5"]

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not TEXT.strip():
    out({"in_scope": [], "out_of_scope": [], "error": "no text"})


def llm(system, user, max_tokens=1800, timeout=90):
    try:
        import urllib.request, urllib.error, time as _t
        from llm_auth import llm_headers
        hdrs, _ = llm_headers()
        if not hdrs:
            return None
        hdrs["content-type"] = "application/json"
        for m in MODELS:
            body = json.dumps({"model": m, "max_tokens": max_tokens, "system": system,
                               "messages": [{"role": "user", "content": user}]}).encode()
            for attempt in range(3):
                try:
                    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers=hdrs, method="POST")
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        data = json.loads(r.read())
                    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
                except urllib.error.HTTPError as e:
                    if e.code == 429 and attempt < 2:
                        _t.sleep(2 * (attempt + 1)); continue
                    break
                except Exception:
                    break
        return None
    except Exception:
        return None


def ljson(system, user, **kw):
    txt = llm(system, user, **kw)
    if not txt:
        return None
    t = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", txt.strip(), flags=re.I | re.M).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    m = re.search(r"\{.*\}", t, re.S)
    if m:
        try: return json.loads(m.group(0))
        except Exception: return None
    return None


def regex_fallback(text):
    """No LLM available → best-effort regex extraction so paste still works offline."""
    assets = re.findall(r"(?:https?://)?(?:\*\.)?[a-z0-9.-]+\.[a-z]{2,}(?:/[\w./-]*)?", text, re.I)
    # crude in/out split by nearest heading
    low = text.lower()
    out_start = low.find("out of scope") if "out of scope" in low else low.find("out-of-scope")
    in_scope, out_scope = [], []
    for a in dict.fromkeys(assets):
        pos = text.find(a)
        (out_scope if out_start >= 0 and pos > out_start else in_scope).append(a)
    def typ(a):
        al = a.lower()
        if "github.com" in al or "gitlab.com" in al: return "source"
        if "api" in al or al.startswith("http") and "/api" in al: return "api"
        return "web"
    return {"in_scope": [{"asset": a, "type": typ(a)} for a in in_scope[:40]],
            "out_of_scope": out_scope[:40], "rewards": "", "ua_required": "", "notes": "(regex fallback — LLM unavailable)"}


SYS = ("You organize a bug-bounty PROGRAM PAGE into a precise, machine-usable scope. From the pasted text "
       "extract ONLY what the program states. Classify each in-scope asset by type: 'web' (web app / domain), "
       "'api' (API host/base), 'mobile' (app/APK/package), 'source' (a GitHub/GitLab repo), or 'other'. "
       "Keep wildcards exactly as written (e.g. *.example.com). Put anything the program marks out-of-scope "
       "(hosts, paths, or classes of asset) in out_of_scope so the hunt avoids it. Reply STRICT JSON only: "
       "{\"in_scope\":[{\"asset\":\"..\",\"type\":\"web|api|mobile|source|other\"}],\"out_of_scope\":[\"..\"],"
       "\"rewards\":\"one short line\",\"ua_required\":\"required user-agent string/suffix if any, else empty\","
       "\"notes\":\"one-line key rule (e.g. test only your own account)\"}. No prose outside the JSON.")

d = ljson(SYS, TEXT[:14000])
if not isinstance(d, dict) or not d.get("in_scope"):
    d = regex_fallback(TEXT)
# normalize
d.setdefault("out_of_scope", []); d.setdefault("rewards", ""); d.setdefault("ua_required", ""); d.setdefault("notes", "")
d["in_scope"] = [x for x in d.get("in_scope", []) if isinstance(x, dict) and x.get("asset")]
out(d)
