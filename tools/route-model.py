#!/usr/bin/env python3
"""
route-model — spend the expensive model only where it changes the outcome.

Hunting is a mix of hard reasoning (worth the strong model) and grunt work (a cheap model does it
identically for a fraction of the cost). This encodes the routing policy: given a task, it says which
tier to use and why, so a run doesn't burn top-tier tokens on log-summarising or payload-stamping.

Tiers resolve to model ids (override via env HUNT_MODEL_STRONG / _MID / _CHEAP):
  strong  deep reasoning / novel exploitation      (default: nvidia/nemotron-3-ultra-550b-a55b)
  mid     structured writing / moderate reasoning   (default: nvidia/nemotron-3-ultra-550b-a55b)
  cheap   mechanical / high-volume / deterministic  (default: nvidia/nemotron-3-ultra-550b-a55b)

Provider is set by HUNT_LLM_PROVIDER (default: nvidia). API key via HUNT_LLM_API_KEY.

Usage:
  route-model.py --task hypothesis        # → tier + model id + rationale
  route-model.py --list                   # the whole policy table
  route-model.py --task report --json
Exit: 0.
"""
import sys, os, json

# Stability-pinned defaults. Override via env HUNT_MODEL_STRONG / _MID / _CHEAP.
# Default provider is NVIDIA Nemotron 3 Ultra (set HUNT_LLM_PROVIDER to change).
TIER_MODEL = {
    "strong": os.environ.get("HUNT_MODEL_STRONG", "nvidia/nemotron-3-ultra-550b-a55b"),
    "mid": os.environ.get("HUNT_MODEL_MID", "nvidia/nemotron-3-ultra-550b-a55b"),
    "cheap": os.environ.get("HUNT_MODEL_CHEAP", "nvidia/nemotron-3.5-lightning-30b-a3b"),
}

# task → (tier, rationale, needs_llm). needs_llm=False → a Python tool does it; NO provider needed.
POLICY = {
    "intake":        ("cheap",  "deterministic parse of pasted program text — no reasoning", False),
    "recon":         ("cheap",  "normalise/dedupe recon output — mechanical", False),
    "aggregate":     ("cheap",  "merge signals — mechanical", False),
    "hypothesis":    ("strong", "novel 'signal ⇒ likely bug' reasoning sets the whole run's direction", True),
    "exploit":       ("strong", "designing/adapting an exploit is where the strong model pays for itself", True),
    "chain":         ("strong", "multi-step chain planning / capability reasoning", True),
    "verify":        ("strong", "adversarial falsification + escalation needs careful reasoning", True),
    "fuzz":          ("cheap",  "stamping payloads / iterating requests — high volume, low reasoning", True),
    "triage":        ("cheap",  "mechanical gate checks against a checklist", False),
    "dedup":         ("cheap",  "similarity check — deterministic", False),
    "report":        ("mid",    "structured, faithful writeup — quality matters, novelty doesn't", True),
    "summarize":     ("cheap",  "condense logs / state — mechanical", False),
    "recover":       ("cheap",  "reload ./.hunt state — mechanical", False),
}
ALIAS = {"hypothesise": "hypothesis", "exploitation": "exploit", "chain-plan": "chain",
         "adversarial": "verify", "validate": "triage", "recon-aggregate": "aggregate",
         "poc": "exploit", "write": "report", "reporting": "report", "parse": "intake"}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def resolve(task):
    t = (task or "").lower().strip()
    t = ALIAS.get(t, t)
    return t, POLICY.get(t)


def main():
    offline = "--offline" in sys.argv or os.environ.get("HUNT_LLM") == "off"
    if "--list" in sys.argv:
        print(f"[route-model] policy  (strong={TIER_MODEL['strong']}  mid={TIER_MODEL['mid']}  cheap={TIER_MODEL['cheap']})")
        det = sum(1 for _, _, n in POLICY.values() if not n)
        print(f"  {det}/{len(POLICY)} task types are DETERMINISTIC (Python tools, no LLM/provider). "
              f"A provider outage degrades reasoning, never kills the engine.\n")
        print(f"{'TASK':<14}{'TIER':<8}{'LLM':<5}{'MODEL':<28}WHY")
        for task, (tier, why, needs) in POLICY.items():
            print(f"{task:<14}{tier:<8}{('yes' if needs else 'no'):<5}{(TIER_MODEL[tier] if needs else '—'):<28}{why}")
        print("\n  aliases: " + ", ".join(f"{k}→{v}" for k, v in ALIAS.items()))
        print("  offline mode: route-model.py --task X --offline  (or HUNT_LLM=off) — LLM tasks report 'defer'.")
        return
    task = arg("--task")
    if not task:
        print(__doc__); return
    name, hit = resolve(task)
    if not hit:
        print(f"[route-model] unknown task '{task}' → default STRONG ({TIER_MODEL['strong']}) to be safe.")
        if "--json" in sys.argv:
            print(json.dumps({"task": task, "tier": "strong", "model": TIER_MODEL["strong"], "known": False}))
        return
    tier, why, needs = hit
    if not needs:
        if "--json" in sys.argv:
            print(json.dumps({"task": name, "deterministic": True, "why": why}))
        else:
            print(f"[route-model] {name}: DETERMINISTIC — a Python tool does this, no LLM/provider needed.\n  why: {why}")
        return
    if offline:
        if "--json" in sys.argv:
            print(json.dumps({"task": name, "offline": True, "action": "defer", "why": why}))
        else:
            print(f"[route-model] {name}: needs an LLM but OFFLINE — defer this step (queue) or run deterministic phases only.")
        return
    model = TIER_MODEL[tier]
    if "--json" in sys.argv:
        print(json.dumps({"task": name, "tier": tier, "model": model, "why": why, "known": True}))
    else:
        print(f"[route-model] {name}: {tier.upper()} → {model}\n  why: {why}")


if __name__ == "__main__":
    main()
