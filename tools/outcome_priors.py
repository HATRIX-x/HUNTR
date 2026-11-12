"""outcome_priors — the Phase-1 learning-loop bridge.

Turns HUNTR's two disconnected outcome stores into one signal:

  funnel.jsonl        (human submission ledger: flagged→accepted/dupe/rejected/paid)
  corpus/outcomes.jsonl (the learning store outcome-check.py scores into priors)

Every funnel adjudication is a *human-labelled* training example — the exact
thing XBOW's autonomous-submission pile lacks. This module bridges them and
exposes the learned priors so finding-pipeline (FP pre-kill) and hypo-gen
(EV ranking) consult real acceptance history instead of only hardcoded guesses.

Importable by the hyphenated tools because, when a tool runs as
`python3 tools/<x>.py`, its own directory (tools/) is sys.path[0].
"""
import importlib.util
import json
import os
import time
from pathlib import Path

# Funnel terminal stage → outcome-check verdict. Non-terminal stages
# (flagged/confirmed/submitted) are not outcomes and are skipped.
STAGE_TO_VERDICT = {
    "accepted": "accepted",
    "paid": "paid",
    "dupe": "duplicate",
    "rejected": "rejected",
}

_OC = None


def _corpus_dir():
    return Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))


def _global_store():
    return _corpus_dir() / "outcomes.jsonl"


def _oc():
    """Load outcome-check.py (hyphenated → importlib) for its pure scorers."""
    global _OC
    if _OC is None:
        p = Path(__file__).with_name("outcome-check.py")
        spec = importlib.util.spec_from_file_location("outcome_check", p)
        _OC = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_OC)
    return _OC


def norm_cls(c):
    return _oc().norm_cls(c)


def priors(stacks=None):
    """{cls: {n, acc, dup, p_accept, reward_hat, dup_pen, ev}} incl. cold-start classes."""
    oc = _oc()
    recs = oc.load(_global_store())
    return oc.all_classes_with_priors(oc.score(recs, stacks))


def record(cls, verdict, *, reward=0.0, stack="generic", program="",
           endpoint="", title="", src_funnel_id=None):
    """Append one labelled outcome to the global learning store (schema-compatible
    with outcome-check.py:cmd_record, plus src_funnel_id for idempotent syncing)."""
    rec = {"cls": norm_cls(cls), "stack": (stack or "generic").lower(),
           "program": program or "", "verdict": verdict, "reward": float(reward or 0),
           "endpoint": endpoint or "", "title": title or "",
           "ts": time.strftime("%Y-%m-%d")}
    if src_funnel_id is not None:
        rec["src_funnel_id"] = src_funnel_id
    store = _global_store()
    store.parent.mkdir(parents=True, exist_ok=True)
    with store.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def synced_funnel_ids():
    """Funnel ids already bridged into the learning store (for idempotent sync)."""
    oc = _oc()
    return {r.get("src_funnel_id") for r in oc.load(_global_store())
            if r.get("src_funnel_id")}


def rank_classes(classes, stacks=None):
    """Order the given attack classes by learned expected value, high first.
    Returns [(cls, ev, agg_entry)]; unknown classes fall back to cold-start priors."""
    agg = priors(stacks)
    out = []
    for c in classes:
        a = agg.get(norm_cls(c))
        out.append((c, a["ev"] if a else 0.0, a or {}))
    out.sort(key=lambda t: -t[1])
    return out


def fp_signal(cls, stacks=None, min_n=5, low_p=0.15):
    """FP pre-kill signal for finding-pipeline. Only fires once there is ENOUGH
    history (min_n adjudications of this class) AND acceptance is low — so a
    historically-rejected signature is down-ranked before a human looks, but a
    cold or healthy class is never penalised.

    Returns {bias: 'hold'|'review'|None, reason, p_accept, n}."""
    a = priors(stacks).get(norm_cls(cls))
    if not a or a["n"] < min_n:
        return {"bias": None, "reason": "", "p_accept": (a or {}).get("p_accept"),
                "n": (a or {}).get("n", 0)}
    p = a["p_accept"]
    if p < low_p:
        return {"bias": "hold", "n": a["n"], "p_accept": p,
                "reason": f"class {norm_cls(cls)} historically rejected "
                          f"({a['acc']}/{a['n']} accepted, p_accept={p:.0%})"}
    if p < low_p * 2:
        return {"bias": "review", "n": a["n"], "p_accept": p,
                "reason": f"class {norm_cls(cls)} has low acceptance "
                          f"({a['acc']}/{a['n']}, p_accept={p:.0%}) — differentiate first"}
    return {"bias": None, "reason": "", "p_accept": p, "n": a["n"]}


def sync_from_funnel(funnel_events):
    """Bridge terminal funnel events into the learning store. Idempotent: an event
    whose id is already recorded (by src_funnel_id) is skipped. Takes the latest
    terminal stage per finding id. Returns the list of records written."""
    # latest terminal state per id (funnel is append-only; last write wins)
    latest = {}
    for ev in funnel_events:
        stage = ev.get("stage")
        if stage in STAGE_TO_VERDICT and ev.get("id"):
            latest[ev["id"]] = ev
    already = synced_funnel_ids()
    written = []
    for fid, ev in latest.items():
        if fid in already:
            continue
        written.append(record(
            ev.get("class") or ev.get("cls") or "misc",
            STAGE_TO_VERDICT[ev["stage"]],
            reward=ev.get("amount") or 0,
            stack=ev.get("stack") or "generic",
            program=ev.get("program") or ev.get("target") or "",
            endpoint=ev.get("endpoint") or "",
            title=ev.get("title") or "",
            src_funnel_id=fid,
        ))
    return written
