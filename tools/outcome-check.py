#!/usr/bin/env python3
"""
outcome-check — close the loop. Record what the platform actually said about a submission,
then turn that history into priors so the engine hunts where it has really been paid.

submitted.jsonl records what you SENT. Nothing recorded what came BACK — so ranking could
never get smarter. This adds the missing half:

  ~/.claude/hunt-corpus/outcomes.jsonl   institutional, cross-target (drives ranking everywhere)
  ./.hunt/outcomes.jsonl                  this target's copy (local audit)

Each record: {cls, stack, program, verdict, reward, endpoint, title, ts}
Verdicts:  paid · accepted · duplicate · na · informative · rejected

Scoring (per bug class, optionally per stack):
  p_accept  = Beta(1,3) posterior = (accepted+1)/(attempts+4)   # cold-start ~0.25, honest
  reward^   = (paid_$ + kappa*prior_reward)/(paid_count + kappa) # shrinks to a class prior
  dup_pen   = 1 - 0.5*dup_rate                                    # crowded classes are worth less
  EV        = p_accept * reward^ * dup_pen                        # expected $ per attempt

Usage:
  outcome-check.py --record --class idor --stack saas --program "Acme" \
                   --verdict paid --reward 1500 [--endpoint /api/..] [--title "..."]
  outcome-check.py --stats [--stack fintech,saas]         # hit-rates + EV by class
  outcome-check.py --rank  [--stack fintech,saas] [--top 12]   # classes to hunt first
  outcome-check.py --sync-submitted                       # scaffold pending records from submitted.jsonl
Exit: 0 ok.
"""
import sys, os, json, time
from pathlib import Path

CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
GLOBAL = CORPUS / "outcomes.jsonl"
HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
LOCAL = HUNT / "outcomes.jsonl"

VERDICTS = {"paid", "accepted", "duplicate", "na", "informative", "rejected"}
ACCEPTED = {"paid", "accepted"}          # a real, unique, rewarded/triaged bug
FOUND = {"paid", "accepted", "duplicate"}  # bug was real even if someone beat you

# cold-start priors (internal only): rough expected reward $ per class, used until real data exists
PRIOR_REWARD = {
    "rce": 3000, "deserialization": 2000, "sqli": 1500, "ssti": 1500, "ssrf": 1200,
    "xxe": 1000, "saml": 1000, "oauth": 900, "jwt": 900, "auth": 900, "authbypass": 900,
    "idor": 800, "authz": 700, "bfla": 700, "race": 700, "logic": 600, "session": 500,
    "fileupload": 700, "nosqli": 900, "lfi": 900, "xss": 400, "csrf": 300, "cors": 150,
    "openredirect": 150, "clickjacking": 120, "misc": 300,
}
KAPPA = 1.0
ALPHA, BETA = 1, 3   # Beta prior → cold-start p_accept = 1/4


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def norm_cls(c):
    return (c or "").lower().strip().replace(" ", "").replace("-", "").replace("_", "")


def load(path):
    out = []
    if path.exists():
        for ln in path.read_text().splitlines():
            if ln.strip():
                try:
                    out.append(json.loads(ln))
                except Exception:
                    pass
    return out


def cmd_record():
    cls = norm_cls(arg("--class"))
    verdict = (arg("--verdict", "") or "").lower().strip()
    if not cls or verdict not in VERDICTS:
        sys.exit("usage: --record --class <c> --verdict <%s> [--reward N] [--stack ..] "
                 "[--program ..] [--endpoint ..] [--title ..]" % "|".join(sorted(VERDICTS)))
    try:
        reward = float(arg("--reward", "0") or 0)
    except ValueError:
        reward = 0.0
    rec = {"cls": cls, "stack": (arg("--stack", "generic") or "generic").lower(),
           "program": arg("--program", ""), "verdict": verdict, "reward": reward,
           "endpoint": arg("--endpoint", ""), "title": arg("--title", ""),
           "ts": time.strftime("%Y-%m-%d")}
    CORPUS.mkdir(parents=True, exist_ok=True)
    with GLOBAL.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    if HUNT.exists():
        with LOCAL.open("a") as f:
            f.write(json.dumps(rec) + "\n")
    tag = {"paid": "💰 paid", "accepted": "✓ accepted", "duplicate": "= dup",
           "na": "✗ N/A", "informative": "i info", "rejected": "✗ rejected"}[verdict]
    print(f"[outcome] {tag}  {cls}  ({rec['stack']}, {rec['program'] or 'program?'})"
          f"{'  $%.0f' % reward if reward else ''}")
    print(f"          → learned globally ({GLOBAL}); future ranking will weight {cls} on {rec['stack']}.")


def score(records, stacks=None):
    """Return {cls: {n,acc,dup,paid_n,reward_sum,p_accept,reward_hat,dup_pen,ev}}"""
    if stacks:
        st = {s.strip().lower() for s in stacks}
        records = [r for r in records if r.get("stack", "generic") in st or r.get("stack") == "generic"]
    agg = {}
    for r in records:
        c = norm_cls(r.get("cls"))
        if not c:
            continue
        a = agg.setdefault(c, {"n": 0, "acc": 0, "dup": 0, "paid_n": 0, "reward_sum": 0.0})
        a["n"] += 1
        v = r.get("verdict")
        if v in ACCEPTED:
            a["acc"] += 1
        if v == "duplicate":
            a["dup"] += 1
        if r.get("reward", 0) and v in ACCEPTED:
            a["paid_n"] += 1
            a["reward_sum"] += float(r.get("reward", 0))
    for c, a in agg.items():
        prior = PRIOR_REWARD.get(c, PRIOR_REWARD["misc"])
        a["p_accept"] = (a["acc"] + ALPHA) / (a["n"] + ALPHA + BETA)
        a["reward_hat"] = (a["reward_sum"] + KAPPA * prior) / (a["paid_n"] + KAPPA)
        a["dup_pen"] = 1 - 0.5 * (a["dup"] / a["n"] if a["n"] else 0)
        a["ev"] = a["p_accept"] * a["reward_hat"] * a["dup_pen"]
    return agg


def all_classes_with_priors(agg):
    """Include never-tried classes at their cold-start prior so ranking is complete."""
    for c, prior in PRIOR_REWARD.items():
        if c not in agg and c != "misc":
            p = (0 + ALPHA) / (0 + ALPHA + BETA)
            agg[c] = {"n": 0, "acc": 0, "dup": 0, "paid_n": 0, "reward_sum": 0.0,
                      "p_accept": p, "reward_hat": prior, "dup_pen": 1.0, "ev": p * prior}
    return agg


def cmd_stats():
    stacks = (arg("--stack") or "").split(",") if arg("--stack") else None
    recs = load(GLOBAL)
    agg = score(recs, stacks)
    if not recs:
        print("[outcome] no outcomes recorded yet — ranking runs on cold-start priors.")
    print(f"[outcome] {len(recs)} outcomes"
          f"{' · stacks: ' + ','.join(stacks) if stacks else ''}\n")
    print(f"{'CLASS':<16}{'n':>3}{'acc':>5}{'dup':>5}{'p_acc':>7}{'reward^':>9}{'EV/att':>9}")
    for c, a in sorted(agg.items(), key=lambda kv: -kv[1]["ev"]):
        print(f"{c:<16}{a['n']:>3}{a['acc']:>5}{a['dup']:>5}"
              f"{a['p_accept']:>7.2f}{a['reward_hat']:>9.0f}{a['ev']:>9.0f}")


def cmd_rank():
    stacks = (arg("--stack") or "").split(",") if arg("--stack") else None
    top = int(arg("--top", "12") or 12)
    agg = all_classes_with_priors(score(load(GLOBAL), stacks))
    ranked = sorted(agg.items(), key=lambda kv: -kv[1]["ev"])[:top]
    tag = "learned+prior" if load(GLOBAL) else "cold-start prior"
    print(f"[outcome] hunt order by expected value ({tag}"
          f"{', stacks: ' + ','.join(stacks) if stacks else ''}):\n")
    for i, (c, a) in enumerate(ranked, 1):
        seen = f"{a['n']} tried, {a['acc']} hit" if a["n"] else "no history"
        print(f"  {i:>2}. hunt-{c:<14} EV≈${a['ev']:>5.0f}/attempt   ({seen})")
    print("\n  → feed this order into the HUNT phase: test high-EV classes first, per cell.")


def cmd_sync():
    """Scaffold 'pending' outcome stubs from submitted.jsonl so verdicts are easy to fill later."""
    sub = HUNT / "submitted.jsonl"
    if not sub.exists():
        sys.exit(f"no {sub}")
    done = {(norm_cls(r.get("cls")), r.get("endpoint", "")) for r in load(GLOBAL)}
    n = 0
    for r in load(sub):
        key = (norm_cls(r.get("class")), r.get("endpoint", ""))
        if key in done:
            continue
        print(json.dumps({"cls": norm_cls(r.get("class")), "endpoint": r.get("endpoint", ""),
                          "title": r.get("title", ""), "verdict": "PENDING",
                          "note": "run --record with the real verdict when the platform responds"}))
        n += 1
    sys.stderr.write(f"[outcome] {n} submission(s) awaiting a verdict — record each with --record.\n")


def main():
    if "--record" in sys.argv:
        return cmd_record()
    if "--stats" in sys.argv:
        return cmd_stats()
    if "--rank" in sys.argv:
        return cmd_rank()
    if "--sync-submitted" in sys.argv:
        return cmd_sync()
    print(__doc__)


if __name__ == "__main__":
    main()
