#!/usr/bin/env python3
"""
hunt-memory — the engine's long-term memory. Recall analogous situations from every past hunt.

The corpus stores rules + outcomes as flat records. This stores SITUATIONS — findings, response
shapes, error strings, endpoint patterns — and recalls the most similar ones on demand:
  "this 500 + this ORM error + this param shape looks like the SQLi that paid $8k on target Y —
   here's the technique that worked."
That turns N past hunts into instant recall on hunt N+1. Retrieval is local (character n-gram +
token cosine, weighted by what paid) — no cloud, no keys. Swap in real embeddings later without
changing callers.

Store: ~/.claude/hunt-corpus/memory.jsonl  {id,kind,cls,stack,program,reward,outcome,text,ts}

Usage:
  hunt-memory.py --add --kind finding --cls sqli --stack fintech --program Acme --reward 8000 \
                 --text "error-based SQLi in q param; MySQL 'You have an error'; UNION 4 cols"
  hunt-memory.py --add --kind response --file resp.txt --cls idor
  hunt-memory.py --recall --text "500 ORM error on /search?q=" [--stack fintech] [--k 5]
  hunt-memory.py --recall --file resp.txt --k 5
  hunt-memory.py --stats
Exit: 0.
"""
import sys, os, re, json, math, time
from collections import Counter
from pathlib import Path

CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
MEM = CORPUS / "memory.jsonl"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def toks(text):
    t = (text or "").lower()[:2000]
    words = re.findall(r"[a-z0-9_/{}.\-]{2,}", t)
    grams = [t[i:i + 3] for i in range(max(0, len(t) - 2))]
    return words + grams


def vec(text):
    return Counter(toks(text))


def cosine(a, b):
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def load():
    out = []
    if MEM.exists():
        for ln in MEM.read_text().splitlines():
            if ln.strip():
                try:
                    out.append(json.loads(ln))
                except Exception:
                    pass
    return out


def read_text():
    f = arg("--file")
    if f:
        return Path(f).read_text(errors="replace")
    t = arg("--text")
    if t:
        return t
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def cmd_add():
    text = read_text()
    if not text.strip():
        sys.exit("--add needs --text, --file, or stdin")
    try:
        reward = float(arg("--reward", "0") or 0)
    except ValueError:
        reward = 0.0
    rec = {"id": "M" + str(int(time.time() * 1000)), "kind": arg("--kind", "finding"),
           "cls": (arg("--cls", "") or "").lower(), "stack": (arg("--stack", "generic") or "generic").lower(),
           "program": arg("--program", ""), "reward": reward, "outcome": arg("--outcome", ""),
           "text": text.strip()[:2000], "ts": time.strftime("%Y-%m-%d")}
    CORPUS.mkdir(parents=True, exist_ok=True)
    with MEM.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[memory] stored {rec['kind']}/{rec['cls'] or '?'} ({rec['program'] or 'program?'}"
          f"{', $%.0f' % reward if reward else ''}) — recallable on future hunts.")


def embed_cmd(text):
    """Optional real embeddings: set HUNT_EMBED_CMD to a program that reads text on stdin and
    prints a JSON float list. Lets you drop in a local model without changing callers."""
    cmd = os.environ.get("HUNT_EMBED_CMD")
    if not cmd:
        return None
    try:
        import subprocess
        r = subprocess.run(cmd, shell=True, input=text, capture_output=True, text=True, timeout=20)
        v = json.loads(r.stdout)
        return v if isinstance(v, list) and v else None
    except Exception:
        return None


def dot_cos(a, b):
    import math
    n = min(len(a), len(b))
    if not n:
        return 0.0
    dot = sum(a[i] * b[i] for i in range(n))
    na = math.sqrt(sum(x * x for x in a[:n])); nb = math.sqrt(sum(x * x for x in b[:n]))
    return dot / (na * nb) if na and nb else 0.0


def build_idf(recs):
    """document frequency → idf weights over the corpus (distinctive terms win)."""
    import math
    from collections import Counter
    df = Counter()
    for r in recs:
        for t in set(toks(r.get("text", ""))):
            df[t] += 1
    N = len(recs) or 1
    return {t: math.log((N + 1) / (c + 1)) + 1 for t, c in df.items()}


def wvec(text, idf):
    v = vec(text)
    return {t: c * idf.get(t, 1.0) for t, c in v.items()}


def wcos(a, b):
    import math
    common = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(x * x for x in a.values())); nb = math.sqrt(sum(x * x for x in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def cmd_recall():
    q = read_text()
    if not q.strip():
        sys.exit("--recall needs --text, --file, or stdin")
    k = int(arg("--k", "5") or 5)
    stack = (arg("--stack") or "").lower()
    recs = load()
    if not recs:
        print("[memory] empty — nothing to recall yet. Feed it with --add (or corpus-ingest.py).")
        return
    use_embed = os.environ.get("HUNT_EMBED_CMD")
    qe = embed_cmd(q) if use_embed else None
    idf = None if qe else build_idf(recs)
    qv = None if qe else wvec(q, idf)
    scored = []
    for r in recs:
        if stack and r.get("stack") not in (stack, "generic"):
            continue
        if qe is not None:
            re_ = embed_cmd(r.get("text", ""))
            cos = dot_cos(qe, re_) if re_ else 0.0
        else:
            cos = wcos(qv, wvec(r.get("text", ""), idf))
        rw = float(r.get("reward", 0) or 0)
        score = cos * (1 + min(rw, 10000) / 10000 * 0.5)  # paid situations rank higher
        scored.append((score, cos, r))
    scored.sort(key=lambda x: -x[0])
    top = [s for s in scored if s[1] > 0.05][:k]
    if not top:
        print("[memory] no analogous past situation (cosine < 0.05). This looks new — hunt it fresh.")
        return
    print(f"[memory] {len(top)} analogous past situation(s)"
          f"{' · stack ' + stack if stack else ''}:\n")
    for score, cos, r in top:
        rw = f"  💰${r['reward']:.0f}" if r.get("reward") else ""
        print(f"  [{cos:.2f}] {r.get('kind','?')}/{r.get('cls','?')} · {r.get('program','?')}{rw}")
        print(f"        {r.get('text','')[:160]}")
    best = top[0][2]
    print(f"\n  ➜ closest match paid via hunt-{best.get('cls','?')} — replay that technique first.")


def cmd_stats():
    recs = load()
    by_cls = Counter(r.get("cls", "?") for r in recs)
    paid = sum(1 for r in recs if r.get("reward"))
    print(f"[memory] {len(recs)} situations · {paid} paid · {MEM}")
    for c, n in by_cls.most_common(12):
        print(f"  {c or '?':<16}{n}")


def main():
    if "--add" in sys.argv:
        return cmd_add()
    if "--recall" in sys.argv:
        return cmd_recall()
    if "--stats" in sys.argv:
        return cmd_stats()
    print(__doc__)


if __name__ == "__main__":
    main()
