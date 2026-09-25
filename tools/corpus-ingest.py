#!/usr/bin/env python3
"""
corpus-ingest — learn from the whole community, not just your own hunts.

Paste a disclosed report / writeup (HackerOne hacktivity, a blog PoC, a changelog). This classifies it,
pulls the key technique + endpoints, and writes it into BOTH institutional stores:
  ~/.claude/hunt-corpus/learned.jsonl   → suggested on future hunts (hunt-corpus.py)
  ~/.claude/hunt-corpus/memory.jsonl    → recallable by similarity (hunt-memory.py)
Run it on every good writeup you read; the engine gets sharper for free.

Usage:
  corpus-ingest.py --file report.md [--stack saas] [--program Acme] [--reward 3000] [--url https://..]
  pbpaste | corpus-ingest.py --stack fintech
Exit: 0 ok.
"""
import sys, os, re, json, time
from pathlib import Path

CORPUS = Path(os.environ.get("HUNT_CORPUS", str(Path.home() / ".claude" / "hunt-corpus")))
LEARNED = CORPUS / "learned.jsonl"
MEM = CORPUS / "memory.jsonl"

CLASS_KW = [
    ("idor", ["idor", "bola", "insecure direct object", "object reference", "authorization bypass by id"]),
    ("authz", ["broken access control", "privilege escalation", "authorization", "access control", "bfla", "forced browsing"]),
    ("sqli", ["sql injection", "sqli", "union select", "error-based", "boolean-based", "time-based blind"]),
    ("ssrf", ["ssrf", "server-side request forgery", "metadata endpoint", "169.254.169.254"]),
    ("rce", ["remote code execution", "rce", "command injection", "code execution", "webshell"]),
    ("xss", ["xss", "cross-site scripting", "cross site scripting", "stored xss", "reflected xss", "dom xss"]),
    ("ssti", ["ssti", "template injection", "jinja", "twig", "freemarker"]),
    ("xxe", ["xxe", "xml external entity"]),
    ("deserialization", ["deserialization", "insecure deserialization", "gadget chain", "ysoserial"]),
    ("race", ["race condition", "toctou", "double spend", "concurrent request"]),
    ("cors", ["cors", "cross-origin resource sharing", "access-control-allow-origin"]),
    ("csrf", ["csrf", "cross-site request forgery"]),
    ("jwt", ["jwt", "json web token", "alg none", "algorithm confusion"]),
    ("oauth", ["oauth", "redirect_uri", "openid", "oidc"]),
    ("saml", ["saml", "signature wrapping", "xsw"]),
    ("ssrf", ["blind ssrf", "out-of-band"]),
    ("auth", ["authentication bypass", "auth bypass", "login bypass", "2fa bypass", "mfa bypass"]),
    ("fileupload", ["file upload", "unrestricted upload", "arbitrary file upload"]),
    ("openredirect", ["open redirect", "unvalidated redirect"]),
    ("logic", ["business logic", "logic flaw", "price manipulation", "coupon"]),
    ("session", ["session fixation", "session not invalidated", "token not revoked"]),
    ("prototype", ["prototype pollution", "__proto__"]),
    ("smuggling", ["request smuggling", "desync", "cl.te", "te.cl"]),
]
TYPE_OF = {"idor": "noaccess", "authz": "deny", "bfla": "deny", "logic": "rejects",
           "race": "once", "session": "lifecycle"}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def read():
    f = arg("--file")
    if f:
        return Path(f).read_text(errors="replace")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    sys.exit("paste a report on stdin, or --file report.md")


def classify(text):
    low = text.lower()
    scores = {}
    for cls, kws in CLASS_KW:
        for kw in kws:
            if kw in low:
                scores[cls] = scores.get(cls, 0) + (2 if len(kw) > 10 else 1)
    if not scores:
        return "misc"
    return max(scores, key=scores.get)


def summary(text):
    # title = first heading or first non-empty line; technique = first sentence mentioning a verb
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    title = ""
    for l in lines:
        if l.startswith("#"):
            title = l.lstrip("# ").strip(); break
    if not title and lines:
        title = lines[0][:120]
    # a couple of key sentences
    key = re.findall(r"[^.\n]{20,180}(?:inject|bypass|swap|forge|leak|exfil|redeem|escalat|dump|reach|read|overwrite)[^.\n]{0,80}", text, re.I)
    return title, (key[0].strip() if key else "")


def endpoints(text):
    eps = set()
    for m in re.finditer(r"(?<![\w])/[a-z0-9][a-z0-9/_{}.\-]{2,}", text, re.I):
        eps.add(m.group(0))
    return sorted(eps)[:8]


def main():
    text = read()
    if not text.strip():
        sys.exit("empty")
    cls = classify(text)
    stack = (arg("--stack", "generic") or "generic").lower()
    program = arg("--program", "")
    url = arg("--url", "")
    try:
        reward = float(arg("--reward", "0") or 0)
    except ValueError:
        reward = 0.0
    title, technique = summary(text)
    eps = endpoints(text)
    note = (technique or title)[:220]

    CORPUS.mkdir(parents=True, exist_ok=True)
    # learned.jsonl (suggested on future hunts)
    lrec = {"type": TYPE_OF.get(cls, "technique"), "fam": cls, "stack": stack,
            "note": note or title, "url": url, "ts": time.strftime("%Y-%m-%d")}
    with LEARNED.open("a") as f:
        f.write(json.dumps(lrec) + "\n")
    # memory.jsonl (recallable by similarity)
    mtext = " | ".join(x for x in [title, technique, "endpoints: " + ", ".join(eps) if eps else ""] if x)[:2000]
    mrec = {"id": "M" + str(int(time.time() * 1000)), "kind": "disclosed", "cls": cls, "stack": stack,
            "program": program or "disclosed", "reward": reward, "outcome": "disclosed",
            "text": mtext or title, "ts": time.strftime("%Y-%m-%d")}
    with MEM.open("a") as f:
        f.write(json.dumps(mrec) + "\n")

    print(f"[ingest] class={cls}  stack={stack}  → learned.jsonl + memory.jsonl")
    print(f"  title:     {title[:100]}")
    if technique:
        print(f"  technique: {technique[:120]}")
    if eps:
        print(f"  endpoints: {', '.join(eps[:6])}")
    print(f"  → will be suggested on future {stack} hunts and recalled on similar situations.")


if __name__ == "__main__":
    main()
