#!/usr/bin/env python3
"""Seed hunt-memory + corpus from the local skill library (idempotent).
Tags everything program='skill-library' / url='skill:<name>' so a re-run replaces cleanly."""
import re, json, time, os
from pathlib import Path

SKILLS = Path.home() / ".claude" / "skills"
CORPUS = Path.home() / ".claude" / "hunt-corpus"
MEM = CORPUS / "memory.jsonl"
LEARNED = CORPUS / "learned.jsonl"
TAG = "skill-library"

# folder suffix -> canonical engine class (fallbacks to normalized suffix)
CLSMAP = {
    "auth-bypass": "authbypass", "business-logic": "logic", "race": "race",
    "race-condition": "race", "open-redirect": "openredirect", "file-upload": "fileupload",
    "prototype-pollution": "prototype", "http-smuggling": "smuggling", "host-header": "hostheader",
    "cache-poison": "cache", "cache-poisoning": "cache", "source-leak": "sourceleak",
    "shadow-api": "shadowapi", "api-misconfig": "apimisconfig", "jwt-crypto": "jwt",
    "mfa-bypass": "mfabypass", "forgot-password": "auth", "js-analysis": "recon",
    "llm-ai": "llm", "rag-vector": "llm", "html-injection": "xss", "clickjacking": "clickjacking",
    "captcha-bypass": "captcha", "brute-force": "bruteforce", "tls-network": "network",
    "ntlm-info": "network", "exceptional-conditions": "errorhandling",
}
STACKMAP = {
    "nextjs": "saas", "nodejs": "saas", "django": "saas", "laravel": "saas", "aspnet": "saas",
    "springboot": "saas", "fintech-graphql": "fintech", "k8s": "cloud", "cloud-misconfig": "cloud",
    "grpc": "saas", "graphql": "saas", "spa-api": "saas",
}


def cls_of(name):
    suf = name[len("hunt-"):]
    return CLSMAP.get(suf, suf.replace("-", ""))


def read(p):
    try:
        return p.read_text(errors="replace")
    except Exception:
        return ""


def frontmatter_desc(text):
    m = re.search(r"^description:\s*(.+)$", text, re.M)
    return m.group(1).strip() if m else ""


def why_pays(text):
    # first substantive paragraph after the first '## ' header
    body = re.split(r"\n##\s", text, maxsplit=1)
    if len(body) < 2:
        return ""
    seg = body[1]
    for para in re.split(r"\n\s*\n", seg):
        p = " ".join(l.strip() for l in para.splitlines() if l.strip() and not l.startswith(("#", ">", "|", "-", "*")))
        if len(p) > 60:
            return p[:400]
    return ""


def gold_lines(text):
    # lines carrying real paid examples / concrete techniques
    out = []
    for l in text.splitlines():
        s = l.strip(" -*|>")
        if len(s) < 12:
            continue
        if re.search(r"(\$\s?[\d,]+|paid|bounty|CVE-\d|Immunefi|HackerOne|real |→|payload:|bypass:)", s, re.I):
            out.append(s[:180])
        if len(out) >= 6:
            break
    return out


def strip_tag(path, keyfn):
    if not path.exists():
        return []
    kept = []
    for ln in path.read_text().splitlines():
        if not ln.strip():
            continue
        try:
            r = json.loads(ln)
        except Exception:
            continue
        if not keyfn(r):
            kept.append(r)
    return kept


def main():
    CORPUS.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d")
    # drop prior skill-library rows so this is idempotent
    mem = strip_tag(MEM, lambda r: r.get("program") == TAG or r.get("outcome") == TAG)
    learned = strip_tag(LEARNED, lambda r: str(r.get("url", "")).startswith("skill:"))

    n_mem = n_rule = 0
    for d in sorted(SKILLS.glob("hunt-*")):
        if not d.is_dir() or d.name.endswith(".md"):
            continue
        f = d / "SKILL.md"
        if not f.exists():
            cand = list(d.glob("*.md"))
            if not cand:
                continue
            f = cand[0]
        text = read(f)
        if not text:
            continue
        cls = cls_of(d.name)
        stack = STACKMAP.get(d.name[len("hunt-"):], "generic")
        desc = frontmatter_desc(text)
        why = why_pays(text)
        gold = gold_lines(text)
        rc = re.search(r"report_count:\s*(\d+)", text)
        body_txt = " | ".join(x for x in [desc, why] + gold if x)[:2000]
        if not body_txt:
            continue
        mem.append({"id": "S" + str(int(time.time() * 1000)) + str(n_mem), "kind": "pattern",
                    "cls": cls, "stack": stack, "program": TAG, "reward": 0, "outcome": TAG,
                    "text": f"[{cls}] {body_txt}", "ts": ts})
        n_mem += 1
        learned.append({"type": "technique", "fam": cls, "stack": stack,
                        "note": (why or desc)[:220], "url": "skill:" + d.name, "ts": ts})
        n_rule += 1

    # reference skills with real paid examples → mine per-line gold as memory
    for ref in ("web2-vuln-classes", "security-arsenal"):
        f = SKILLS / ref / "SKILL.md"
        if not f.exists():
            continue
        text = read(f)
        for g in gold_lines(text) + [frontmatter_desc(text)[:400]]:
            if not g:
                continue
            mem.append({"id": "S" + str(int(time.time() * 1000)) + str(n_mem), "kind": "reference",
                        "cls": "misc", "stack": "generic", "program": TAG, "reward": 0, "outcome": TAG,
                        "text": f"[ref:{ref}] {g}", "ts": ts})
            n_mem += 1

    MEM.write_text("\n".join(json.dumps(r) for r in mem) + "\n")
    LEARNED.write_text("\n".join(json.dumps(r) for r in learned) + "\n")
    print(f"[seed] memory: {n_mem} skill entries (+ prior kept = {len(mem)} total)")
    print(f"[seed] learned: {n_rule} skill rules (+ prior kept = {len(learned)} total)")


if __name__ == "__main__":
    main()
