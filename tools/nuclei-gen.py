#!/usr/bin/env python3
"""
nuclei-gen — turn a confirmed finding into a reusable Nuclei template (YAML,
hand-built, no yaml dep). Feeds your own regression suite and, if you choose,
the community. Pairs with retest.py to prove a fix later.

Reads a finding JSON (from any HUNTR probe, or hand-written) with as much of:
  url, method, param, payload, match (string that proves it), status,
  severity, attack/class, title, note.

Emits a matcher-based template:
  · request: raw path/method/body from the finding
  · matchers: status (if given) AND a word/regex match on the proof string
  · info: name / author / severity / tags derived from the finding class

Usage:
  nuclei-gen.py --finding-file f.json [--author you] [--id my-idor-orders] \
                [--out tmpl.yaml] [--json]
Exit: 0 ok.
"""
import sys, re, json, time
from pathlib import Path
from urllib.parse import urlparse


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:60] or "huntr-finding"


def yaml_str(s):
    s = str(s)
    if s == "" or re.search(r'[:#\{\}\[\],&\*\?\|<>=!%@`"\']', s) or s != s.strip():
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def main():
    ff = arg("--finding-file")
    author = arg("--author", "huntr")
    tid = arg("--id")
    out = arg("--out")

    if not ff or not Path(ff).exists():
        print(__doc__)
        sys.exit(0)

    try:
        f = json.loads(Path(ff).read_text())
    except Exception as ex:
        print(json.dumps({"ok": False, "error": f"bad finding json: {ex}"}) if flag("--json")
              else f"bad finding json: {ex}")
        sys.exit(0)

    url = f.get("url") or f.get("base_url") or f.get("poc_url") or ""
    method = (f.get("method") or "GET").upper()
    status = f.get("status") or f.get("status_b")
    severity = (f.get("severity") or f.get("estimated_severity") or "info").lower()
    cls = f.get("attack") or f.get("test") or f.get("class") or "misc"
    title = f.get("title") or f"{cls} at {urlparse(url).path or url}"
    body = f.get("data") or f.get("body") or ""
    match = f.get("match") or f.get("response_snippet") or f.get("snippet") or ""
    match = re.sub(r"\s+", " ", str(match)).strip()[:80]

    u = urlparse(url)
    base = f"{u.scheme}://{u.netloc}" if u.scheme else "{{BaseURL}}"
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    tid = tid or slug(f"{cls}-{u.path}")

    lines = []
    lines.append(f"id: {tid}")
    lines.append("")
    lines.append("info:")
    lines.append(f"  name: {yaml_str(title)}")
    lines.append(f"  author: {yaml_str(author)}")
    lines.append(f"  severity: {severity if severity in ('info','low','medium','high','critical') else 'info'}")
    lines.append(f"  description: {yaml_str(f.get('note','') or f'HUNTR-derived template for {cls}')}")
    lines.append("  tags: " + ",".join(dict.fromkeys([slug(cls), "huntr"])))
    lines.append("")
    lines.append("http:")
    lines.append("  - raw:")
    raw_req = [f"      - |"]
    reqline = f"        {method} {path} HTTP/1.1"
    raw_req.append(reqline)
    raw_req.append(f"        Host: {u.netloc or '{{Hostname}}'}")
    if body:
        raw_req.append("        Content-Type: application/json")
    raw_req.append("        User-Agent: nuclei/huntr")
    if body:
        raw_req.append("")
        raw_req.append("        " + json.dumps(json.loads(body)) if _is_json(body) else "        " + body)
    lines += raw_req
    lines.append("")
    lines.append("    matchers-condition: and")
    lines.append("    matchers:")
    if status:
        lines.append("      - type: status")
        lines.append("        status:")
        lines.append(f"          - {int(status)}")
    if match:
        lines.append("      - type: word")
        lines.append("        part: body")
        lines.append("        words:")
        lines.append(f"          - {yaml_str(match)}")
    if not status and not match:
        lines.append("      - type: dsl")
        lines.append("        dsl:")
        lines.append('          - "true"  # TODO: add a real matcher (proof string / status)')

    template = "\n".join(lines) + "\n"

    if out:
        Path(out).write_text(template)

    result = {
        "ok": True, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "id": tid, "severity": severity,
        "has_status_matcher": bool(status), "has_word_matcher": bool(match),
        "out": out or None, "template": template,
    }
    if flag("--json"):
        print(json.dumps(result))
        sys.exit(0)

    print(template)
    if not (status or match):
        print("# ⚠ no status/proof in the finding — add a matcher before using.", file=sys.stderr)
    sys.exit(0)


def _is_json(s):
    try:
        json.loads(s)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
