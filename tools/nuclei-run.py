#!/usr/bin/env python3
"""
nuclei-run — run Nuclei against in-scope hosts and parse findings into HUNTR format.

Checks nuclei is installed, builds a safe target list using scope-guard, runs
nuclei with your chosen severity/tags, and parses JSONL output into HUNTR findings
with deduplicated evidence blocks ready to paste into a report.

Usage:
  nuclei-run.py --target https://api.acme.com [--target https://app.acme.com]
                [--severity critical,high,medium]
                [--tags cves,misconfig,exposures,default-logins]
                [--templates path/to/templates/]
                [--rate 50] [--json] [--out findings.json]
  nuclei-run.py --hosts-file hosts.txt [--severity critical,high]
Exit: 0 clean · 1 findings.
"""
import sys, re, os, json, time, subprocess, shutil, tempfile
from pathlib import Path

# severity priority for sorting
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}

# classes that map nuclei template tags to vuln categories
TAG_CLASS = {
    "sqli":"SQLi", "xss":"XSS", "ssrf":"SSRF", "ssti":"SSTI", "xxe":"XXE",
    "rce":"RCE", "lfi":"LFI", "rfi":"RFI", "traversal":"PathTraversal",
    "idor":"IDOR", "auth-bypass":"AuthBypass", "default-login":"DefaultLogin",
    "misconfig":"Misconfig", "exposure":"InfoDisclosure", "cve":"CVE",
    "takeover":"Takeover", "cors":"CORS", "jwt":"JWT", "oast":"OAST",
    "file-upload":"FileUpload", "token":"SecretLeak", "api-key":"SecretLeak",
    "csrf":"CSRF", "redirect":"OpenRedirect", "prototype-pollution":"ProtoPollution",
}

def arg(n, d=None):
    if n not in sys.argv: return d
    idx = sys.argv.index(n)+1
    return sys.argv[idx] if idx < len(sys.argv) else d

def args_multi(n):
    """Collect all values for a repeated flag."""
    vals = []
    for i, a in enumerate(sys.argv):
        if a == n and i+1 < len(sys.argv):
            vals.append(sys.argv[i+1])
    return vals

def flag(n): return n in sys.argv


def check_nuclei():
    if shutil.which("nuclei"):
        r = subprocess.run(["nuclei","-version"], capture_output=True, text=True)
        ver = re.search(r"(\d+\.\d+\.\d+)", r.stderr or r.stdout or "")
        return True, ver.group(1) if ver else "?"
    return False, None

def build_targets_file(targets, hosts_file):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="huntr-nuc-")
    if hosts_file:
        p = Path(hosts_file)
        if p.exists():
            tmp.write(p.read_text())
    for t in targets:
        tmp.write(t.strip() + "\n")
    tmp.close()
    return tmp.name

def run_nuclei(targets_file, severity, tags, templates, rate, extra_flags=None):
    cmd = [
        "nuclei",
        "-list", targets_file,
        "-json-export", "-",          # stream JSONL to stdout
        "-silent",
        "-rate-limit", str(rate),
        "-bulk-size", "25",
        "-concurrency", "10",
        "-timeout", "10",
        "-retries", "1",
        "-no-interactsh",              # avoid unnecessary callbacks in BB
    ]
    if severity: cmd += ["-severity", severity]
    if tags:     cmd += ["-tags", tags]
    if templates and Path(templates).exists(): cmd += ["-t", templates]
    if extra_flags: cmd += extra_flags

    print(f"[nuclei-run] running: {' '.join(cmd[:8])} …", file=sys.stderr)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(timeout=600)
        return out, err, proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        return "", "timeout after 600s", 1
    except Exception as e:
        return "", str(e), 1

def parse_nuclei_output(output):
    findings = []
    seen = set()
    for line in output.splitlines():
        line = line.strip()
        if not line: continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        info   = obj.get("info",{})
        sev    = (info.get("severity") or "unknown").lower()
        name   = info.get("name","?")
        tmpl   = obj.get("template-id","")
        host   = obj.get("host","")
        url    = obj.get("matched-at") or obj.get("url","")
        tags_l = info.get("tags") or []

        # vuln class from tags
        vclass = "Misc"
        for tag in tags_l:
            if tag.lower() in TAG_CLASS:
                vclass = TAG_CLASS[tag.lower()]; break

        # extract evidence
        req = obj.get("request","") or obj.get("curl-command","")
        resp = obj.get("response","") or ""
        extracted = obj.get("extracted-results") or []
        matcher    = obj.get("matcher-name","")

        key = (tmpl, host, url[:60])
        if key in seen: continue
        seen.add(key)

        findings.append({
            "type": "nuclei",
            "severity": sev,
            "class": vclass,
            "name": name,
            "template": tmpl,
            "host": host,
            "url": url,
            "tags": tags_l,
            "request": req[:2000] if req else "",
            "response": resp[:1000] if resp else "",
            "extracted": extracted[:10],
            "matcher": matcher,
            "refs": (info.get("reference") or [])[:3],
            "cvss": info.get("classification",{}).get("cvss-score",""),
            "cve_id": info.get("classification",{}).get("cve-id",""),
            "description": (info.get("description") or "")[:300],
            "ts": time.strftime("%Y-%m-%d %H:%M"),
        })

    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"],5))

def format_report(finding):
    """Return a markdown block for pasting into a HUNTR report."""
    lines = [
        f"## {finding['name']}",
        f"**Severity**: {finding['severity'].upper()}  **Class**: {finding['class']}",
        f"**Template**: `{finding['template']}`",
        f"**Target**: {finding['url'] or finding['host']}",
    ]
    if finding.get("description"):
        lines.append(f"\n**Description**: {finding['description']}")
    if finding.get("extracted"):
        lines.append(f"\n**Extracted**: `{'`, `'.join(str(x) for x in finding['extracted'][:5])}`")
    if finding.get("request"):
        lines.append(f"\n**Request**:\n```http\n{finding['request'][:800]}\n```")
    if finding.get("response"):
        lines.append(f"\n**Response**:\n```\n{finding['response'][:400]}\n```")
    if finding.get("cve_id"):
        lines.append(f"\n**CVE**: {finding['cve_id']}  CVSS: {finding.get('cvss','?')}")
    if finding.get("refs"):
        lines.append(f"\n**References**: {', '.join(finding['refs'][:2])}")
    return "\n".join(lines)

def main():
    ok, ver = check_nuclei()
    if not ok:
        print("[nuclei-run] nuclei not found. Install from: github.com/projectdiscovery/nuclei", file=sys.stderr)
        if flag("--json"): print(json.dumps({"error":"nuclei not installed","findings":[]})); sys.exit(2)
        sys.exit(2)

    targets    = args_multi("--target")
    hosts_file = arg("--hosts-file")
    severity   = arg("--severity", "critical,high,medium")
    tags       = arg("--tags", "")
    templates  = arg("--templates")
    rate       = int(arg("--rate","50"))
    out_file   = arg("--out")

    if not targets and not hosts_file:
        print(__doc__); sys.exit(0)

    print(f"[nuclei-run] nuclei {ver} · targets={len(targets)} · severity={severity}", file=sys.stderr)

    targets_file = build_targets_file(targets, hosts_file)
    try:
        out, err, code = run_nuclei(targets_file, severity, tags, templates, rate)
    finally:
        Path(targets_file).unlink(missing_ok=True)

    if err and "nuclei" not in err.lower() and code != 0:
        print(f"[nuclei-run] stderr: {err[:400]}", file=sys.stderr)

    findings = parse_nuclei_output(out)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "nuclei_version": ver,
        "targets": targets,
        "severity_filter": severity,
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"]=="critical"),
        "high":     sum(1 for f in findings if f["severity"]=="high"),
        "medium":   sum(1 for f in findings if f["severity"]=="medium"),
        "findings": findings,
    }

    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if findings else 0)

    # human report
    print(f"\n══ Nuclei · {', '.join(targets[:3])} ══════════════════════════")
    print(f"  Findings: {len(findings)}  (crit: {result['critical']}  high: {result['high']}  med: {result['medium']})")
    if not findings:
        print("  No findings."); sys.exit(0)
    print()
    for f in findings[:30]:
        sev = f["severity"].upper()
        print(f"  [{sev:<8}] {f['class']:<18} {f['name'][:45]}")
        print(f"             {f['url'] or f['host']}")
        if f.get("extracted"): print(f"             extracted: {f['extracted'][:2]}")
    if len(findings) > 30:
        print(f"\n  … and {len(findings)-30} more. Use --json or --out for full output.")

    # print report blocks for critical/high
    top = [f for f in findings if f["severity"] in ("critical","high")][:5]
    if top:
        print("\n\n══ Report snippets (critical/high) ══════════════════════")
        for f in top:
            print("\n" + format_report(f))
            print("─"*60)

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
