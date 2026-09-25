#!/usr/bin/env python3
"""
github-recon — scan public org repos for secrets, staging hosts, CI/CD issues.

Fetches the org's public repos, clones them shallow, and runs:
  • trufflehog (if installed) for secrets
  • gitleaks (if installed) for secrets
  • regex patterns for staging URLs, API keys, tokens, CI/CD configs
  • pull_request_target workflows (CI/CD injection)
  • hardcoded IPs and internal domains

Usage:
  github-recon.py --org acmecorp [--token ghp_xxx] [--json] [--out report.json]
  github-recon.py --repo https://github.com/acme/api [--token ghp_xxx] [--json]
Exit: 0 clean · 1 findings.
"""
import sys, re, os, json, time, subprocess, tempfile, shutil
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

API = "https://api.github.com"

# ── patterns ─────────────────────────────────────────────────────────────────
SECRET_PATS = [
    ("aws_key",          re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret",       re.compile(r"(?i)aws.{0,30}secret.{0,10}['\"][A-Za-z0-9+/]{40}['\"]")),
    ("google_api_key",   re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("firebase_url",     re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("jwt",              re.compile(r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+")),
    ("bearer_token",     re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
    ("github_token",     re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("slack_token",      re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("stripe_key",       re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24}")),
    ("private_key",      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY")),
    ("password_field",   re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}")),
    ("generic_secret",   re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9\-_]{16,}")),
]

STAGING_PAT = re.compile(
    r"https?://(?:staging|stage|stg|dev|develop|test|qa|uat|sandbox|pre-?prod|internal)[.\-][a-z0-9\-./]{4,80}",
    re.I
)
INTERNAL_IP = re.compile(r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}")
PRT_VULN    = re.compile(r"pull_request_target")
GITLEAKS_SKIP = re.compile(r"#\s*gitleaks:allow|nosec", re.I)

SKIP_EXTS = {".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",
             ".ttf",".eot",".mp4",".mp3",".pdf",".zip",".tar",".gz"}
SKIP_DIRS = {".git","node_modules","vendor","dist","build",".venv","venv","__pycache__"}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def flag(n): return n in sys.argv

def gh(path, token=None):
    headers = {"Accept":"application/vnd.github+json","User-Agent":"huntr-recon/1.0"}
    if token: headers["Authorization"] = f"Bearer {token}"
    try:
        req = Request(f"{API}{path}", headers=headers)
        with urlopen(req, timeout=15) as r:
            return json.loads(r.read()), r.getcode()
    except URLError as e:
        return {"error": str(e)}, 0

def list_repos(org, token):
    repos = []; page = 1
    while True:
        data, code = gh(f"/orgs/{org}/repos?type=public&per_page=100&page={page}", token)
        if not isinstance(data, list): break
        repos.extend(data)
        if len(data) < 100: break
        page += 1
    return repos

def scan_file_content(path, content, findings):
    fname = str(path)
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if GITLEAKS_SKIP.search(line): continue
        for name, pat in SECRET_PATS:
            m = pat.search(line)
            if m:
                snippet = line.strip()[:120]
                findings.append({
                    "type": "secret", "class": name,
                    "file": fname, "line": i, "snippet": snippet,
                    "severity": "critical" if name in ("private_key","aws_key","stripe_key") else "high",
                })
                break
        # staging URLs
        for m in STAGING_PAT.finditer(line):
            findings.append({
                "type": "staging_url", "class": "info_disclosure",
                "file": fname, "line": i, "snippet": m.group(0)[:120],
                "severity": "low",
            })
        # internal IPs
        for m in INTERNAL_IP.finditer(line):
            findings.append({
                "type": "internal_ip", "class": "info_disclosure",
                "file": fname, "line": i, "snippet": line.strip()[:80],
                "severity": "low",
            })

def scan_ci_workflows(repo_dir, findings):
    wf_dir = repo_dir / ".github" / "workflows"
    if not wf_dir.exists(): return
    for wf in wf_dir.glob("*.yml"):
        content = wf.read_text("utf-8","ignore")
        if PRT_VULN.search(content):
            # check if it also checks out PR code and runs uncontrolled commands
            if re.search(r"actions/checkout", content) and re.search(r"run:", content):
                findings.append({
                    "type": "ci_injection", "class": "pull_request_target",
                    "file": str(wf.relative_to(repo_dir)),
                    "line": 0,
                    "snippet": "pull_request_target + actions/checkout + run: — potential CI/CD injection",
                    "severity": "high",
                })

def scan_repo_dir(repo_dir):
    findings = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() in SKIP_EXTS: continue
            try:
                content = fpath.read_text("utf-8","ignore")
                rel = str(fpath.relative_to(repo_dir))
                scan_file_content(rel, content, findings)
            except Exception:
                pass
    scan_ci_workflows(repo_dir, findings)
    return findings

def run_trufflehog(repo_dir):
    if not shutil.which("trufflehog"): return []
    try:
        r = subprocess.run(
            ["trufflehog","filesystem",str(repo_dir),"--json","--no-update"],
            capture_output=True, text=True, timeout=120
        )
        results = []
        for line in r.stdout.splitlines():
            try:
                obj = json.loads(line)
                results.append({
                    "type": "secret", "class": obj.get("DetectorName","secret"),
                    "file": obj.get("SourceMetadata",{}).get("Data",{}).get("Filesystem",{}).get("file",""),
                    "line": 0, "snippet": obj.get("Raw","")[:100],
                    "severity": "critical", "source": "trufflehog",
                })
            except Exception: pass
        return results
    except Exception as e:
        return [{"type":"tool_error","class":"trufflehog","snippet":str(e),"severity":"info"}]

def run_gitleaks(repo_dir):
    if not shutil.which("gitleaks"): return []
    try:
        r = subprocess.run(
            ["gitleaks","detect","--source",str(repo_dir),"-r","/dev/stdout","--report-format","json","--exit-code","0"],
            capture_output=True, text=True, timeout=120
        )
        results = []
        try:
            data = json.loads(r.stdout or "[]") or []
            for item in data:
                results.append({
                    "type": "secret", "class": item.get("RuleID","secret"),
                    "file": item.get("File",""), "line": item.get("StartLine",0),
                    "snippet": item.get("Secret","")[:80],
                    "severity": "high", "source": "gitleaks",
                })
        except Exception: pass
        return results
    except Exception as e:
        return [{"type":"tool_error","class":"gitleaks","snippet":str(e),"severity":"info"}]

def clone_and_scan(url, token=None):
    tmpdir = tempfile.mkdtemp(prefix="huntr-gh-")
    try:
        clone_url = url
        if token:
            from urllib.parse import urlparse
            p = urlparse(url)
            clone_url = f"{p.scheme}://{token}@{p.netloc}{p.path}"
        r = subprocess.run(
            ["git","clone","--depth=1","--quiet", clone_url, tmpdir],
            capture_output=True, text=True, timeout=120
        )
        if r.returncode != 0:
            return [], f"clone failed: {r.stderr[:200]}"
        findings = scan_repo_dir(Path(tmpdir))
        findings += run_trufflehog(Path(tmpdir))
        findings += run_gitleaks(Path(tmpdir))
        # dedup by (type, class, file, snippet[:40])
        seen = set(); deduped = []
        for f in findings:
            key = (f["type"], f.get("class",""), f.get("file",""), f.get("snippet","")[:40])
            if key not in seen:
                seen.add(key); deduped.append(f)
        return deduped, None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def main():
    org      = arg("--org")
    repo_url = arg("--repo")
    token    = arg("--token")
    out_file = arg("--out")

    if not org and not repo_url:
        print(__doc__); sys.exit(0)

    all_findings = []; repo_summaries = []

    if repo_url:
        repos_to_scan = [{"clone_url": repo_url, "name": repo_url.split("/")[-1], "html_url": repo_url}]
    else:
        print(f"[github-recon] listing repos for org: {org}", file=sys.stderr)
        repos = list_repos(org, token)
        if not repos:
            print(f"[github-recon] no public repos found for {org}", file=sys.stderr)
            sys.exit(0)
        print(f"[github-recon] found {len(repos)} repos", file=sys.stderr)
        repos_to_scan = repos

    for repo in repos_to_scan:
        name = repo.get("name","?")
        url  = repo.get("clone_url") or repo.get("html_url","")
        print(f"[github-recon] scanning {name} …", file=sys.stderr)
        findings, err = clone_and_scan(url, token)
        if err: print(f"  ! {err}", file=sys.stderr)
        for f in findings: f["repo"] = name
        all_findings += findings
        crit = sum(1 for f in findings if f.get("severity")=="critical")
        high = sum(1 for f in findings if f.get("severity")=="high")
        repo_summaries.append({"repo":name,"url":repo.get("html_url",""),"findings":len(findings),"critical":crit,"high":high})

    total = len(all_findings)
    result = {
        "org": org or repo_url, "ts": time.strftime("%Y-%m-%d %H:%M"),
        "repos_scanned": len(repos_to_scan), "total_findings": total,
        "critical": sum(1 for f in all_findings if f.get("severity")=="critical"),
        "high":     sum(1 for f in all_findings if f.get("severity")=="high"),
        "repos": repo_summaries,
        "findings": all_findings,
    }

    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if total else 0)

    print(f"\n══ GitHub recon · {org or repo_url} ══════════════════════════")
    print(f"  Repos scanned: {len(repos_to_scan)}")
    print(f"  Findings:  {total}  (critical: {result['critical']}  high: {result['high']})")
    if all_findings:
        print(f"\n  Top findings:")
        for f in sorted(all_findings, key=lambda x: {"critical":0,"high":1}.get(x.get("severity",""),2))[:20]:
            print(f"    [{f['severity'].upper():<8}] {f['class']:<25} {f.get('repo','?')}:{f.get('file','?')[:40]}")
            if f.get("snippet"): print(f"             {f['snippet'][:90]}")
    sys.exit(1 if total else 0)

if __name__ == "__main__":
    main()
