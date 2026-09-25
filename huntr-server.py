#!/usr/bin/env python3
"""
huntr-server — the bridge. Runs the engine as a real local app so a UI can drive it.

The claude.ai artifact is sandboxed (its CSP can't reach localhost), so the SELLABLE product is HUNTR
run locally: this server serves a UI and exposes the ~30 engine tools over http://127.0.0.1:8899.
Every request maps to a per-target working dir (~/.huntr/targets/<t>/.hunt) and shells the real tools
(scope-guard, hunt-next, exec-http, hunt-status, hypothesize, diff-oracle, …). Nothing here bypasses
scope-guard — writes/out-of-scope still refuse. Bound to loopback only.

Run:   huntr-server.py [--port 8899]
Then:  open http://127.0.0.1:8899   ·  or POST the JSON API below.

API (JSON):
  POST /api/intake      {text}                       → parse a pasted program → scope+signals
  GET  /api/targets                                  → list target workspaces
  GET  /api/next?target=T                            → the single next action (hunt-next --json)
  GET  /api/status?target=T                          → hunt-status snapshot
  GET  /api/surface?target=T                         → signals.json + coverage summary
  POST /api/exec        {target,url,method,identity,data,diff,expect}  → fire via exec-http (evidence-bound)
  POST /api/hypothesize {target,stack}               → ranked leads
  POST /api/recall      {text,stack}                 → analogous past hunts
"""
import sys, os, re, json, subprocess, tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TOOLS = Path.home() / ".claude" / "tools"
ROOT = Path(os.environ.get("HUNTR_HOME", str(Path.home() / ".huntr")))
TARGETS = ROOT / "targets"
PORT = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8899


def safe(t):
    return re.sub(r"[^a-z0-9._-]+", "_", (t or "default").lower()) or "default"


def hunt_dir(target):
    d = TARGETS / safe(target) / ".hunt"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run(tool, args, target=None, stdin=None, timeout=120):
    """Run an engine tool with HUNT_DIR pinned to the target workspace."""
    env = dict(os.environ)
    if target is not None:
        env["HUNT_DIR"] = str(hunt_dir(target))
    cmd = [sys.executable, str(TOOLS / tool)] + [str(a) for a in args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, input=stdin, env=env, timeout=timeout)
        return {"ok": r.returncode in (0, 1, 3), "code": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -1, "out": "", "err": "timeout"}
    except FileNotFoundError:
        return {"ok": False, "code": -1, "out": "", "err": f"tool not found: {tool}"}


INDEX = """<!doctype html><meta charset=utf8><title>HUNTR (local)</title>
<style>body{background:#0A0714;color:#F3F1FB;font-family:system-ui;max-width:720px;margin:60px auto;padding:0 20px;line-height:1.6}
code{background:rgba(255,255,255,.08);padding:2px 7px;border-radius:6px;font-size:13px}
h1{letter-spacing:2px}b{color:#A78BFA}.ok{color:#4ADE80}</style>
<h1>HUNTR<b>.</b> <span style=font-size:14px;color:#948CB6>local engine bridge</span></h1>
<p class=ok>● engine online — the ~30 tools are reachable over this loopback API.</p>
<p>This is the bridge that makes the workbench real: point a locally-served UI at
<code>http://127.0.0.1:%d/api/*</code> and Send/Diff fire the actual engine through scope-guard.</p>
<p>Quick check:</p>
<pre><code>curl -s 127.0.0.1:%d/api/targets
curl -s '127.0.0.1:%d/api/next?target=acme'</code></pre>
<p style=color:#948CB6;font-size:13px>Bound to 127.0.0.1 only. Nothing bypasses scope-guard.</p>
""" % (PORT, PORT, PORT)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200, ctype="application/json"):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(b"", 204)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        t = q.get("target")
        if u.path == "/":
            ui = TOOLS / "huntr-ui.html"
            if ui.exists():
                html = ui.read_text()
                tag = '<script src="/huntr-bridge.js"></script>'
                if (TOOLS / "huntr-bridge.js").exists() and tag not in html:
                    html = html.replace("</body>", tag + "\n</body>", 1) if "</body>" in html else html + tag
                return self._send(html, ctype="text/html; charset=utf-8")
            return self._send(INDEX, ctype="text/html; charset=utf-8")
        if u.path == "/huntr-bridge.js":
            bp = TOOLS / "huntr-bridge.js"
            if bp.exists():
                return self._send(bp.read_text(), ctype="application/javascript; charset=utf-8")
            return self._send("// no bridge", ctype="application/javascript")
        if u.path == "/api/targets":
            out = []
            if TARGETS.exists():
                for d in sorted(TARGETS.iterdir()):
                    hd = d / ".hunt"
                    if hd.exists():
                        fc = len(list((hd / "findings").glob("F*.md"))) if (hd / "findings").exists() else 0
                        out.append({"target": d.name, "findings": fc,
                                    "scope": (hd / "scope.allow").exists()})
            return self._send({"targets": out})
        if u.path == "/api/next":
            return self._send(run("hunt-next.py", ["--stack", q.get("stack", "generic"), "--json"], t))
        if u.path == "/api/status":
            return self._send(run("hunt-status.py", [], t))
        if u.path == "/api/earnings":  # the bounty-business ledger summary
            r = run("earnings.py", ["--json"])
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"paid": {}, "pending": {}, "ytd": {}, "counts": {}})
        if u.path == "/api/mobile/analyze":  # GET ?file=<path>&deep=1
            fp = q.get("file","")
            if not fp or not Path(fp).exists():
                return self._send({"error": f"file not found: {fp}"}, 404)
            args = ["--json"]
            if fp.lower().endswith(".apk"): args = ["--apk", fp] + args
            elif fp.lower().endswith(".ipa"): args = ["--ipa", fp] + args
            else: return self._send({"error": "must be .apk or .ipa"}, 400)
            if q.get("deep"): args.append("--deep")
            r = run("mobile-extract.py", args, timeout=300)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","parse error"), "raw": r.get("out","")[:2000]})
        if u.path == "/api/earnings/detail":  # full breakdown: by_program, by_platform, by_month
            r = run("earnings.py", ["--json-full"])
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"paid": {}, "pending": {}, "ytd": {}, "counts": {},
                                   "by_program": {}, "by_platform": {}, "by_month": {},
                                   "by_severity": {}, "recent": []})
        if u.path == "/api/earnings/export":  # stream the CSV for download
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
                tmp = f.name
            year = q.get("year")
            args = ["--export", "--csv", tmp]
            if year: args += ["--year", year]
            run("earnings.py", args)
            try:
                data = Path(tmp).read_bytes()
                Path(tmp).unlink(missing_ok=True)
            except Exception:
                data = b""
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=\"huntr-earnings.csv\"")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/api/js-diff/check":  # diff all tracked JS bundles for target
            r = run("js-diff.py", ["--target", q.get("target","default"), "--check", "--json"])
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"changes": [], "raw": r.get("out","") + r.get("err","")})
        if u.path == "/api/js-diff/report":  # show all logged changes
            args = ["--target", q.get("target","default"), "--report", "--json"]
            if q.get("all"): args.append("--all")
            r = run("js-diff.py", args)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"changes": []})
        if u.path == "/api/scope-radar":  # program scope/reward changes feed
            args = ["--json"]
            if q.get("h1"): args += ["--h1", q["h1"]]
            if q.get("bc"): args += ["--bc", q["bc"]]
            if q.get("ywh"): args += ["--ywh", q["ywh"]]
            if q.get("ing"): args += ["--ing", q["ing"]]
            if q.get("snapshot_only"): args.append("--snapshot-only")
            r = run("scope-radar.py", args, timeout=60)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"changes_found": False, "results": []})
        if u.path == "/api/subdomain":  # GET ?domain=acme.com&brute=1&seed=1
            args = ["--domain", q.get("domain",""), "--json"]
            if q.get("brute"): args.append("--brute")
            if q.get("seed"): args.append("--seed-coverage")
            if q.get("resolve_only"): args.append("--resolve-only")
            r = run("subdomain-enum.py", args, t, timeout=300)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total_found": 0, "live": 0, "results": []})
        if u.path == "/api/roi":  # which program to hunt now, by $/hr tuned to your history
            a = ["--rank", "--json"] + (["--stack", q["stack"]] if q.get("stack") else [])
            r = run("program-roi.py", a)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"programs": [], "raw": r.get("out", "") + r.get("err", "")})
        if u.path == "/api/surface":
            hd = hunt_dir(t)
            sig = {}
            if (hd / "signals.json").exists():
                try:
                    sig = json.loads((hd / "signals.json").read_text())
                except Exception:
                    pass
            scope_hosts = []
            if (hd / "scope.allow").exists():
                for ln in (hd / "scope.allow").read_text().splitlines():
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        scope_hosts.append(ln)
            return self._send({"signals": sig, "scopeHosts": scope_hosts,
                               "coverage": run("hunt-status.py", [], t)["out"]})
        return self._send({"error": "unknown route"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        b = self._body()
        t = b.get("target")
        if u.path == "/api/js-diff/add-url":  # POST {target, url}
            r = run("js-diff.py", ["--target", b.get("target","default"), "--add-url", b.get("url","")])
            return self._send({"ok": r["code"] == 0, "msg": r["out"].strip()})
        if u.path == "/api/js-diff/crawl":  # POST {target, base}
            r = run("js-diff.py", ["--target", b.get("target","default"), "--crawl", b.get("base","")])
            return self._send({"ok": r["code"] == 0, "msg": r["out"].strip(), "err": r.get("err","")})
        if u.path == "/api/graphql":  # POST {url, token?}
            args = ["--url", b.get("url",""), "--json"]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("seed_coverage"): args.append("--seed-coverage")
            r = run("graphql-map.py", args, b.get("target"))
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err",""), "introspection": False, "operations": []})
        if u.path == "/api/report/score":  # POST {title, cls, cvss, sev, impact, repro, endpoint, ...}
            args = []
            for k, flag_name in [("title","--title"),("cls","--class"),("cvss","--cvss"),
                                  ("sev","--sev"),("their_sev","--their-sev"),("impact","--impact"),
                                  ("repro","--repro"),("endpoint","--endpoint")]:
                if b.get(k): args += [flag_name, b[k]]
            for flag_name in ["--has-poc","--has-evidence","--has-video"]:
                k = flag_name[2:].replace("-","_")
                if b.get(k): args.append(flag_name)
            args.append("--json")
            r = run("report-score.py", args)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"score": 0, "verdict": "HOLD", "tips": [], "dimensions": {}})
        if u.path == "/api/github/recon":  # POST {org?, repo?, token?}
            args = ["--json"]
            if b.get("org"): args += ["--org", b["org"]]
            elif b.get("repo"): args += ["--repo", b["repo"]]
            else: return self._send({"error": "org or repo required"}, 400)
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("out"): args += ["--out", b["out"]]
            r = run("github-recon.py", args, timeout=600)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err",""), "total_findings": 0, "findings": []})
        if u.path == "/api/ssrf":  # POST {url, param, method?, token?, callback?}
            args = ["--url", b.get("url",""), "--param", b.get("param","url"), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("callback"): args += ["--callback-domain", b["callback"]]
            if b.get("data"): args += ["--data", b["data"]]
            r = run("ssrf-probe.py", args, timeout=180)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/race":  # POST {url, method?, data?, token?, count?}
            args = ["--url", b.get("url",""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("data"): args += ["--data", b["data"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("count"): args += ["--count", str(b["count"])]
            if b.get("warmup"): args += ["--warmup", str(b["warmup"])]
            for hdr in (b.get("headers") or []):
                args += ["--header", hdr]
            r = run("race-fire.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total_findings": 0, "findings": []})
        if u.path == "/api/ssti":  # POST {url, param, method?, token?, data?}
            args = ["--url", b.get("url",""), "--param", b.get("param",""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("data"): args += ["--data", b["data"]]
            r = run("ssti-probe.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/takeover":  # POST {hosts:[], domain?}
            args = ["--json"]
            hosts = b.get("hosts", [])
            domain = b.get("domain","")
            import tempfile
            if hosts:
                tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
                tf.write("\n".join(hosts)); tf.close()
                args += ["--subs-file", tf.name]
            elif domain:
                args += ["--domain", domain]
            else:
                return self._send({"error":"hosts or domain required"}, 400)
            r = run("takeover-check.py", args, timeout=300)
            if hosts:
                import os; os.unlink(tf.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "confirmed": 0, "findings": []})
        if u.path == "/api/redirect":  # POST {url, param, method?, token?, oauth_url?}
            args = ["--url", b.get("url",""), "--param", b.get("param",""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("oauth_url"): args += ["--oauth-auth-url", b["oauth_url"]]
            r = run("open-redirect.py", args, timeout=60)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/cors":  # POST {url, token?, headers:[]}
            args = ["--url", b.get("url",""), "--json"]
            if b.get("token"): args += ["--token", b["token"]]
            for h in (b.get("headers") or []):
                args += ["--header", h]
            r = run("cors-test.py", args, timeout=60)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/jwt":  # POST {token, url, method?, wordlist?, pubkey?}
            args = ["--token", b.get("token",""), "--url", b.get("url",""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("wordlist"): args += ["--wordlist", b["wordlist"]]
            if b.get("pubkey"): args += ["--pubkey", b["pubkey"]]
            for h in (b.get("headers") or []):
                args += ["--header", h]
            r = run("jwt-test.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/params":  # POST {url, method?, token?, data?, wordlist?, idor_field?, idor_base?}
            args = ["--url", b.get("url",""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("data"): args += ["--data", b["data"]]
            if b.get("wordlist"): args += ["--wordlist", b["wordlist"]]
            if b.get("idor_field"): args += ["--idor-field", b["idor_field"]]
            if b.get("idor_base"): args += ["--idor-base", str(b["idor_base"])]
            if b.get("batch"): args += ["--batch", str(b["batch"])]
            for h in (b.get("headers") or []):
                args += ["--header", h]
            r = run("param-fuzz.py", args, timeout=300)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/nuclei":  # POST {targets:[], severity?, tags?, rate?}
            targets = b.get("targets",[])
            args = ["--json"]
            for tgt in targets: args += ["--target", tgt]
            if b.get("severity"): args += ["--severity", b["severity"]]
            if b.get("tags"): args += ["--tags", b["tags"]]
            if b.get("rate"): args += ["--rate", str(b["rate"])]
            if b.get("templates"): args += ["--templates", b["templates"]]
            r = run("nuclei-run.py", args, timeout=600)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","")[:500], "total": 0, "findings": []})
        if u.path == "/api/intake":
            tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
            tmp.write(b.get("text", "")); tmp.close()
            r = run("hunt-intake.py", ["--file", tmp.name] + (["--stack", b["stack"]] if b.get("stack") else []), t)
            os.unlink(tmp.name)
            return self._send(r)
        if u.path == "/api/exec":
            if b.get("engine") == "cdp":  # fire from the real browser (bot-manager bypass)
                cargs = ["--url", b.get("url", ""), "--method", b.get("method", "GET")]
                if b.get("port"): cargs += ["--port", str(b["port"])]
                if b.get("approve"): cargs += ["--approve"]
                return self._send(run("exec-cdp.py", cargs, t))
            args = ["--url", b.get("url", ""), "--method", b.get("method", "GET")]
            if b.get("identity"): args += ["--identity", b["identity"]]
            if b.get("data"): args += ["--data", b["data"]]
            if b.get("diff"): args += ["--diff", b["diff"]]
            if b.get("expect"): args += ["--expect", b["expect"]]
            if b.get("approve"): args += ["--approve"]
            return self._send(run("exec-http.py", args, t))
        if u.path == "/api/browser":  # is a debuggable Chrome reachable?
            import urllib.request as ur
            port = b.get("port", 9222)
            try:
                ur.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2)
                return self._send({"up": True, "port": port})
            except Exception:
                return self._send({"up": False, "port": port})
        if u.path == "/api/hypothesize":
            hd = hunt_dir(t)
            return self._send(run("hunt-hypothesize.py",
                              ["--signals", str(hd / "signals.json"), "--stack", b.get("stack", "generic"),
                               "--emit", str(hd / "hypotheses.tsv")], t))
        if u.path == "/api/recall":
            return self._send(run("hunt-memory.py", ["--recall", "--text", b.get("text", ""),
                              "--stack", b.get("stack", "generic")], t))
        if u.path == "/api/mobile/upload":  # POST {filename, data_b64} → analyze
            fname = b.get("filename","upload.apk")
            data_b64 = b.get("data_b64","")
            if not data_b64:
                return self._send({"error": "no data"}, 400)
            import base64, tempfile
            ext = ".ipa" if fname.lower().endswith(".ipa") else ".apk"
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                tf.write(base64.b64decode(data_b64)); tmp = tf.name
            args = ["--ipa" if ext==".ipa" else "--apk", tmp, "--json"]
            if b.get("deep"): args.append("--deep")
            r = run("mobile-extract.py", args, timeout=300)
            Path(tmp).unlink(missing_ok=True)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err","parse error"), "raw": r.get("out","")[:2000]})
        if u.path == "/api/earnings/add":  # quick log a payout
            a = ["--add", "--program", b.get("program", "?"), "--platform", b.get("platform", "?"),
                 "--amount", str(b.get("amount", 0)), "--currency", b.get("currency", "USD"),
                 "--sev", b.get("sev", ""), "--title", b.get("title", ""),
                 "--status", b.get("status", "paid")]
            if b.get("date"): a += ["--date", b["date"]]
            if b.get("fee"): a += ["--fee", str(b["fee"])]
            if b.get("note"): a += ["--note", b["note"]]
            r = run("earnings.py", a)
            return self._send({"ok": r["code"] == 0, "msg": r["out"].strip()})
        if u.path == "/api/appeal":  # downgrade/appeal assistant
            a = ["--reason", b.get("reason", ""), "--class", b.get("cls", b.get("class", "")), "--json"]
            for k, fl in [("severity", "--severity"), ("their_severity", "--their-severity"),
                          ("endpoint", "--endpoint"), ("impact", "--impact"), ("title", "--title")]:
                if b.get(k): a += [fl, b[k]]
            r = run("appeal.py", a)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"decision": "?", "draft": r.get("out", "") + r.get("err", "")})
        if u.path == "/api/dup":  # pre-submit duplicate probability
            a = ["--class", b.get("cls", b.get("class", "")), "--endpoint", b.get("endpoint", ""), "--json"]
            if b.get("param"): a += ["--param", b["param"]]
            if b.get("title"): a += ["--title", b["title"]]
            if b.get("program"): a += ["--program", b["program"]]
            if b.get("stack"): a += ["--stack", b["stack"]]
            r = run("dup-score.py", a, t)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"prob": None, "raw": r.get("out", "") + r.get("err", "")})
        if u.path == "/api/identity":
            hd = hunt_dir(t)
            p = hd / "identities.json"
            try:
                ids = json.loads(p.read_text()) if p.exists() else {}
            except Exception:
                ids = {}
            name = b.get("name", "session")
            rec = {}
            if b.get("authorization"):
                rec["authorization"] = b["authorization"]
            if b.get("cookie"):
                rec["cookie"] = b["cookie"]
            ids[name] = rec
            p.write_text(json.dumps(ids, indent=2))
            return self._send({"ok": True, "identities": list(ids.keys())})
        return self._send({"error": "unknown route"}, 404)


def main():
    TARGETS.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"[huntr-server] engine bridge on http://127.0.0.1:{PORT}  (targets: {TARGETS})")
    print("[huntr-server] loopback only · scope-guard still gates every request · Ctrl-C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[huntr-server] stopped.")


if __name__ == "__main__":
    main()
