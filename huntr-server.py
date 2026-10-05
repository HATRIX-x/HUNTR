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
                # the server IS the real engine → enable live mode so entering a scope runs the
                # actual hunt (not the offline demo pipeline)
                live = '<script>window.__HUNTR_LIVE=true;</script>'
                if "window.__HUNTR_LIVE=true" not in html:
                    # inject INSIDE <head> (after the opening tag) so the doctype stays first — injecting
                    # before <!doctype> forces quirks mode and breaks the layout
                    if "<head>" in html:
                        html = html.replace("<head>", "<head>" + live, 1)
                    elif "</head>" in html:
                        html = html.replace("</head>", live + "</head>", 1)
                    elif "<body>" in html:
                        html = html.replace("<body>", "<body>" + live, 1)
                    else:
                        html = html + live   # last resort: after everything (never before doctype)
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
                        rec = {"target": d.name, "findings": fc, "scope": (hd / "scope.allow").exists()}
                        rf = hd / "run.json"
                        if rf.exists():
                            try:
                                r = json.loads(rf.read_text())
                                rec["status"] = r.get("status")          # running/paused/done/error/stopped
                                rec["pct"] = r.get("pct", 0)
                                rec["stage"] = r.get("stage", "")
                                rec["nfind"] = len(r.get("findings", []))
                                rec["updated"] = r.get("updated", 0)
                            except Exception:
                                pass
                        out.append(rec)
            return self._send({"targets": out})
        if u.path == "/api/next":
            return self._send(run("hunt-next.py", ["--stack", q.get("stack", "generic"), "--json"], t))
        if u.path == "/api/status":
            return self._send(run("hunt-status.py", [], t))
        if u.path == "/api/hunt/status":  # GET ?target=<t> — live state of a dashboard-driven hunt
            rf = hunt_dir(q.get("target", "")) / "run.json"
            if rf.exists():
                try:
                    return self._send(json.loads(rf.read_text()))
                except Exception:
                    return self._send({"status": "none"})
            return self._send({"status": "none"})
        if u.path == "/api/log-doctor":  # GET ?apply=1 — the self-healing agent: diagnose + fix engine problems
            a = ["--json"] + ([] if q.get("apply") else ["--dry"])
            r = run("log-doctor.py", a, timeout=90)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:400], "problems": [], "fixes_applied": []})
        if u.path == "/api/outcomes":  # GET calibrated priors from the learning loop
            pf = ROOT / "corpus" / "priors.json"
            try:
                return self._send(json.loads(pf.read_text()) if pf.exists() else {"total": 0, "buckets": {}})
            except Exception:
                return self._send({"total": 0, "buckets": {}})
        if u.path == "/api/claude-account":  # how the engine authenticates to Claude (API key vs linked account)
            try:
                import importlib.util as _il
                _spec = _il.spec_from_file_location("llm_auth", str(TOOLS / "llm_auth.py"))
                _m = _il.module_from_spec(_spec); _spec.loader.exec_module(_m)
                st = _m.account_status(); _h, mode = _m.llm_headers()
                st["mode"] = mode
                return self._send(st)
            except Exception as e:
                return self._send({"linked": False, "mode": None, "error": str(e)[:200]})
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
        if u.path == "/api/hunt/start":  # POST {target, program?, mode?, scope_types?, session_token?, token2?, cookie?, ua?, stealth?, single_host?, budget_sec?} — start a REAL hunt
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            hd = hunt_dir(t)
            # credentials go to a 0600 file (never argv — keeps tokens/cookies out of `ps`)
            st = (b.get("session_token") or "").strip()
            t2 = (b.get("token2") or "").strip()
            ck = (b.get("cookie") or "").strip()      # cookie-session auth (web apps that don't use bearer)
            ua = (b.get("ua") or "").strip()          # program-required UA suffix (e.g. yeswehack)
            cf = hd / "creds.json"
            try:
                creds = {k: v for k, v in (("session_token", st), ("token2", t2), ("cookie", ck), ("ua", ua)) if v}
                if creds:
                    cf.write_text(json.dumps(creds))
                    try: os.chmod(cf, 0o600)
                    except Exception: pass
                elif cf.exists():
                    cf.unlink()
            except Exception:
                pass
            # persist launch opts so a rate-limit-paused hunt can be resumed with the same settings
            opts = {"program": b.get("program", ""), "mode": b.get("mode", "grey"),
                    "scope_types": b.get("scope_types") or ["web", "api"],
                    "stealth": bool(b.get("stealth")), "single_host": bool(b.get("single_host")),
                    "llm_light": bool(b.get("llm_light")), "budget_sec": int(b.get("budget_sec") or 1200)}
            try: (hd / "launch.json").write_text(json.dumps(opts))
            except Exception: pass
            args = [sys.executable, str(TOOLS / "hunt-run.py"), "--target", t,
                    "--program", opts["program"], "--mode", opts["mode"],
                    "--scope-types", ",".join(opts["scope_types"]),
                    "--budget-sec", str(opts["budget_sec"])]
            if opts["stealth"]:
                args.append("--stealth")
            env = dict(os.environ); env["HUNT_DIR"] = str(hd)
            if opts["stealth"]:      env["HUNT_STEALTH"] = "1"   # throttle loud scanners (WAF-safe)
            if opts["single_host"]:  env["HUNT_SINGLE"] = "1"    # strict exact-host scope (no subdomain creep)
            if opts["llm_light"]:    env["HUNT_LLM"] = "haiku"   # Haiku-only — minimise rate limits (no paid API key)
            try:
                lf = open(hd / "run.log", "a")
                subprocess.Popen(args, stdout=lf, stderr=lf, env=env, start_new_session=True)
                return self._send({"ok": True, "target": t})
            except Exception as e:
                return self._send({"ok": False, "error": str(e)[:200]}, 500)
        if u.path == "/api/hunt/control":  # POST {target, action: stop|pause|resume}
            tgt = t; act = (b.get("action") or "").strip()
            hd = hunt_dir(tgt); pidf = hd / "run.pid"
            try:
                pid = int(pidf.read_text().strip())
            except Exception:
                pid = None
            def _alive(p):
                try: os.kill(p, 0); return True
                except Exception: return False
            # resume of a RATE-LIMIT-PAUSED hunt: the process exited, so re-launch it with --resume
            rf = hd / "run.json"
            cur_status = ""
            try: cur_status = json.loads(rf.read_text()).get("status", "")
            except Exception: pass
            if act == "resume" and (pid is None or not _alive(pid) or cur_status == "paused"):
                try:
                    opts = json.loads((hd / "launch.json").read_text())
                except Exception:
                    opts = {"mode": "grey", "scope_types": ["web", "api"], "budget_sec": 1200}
                args = [sys.executable, str(TOOLS / "hunt-run.py"), "--target", tgt, "--resume",
                        "--program", opts.get("program", ""), "--mode", opts.get("mode", "grey"),
                        "--scope-types", ",".join(opts.get("scope_types") or ["web", "api"]),
                        "--budget-sec", str(int(opts.get("budget_sec") or 1200))]
                if opts.get("stealth"): args.append("--stealth")
                env = dict(os.environ); env["HUNT_DIR"] = str(hd)
                if opts.get("stealth"):     env["HUNT_STEALTH"] = "1"
                if opts.get("single_host"): env["HUNT_SINGLE"] = "1"
                if opts.get("llm_light"):   env["HUNT_LLM"] = "haiku"
                try:
                    lf = open(hd / "run.log", "a")
                    subprocess.Popen(args, stdout=lf, stderr=lf, env=env, start_new_session=True)
                    return self._send({"ok": True, "action": "resume", "relaunched": True})
                except Exception as e:
                    return self._send({"ok": False, "error": str(e)[:200]}, 500)
            if pid is None:
                return self._send({"ok": False, "error": "no running hunt"}, 404)
            import signal
            sig = {"stop": signal.SIGTERM, "pause": signal.SIGSTOP, "resume": signal.SIGCONT}.get(act)
            if not sig:
                return self._send({"ok": False, "error": "bad action"}, 400)
            try:
                os.killpg(os.getpgid(pid), sig)
            except Exception as e:
                return self._send({"ok": False, "error": str(e)[:120]}, 500)
            if act == "stop":
                try:
                    rf = hd / "run.json"; d = json.loads(rf.read_text())
                    d["status"] = "stopped"; d["stage"] = "Stopped"
                    d.setdefault("logs", []).append({"t": "warn", "v": "■ hunt stopped by operator"})
                    rf.write_text(json.dumps(d))
                except Exception:
                    pass
            return self._send({"ok": True, "action": act})
        if u.path == "/api/outcome":  # POST a finding outcome → fleet learning loop
            import time as _t
            rec = {k: b.get(k) for k in ("target", "program", "stack", "cls", "sev", "title", "endpoint", "outcome", "bounty", "dup", "ev", "chain")}
            rec["ts"] = _t.time()
            if not rec.get("outcome"):
                return self._send({"ok": False, "error": "no outcome"}, 400)
            corp = ROOT / "corpus"
            try:
                corp.mkdir(parents=True, exist_ok=True)
                with open(corp / "outcomes.jsonl", "a") as fh:
                    fh.write(json.dumps(rec) + "\n")
            except Exception as e:
                return self._send({"ok": False, "error": str(e)[:120]}, 500)
            try:  # recalibrate priors from all outcomes so far
                subprocess.run([sys.executable, str(TOOLS / "hunt-learn.py")], timeout=30, capture_output=True)
            except Exception:
                pass
            return self._send({"ok": True, "recorded": rec.get("outcome")})
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
                os.unlink(tf.name)
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
        if u.path == "/api/idor":  # POST {base_url, token, token2, id_field, id_range, method?, data?}
            args = ["--base-url", b.get("base_url", ""), "--json"]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("token2"): args += ["--token2", b["token2"]]
            if b.get("id_field"): args += ["--id-field", b["id_field"]]
            if b.get("id_range"): args += ["--id-range", str(b["id_range"])]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("data"): args += ["--data", b["data"]]
            r = run("idor-chain.py", args, timeout=180)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "total": 0, "findings": []})
        if u.path == "/api/auth-bypass":  # POST {url, token, method?, data?}
            args = ["--url", b.get("url", ""), "--json"]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("data"): args += ["--data", b["data"]]
            r = run("auth-bypass.py", args, timeout=60)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "total": 0, "findings": []})
        if u.path == "/api/rate-limit":  # POST {url, method?, token?, data?, count?, threads?}
            args = ["--url", b.get("url", ""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("data"): args += ["--data", b["data"]]
            if b.get("count"): args += ["--count", str(b["count"])]
            if b.get("threads"): args += ["--threads", str(b["threads"])]
            r = run("rate-limit.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "limit_detected": False,
                                   "bypass_found": False, "findings": []})
        if u.path == "/api/oauth":  # POST {auth_url, token_url?, client_id?, redirect_uri?, scope?, code?}
            args = ["--auth-url", b.get("auth_url", ""), "--json"]
            if b.get("token_url"): args += ["--token-url", b["token_url"]]
            if b.get("client_id"): args += ["--client-id", b["client_id"]]
            if b.get("redirect_uri"): args += ["--redirect-uri", b["redirect_uri"]]
            if b.get("scope"): args += ["--scope", b["scope"]]
            if b.get("code"): args += ["--code", b["code"]]
            r = run("oauth-probe.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "total": 0, "findings": []})
        if u.path == "/api/logic":  # POST {url, method?, token?, data}
            args = ["--url", b.get("url", ""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("data"): args += ["--data", b["data"]]
            r = run("logic-fuzz.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "total": 0, "findings": []})
        if u.path == "/api/hypo":  # POST {endpoints:[], findings:[], program?, model?, max?}
            ef = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            ff = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            ef.write(json.dumps(b.get("endpoints", []))); ef.close()
            ff.write(json.dumps(b.get("findings", []))); ff.close()
            args = ["--endpoints-file", ef.name, "--findings-file", ff.name, "--json"]
            if b.get("program"): args += ["--program", b["program"]]
            if b.get("model"): args += ["--model", b["model"]]
            if b.get("max"): args += ["--max", str(b["max"])]
            r = run("hypo-gen.py", args, timeout=60)
            os.unlink(ef.name); os.unlink(ff.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500], "hypotheses": []})
        if u.path == "/api/chain":  # POST {findings:[], model?}
            ff = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            ff.write(json.dumps(b.get("findings", []))); ff.close()
            args = ["--findings-file", ff.name, "--json"]
            if b.get("model"): args += ["--model", b["model"]]
            r = run("chain-builder.py", args, timeout=60)
            os.unlink(ff.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500], "chains": []})
        if u.path == "/api/report-draft":  # POST {finding:{}, template?, model?}
            ff = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            ff.write(json.dumps(b.get("finding", {}))); ff.close()
            args = ["--finding-file", ff.name, "--json"]
            if b.get("template"): args += ["--template", b["template"]]
            if b.get("model"): args += ["--model", b["model"]]
            r = run("report-draft.py", args, timeout=90)
            os.unlink(ff.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/funnel":  # POST {action:log|stats|list, id?, target?, tool?, class?, stage?, amount?, note?}
            action = b.get("action", "stats")
            args = ["--json"]
            if action == "log":
                args += ["--log", "--stage", b.get("stage", "flagged")]
                for k, fl in [("id", "--id"), ("target", "--target"), ("tool", "--tool"),
                              ("class", "--class"), ("amount", "--amount"), ("note", "--note")]:
                    if b.get(k) is not None: args += [fl, str(b[k])]
            elif action == "list":
                args += ["--list"]
                if b.get("target"): args += ["--target", b["target"]]
            else:
                if b.get("target"): args += ["--target", b["target"]]
            r = run("funnel.py", args, timeout=20)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/mass-assign":  # POST {url, method?, id_field?, id, token?, data?, verify_get?, fields?}
            args = ["--url", b.get("url", ""), "--json"]
            if b.get("method"): args += ["--method", b["method"]]
            if b.get("id_field"): args += ["--id-field", b["id_field"]]
            if b.get("id"): args += ["--id", str(b["id"])]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("data"): args += ["--data", b["data"]]
            if b.get("verify_get"): args += ["--verify-get", b["verify_get"]]
            if b.get("fields"): args += ["--fields", b["fields"]]
            r = run("mass-assign.py", args, timeout=120)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "total": 0, "findings": []})
        if u.path == "/api/pipeline":  # POST {finding, program?, stack?, template?, model?, token?, class?, no_verify?, no_draft?, skip_evidence?}
            ftmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            ftmp.write(json.dumps(b.get("finding", {}))); ftmp.close()
            args = ["--finding-file", ftmp.name, "--json"]
            if b.get("program"): args += ["--program", b["program"]]
            if b.get("stack"): args += ["--stack", b["stack"]]
            if b.get("template"): args += ["--template", b["template"]]
            if b.get("model"): args += ["--model", b["model"]]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("class"): args += ["--class", b["class"]]
            if b.get("no_verify"): args += ["--no-verify"]
            if b.get("no_draft"): args += ["--no-draft"]
            if b.get("skip_evidence"): args += ["--skip-evidence"]
            r = run("finding-pipeline.py", args, b.get("target"), timeout=240)
            os.unlink(ftmp.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500], "verdict": "?"})
        if u.path == "/api/disclosed":  # POST {program, handle?, limit?, weakness?}
            args = ["--program", b.get("program", ""), "--json"]
            if b.get("handle"): args += ["--handle", b["handle"]]
            if b.get("limit"): args += ["--limit", str(b["limit"])]
            if b.get("weakness"): args += ["--weakness", b["weakness"]]
            r = run("disclosed-index.py", args, b.get("target"), timeout=60)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/evidence":  # POST {id, finding?, capture?, screenshot?}
            args = ["--id", b.get("id", ""), "--json"]
            if b.get("capture"): args += ["--capture", b["capture"]]
            if b.get("screenshot"): args += ["--screenshot", b["screenshot"]]
            ftmp = None
            if b.get("finding"):
                ftmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
                ftmp.write(json.dumps(b["finding"])); ftmp.close()
                args += ["--finding-file", ftmp.name]
            r = run("evidence-bundle.py", args, b.get("target"), timeout=90)
            if ftmp: os.unlink(ftmp.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/rate-gov":  # POST {action:acquire|status|set|reset, program?, acquire?, rps?, burst?}
            action = b.get("action", "status")
            args = ["--json"]
            if b.get("program"): args += ["--program", b["program"]]
            if action == "acquire":
                args += ["--acquire", str(b.get("acquire", 1))]
            elif action == "set":
                args += ["--set"]
                if b.get("rps"): args += ["--rps", str(b["rps"])]
                if b.get("burst"): args += ["--burst", str(b["burst"])]
            elif action == "reset":
                args += ["--reset"]
            else:
                args += ["--status"]
            r = run("rate-governor.py", args, timeout=15)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/proxy-ingest":  # POST {content, filename?, scope?, in_scope_only?}
            ext = ".xml" if "<items" in (b.get("content", "")[:200]) else (".har" if b.get("content", "").lstrip()[:1] == "{" else ".txt")
            tmp = tempfile.NamedTemporaryFile("w", suffix=ext, delete=False)
            tmp.write(b.get("content", "")); tmp.close()
            args = ["--file", tmp.name, "--json"]
            if b.get("scope"): args += ["--scope", b["scope"]]
            if b.get("in_scope_only"): args += ["--in-scope-only"]
            r = run("proxy-ingest.py", args, b.get("target"), timeout=60)
            os.unlink(tmp.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500], "endpoints": 0})
        if u.path == "/api/notify":  # POST {title, text, severity?, link?, url?, format?} or {set_webhook}
            if b.get("set_webhook"):
                r = run("notify.py", ["--set-webhook", b["set_webhook"], "--json"], timeout=15)
            else:
                args = ["--title", b.get("title", "HUNTR"), "--text", b.get("text", ""), "--json"]
                if b.get("severity"): args += ["--severity", b["severity"]]
                if b.get("link"): args += ["--link", b["link"]]
                if b.get("url"): args += ["--url", b["url"]]
                if b.get("format"): args += ["--format", b["format"]]
                r = run("notify.py", args, timeout=20)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/auth-session":  # POST {action:status|refresh|refresh-all|set|set-refresh, ...}
            action = b.get("action", "status")
            args = ["--json"]
            if b.get("name"): args += ["--name", b["name"]]
            if action == "status":
                args += ["--status"]
            elif action == "refresh":
                args += ["--refresh"]
            elif action == "refresh-all":
                args += ["--refresh-all"]
                if b.get("skew"): args += ["--skew", str(b["skew"])]
            elif action == "set":
                args += ["--set"]
                if b.get("authorization"): args += ["--authorization", b["authorization"]]
                if b.get("cookie"): args += ["--cookie", b["cookie"]]
                for h in (b.get("headers") or []):
                    args += ["--header", h]
            elif action == "set-refresh":
                args += ["--set-refresh", "--token-url", b.get("token_url", ""),
                         "--refresh-token", b.get("refresh_token", "")]
                if b.get("client_id"): args += ["--client-id", b["client_id"]]
                if b.get("client_secret"): args += ["--client-secret", b["client_secret"]]
            r = run("auth-session.py", args, b.get("target"), timeout=30)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500], "identities": []})
        if u.path == "/api/ws":  # POST {url, token?, origin?, message?, graphql_sub?}
            args = ["--url", b.get("url", ""), "--json"]
            if b.get("token"): args += ["--token", b["token"]]
            if b.get("origin"): args += ["--origin", b["origin"]]
            if b.get("message"): args += ["--message", b["message"]]
            if b.get("graphql_sub"): args += ["--graphql-sub", b["graphql_sub"]]
            r = run("ws-probe.py", args, timeout=60)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"error": r.get("err", "")[:500], "total": 0, "findings": []})
        if u.path == "/api/nuclei-gen":  # POST {finding, author?, id?}
            ftmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
            ftmp.write(json.dumps(b.get("finding", {}))); ftmp.close()
            args = ["--finding-file", ftmp.name, "--json"]
            if b.get("author"): args += ["--author", b["author"]]
            if b.get("id"): args += ["--id", b["id"]]
            r = run("nuclei-gen.py", args, timeout=20)
            os.unlink(ftmp.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
        if u.path == "/api/retest":  # POST {id?, finding?, match?, token?}
            args = ["--json"]
            ftmp = None
            if b.get("id"): args += ["--id", b["id"]]
            if b.get("finding"):
                ftmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
                ftmp.write(json.dumps(b["finding"])); ftmp.close()
                args += ["--finding-file", ftmp.name]
            if b.get("match"): args += ["--match", b["match"]]
            if b.get("token"): args += ["--token", b["token"]]
            r = run("retest.py", args, b.get("target"), timeout=60)
            if ftmp: os.unlink(ftmp.name)
            try:
                return self._send(json.loads(r["out"]))
            except Exception:
                return self._send({"ok": False, "error": r.get("err", "")[:500]})
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
            import base64
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
        # ── Cloud config / sync ─────────────────────────────────────────
        if u.path == "/api/cloud/config":  # POST {agent_token?, cloud_url?}
            args = []
            if b.get("agent_token"): args += ["--set-token", b["agent_token"]]
            if b.get("cloud_url"):   args += ["--set-url",   b["cloud_url"]]
            if not args:
                r = run("cloud-config.py", ["--show"])
                return self._send({"ok": True, "output": r.get("out", "")})
            for i in range(0, len(args), 2):
                run("cloud-config.py", args[i:i+2])
            return self._send({"ok": True})
        if u.path == "/api/cloud/sync":  # POST {finding_file?, finding?, funnel?, flush?}
            if b.get("flush"):
                r = run("sync.py", ["--flush"])
                try:    return self._send(json.loads(r["out"]))
                except: return self._send({"ok": True, "output": r.get("out", "")})
            if b.get("funnel"):
                ev = b["funnel"]
                args = ["--funnel-finding-id", ev.get("finding_id",""),
                        "--funnel-stage", ev.get("stage","confirmed")]
                if ev.get("amount"): args += ["--amount", str(ev["amount"])]
                if ev.get("program"): args += ["--program", ev["program"]]
                r = run("sync.py", args)
                try:    return self._send(json.loads(r["out"]))
                except: return self._send({"ok": False, "error": r.get("err","")[:300]})
            if b.get("finding"):
                ftmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
                ftmp.write(json.dumps(b["finding"])); ftmp.close()
                args = ["--finding-file", ftmp.name]
                if b.get("program"): args += ["--program", b["program"]]
                r = run("sync.py", args)
                os.unlink(ftmp.name)
                try:    return self._send(json.loads(r["out"]))
                except: return self._send({"ok": False, "error": r.get("err","")[:300]})
            return self._send({"error": "pass finding, funnel, or flush:true"}, 400)
        if u.path == "/api/cloud/status":  # POST {}
            r = run("sync.py", ["--status"])
            return self._send({"ok": True, "output": r.get("out","")})
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
