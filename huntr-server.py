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
import sys, os, re, json, subprocess, tempfile, threading, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Self-load the hunting-LLM config so the server's tool subprocesses (scope-parse, hunt-run, …) always
# get the CLI-mode / model settings, regardless of how the server was launched (nohup from a non-login
# shell won't source ~/.zshrc). Existing env wins; file only fills what's unset.
def _load_hunt_env():
    for p in (Path.home() / ".claude" / "tools" / "huntr-llm.env",):
        try:
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                line = line[len("export "):] if line.startswith("export ") else line
                k, _, v = line.partition("=")
                k = k.strip(); v = v.strip().strip('"').strip("'")
                v = v.replace("$HOME", str(Path.home()))
                if k and k not in os.environ:
                    os.environ[k] = v
        except Exception:
            pass
_load_hunt_env()

ROOT = Path(os.environ.get("HUNTR_HOME", str(Path.home() / ".huntr")))
TARGETS = ROOT / "targets"
REPO = Path(__file__).resolve().parent
LOCAL_TOOLS = REPO / "tools"
TOOLS = LOCAL_TOOLS if LOCAL_TOOLS.exists() else Path.home() / ".claude" / "tools"
# UI/bridge live in the repo root, NOT in tools/ — look in both so either layout works
ASSETS = [REPO, Path.home() / ".claude" / "tools", TOOLS]


def asset(name):
    for d in ASSETS:
        p = d / name
        if p.exists():
            return p
    return None
PORT = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8899
START_TS = time.time()  # process start, for /api/health uptime


def safe(t):
    s = re.sub(r"[^a-z0-9._-]+", "_", (t or "default").lower()).strip("_") or "default"
    # Bound the workspace dir name: a pasted program page (thousands of chars) as the "target" made
    # mkdir() raise "File name too long" and crashed the start request (UI then shows "server not
    # running"). Cap length and append a short hash of the full input so distinct long inputs stay unique.
    if len(s) > 80:
        import hashlib
        s = s[:72] + "_" + hashlib.sha1((t or "").encode("utf-8", "ignore")).hexdigest()[:8]
    return s


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
        if ctype.startswith("text/html"):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://127.0.0.1") or origin.startswith("http://localhost"):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(b"", 204)

    MAX_BODY = 1024 * 1024  # 1MB limit

    def _body(self):
        # A non-numeric Content-Length used to crash the handler thread with a
        # ValueError before any response; treat anything unparseable as 0.
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n < 0:
            n = 0
        if n > self.MAX_BODY:
            # Drain (bounded) what the client is still sending so we can reply
            # with a clean 413 instead of closing mid-write — an unread body
            # resets the socket, which the dashboard renders as "server down".
            remaining = min(n, self.MAX_BODY * 8)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            return {"__too_large__": True}
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}
        # Every POST handler treats the body as a JSON object (b.get(...)). A
        # JSON array/number/string/null is valid JSON but has no .get, which
        # previously crashed do_POST on the first access. Always hand back a dict.
        return d if isinstance(d, dict) else {}

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        t = q.get("target")
        if u.path == "/api/health":  # liveness + observability for the UI and uptime checks
            active = 0
            try:
                for pidf in (TARGETS.glob("*/.hunt/run.pid") if TARGETS.exists() else []):
                    try:
                        os.kill(int(pidf.read_text().strip()), 0); active += 1
                    except Exception:
                        pass
            except Exception:
                pass
            return self._send({"ok": True, "port": PORT,
                               "uptime_sec": round(time.time() - START_TS, 1),
                               "active_hunts": active})
        if u.path == "/":
            ui = asset("huntr-ui.html")
            if ui:
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
                # NOTE: huntr-bridge.js is legacy — it injected the old workbench's Send/Diff/mobile/
                # earnings panels and an HTTP|Browser toggle that target DOM the rewritten UI no longer
                # has. The new UI talks to /api/* directly, so the bridge is NOT injected. Set
                # HUNTR_BRIDGE=1 to re-enable it for the old UI.
                if os.environ.get("HUNTR_BRIDGE") == "1":
                    tag = '<script src="/huntr-bridge.js"></script>'
                    if asset("huntr-bridge.js") and tag not in html:
                        html = html.replace("</body>", tag + "\n</body>", 1) if "</body>" in html else html + tag
                return self._send(html, ctype="text/html; charset=utf-8")
            return self._send(INDEX, ctype="text/html; charset=utf-8")
        if u.path == "/huntr-bridge.js":
            bp = asset("huntr-bridge.js")
            if bp:
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
                                # Zombie guard: a run whose process died without a clean exit stays "running"
                                # forever, which locks the dashboard's Pause/Stop (they signal a dead pid) and
                                # blocks New-hunt. If the pid is dead AND the file is stale (>90s), report stalled.
                                if rec["status"] in ("running", "active"):
                                    _st = (time.time() - (r.get("updated") or 0)) > 90
                                    _alive = False
                                    try:
                                        _p = int((hd / "run.pid").read_text().strip()); os.kill(_p, 0); _alive = True
                                    except Exception:
                                        _alive = False
                                    if _st and not _alive:
                                        rec["status"] = "stalled"
                                rec["pct"] = r.get("pct", 0)
                                rec["stage"] = r.get("stage", "")
                                rec["nfind"] = len(r.get("findings", []))
                                rec["updated"] = r.get("updated", 0)
                                # return the ORIGINAL scope so UI can pass it back on resume
                                # (d.name is the safe-encoded dir key, not the raw scope)
                                raw_scope = r.get("scope") or r.get("raw_scope") or r.get("target")
                                if raw_scope and raw_scope != d.name:
                                    rec["raw_scope"] = raw_scope
                            except Exception:
                                pass
                        out.append(rec)
            return self._send({"targets": out})
        if u.path == "/api/next":
            return self._send(run("hunt-next.py", ["--stack", q.get("stack", "generic"), "--json"], t))
        if u.path == "/api/status":
            return self._send(run("hunt-status.py", [], t))
        if u.path == "/api/hunt/status":  # GET ?target=<t> — live state of a dashboard-driven hunt
            _hd = hunt_dir(q.get("target", ""))
            rf = _hd / "run.json"
            if rf.exists():
                try:
                    d = json.loads(rf.read_text())
                    # Zombie detection: a run whose process died without a clean exit leaves status stuck on
                    # "running"/"active", so the dashboard spins forever on the empty "surface still being
                    # tested" state. If run.pid is dead AND the file hasn't advanced in >90s, report "stalled"
                    # (terminal) so the UI stops waiting and offers Resume.
                    if d.get("status") in ("running", "active"):
                        _stale = (time.time() - (d.get("updated") or 0)) > 90
                        _pid_alive = False
                        try:
                            _p = int((_hd / "run.pid").read_text().strip())
                            os.kill(_p, 0); _pid_alive = True
                        except Exception:
                            _pid_alive = False
                        if _stale and not _pid_alive:
                            d["status"] = "stalled"
                            d["paused_reason"] = "process exited without finishing — click Resume to continue"
                    # slim payload: keep only what the dashboard renders (avoids 56KB+ on every 2s tick)
                    slim = {
                        "status": d.get("status"), "stage": d.get("stage"), "pct": d.get("pct"),
                        "updated": d.get("updated"), "started": d.get("started"),
                        "paused_reason": d.get("paused_reason"),
                        "findings": d.get("findings", []),
                        "leads": (d.get("leads") or [])[-30:],
                        "logs": (d.get("logs") or [])[-200:],
                        "hosts": d.get("hosts", []),
                        "endpoints": [e if isinstance(e, str) else e.get("url", "") for e in (d.get("endpoints") or [])][:200],
                        "tested": {k: v for k, v in list((d.get("tested") or {}).items())[:100]},
                        "nuclei_count": d.get("nuclei_count"), "gau_count": d.get("gau_count"),
                        "js_secrets": len(d.get("js_secrets") or []),
                    }
                    # full=1 sends everything (used by report generator)
                    if q.get("full") == "1":
                        return self._send(d)
                    return self._send(slim)
                except Exception:
                    return self._send({"status": "none"})
            return self._send({"status": "none"})
        if u.path == "/api/hunt/watch":  # GET ?target=<t> — monitor status
            wj = hunt_dir(q.get("target", "")) / "watch.json"
            pidf = hunt_dir(q.get("target", "")) / "watch.pid"
            alive = False
            try:
                alive = (os.kill(int(pidf.read_text().strip()), 0) is None)
            except Exception:
                alive = False
            try:
                d = json.loads(wj.read_text()); d["alive"] = alive
                return self._send({"ok": True, **d})
            except Exception:
                return self._send({"ok": True, "status": "off", "alive": alive})
        if u.path == "/api/hunt/zeroday":  # GET ?target=<t> — novel target-specific hypotheses
            if not q.get("target", "").strip():  # blank target used to resolve to the stale "default" dir and run the long tool
                return self._send({"ok": False, "error": "no target"}, 400)
            rf = hunt_dir(q.get("target", "")) / "run.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no hunt"}, 404)
            r = run("agent-zeroday.py", [], q.get("target", ""), stdin=json.dumps({"target": q.get("target", "")}), timeout=150)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "zeroday failed")[:200]}, 500)
        if u.path == "/api/hunt/plan":  # GET ?target=<t> — graph-driven attack plan (ranked)
            if not q.get("target", "").strip():
                return self._send({"ok": False, "error": "no target"}, 400)
            rf = hunt_dir(q.get("target", "")) / "run.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no hunt"}, 404)
            r = run("hunt-planner.py", [], q.get("target", ""), stdin=json.dumps({"target": q.get("target", "")}), timeout=150)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "planner failed")[:200]}, 500)
        if u.path == "/api/hunt/kgraph":  # GET ?target=<t>[&force=1] — cached knowledge graph (communities/god-nodes)
            if not q.get("target", "").strip():
                return self._send({"ok": False, "error": "no target"}, 400)
            rf = hunt_dir(q.get("target", "")) / "run.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no hunt"}, 404)
            args = ["--run", str(rf), "--json"] + (["--force"] if q.get("force") == "1" else [])
            r = run("hunt-graph.py", args, timeout=120)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "graph build failed")[:200]}, 500)
        if u.path == "/api/hunt/scope":  # GET ?target= — current scope.allow / scope.deny
            hd = hunt_dir(q.get("target", ""))
            def _rdscope(fn):
                p = hd / fn
                return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")] if p.exists() else []
            return self._send({"ok": True, "allow": _rdscope("scope.allow"), "deny": _rdscope("scope.deny")})
        if u.path == "/api/hunt/probe":  # GET ?target=&url=&method= — live scope-guarded request/response (Burp-style)
            url = q.get("url", "")
            if not url:
                return self._send({"ok": False, "error": "no url"}, 400)
            r = run("exec-http.py", ["--url", url, "--method", q.get("method", "GET")], q.get("target", ""), timeout=40)
            out_s = r.get("out", "") or r.get("err", "")
            m = re.search(r"\(([^)]*evidence[^)]*)\)", out_s)
            req = resp = ""
            if m:
                ed = Path(m.group(1).strip())
                try: req = (ed / "request.txt").read_text()[:4000]
                except Exception: pass
                try: resp = (ed / "response.txt").read_text()[:9000]
                except Exception: pass
            return self._send({"ok": "⛔" not in out_s, "request": req, "response": resp, "summary": out_s[:300]})
        if u.path == "/api/hunt/diff":  # GET ?target= — what changed since the saved baseline snapshot
            hd = hunt_dir(q.get("target", "")); rf = hd / "run.json"; sf = hd / "snapshot.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no hunt"}, 404)
            cur = json.loads(rf.read_text())
            cur_eps = set(e if isinstance(e, str) else e.get("url", "") for e in (cur.get("endpoints") or []))
            cur_finds = [(f.get("title", ""), f.get("endpoint", "")) for f in (cur.get("findings") or []) if f.get("verdict") != "false_positive"]
            if not sf.exists():
                return self._send({"ok": True, "baseline": False, "new_endpoints": [], "new_findings": [], "gone_endpoints": []})
            snap = json.loads(sf.read_text())
            s_eps = set(snap.get("endpoints") or [])
            s_finds = set(tuple(x) for x in (snap.get("findings") or []))
            return self._send({"ok": True, "baseline": True, "baseline_ts": snap.get("ts"),
                               "new_endpoints": sorted(cur_eps - s_eps)[:150],
                               "gone_endpoints": sorted(s_eps - cur_eps)[:60],
                               "new_findings": [{"title": tt, "endpoint": ee} for (tt, ee) in cur_finds if (tt, ee) not in s_finds]})
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
            origin = self.headers.get("Origin", "")
            if origin.startswith("http://127.0.0.1") or origin.startswith("http://localhost"):
                self.send_header("Access-Control-Allow-Origin", origin)
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
        if u.path == "/api/surface-graph":
            # Serve the graphify knowledge graph HTML for the target's recon surface.
            # Returns {available: true, url: "/surface-graph-frame?target=T"} when built,
            # {available: false} otherwise — the UI renders an iframe or a "not ready" placeholder.
            hd = hunt_dir(q.get("target", ""))
            gf = hd / "graphify-out" / "graph.html"
            return self._send({"available": gf.exists(),
                               "url": "/surface-graph-frame?target=" + q.get("target", "")
                                      if gf.exists() else None})
        if u.path == "/surface-graph-frame":
            # Serve the raw graph.html so it can be embedded in an <iframe>.
            hd = hunt_dir(q.get("target", ""))
            gf = hd / "graphify-out" / "graph.html"
            if gf.exists():
                return self._send(gf.read_text(), ctype="text/html; charset=utf-8")
            return self._send("<p style='font-family:monospace;color:#888;padding:32px'>Surface graph not built yet — starts automatically after the first crawl.</p>",
                              ctype="text/html; charset=utf-8")
        return self._send({"error": "unknown route"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        b = self._body()
        if b.get("__too_large__"):
            return self._send({"ok": False, "error": "request too large"}, 413)
        t = b.get("target")
        if u.path == "/api/scope/parse":  # POST {text} — deterministic scope extract + optional LLM enrich
            text = b.get("text") or ""
            if not text.strip():
                return self._send({"ok": False, "error": "no text"}, 400)
            # scope_ingest extracts the asset list deterministically (reliable, instant)
            # and enriches rewards/rules/etc with the LLM only when creds exist. The live
            # as-you-type preview sends {enrich:false} for an instant deterministic parse;
            # the explicit "AI enrich" button omits it (enrich on).
            _enrich = b.get("enrich", True)
            _args = ["--json"] if _enrich else ["--json", "--no-enrich"]
            r = run("scope_ingest.py", _args, stdin=text, timeout=(100 if _enrich else 15))
            try:
                parsed = json.loads((r.get("out") or "").strip().splitlines()[-1])
            except Exception:
                parsed = {"in_scope": [], "out_of_scope": [], "error": "parse failed"}
            return self._send({"ok": True, "scope": parsed})
        if u.path == "/api/hunt/start":  # POST {target, program?, mode?, scope_types?, session_token?, token2?, cookie?, ua?, stealth?, single_host?, budget_sec?, scope_deny?} — start a REAL hunt
            if not isinstance(t, str) or not t.strip():
                # Whitespace-only used to collapse via safe() to the shared
                # "default" workspace and silently start a real hunt there.
                return self._send({"ok": False, "error": "no target"}, 400)
            # If a whole program page was pasted, deterministically extract the real
            # scope here instead of handing the page text to hunt-run.py --target
            # (which whitespace-splits it into hundreds of junk "assets"). Runs
            # without the LLM so Start is fast and reliable; the structured scope is
            # persisted below as the single source of truth.
            _scope_obj = None
            if ("\n" in t) or (len(t) > 120) or (len(t.split()) > 6):
                try:
                    import importlib.util as _ilu
                    _spec = _ilu.spec_from_file_location("scope_ingest", str(TOOLS / "scope_ingest.py"))
                    _si = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_si)
                    _scope_obj = _si.ingest(t, enrich=False)
                    if _scope_obj.get("targets"):
                        t = ",".join(_scope_obj["targets"])  # clean asset list, not the page
                    else:
                        _scope_obj = None
                except Exception:
                    _scope_obj = None
            hd = hunt_dir(t)
            if _scope_obj:  # persist the canonical scope the hunt will read
                try:
                    hd.mkdir(parents=True, exist_ok=True)
                    if _scope_obj.get("allow"):
                        (hd / "scope.allow").write_text("\n".join(_scope_obj["allow"]) + "\n")
                    if _scope_obj.get("deny"):
                        (hd / "scope.deny").write_text("\n".join(_scope_obj["deny"]) + "\n")
                    (hd / "program.json").write_text(json.dumps(_scope_obj, indent=2))
                except Exception:
                    pass
            # Idempotent start: if a live hunt already owns this target, adopt it
            # instead of forking a duplicate hunt-run.py that races on the same
            # run.json/run.pid (double-click, client retry, or a second tab).
            try:
                _pid = int((hd / "run.pid").read_text().strip())
                os.kill(_pid, 0)
                return self._send({"ok": True, "target": t, "already_running": True})
            except Exception:
                pass
            # credentials go to a 0600 file (never argv — keeps tokens/cookies out of `ps`)
            st = (b.get("session_token") or "").strip()
            t2 = (b.get("token2") or "").strip()
            ck = (b.get("cookie") or "").strip()      # cookie-session auth (web apps that don't use bearer)
            # If the operator pasted a whole Netscape cookie file (curl/Firefox export), convert it to a
            # real `name=value; name=value` header. Drop analytics/tracking noise so only session cookies
            # go to the scanners. A bare header is passed through unchanged.
            if ck and ("# Netscape HTTP Cookie File" in ck or "\t" in ck):
                _NOISE = ("_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "_uetsid", "_uetvid",
                          "utm_", "snitcher_device_id", "homesubdomain", "_hjsession", "ajs_",
                          "amplitude", "mp_", "__hssc", "__hssrc", "__hstc", "hubspotutk")
                pairs = []
                for ln in ck.replace("\\t", "\t").splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    parts = ln.split("\t")
                    if len(parts) >= 7:
                        name, val = parts[5].strip(), parts[6].strip()
                    else:  # maybe already "name=value; ..." mixed in
                        continue
                    if not name or name.lower().startswith(_NOISE) or any(name.lower().startswith(n) for n in _NOISE):
                        continue
                    pairs.append(f"{name}={val}")
                if pairs:
                    ck = "; ".join(pairs)
            ua = (b.get("ua") or "").strip()          # program-required UA suffix (e.g. yeswehack)
            cf = hd / "creds.json"
            try:
                ah = (b.get("auth_header") or "").strip()   # custom auth header(s), e.g. X-FilesAPI-Auth: <tok>
                creds = {k: v for k, v in (("session_token", st), ("token2", t2), ("cookie", ck), ("auth_header", ah), ("ua", ua)) if v}
                if creds:
                    cf.write_text(json.dumps(creds))
                    try: os.chmod(cf, 0o600)
                    except Exception: pass
                elif cf.exists():
                    cf.unlink()
            except Exception:
                pass
            # out-of-scope list → scope.deny (deny wins in scope-guard, so the hunt sticks to scope)
            deny = b.get("scope_deny") or []
            if isinstance(deny, list) and deny:
                try:
                    lines = {d.strip() for d in deny if isinstance(d, str) and d.strip()
                             and "all " not in d.lower()}   # drop vague "all domains not listed" phrasing
                    if lines:
                        (hd / "scope.deny").write_text("\n".join(sorted(lines)) + "\n")
                except Exception:
                    pass
            # persist the parsed program summary (rewards/rules/focus/caps/poc/ai/out-of-scope) so the
            # sweep, triage, and report generation can honor it — and the operator can see it later.
            pm = b.get("program_meta")
            if isinstance(pm, dict) and pm:
                try: (hd / "program.json").write_text(json.dumps(pm, indent=2))
                except Exception: pass
            # program's request-rate cap (e.g. 2 req/s) → rules.json, which scope-guard throttles to
            try:
                rps = b.get("rate_rps")
                if rps and float(rps) > 0:
                    (hd / "rules.json").write_text(json.dumps({"rate_rps": float(rps)}))
            except Exception:
                pass
            # persist launch opts so a rate-limit-paused hunt can be resumed with the same settings
            try:
                budget_sec = int(b.get("budget_sec") or 86400)
            except (ValueError, TypeError):
                budget_sec = 86400
            opts = {"program": b.get("program", ""), "mode": b.get("mode", "grey"),
                    "scope_types": b.get("scope_types") or ["web", "api"],
                    "stealth": bool(b.get("stealth")), "single_host": bool(b.get("single_host")),
                    "llm_light": bool(b.get("llm_light")), "budget_sec": budget_sec}
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
            # resume of a paused/done/stopped hunt: the process exited, re-launch it with --resume
            rf = hd / "run.json"
            cur_status = ""
            try: cur_status = json.loads(rf.read_text()).get("status", "")
            except Exception: pass
            if act == "resume" and (pid is None or not _alive(pid) or cur_status in ("paused", "done", "stopped", "error")):
                try:
                    opts = json.loads((hd / "launch.json").read_text())
                except Exception:
                    opts = {"mode": "grey", "scope_types": ["web", "api"], "budget_sec": 86400}
                args = [sys.executable, str(TOOLS / "hunt-run.py"), "--target", tgt, "--resume",
                        "--program", opts.get("program", ""), "--mode", opts.get("mode", "grey"),
                        "--scope-types", ",".join(opts.get("scope_types") or ["web", "api"]),
                        "--budget-sec", str(int(opts.get("budget_sec") or 86400))]
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
        if u.path == "/api/hunt/triage":  # POST {target, fi, verdict: confirmed|false_positive} — operator manual triage
            fi = b.get("fi"); verdict = (b.get("verdict") or "").strip()
            if not t or fi is None or verdict not in ("confirmed", "false_positive", "likely"):
                return self._send({"ok": False, "error": "bad params"}, 400)
            hd = hunt_dir(t); rf = hd / "run.json"
            try:
                d = json.loads(rf.read_text())
                fi = int(fi)
                if 0 <= fi < len(d.get("findings", [])):
                    d["findings"][fi]["verdict"] = verdict
                    if verdict == "false_positive":
                        d["findings"][fi]["judge_disputed"] = True
                    tmp = rf.with_suffix(".json.tmp")
                    tmp.write_text(json.dumps(d)); tmp.replace(rf)
                    return self._send({"ok": True, "fi": fi, "verdict": verdict})
                return self._send({"ok": False, "error": "finding index out of range"}, 400)
            except Exception as e:
                return self._send({"ok": False, "error": str(e)[:200]}, 500)
        if u.path == "/api/hunt/reverify":  # POST {target, fi} — re-run the AI judge on ONE finding
            fi = b.get("fi")
            if not t or fi is None:
                return self._send({"ok": False, "error": "need target + fi"}, 400)
            hd = hunt_dir(t); rf = hd / "run.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no run.json"}, 404)
            r = run("verify-one.py", ["--run", str(rf), "--fi", int(fi), "--json"], t, timeout=180)
            try:
                res = json.loads((r.get("out") or "").strip().splitlines()[-1])
                return self._send(res)
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "verify failed")[:200]}, 500)
        if u.path == "/api/hunt/chat":  # POST {target, message, history?} — conversational assistant
            msg = (b.get("message") or "").strip()
            if not t or not msg:
                return self._send({"ok": False, "error": "need target + message"}, 400)
            hd = hunt_dir(t); rf = hd / "run.json"
            ctx = {"target": t}
            try:
                d = json.loads(rf.read_text())
                ctx = {
                    "target": d.get("target", t),
                    "status": d.get("status", ""),
                    "stage": d.get("stage", ""),
                    "findings": [{"i": i, "title": f.get("title"), "sev": f.get("sev"),
                                  "verdict": f.get("verdict"), "endpoint": f.get("endpoint"),
                                  "cls": f.get("cls"), "detail": (f.get("detail") or "")[:360]}
                                 for i, f in enumerate(d.get("findings", []))],
                }
            except Exception:
                pass
            payload = json.dumps({"context": ctx, "message": msg, "history": b.get("history", []),
                                   "session_cookie": b.get("session_cookie", "")})
            r = run("hunt-agent.py", [], t, stdin=payload, timeout=200)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "agent failed")[:200]}, 500)
        if u.path == "/api/hunt/scope":  # POST {target, allow[], deny[]} — edit scope (blast radius)
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            hd = hunt_dir(t)
            try:
                allow = [str(x).strip() for x in (b.get("allow") or []) if str(x).strip()]
                deny = [str(x).strip() for x in (b.get("deny") or []) if str(x).strip()]
                (hd / "scope.allow").write_text("# in-scope host globs\n" + "\n".join(allow) + "\n")
                (hd / "scope.deny").write_text("# out-of-scope host globs (deny wins)\n" + "\n".join(deny) + "\n")
                return self._send({"ok": True, "allow": allow, "deny": deny})
            except Exception as e:
                return self._send({"ok": False, "error": str(e)[:150]}, 500)
        if u.path == "/api/hunt/watch":  # POST {target, action:start|stop, interval?, auto_hunt?} — continuous monitoring
            action = (b.get("action") or "start").strip()
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            hd = hunt_dir(t); pidf = hd / "watch.pid"
            if action == "stop":
                try:
                    pid = int(pidf.read_text().strip()); os.kill(pid, 15); pidf.unlink(missing_ok=True)
                except Exception:
                    pass
                wj = hd / "watch.json"
                try:
                    import json as _j
                    d = _j.loads(wj.read_text()); d["status"] = "stopped"; wj.write_text(_j.dumps(d))
                except Exception:
                    pass
                return self._send({"ok": True, "status": "stopped"})
            # start
            a = ["--target", t, "--interval", str(int(b.get("interval", 3600) or 3600))]
            if b.get("auto_hunt"):
                a.append("--auto-hunt")
            try:
                env = dict(os.environ); env["HUNT_DIR"] = str(hd)
                lf = open(hd / "watch.log", "a")
                subprocess.Popen([sys.executable, str(TOOLS / "hunt-watch.py")] + a, stdout=lf, stderr=lf,
                                 env=env, start_new_session=True)
                return self._send({"ok": True, "status": "watching", "interval": int(b.get("interval", 3600) or 3600)})
            except Exception as e:
                return self._send({"ok": False, "error": str(e)[:150]}, 500)
        if u.path == "/api/hunt/snapshot":  # POST {target} — save current surface as the diff baseline
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            hd = hunt_dir(t); rf = hd / "run.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no hunt"}, 404)
            cur = json.loads(rf.read_text())
            snap = {"ts": int(time.time()),
                    "endpoints": [e if isinstance(e, str) else e.get("url", "") for e in (cur.get("endpoints") or [])],
                    "findings": [[f.get("title", ""), f.get("endpoint", "")] for f in (cur.get("findings") or []) if f.get("verdict") != "false_positive"]}
            (hd / "snapshot.json").write_text(json.dumps(snap))
            return self._send({"ok": True, "ts": snap["ts"], "endpoints": len(snap["endpoints"]), "findings": len(snap["findings"])})
        # ── specialized agents: report / exploit / authtest / chain / recon ──
        if u.path == "/api/hunt/auth":  # POST {target, creds?, signup?, login_url?} — auto-authenticate
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            r = run("agent-auth.py", [], t, stdin=json.dumps({k: v for k, v in b.items() if k != "target"} | {"target": t}), timeout=200)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "auth failed")[:200]}, 500)
        if u.path == "/api/hunt/bypass":  # POST {target, url, status, method?} — doors-not-walls bypass
            if not b.get("url"):
                return self._send({"ok": False, "error": "need url"}, 400)
            r = run("agent-bypass.py", [], t, stdin=json.dumps({k: v for k, v in b.items() if k != "target"}), timeout=180)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "bypass failed")[:200]}, 500)
        if u.path == "/api/hunt/postexploit":  # POST {target, fi} — escalate impact on a proven finding
            fi = b.get("fi")
            if not t or fi is None:
                return self._send({"ok": False, "error": "need target + fi"}, 400)
            hd = hunt_dir(t); rf = hd / "run.json"
            try:
                dd = json.loads(rf.read_text()); fnd = dd["findings"][int(fi)]
            except Exception:
                return self._send({"ok": False, "error": "bad finding"}, 400)
            r = run("agent-postexploit.py", [], t, stdin=json.dumps({"finding": fnd,
                    "session_cookie": b.get("session_cookie", "")}), timeout=240)
            try:
                res = json.loads((r.get("out") or "").strip().splitlines()[-1])
                # persist impact onto the finding
                if res.get("ok") and res.get("impact_proven"):
                    dd["findings"][int(fi)]["impact_proven"] = True
                    dd["findings"][int(fi)]["impact_level"] = res.get("impact_level", "")
                    dd["findings"][int(fi)]["impact_evidence"] = res.get("evidence", "")
                    tmp = rf.with_suffix(".json.tmp"); tmp.write_text(json.dumps(dd)); tmp.replace(rf)
                return self._send(res)
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or "postexploit failed")[:200]}, 500)
        _AGENTS = {
            "/api/hunt/report":   ("agent-report.py",   240),
            "/api/hunt/exploit":  ("agent-exploit.py",  300),
            "/api/hunt/authtest": ("agent-authtest.py", 360),
            "/api/hunt/chain":    ("agent-chain.py",    300),
            "/api/hunt/recon":    ("agent-recon.py",    300),
            "/api/hunt/scenario": ("agent-scenario.py", 300),
        }
        if u.path in _AGENTS:
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            if not (hunt_dir(t) / "run.json").exists():
                return self._send({"ok": False, "error": "no run.json for target"}, 404)
            tool, to = _AGENTS[u.path]
            agent_in = {k: v for k, v in b.items() if k != "target"}
            r = run(tool, [], t, stdin=json.dumps(agent_in), timeout=to)
            try:
                return self._send(json.loads((r.get("out") or "").strip().splitlines()[-1]))
            except Exception:
                return self._send({"ok": False, "error": (r.get("err") or (tool + " failed"))[:200]}, 500)
        if u.path == "/api/hunt/delete":  # POST {target} — delete a hunt workspace
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            hd = hunt_dir(t)
            # refuse to delete if hunt is actively running
            pidf = hd / "run.pid"
            try:
                pid = int(pidf.read_text().strip())
                try:
                    os.kill(pid, 0)  # process alive?
                    return self._send({"ok": False, "error": "hunt is running — stop it first"}, 409)
                except OSError:
                    pass  # process dead, safe to delete
            except Exception:
                pass
            import shutil
            target_dir = TARGETS / safe(t)
            if target_dir.exists():
                shutil.rmtree(target_dir)
                return self._send({"ok": True, "deleted": t})
            return self._send({"ok": False, "error": "target not found"}, 404)

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
            import base64, binascii
            ext = ".ipa" if fname.lower().endswith(".ipa") else ".apk"
            try:
                raw = base64.b64decode(data_b64, validate=True)
            except (binascii.Error, ValueError):
                # Unwrapped decode used to raise and reset the connection with no
                # response — the UI then just saw a generic failure.
                return self._send({"error": "data_b64 is not valid base64"}, 400)
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                tf.write(raw); tmp = tf.name
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

        if u.path == "/api/ai-write-report":  # POST {target, fi} — Haiku writes a polished report
            fi = b.get("fi")
            if not t or fi is None:
                return self._send({"ok": False, "error": "need target + fi"}, 400)
            hd = hunt_dir(t)
            rf = hd / "run.json"
            if not rf.exists():
                return self._send({"ok": False, "error": "no hunt data"}, 400)
            try:
                import importlib.util as _ilu2
                _spec2 = _ilu2.spec_from_file_location("llm_auth", str(TOOLS / "llm_auth.py"))
                _la = _ilu2.module_from_spec(_spec2); _spec2.loader.exec_module(_la)
                hdrs, mode = _la.llm_headers()
            except Exception as e:
                return self._send({"ok": False, "error": f"llm_auth: {e}"}, 500)
            if not hdrs:
                return self._send({"ok": False, "error": "no Claude credentials"}, 401)
            import urllib.request as _ur2
            d = json.loads(rf.read_text())
            findings = d.get("findings") or []
            if fi >= len(findings):
                return self._send({"ok": False, "error": "fi out of range"}, 400)
            f = findings[fi]
            scope = d.get("scope") or t
            program = d.get("program") or scope
            prompt = f"""You are an expert bug bounty report writer. Write a professional, submission-ready bug bounty report for HackerOne/YesWeHack/Intigriti.

Finding data:
- Title: {f.get('title','')}
- Class: {f.get('cls','')}
- Severity: {f.get('sev','')} (label: {f.get('label','')})
- CVSS: {f.get('cvss','unscored')}
- Endpoint: {f.get('endpoint','')}
- Evidence / raw detail: {(f.get('detail') or '')[:1500]}
- Existing steps: {(f.get('steps') or 'none')[:800]}
- Remediation hint: {(f.get('remediation') or 'none')[:400]}
- Program: {program}
- Scope: {scope}

Write the following sections ONLY (no preamble, no meta-commentary):

## Summary
[1-3 sentences: what is the vulnerability, where is it, what can an attacker do]

## Vulnerability Details
[Technical root cause: HTTP method, parameter, header, logic flaw, etc.]

## Steps to Reproduce
[Numbered steps with exact curl/request. Use the evidence above.]

## Impact
[Concrete business impact: what data can be accessed, what actions can be performed, what systems are affected]

## Remediation
[Developer-friendly fix with specific guidance]

Be specific, technical, and concise. Do not add any text outside these 5 sections."""
            payload = json.dumps({
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 2048,
                "messages": [{"role": "user", "content": prompt}]
            }).encode()
            hdrs2 = dict(hdrs)
            hdrs2["content-type"] = "application/json"
            try:
                req = _ur2.Request("https://api.anthropic.com/v1/messages",
                                   data=payload, headers=hdrs2, method="POST")
                with _ur2.urlopen(req, timeout=60) as resp:
                    rj = json.loads(resp.read())
                ai_text = (rj.get("content") or [{}])[0].get("text", "")
            except Exception as e:
                return self._send({"ok": False, "error": f"Claude API: {e}"}, 502)
            # parse sections from AI response
            def _sec(text, header):
                import re
                m = re.search(r'##\s+' + header + r'\s*\n(.*?)(?=\n##\s+|\Z)', text, re.S | re.I)
                return m.group(1).strip() if m else ""
            f["reco"] = _sec(ai_text, "Summary") or f.get("reco","")
            if _sec(ai_text, "Steps to Reproduce"):
                f["steps"] = _sec(ai_text, "Steps to Reproduce")
            if _sec(ai_text, "Impact"):
                f["impact_text"] = _sec(ai_text, "Impact")
            if _sec(ai_text, "Remediation"):
                f["remediation"] = _sec(ai_text, "Remediation")
            if _sec(ai_text, "Vulnerability Details"):
                f["vuln_detail"] = _sec(ai_text, "Vulnerability Details")
            f["ai_report"] = ai_text
            f["ai_report_ts"] = int(time.time())
            tmp = rf.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(d)); tmp.replace(rf)
            return self._send({"ok": True, "ai_report": ai_text, "fi": fi})

        if u.path == "/api/graphify-build":  # POST {target} — build force-directed surface graph
            if not t:
                return self._send({"ok": False, "error": "no target"}, 400)
            hd = hunt_dir(t)
            run_json = hd / "run.json"
            if not run_json.exists():
                return self._send({"ok": False, "error": "no hunt data yet"}, 400)
            out_dir = hd / "graphify-out"
            out_dir.mkdir(exist_ok=True)
            def _build_graph():
                try:
                    from urllib.parse import urlparse
                    d = json.loads(run_json.read_text())
                    endpoints = [e if isinstance(e, str) else e.get("url", "") for e in (d.get("endpoints") or [])]
                    findings = d.get("findings") or []
                    # map endpoint → finding severity
                    finding_map = {}
                    for fi, f in enumerate(findings):
                        ep = f.get("endpoint", "")
                        if ep and f.get("sev"):
                            finding_map[ep] = (f.get("sev", ""), f.get("title", ""), fi)
                    nodes, edges, seen = [], [], set()
                    node_ids = {}  # key → node id
                    counter = [0]
                    def _nid(key):
                        if key not in node_ids:
                            node_ids[key] = f"n{counter[0]}"; counter[0] += 1
                        return node_ids[key]
                    def _add_node(key, label, group, size, title=""):
                        nid = _nid(key)
                        if not any(n["id"] == nid for n in nodes):
                            nodes.append({"id": nid, "label": label, "group": group,
                                          "size": size, "title": title or label})
                        return nid
                    def _add_edge(fr, to):
                        eid = f"{fr}->{to}"
                        if eid not in seen:
                            seen.add(eid)
                            edges.append({"from": fr, "to": to})
                    for ep in endpoints[:400]:
                        if not ep: continue
                        try:
                            p = urlparse(ep)
                            host = p.netloc or ep
                            segs = [s for s in (p.path or "/").split("/") if s]
                        except Exception:
                            host = ep; segs = []
                        # host node
                        h_nid = _add_node(f"host:{host}", host, "host", 28)
                        # path-prefix cluster (first 1-2 segments)
                        if segs:
                            prefix = "/" + segs[0]
                            pfx_key = f"pfx:{host}:{prefix}"
                            p_nid = _add_node(pfx_key, prefix, "prefix", 14)
                            _add_edge(h_nid, p_nid)
                            # endpoint node under prefix
                            full_path = "/" + "/".join(segs)
                            sev, f_title, fi = finding_map.get(ep, ("", "", -1))
                            label = ("/" + "/".join(segs[1:])) if len(segs) > 1 else prefix
                            title = f"{ep}\n{'⚠ ' + f_title if f_title else ''}"
                            e_nid = _add_node(f"ep:{ep}", label[:35], sev or "endpoint", 7 if not sev else 13, title)
                            _add_edge(p_nid, e_nid)
                        else:
                            e_nid = _add_node(f"ep:{ep}", "/", "endpoint", 7, ep)
                            _add_edge(h_nid, e_nid)
                    # also add finding nodes not in endpoint list
                    for fi, f in enumerate(findings):
                        ep = f.get("endpoint", "")
                        sev = f.get("sev", "")
                        title = f.get("title", "Finding")
                        if not ep:
                            f_nid = _add_node(f"find:{fi}", title[:30], sev or "m", 13, title)
                    graph_data = json.dumps({"nodes": nodes, "edges": edges})
                    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Surface Graph — {t}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/vis-network.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/dist/vis-network.min.css">
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#0a0a0f;color:#e0e0e0;font-family:monospace;overflow:hidden}}
#graph{{width:100vw;height:100vh}}
#legend{{position:fixed;bottom:14px;left:14px;background:rgba(15,15,25,0.92);border:1px solid #222;border-radius:8px;padding:10px 14px;font-size:11px;line-height:2;z-index:9}}
#stats{{position:fixed;top:14px;right:14px;background:rgba(15,15,25,0.92);border:1px solid #222;border-radius:8px;padding:8px 12px;font-size:11px;z-index:9;color:#aaa}}
</style></head><body>
<div id="graph"></div>
<div id="legend">
  <span style="color:#4fc3f7">◆ Host</span> &nbsp;
  <span style="color:#607d8b">● Path group</span> &nbsp;
  <span style="color:#546e7a">· Endpoint</span><br>
  <span style="color:#ef5350">● Critical</span> &nbsp;
  <span style="color:#ff7043">● High</span> &nbsp;
  <span style="color:#ffa726">● Medium</span> &nbsp;
  <span style="color:#66bb6a">● Low</span>
</div>
<div id="stats" id="stats">Loading…</div>
<script>
var raw={graph_data};
var COLORS={{host:'#4fc3f7',prefix:'#607d8b',endpoint:'#546e7a',c:'#ef5350',h:'#ff7043',m:'#ffa726',l:'#66bb6a',i:'#42a5f5'}};
var SHAPES={{host:'diamond',prefix:'square',endpoint:'dot',c:'dot',h:'dot',m:'dot',l:'dot',i:'dot'}};
var nodes=new vis.DataSet(raw.nodes.map(function(n){{
  var c=COLORS[n.group]||COLORS.endpoint;
  var s=SHAPES[n.group]||'dot';
  var bold=n.group==='host';
  return Object.assign({{}},n,{{
    color:{{background:c,border:n.group==='host'?'#81d4fa':'transparent',highlight:{{background:c,border:'#fff'}},hover:{{background:c,border:'#fff'}}}},
    shape:s,
    font:{{color: bold?'#e0e0e0':'#888', size: bold?13:10, bold:bold}},
    borderWidth: n.group==='host'?2:0,
    shadow: n.group==='host'?{{enabled:true,color:'rgba(79,195,247,0.4)',size:12}}:false
  }});
}}));
var edges=new vis.DataSet(raw.edges.map(function(e){{
  return Object.assign({{}},e,{{color:{{color:'#2a2a3a',highlight:'#4fc3f7',hover:'#607d8b'}},width:1,smooth:{{type:'continuous'}}}});
}}));
var options={{
  physics:{{
    enabled:true,
    stabilization:{{enabled:true,iterations:300,fit:true}},
    barnesHut:{{
      gravitationalConstant:-12000,
      centralGravity:0.1,
      springLength:180,
      springConstant:0.03,
      damping:0.25,
      avoidOverlap:0.5
    }}
  }},
  interaction:{{hover:true,tooltipDelay:150,navigationButtons:true,keyboard:{{enabled:true}},zoomView:true}},
  nodes:{{scaling:{{min:6,max:30}}}},
  edges:{{arrows:{{to:{{enabled:false}}}}}},
  layout:{{improvedLayout:false}}
}};
var network=new vis.Network(document.getElementById('graph'),{{nodes:nodes,edges:edges}},options);
network.on('stabilizationProgress',function(p){{document.getElementById('stats').textContent='Stabilizing… '+Math.round(p.iterations/p.total*100)+'%';}});
network.on('stabilizationIterationsDone',function(){{
  network.setOptions({{physics:{{barnesHut:{{gravitationalConstant:-6000,springLength:120}}}}}});
  document.getElementById('stats').textContent='Nodes: '+raw.nodes.length+' · Edges: '+raw.edges.length;
}});
network.on('click',function(p){{
  if(p.nodes.length){{
    var n=nodes.get(p.nodes[0]);
    document.getElementById('stats').textContent=n.title||n.label;
  }}
}});
</script></body></html>"""
                    (out_dir / "graph.html").write_text(html)
                except Exception as ex:
                    (out_dir / "graph.error.txt").write_text(str(ex))
            threading.Thread(target=_build_graph, daemon=True).start()
            return self._send({"ok": True, "building": True,
                               "poll": f"/api/surface-graph?target={t}"})
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
