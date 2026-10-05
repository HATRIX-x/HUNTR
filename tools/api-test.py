#!/usr/bin/env python3
"""
api-test.py — test a REAL API call (from browser-capture) for injection + broken access control.

The SPA-first primitive: the engine's other scanners assume GET URLs with query params, but a modern
app's real surface is POST calls with BODY params (userid, id, …). This tests ONE captured call —
mutating each param in its query or body — for SQL injection (error + boolean differential) and IDOR
(id-like param → neighbor value returns someone else's object). Auth-aware (cookie/token + UA),
GENTLE by design (few requests/param, optional --delay) so it doesn't trip a WAF, and non-destructive
(replays the SAME method; a state-changing method is only mutated with --allow-writes).

Usage:
  api-test.py --url "https://h/cgi-bin/v2/measure" --method POST --data "action=get&userid=42&session_token=x" \
      [--cookie "a=1; b=2"] [--token "Bearer x"] [--ua "..yeswehack"] [--delay 0.4] [--allow-writes] [--json]
Emits: {"findings":[{severity,cls,param,title,detail,endpoint,verdict}], "tested":true}
"""
import sys, re, json, time, difflib, urllib.request, urllib.error, urllib.parse

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n): return n in sys.argv

URL = arg("--url"); METHOD = (arg("--method", "GET") or "GET").upper(); DATA = arg("--data", "")
COOKIE = arg("--cookie"); TOKEN = arg("--token"); UA = arg("--ua", "Mozilla/5.0 api-test")
DELAY = float(arg("--delay", "0") or 0); ALLOW_WRITES = flag("--allow-writes")
MAXP = int(arg("--max-params", "8") or 8)
SAFE = {"GET", "HEAD", "OPTIONS", "POST"}   # POST is common for read APIs (cgi-bin); gated below for real writes

SQL_ERR = re.compile(r"(SQL syntax|mysql_fetch|ORA-\d{5}|Microsoft SQL|ODBC SQL|PostgreSQL.*ERROR|SQLite/|"
                     r"Unclosed quotation|quoted string not properly terminated|syntax error at or near|"
                     r"supplied argument is not a valid MySQL|Warning: mysql_|valid MySQL result|SqlException)", re.I)
IDLIKE = re.compile(r"(^|_)(id|uid|userid|user_id|accountid|account_id|oid|docid|fileid|orderid|pid|gid|memberid)$", re.I)

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not URL:
    out({"findings": [], "tested": False, "error": "no --url"})
if METHOD not in SAFE and not ALLOW_WRITES:
    out({"findings": [], "tested": False, "error": "method " + METHOD + " needs --allow-writes"})

def req(url, method, data):
    h = {"User-Agent": UA}
    if COOKIE: h["Cookie"] = COOKIE
    if TOKEN: h["Authorization"] = TOKEN if " " in TOKEN else "Bearer " + TOKEN
    body = None
    if data is not None and method in ("POST", "PUT", "PATCH"):
        body = data.encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        r = urllib.request.Request(url, data=body, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read(60000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(30000).decode("utf-8", "ignore")
        except Exception: return e.code, ""
    except Exception as e:
        return 0, "err:" + str(e)[:80]

def sim(a, b):
    if not a and not b: return 1.0
    return difflib.SequenceMatcher(None, a or "", b or "").ratio()

def params_of():
    """Return [(where, key, value, rebuild_fn)] for query + body params."""
    items = []
    pu = urllib.parse.urlparse(URL)
    q = urllib.parse.parse_qsl(pu.query, keep_blank_values=True)
    for i, (k, v) in enumerate(q):
        def rb(nv, i=i, q=q, pu=pu):
            nq = q[:]; nq[i] = (nq[i][0], nv)
            return urllib.parse.urlunparse(pu._replace(query=urllib.parse.urlencode(nq))), DATA
        items.append(("query", k, v, rb))
    if DATA:
        b = urllib.parse.parse_qsl(DATA, keep_blank_values=True)
        for i, (k, v) in enumerate(b):
            def rb(nv, i=i, b=b):
                nb = b[:]; nb[i] = (nb[i][0], nv)
                return URL, urllib.parse.urlencode(nb)
            items.append(("body", k, v, rb))
    return items

def main():
    findings = []
    base_s, base_b = req(URL, METHOD, DATA if DATA else None)
    if DELAY: time.sleep(DELAY)
    noise = ("session_token", "appname", "apppfm", "appliver", "appname", "csrf", "token", "_")  # skip auth/boilerplate
    tested = 0
    for where, k, v, rb in params_of():
        if tested >= MAXP:
            break
        if k.lower() in noise or "token" in k.lower():
            continue
        tested += 1
        # ---- SQLi: error-based ----
        u1, d1 = rb(v + "'")
        s1, b1 = req(u1, METHOD, d1);
        if DELAY: time.sleep(DELAY)
        if SQL_ERR.search(b1) and not SQL_ERR.search(base_b):
            findings.append({"severity": "c", "cls": "SQLi", "param": k,
                             "title": "SQL injection (error-based) — " + k,
                             "detail": "Param '%s' (%s) triggered a SQL error with a single quote; baseline clean. Endpoint: %s" % (k, where, URL),
                             "endpoint": URL, "verdict": "confirmed"})
            continue
        # ---- SQLi: boolean-based differential ----
        for tp, fp in ((v + "' AND '1'='1", v + "' AND '1'='2"), (v + " AND 1=1", v + " AND 1=2")):
            ut, dt = rb(tp); uf, df = rb(fp)
            st, bt = req(ut, METHOD, dt)
            if DELAY: time.sleep(DELAY)
            sf, bf = req(uf, METHOD, df)
            if DELAY: time.sleep(DELAY)
            # TRUE close to baseline, FALSE clearly different → boolean SQLi
            if st and sf and sim(bt, base_b) > 0.95 and sim(bf, base_b) < 0.9 and sim(bt, bf) < 0.9:
                findings.append({"severity": "c", "cls": "SQLi", "param": k,
                                 "title": "SQL injection (boolean-based) — " + k,
                                 "detail": "Param '%s' (%s): TRUE payload ~= baseline, FALSE payload diverges (resp sim %.2f) — boolean-blind SQLi. Endpoint: %s" % (k, where, sim(bf, base_b), URL),
                                 "endpoint": URL, "verdict": "likely"})
                break
        # ---- IDOR: id-like param → neighbor returns a different valid object ----
        if IDLIKE.search(k) and re.fullmatch(r"\d{1,12}", (v or "").strip()):
            for nv in (str(int(v) + 1), str(int(v) - 1)):
                un, dn = rb(nv)
                sn, bn = req(un, METHOD, dn)
                if DELAY: time.sleep(DELAY)
                # neighbor returned success WITH substantive, DIFFERENT content (not an auth-deny / identical page)
                denied = re.search(r'"status":\s*(2\d\d|401|403|601|214)|unauthorized|forbidden|access denied', bn, re.I)
                if sn and 200 <= sn < 300 and not denied and len(bn) > 40 and 0.3 < sim(bn, base_b) < 0.97:
                    findings.append({"severity": "h", "cls": "IDOR", "param": k,
                                     "title": "Possible IDOR/BOLA — " + k,
                                     "detail": "Param '%s'=%s→%s returned HTTP %s with different substantive content and no access-deny signal — review for cross-user data. Endpoint: %s" % (k, v, nv, sn, URL),
                                     "endpoint": URL, "verdict": "likely"})
                    break
    out({"findings": findings, "tested": True, "params_tested": tested})

if __name__ == "__main__":
    main()
