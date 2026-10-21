#!/usr/bin/env python3
"""
HUNTR benchmark lab — ONE Flask app (localhost) with GENUINELY planted, known vulnerabilities.
Because we wrote the bugs, the ground truth is exact, so recall/precision are exact. Authorized by
construction (your own app, bound to 127.0.0.1). Flask/Werkzeug tolerates the malformed fuzzing
traffic that crashed the stdlib server, so the target stays up for the whole hunt.

Planted bugs (see bench/benchmark.json for the machine-readable ground truth):
  GET /product?id=   SQL injection (sqlite, numeric context, boolean+error+UNION)  [sqli, critical]
  GET /search?q=     Reflected XSS (unescaped reflection in HTML body)             [xss, medium]
  GET /go?url=       Open redirect (302 to attacker URL)                           [redirect, medium]
  GET /greet?name=   SSTI (Jinja2 render_template_string on user input)           [ssti, critical]
  GET /fetch?url=    Blind SSRF (server-side GET, no reflection)                   [ssrf, high]
  GET /account?uid=  IDOR (returns any user's private data, no ownership check)    [idor, high]
  GET /admin         Auth bypass (?debug=1 grants admin with no credentials)       [authz, critical]
  GET /api/data      CORS misconfig (reflects Origin + Allow-Credentials:true)     [cors, medium]
  GET /download?file= LFI / path traversal (reads arbitrary files)                 [lfi, high]

Run:  labs.py [--port 8980]
"""
import sys, sqlite3, re, urllib.request, urllib.parse
from flask import Flask, request, redirect, Response, render_template_string

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

PORT = int(arg("--port", "8980") or 8980)


def make_app():
    """Build the vulnerable Flask app (used both by the CLI and by the in-process benchmark harness)."""
    return app


app = Flask(__name__)

# in-process sqlite with a seeded table (thread-safe: one connection per request)
def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE products(id INTEGER, name TEXT, secret TEXT)")
    c.executemany("INSERT INTO products VALUES(?,?,?)",
                  [(1, "Widget", "sk_live_AAAA"), (2, "Gadget", "sk_live_BBBB"), (3, "Gizmo", "sk_live_CCCC")])
    return c

INDEX = """<!doctype html><html><head><title>Bench Lab</title></head><body>
<h1>Benchmark Lab</h1><ul>
<li><a href="/product?id=1">product?id=1</a></li>
<li><a href="/search?q=hello">search?q=hello</a></li>
<li><a href="/go?url=/product?id=1">go?url=</a></li>
<li><a href="/greet?name=guest">greet?name=guest</a></li>
<li><a href="/fetch?url=http://example.com">fetch?url=</a></li>
<li><a href="/account?uid=1">account?uid=1</a></li>
<li><a href="/admin">admin</a></li>
<li><a href="/api/data">api/data</a></li>
<li><a href="/download?file=readme.txt">download?file=</a></li>
<li><a href="/lookup?name=alice">lookup?name=</a></li>
<li><a href="/setlang?lang=en">setlang?lang=</a></li>
<li><a href="/reset?email=user@x.com">reset?email=</a></li>
<li><a href="/ping?host=127.0.0.1">ping?host=</a></li>
<li><a href="/merge">merge</a></li>
<li><a href="/profile">profile</a></li>
<li><a href="/api/user">api/user</a></li>
<li><a href="/ldapsearch?user=alice">ldapsearch?user=</a></li>
<li><a href="/xpathsearch?q=doc1">xpathsearch?q=</a></li>
<li><a href="/cvp">cvp</a></li>
<li><a href="/oauth/authorize?redirect_uri=/cb&response_type=code&client_id=lab">oauth/authorize?redirect_uri=</a></li>
<li><a href="/proxy?url=http://example.com">proxy?url=</a></li>
<li><a href="/upload">upload</a></li>
<li><a href="/deser">deser</a></li>
<li><a href="/graphql">graphql</a></li>
<li><a href="/clientpp">clientpp</a></li>
</ul></body></html>"""

# seeded users for the IDOR lab — private data that must only be visible to the owner
_USERS = {"1": {"name": "alice", "email": "alice@corp.internal", "ssn": "111-11-1111", "balance": 4200},
          "2": {"name": "bob", "email": "bob@corp.internal", "ssn": "222-22-2222", "balance": 99999},
          "3": {"name": "carol", "email": "carol@corp.internal", "ssn": "333-33-3333", "balance": 7}}

@app.route("/")
def index():
    return INDEX

@app.route("/product")
def product():
    # VULN sqli: user input concatenated into the query (numeric context, no quoting)
    pid = request.args.get("id", "1")
    try:
        rows = _db().execute("SELECT id, name FROM products WHERE id = " + pid).fetchall()
        return "<h2>Products</h2>" + "".join("<p>%s: %s</p>" % (r[0], r[1]) for r in rows)
    except Exception as e:
        # leaking the DB error is part of the vuln (error-based detection)
        return Response("SQL error: " + str(e), status=500)

@app.route("/search")
def search():
    # VULN reflected xss: raw reflection into the HTML body, no escaping
    q = request.args.get("q", "")
    return Response("<html><body><h2>Results for: " + q + "</h2></body></html>", mimetype="text/html")

@app.route("/go")
def go():
    # VULN open redirect: 302 to an attacker-controlled URL
    dest = request.args.get("url", "/")
    try:
        return redirect(dest, code=302)
    except Exception:
        # scanners inject newline/control payloads — sanitize to the first line so the lab stays up
        return redirect(dest.splitlines()[0] if dest else "/", code=302)

@app.route("/greet")
def greet():
    # VULN ssti: user input rendered as a Jinja2 template
    name = request.args.get("name", "guest")
    return render_template_string("<p>Hello " + name + "</p>")

@app.route("/fetch")
def fetch():
    # VULN blind ssrf: server-side request to a user URL; response is NOT reflected
    target = request.args.get("url", "")
    if target:
        try:
            urllib.request.urlopen(target, timeout=5).read(128)
        except Exception:
            pass
    return "<html><body>Preview generated.</body></html>"

@app.route("/account")
def account():
    # VULN idor: returns ANY user's private record by uid with no ownership/authz check
    uid = request.args.get("uid", "1")
    u = _USERS.get(str(uid))
    if not u:
        return Response("no such user", status=404)
    return Response("<h2>Account</h2><p>name: %s</p><p>email: %s</p><p>ssn: %s</p><p>balance: $%s</p>"
                    % (u["name"], u["email"], u["ssn"], u["balance"]), mimetype="text/html")

@app.route("/admin")
def admin():
    # VULN auth bypass: the admin panel is gated by a trivial, client-controlled flag
    if request.args.get("debug") == "1" or request.headers.get("X-Admin") == "true":
        return Response("<h2>Admin Panel</h2><p>ADMIN ACCESS GRANTED</p>"
                        "<p>api_master_key: sk_live_ADMINMASTER9999</p><p>users: 3</p>", mimetype="text/html")
    return Response("403 Forbidden — admin only", status=403)

@app.route("/api/data")
def api_data():
    # VULN cors: reflects the request Origin into ACAO AND allows credentials
    origin = request.headers.get("Origin", "")
    resp = Response('{"user":"alice","token":"sess_abc123","balance":4200}', mimetype="application/json")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin           # reflects attacker origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"       # + credentials → exploitable
    return resp

@app.route("/ping")
def ping():
    # VULN command injection: user input passed to a shell (our authorized lab demonstrates OAST cmdi)
    import subprocess as _sp
    host = request.args.get("host", "127.0.0.1")
    try:
        _sp.run("ping -c1 " + host, shell=True, capture_output=True, timeout=12)
    except Exception:
        pass
    return "<p>pinged</p>"

@app.route("/lookup")
def lookup():
    # VULN NoSQLi (simulated Mongo operator semantics): [$ne] returns the whole set, else one match
    raw = request.query_string.decode()
    allu = [u["name"] for u in _USERS.values()]
    if "[$ne]" in raw or "$gt" in raw:
        return "<ul>" + "".join("<li>%s</li>" % n for n in allu) + "</ul>"  # operator → all records
    name = request.args.get("name", "alice")
    return "<ul>" + "".join("<li>%s</li>" % n for n in allu if n == name) + "</ul>"

@app.route("/setlang")
def setlang():
    # VULN CRLF / header injection: user value placed into a response header unsanitised
    lang = request.args.get("lang", "en")
    resp = Response("<p>lang set</p>")
    resp.headers["Content-Language"] = lang  # werkzeug blocks \r\n in values; also reflect raw in a custom path
    try:
        # emulate a naive framework that writes the raw bytes (CRLF reaches the client)
        if "\r\n" in lang or "%0d%0a" in lang.lower():
            from urllib.parse import unquote
            for ln in unquote(lang).split("\r\n")[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1); resp.headers[k.strip()] = v.strip()
    except Exception:
        pass
    return resp

@app.route("/reset")
def reset():
    # VULN host-header injection: the reset link is built from the request Host (poisonable)
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
    email = request.args.get("email", "user@x.com")
    return Response('<p>Reset link sent to %s: https://%s/reset/confirm?token=abc</p>' % (email, host), mimetype="text/html")

@app.route("/download")
def download():
    # VULN lfi: user-controlled path read with no traversal sanitisation
    fn = request.args.get("file", "readme.txt")
    try:
        with open(fn, "r", errors="ignore") as fh:
            return Response(fh.read(4000), mimetype="text/plain")
    except Exception as e:
        return Response("cannot read: " + str(e)[:120], status=404)

# ── extended classes (prototype-pollution, WCD, mass-assignment, LDAP, XPath, CSP, OAuth,
#    SSRF→metadata, file-upload, deserialization) ──────────────────────────────────────────
import os as _os, subprocess as _subp, json as _json
_POLLUTED = {}       # simulates a shared prototype object a merge can poison
_UPLOADS = {}        # path → content, for the upload traversal lab

@app.route("/merge", methods=["GET", "POST"])
def merge():
    # VULN prototype pollution: naive recursive merge of user JSON into a shared object
    if request.method == "POST":
        try:
            body = _json.loads(request.get_data() or b"{}")
        except Exception:
            body = {}
        def _merge(dst, src):
            for k, v in (src or {}).items():
                if isinstance(v, dict):
                    _merge(dst.setdefault(k, {}), v)   # __proto__/constructor land in the shared dict
                else:
                    dst[k] = v
        _merge(_POLLUTED, body)
        return Response('{"ok":true}', mimetype="application/json")
    # a later clean GET reflects the (now polluted) shared object + honors a polluted status
    pp = _POLLUTED.get("__proto__", {}) if isinstance(_POLLUTED.get("__proto__"), dict) else {}
    st = pp.get("status", 200)
    try:
        st = int(st)
    except Exception:
        st = 200
    return Response(_json.dumps({"config": dict(pp)}), status=st, mimetype="application/json")

@app.route("/profile")
@app.route("/profile/<path:sub>")
def profile(sub=None):
    # VULN web cache deception: private page served (and marked cacheable) even on /profile/x.css
    body = '{"user":"alice","email":"alice@corp.internal","csrf_token":"a1b2c3d4e5f6g7h8","balance":4200}'
    resp = Response(body, mimetype="application/json")
    if sub and sub.lower().endswith((".css", ".js", ".png", ".jpg")):
        resp.headers["Cache-Control"] = "public, max-age=600"   # cache keys on the extension → WCD
    else:
        resp.headers["Cache-Control"] = "private, no-store"
    return resp

@app.route("/api/user", methods=["PUT", "POST", "PATCH"])
def api_user():
    # VULN mass assignment: blindly binds + echoes every field the client sends
    try:
        body = _json.loads(request.get_data() or b"{}")
    except Exception:
        body = {}
    user = {"id": 7, "name": "alice"}
    user.update(body)     # overposting: isAdmin/role/balance all bound
    return Response(_json.dumps(user), mimetype="application/json")

@app.route("/ldapsearch")
def ldapsearch():
    # VULN LDAP injection: user value is concatenated into a filter; '*' / filter-break returns all
    users = ["alice", "bob", "carol", "dave", "admin"]
    u = request.args.get("user", "alice")            # Flask decodes %2A→* , +→space
    if "*" in u or ")(" in u:                         # LDAP wildcard / filter-break → whole directory
        return "<ul>" + "".join("<li>%s</li>" % x for x in users) + "</ul>"
    return "<ul>" + "".join("<li>%s</li>" % x for x in users if x == u) + "</ul>"

@app.route("/xpathsearch")
def xpathsearch():
    # VULN XPath injection: boolean payloads control the node-set
    items = ["doc1", "doc2", "doc3", "secret-doc"]
    q = request.args.get("q", "doc1")                 # decoded value
    if "'1'='2" in q or "1=2" in q:                   # always-false → empty node-set
        return "<ul></ul>"
    if "'1'='1" in q or "1=1" in q:                   # always-true → whole node-set
        return "<ul>" + "".join("<li>%s</li>" % d for d in items) + "</ul>"
    return "<ul>" + "".join("<li>%s</li>" % d for d in items if d == q) + "</ul>"

@app.route("/cvp")
def cvp():
    # VULN weak CSP: unsafe-inline + wildcard script-src → injected script runs
    resp = Response("<html><body><h1>dashboard</h1></body></html>", mimetype="text/html")
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' *"
    return resp

@app.route("/oauth/authorize")
def oauth_authorize():
    # VULN OAuth redirect_uri not validated: the auth response is sent to any redirect_uri
    ru = request.args.get("redirect_uri", "/")
    return redirect(ru + ("&" if "?" in ru else "?") + "code=AUTHCODE123", code=302)

@app.route("/proxy")
def proxy():
    # VULN SSRF: fetches a user URL and REFLECTS the body (cloud-metadata reachable in a real VPC).
    # In the lab we can't reach 169.254.169.254, so simulate the cloud response for the metadata hosts.
    target = request.args.get("url", "")
    if "169.254.169.254" in target or "metadata.google" in target or "100.100.100.200" in target or "169.254.170.2" in target:
        return Response('{"AccessKeyId":"ASIA_LAB","instance-id":"i-0labAMI","ami-id":"ami-lab",'
                        '"iam/security-credentials":"role-lab"}', mimetype="application/json")
    if target:
        try:
            return Response(urllib.request.urlopen(target, timeout=4).read(2000), mimetype="text/plain")
        except Exception:
            pass
    return "<p>proxy ready</p>"

@app.route("/upload", methods=["POST"])
def upload():
    # VULN file-upload path traversal (zip-slip): the raw filename is joined without sanitisation
    f = request.files.get("file")
    if not f:
        return Response("no file", status=400)
    dest = _os.path.normpath(_os.path.join("/var/www/uploads", f.filename))  # ../ escapes the dir
    _UPLOADS[dest] = f.read().decode("utf-8", "ignore")
    return Response('{"stored":"%s"}' % dest, mimetype="application/json")

@app.route("/tmp/<path:fn>")
@app.route("/files/<path:fn>")
@app.route("/uploads/<path:fn>")
def served(fn):
    for pref in ("/tmp/", "/var/www/uploads/", "/"):
        if (pref + fn) in _UPLOADS:
            return Response(_UPLOADS[pref + fn], mimetype="text/plain")
    return Response("not found", status=404)

@app.route("/clientpp")
def clientpp():
    # VULN client-side prototype pollution: a naive deep-merge of location.search/hash walks __proto__
    return Response("""<!doctype html><html><head><title>cpp</title></head><body><script>
function setDeep(o,path,val){var cur=o;for(var i=0;i<path.length-1;i++){if(!(path[i] in cur))cur[path[i]]={};cur=cur[path[i]];}cur[path[path.length-1]]=val;}
var src=(location.search.slice(1)+'&'+location.hash.slice(1));
src.split('&').forEach(function(p){if(!p)return;var kv=p.split('=');var k=decodeURIComponent(kv[0]||'');var v=decodeURIComponent(kv[1]||'');
var path=k.replace(/\\]/g,'').split(/\\[|\\./).filter(Boolean);try{setDeep({},path,v);}catch(e){}});
document.body.appendChild(document.createTextNode('ok'));
</script></body></html>""", mimetype="text/html")

@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    # VULN graphql: introspection on, field-suggestion on, aliasing + array-batching unrestricted
    try:
        data = _json.loads(request.get_data() or b"{}")
    except Exception:
        data = {}
    def run_one(q):
        q = q or ""
        if "__schema" in q:
            return {"data": {"__schema": {"types": [{"name": "User"}, {"name": "Query"}, {"name": "Secret"}]}}}
        if "nosuchfield" in q or "__huntr" in q:
            return {"errors": [{"message": "Cannot query field 'x'. Did you mean 'user' or 'secret'?"}]}
        out_data = {}
        for al in re.findall(r"(\w+)\s*:\s*__typename", q):   # aliases a0:__typename ...
            out_data[al] = "Query"
        if "__typename" in q and not out_data:
            out_data["__typename"] = "Query"
        return {"data": out_data or {"__typename": "Query"}}
    if isinstance(data, list):                                 # array batching
        return Response(_json.dumps([run_one(d.get("query", "")) for d in data]), mimetype="application/json")
    return Response(_json.dumps(run_one(data.get("query", ""))), mimetype="application/json")

@app.route("/deser", methods=["POST"])
def deser():
    # VULN insecure deserialization: emulates an unsafe YAML/object loader that executes on load
    raw = request.get_data().decode("utf-8", "ignore")
    m = re.search(r"os\.system \['([^']+)'\]", raw) or re.search(r"exec\('([^']+)'\)", raw)
    if m:
        try:
            _subp.run(m.group(1), shell=True, capture_output=True, timeout=10)  # gadget fires on deserialize
        except Exception:
            pass
    return Response('{"loaded":true}', mimetype="application/json")

if __name__ == "__main__":
    print("bench lab on 127.0.0.1:%d" % PORT, flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True)
