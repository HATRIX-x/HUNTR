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

Run:  labs.py [--port 8980]
"""
import sys, sqlite3, urllib.request
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
</ul></body></html>"""

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

if __name__ == "__main__":
    print("bench lab on 127.0.0.1:%d" % PORT, flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True)
