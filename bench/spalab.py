#!/usr/bin/env python3
"""
HUNTR SPA benchmark lab — mirrors a modern app (like Withings healthmate): the page is an SPA whose JS
fires a POST to a JSON/form API at runtime. katana (link crawling) CANNOT see that call; only a real
browser (browser-capture) can. The POST body param `id` is a planted boolean/error SQLi — so this
proves the SPA-first pipeline (spa_capture -> api_test) finds a bug the old crawler would miss.

Planted: POST /api/items  body: action=get&id=<id>  → SQLi on `id` (sqlite, boolean + error)  [sqli, critical]

Run:  spalab.py [--port 8983]
"""
import sys, sqlite3
from flask import Flask, request, Response

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

PORT = int(arg("--port", "8983") or 8983)

def make_app():
    return app

app = Flask(__name__)

# SPA shell: NO links to /api/items — the only way to discover it is to run the JS (real browser)
INDEX = """<!doctype html><html><head><title>Items SPA</title></head><body>
<div id="app">loading…</div>
<script>
// runtime API call — invisible to a link crawler, visible only to a real browser
fetch('/api/items', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'action=get&id=1'}).then(r=>r.text()).then(t=>{document.getElementById('app').textContent='loaded';});
</script></body></html>"""

def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE items(id INTEGER, name TEXT, secret TEXT)")
    c.executemany("INSERT INTO items VALUES(?,?,?)", [(1, "Alpha", "s-AAA"), (2, "Beta", "s-BBB"), (3, "Gamma", "s-CCC")])
    return c

@app.route("/")
def index():
    return INDEX

@app.route("/api/items", methods=["POST"])
def items():
    pid = request.form.get("id", "1")
    try:  # VULN sqli: user input concatenated into the query (numeric context)
        rows = _db().execute("SELECT id, name FROM items WHERE id = " + pid).fetchall()
        return {"status": 0, "items": [{"id": r[0], "name": r[1]} for r in rows]}
    except Exception as e:
        return Response('{"status":500,"error":"SQL error: ' + str(e).replace('"', "'") + '"}', status=500, mimetype="application/json")

if __name__ == "__main__":
    print("spa lab on 127.0.0.1:%d (runtime POST /api/items, SQLi on id)" % PORT, flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True)
