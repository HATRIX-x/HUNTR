#!/usr/bin/env python3
"""
HUNTR authenticated benchmark lab — a Flask API with login and GENUINELY planted ACCESS-CONTROL bugs,
the kind that live behind auth and pay the most. Ground truth is exact (we wrote the bugs). Two real
identities are issued so the exploit agent can prove CROSS-ACCOUNT access.

Identities (bearer tokens; the harness passes A + B to the agent):
  tok-alice → alice (id 1, role user)   tok-bob → bob (id 2, role user)   tok-admin → admin (id 99)

Planted bugs (see benchmark.json for machine-readable ground truth):
  GET /api/orders/<id>   IDOR/BOLA   — no ownership check → alice reads bob's order (card, total)  [idor, high]
  GET /api/admin/users   BFLA        — no role check → a normal user lists every account + secret   [bfla, high]
Discovery aids (realistic): GET /api lists routes; GET /api/me returns the caller's own id + order.

Run:  authlab.py [--port 8982]
"""
import sys
from flask import Flask, request, jsonify

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

PORT = int(arg("--port", "8982") or 8982)

USERS = {
    "tok-alice": {"id": 1, "user": "alice", "role": "user"},
    "tok-bob":   {"id": 2, "user": "bob",   "role": "user"},
    "tok-admin": {"id": 99, "user": "admin", "role": "admin"},
}
# orders keyed by id; owner is the user id. card_last4 is the sensitive field that proves the IDOR.
ORDERS = {
    1: {"id": 1, "owner": 1, "item": "Blue Widget",  "total": 42.00, "card_last4": "4242"},
    2: {"id": 2, "owner": 2, "item": "Red Gadget",   "total": 99.50, "card_last4": "7331"},
    99: {"id": 99, "owner": 99, "item": "Admin Spare", "total": 0.0,  "card_last4": "0000"},
}


def make_app():
    return app

app = Flask(__name__)


def _auth():
    h = request.headers.get("Authorization", "")
    tok = h.split(" ", 1)[1].strip() if " " in h else h.strip()
    return USERS.get(tok)


@app.route("/")
def index():
    return "<h1>Acme Orders API</h1><p>Authenticated API — see <a href='/api'>/api</a>. Log in to get a token.</p>"

@app.route("/api")
def api_index():
    return jsonify({"routes": ["/api/me", "/api/orders/{id}", "/api/admin/users"],
                    "note": "send Authorization: Bearer <token>"})

@app.route("/api/me")
def me():
    u = _auth()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    own = next((o["id"] for o in ORDERS.values() if o["owner"] == u["id"]), None)
    return jsonify({"id": u["id"], "user": u["user"], "role": u["role"], "your_order": own,
                    "hint": "your order is at /api/orders/{id}"})

@app.route("/api/orders/<int:oid>")
def get_order(oid):
    u = _auth()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    o = ORDERS.get(oid)
    if not o:
        return jsonify({"error": "not found"}), 404
    # VULN (IDOR/BOLA): returns ANY order to ANY authenticated user — no ownership check
    return jsonify(o)

@app.route("/api/admin/users")
def admin_users():
    u = _auth()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    # VULN (BFLA): no role check — any authenticated user lists every account + order secrets
    return jsonify({"users": list(USERS.values()),
                    "orders": [{"id": o["id"], "owner": o["owner"], "card_last4": o["card_last4"]} for o in ORDERS.values()]})


if __name__ == "__main__":
    print("auth lab on 127.0.0.1:%d (IDOR /api/orders, BFLA /api/admin/users)" % PORT, flush=True)
    app.run(host="127.0.0.1", port=PORT, threaded=True)
