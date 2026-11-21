"""Founder email alerts: new signup, new payment, a user's first hunt.

Runs as a daemon thread inside the admin service, polling the shared Postgres —
the public API is never touched. The admin runs gunicorn -w 2, so exactly one
worker wins a Postgres advisory lock and runs the loop (each event emailed once).
Cursors live in notify_state(event,last_ts); first run seeds each to "now" so
existing rows are not back-blasted. Fully defensive — can never crash the web app.
Env: RESEND_API_KEY or SMTP_* (send), NOTIFY_EMAIL/ADMIN_EMAILS (to),
NOTIFY_POLL_SECONDS (default 60), NOTIFY_ALERTS=0 to disable.
"""
import os, time, threading, html as _html
from datetime import datetime

from sqlalchemy import text
from .db import SessionLocal, engine, User
from .notifier import send_email

try:
    from .db import CreditTxn
except Exception:   # noqa: BLE001
    CreditTxn = None
try:
    from .db import Hunt
except Exception:   # noqa: BLE001
    Hunt = None

_LOCK_KEY = 718293
_POLL = max(15, int(os.environ.get("NOTIFY_POLL_SECONDS", "60") or 60))
_started = False
_guard = threading.Lock()


def start():
    global _started
    if os.environ.get("NOTIFY_ALERTS", "1") == "0":
        print("[notify] disabled (NOTIFY_ALERTS=0)"); return
    with _guard:
        if _started:
            return
        _started = True
    threading.Thread(target=_run, name="notify-poll", daemon=True).start()
    print("[notify] poller thread started")


def _run():
    try:
        lock_conn = engine.connect()
    except Exception as e:   # noqa: BLE001
        print(f"[notify] cannot connect: {e}"); return
    try:
        got = lock_conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": _LOCK_KEY}).scalar()
        if not got:
            print("[notify] another worker owns the loop; idling out"); lock_conn.close(); return
        _ensure_state()
        print("[notify] this worker owns the alert loop")
        while True:
            try:
                _tick()
            except Exception as e:   # noqa: BLE001
                print(f"[notify] tick error: {e}")
            time.sleep(_POLL)
    finally:
        try:
            lock_conn.close()
        except Exception:   # noqa: BLE001
            pass


def _ensure_state():
    db = SessionLocal()
    try:
        db.execute(text("CREATE TABLE IF NOT EXISTS notify_state "
                        "(event TEXT PRIMARY KEY, last_ts TIMESTAMP NOT NULL)"))
        db.commit()
    finally:
        db.close()


def _cursor(db, ev):
    row = db.execute(text("SELECT last_ts FROM notify_state WHERE event=:e"), {"e": ev}).first()
    if row:
        return row[0]
    now = datetime.utcnow()
    db.execute(text("INSERT INTO notify_state(event,last_ts) VALUES(:e,:t) "
                    "ON CONFLICT (event) DO NOTHING"), {"e": ev, "t": now})
    db.commit()
    return now


def _advance(db, ev, ts):
    db.execute(text("UPDATE notify_state SET last_ts=:t WHERE event=:e"), {"t": ts, "e": ev})
    db.commit()


def _tick():
    db = SessionLocal()
    try:
        _signups(db); _payments(db); _first_hunts(db)
    finally:
        db.close()


def _signups(db):
    cur = _cursor(db, "signup")
    rows = db.query(User).filter(User.created_at > cur).order_by(User.created_at.asc()).limit(50).all()
    newest = cur
    for u in rows:
        _email("🎉 New HUNTR signup", "New signup",
               [("Email", u.email), ("Plan", u.plan or "free"), ("When", f"{u.created_at} UTC")])
        if u.created_at and u.created_at > newest:
            newest = u.created_at
    if newest > cur:
        _advance(db, "signup", newest)


def _payments(db):
    if CreditTxn is None:
        return
    cur = _cursor(db, "payment")
    try:
        rows = (db.query(CreditTxn).filter(CreditTxn.created_at > cur)
                .filter((CreditTxn.reason.like("purchase%")) | (CreditTxn.reason.like("plan%")))
                .order_by(CreditTxn.created_at.asc()).limit(50).all())
    except Exception as e:   # noqa: BLE001
        db.rollback(); print(f"[notify] payments skipped: {e}"); return
    newest = cur
    for t in rows:
        u = db.query(User).filter(User.id == t.user_id).first()
        _email("💰 HUNTR payment", "New payment",
               [("Email", u.email if u else t.user_id), ("Reason", t.reason or ""),
                ("Credits", f"+{t.delta}"), ("When", f"{t.created_at} UTC")])
        if t.created_at and t.created_at > newest:
            newest = t.created_at
    if newest > cur:
        _advance(db, "payment", newest)


def _first_hunts(db):
    if Hunt is None:
        return
    cur = _cursor(db, "first_hunt")
    try:
        rows = db.query(Hunt).filter(Hunt.created_at > cur).order_by(Hunt.created_at.asc()).limit(50).all()
    except Exception as e:   # noqa: BLE001
        db.rollback(); print(f"[notify] hunts skipped: {e}"); return
    newest = cur
    for h in rows:
        earlier = db.query(Hunt).filter(Hunt.user_id == h.user_id, Hunt.created_at < h.created_at).first()
        if earlier is None:
            u = db.query(User).filter(User.id == h.user_id).first()
            _email("🚀 First hunt by a user", "A user ran their first hunt",
                   [("Email", u.email if u else h.user_id),
                    ("Target", getattr(h, "target", "") or ""), ("When", f"{h.created_at} UTC")])
        if h.created_at and h.created_at > newest:
            newest = h.created_at
    if newest > cur:
        _advance(db, "first_hunt", newest)


def _email(subject, headline, rows):
    body = "".join(
        f'<tr><td style="padding:4px 16px 4px 0;color:#8F95A1;font:12px system-ui">{_html.escape(str(k))}</td>'
        f'<td style="padding:4px 0;color:#ECEEF2;font:13px system-ui">{_html.escape(str(v))}</td></tr>'
        for k, v in rows)
    htmlb = (
        '<div style="background:#0A0B0D;padding:28px;font-family:system-ui">'
        '<div style="max-width:440px;margin:0 auto;background:#121419;'
        'border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:4px 24px 22px">'
        '<div style="height:3px;border-radius:3px;margin:0 -24px 16px;'
        'background:linear-gradient(100deg,#A78BFA,#22D3EE 52%,#4ADE80)"></div>'
        f'<div style="font:600 16px system-ui;color:#ECEEF2;margin-bottom:12px">{_html.escape(headline)}</div>'
        f'<table style="border-collapse:collapse">{body}</table>'
        '<div style="margin-top:18px"><a href="https://admin.huntr.run" '
        'style="color:#22D3EE;font:13px system-ui;text-decoration:none">Open dashboard →</a></div>'
        '</div></div>')
    send_email(subject, htmlb)
