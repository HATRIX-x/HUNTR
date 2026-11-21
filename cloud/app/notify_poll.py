"""Founder email alerts: new signup, new payment, a user's first hunt.

Runs as a daemon thread inside the admin service, polling the shared Postgres —
the public API is never touched. The admin runs gunicorn -w 2, so exactly one
worker wins a Postgres advisory lock and runs the loop (each event emailed once).
Cursors live in notify_state(event,last_ts); first run seeds each to "now" so
existing rows are not back-blasted. Fully defensive — can never crash the web app.

Per-event emails are defined in _TPL below — edit the emoji / accent / copy there
to customize each event's look, or tweak _render() for the shared card layout.
Env: RESEND_API_KEY or SMTP_* (send), NOTIFY_EMAIL/ADMIN_EMAILS (to),
NOTIFY_POLL_SECONDS (default 60), NOTIFY_ALERTS=0 to disable.
"""
import os, time, threading, html as _html
from datetime import datetime

from sqlalchemy import func, text
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

# ── per-event templates (edit me to customize each email) ─────────────────────
_TPL = {
    "signup": {
        "subject": "🎉 HUNTR · New signup",
        "emoji": "🎉", "title": "New signup", "accent": "#A78BFA",
        "grad": "linear-gradient(100deg,#A78BFA,#22D3EE)",
        "lead": "Someone just created a HUNTR account.",
    },
    "payment": {
        "subject": "💰 HUNTR · New payment",
        "emoji": "💰", "title": "You just got paid", "accent": "#4ADE80",
        "grad": "linear-gradient(100deg,#4ADE80,#86EFAC)",
        "lead": "A user just put money on the table. Nice.",
    },
    "first_hunt": {
        "subject": "🚀 HUNTR · First hunt",
        "emoji": "🚀", "title": "First hunt", "accent": "#22D3EE",
        "grad": "linear-gradient(100deg,#22D3EE,#4ADE80)",
        "lead": "A user ran their first hunt — activation milestone.",
    },
}


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
        total = db.query(func.count(User.id)).scalar() or 0
        _send("signup",
              hero=u.email,
              rows=[("Plan", u.plan or "free"),
                    ("Total users now", f"{total}"),
                    ("Signed up", f"{u.created_at} UTC")])
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
        _send("payment",
              hero=(u.email if u else t.user_id),
              rows=[("What", t.reason or ""),
                    ("Credits added", f"+{t.delta}"),
                    ("When", f"{t.created_at} UTC")])
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
            _send("first_hunt",
                  hero=(u.email if u else h.user_id),
                  rows=[("Target", getattr(h, "target", "") or "—"),
                        ("Mode", getattr(h, "mode", "") or "—"),
                        ("When", f"{h.created_at} UTC")])
        if h.created_at and h.created_at > newest:
            newest = h.created_at
    if newest > cur:
        _advance(db, "first_hunt", newest)


# ── rendering ─────────────────────────────────────────────────────────────────
def _send(kind, hero, rows):
    t = _TPL[kind]
    send_email(t["subject"], _render(t, hero, rows))


def _render(t, hero, rows):
    body = "".join(
        f'<tr><td style="padding:5px 18px 5px 0;color:#8F95A1;font:12px system-ui;white-space:nowrap">{_html.escape(str(k))}</td>'
        f'<td style="padding:5px 0;color:#ECEEF2;font:600 13px ui-monospace,Menlo,monospace">{_html.escape(str(v))}</td></tr>'
        for k, v in rows)
    return (
        f'<div style="background:#0A0B0D;padding:30px 16px;font-family:system-ui,-apple-system,sans-serif">'
        f'<div style="max-width:460px;margin:0 auto;background:#121419;'
        f'border:1px solid rgba(255,255,255,.1);border-radius:16px;overflow:hidden">'
        f'<div style="height:4px;background:{t["grad"]}"></div>'
        f'<div style="padding:22px 26px 24px">'
        f'<div style="font-size:30px;line-height:1">{t["emoji"]}</div>'
        f'<div style="font:700 19px system-ui;color:#ECEEF2;margin:12px 0 4px">{_html.escape(t["title"])}</div>'
        f'<div style="font:14px/1.5 system-ui;color:#9AA0AD;margin-bottom:6px">{_html.escape(t["lead"])}</div>'
        f'<div style="font:700 17px ui-monospace,Menlo,monospace;color:{t["accent"]};'
        f'margin:14px 0 16px;word-break:break-all">{_html.escape(str(hero))}</div>'
        f'<table style="border-collapse:collapse;width:100%">{body}</table>'
        f'<a href="https://admin.huntr.run" style="display:inline-block;margin-top:22px;'
        f'padding:10px 18px;border-radius:9px;background:{t["accent"]};color:#07131A;'
        f'font:700 13px system-ui;text-decoration:none">Open dashboard →</a>'
        f'</div></div>'
        f'<div style="max-width:460px;margin:12px auto 0;text-align:center;'
        f'font:11px system-ui;color:#6F7684">HUNTR · automated founder alert</div>'
        f'</div>')
