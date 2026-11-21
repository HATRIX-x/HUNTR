"""HUNTR Admin — a STANDALONE app, deployed as its own Railway service on its own subdomain
(e.g. admin.huntr.run), NOT mounted in the public API (api.huntr.run).

Why a separate service: the admin endpoints never exist in the public API process, so no routing or
auth bug there can reach them. This app is read-only against the shared Postgres and has its own
self-contained login — because localStorage is per-origin, the admin subdomain can't read the main
site's session token, so it authenticates you directly against the shared users table (your existing
password + TOTP + lockout, reused from app.auth).

Run (Railway service, Root Directory = cloud):
    gunicorn app.admin_app:app -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:$PORT
Env: DATABASE_URL (same Postgres as the API), SECRET_KEY (a DISTINCT value — isolates admin tokens
from API tokens), ADMIN_EMAILS (comma-separated allowlist; FAIL-CLOSED — unset ⇒ nobody is admin).
"""
import os
import json
import secrets
from collections import Counter
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .db import get_db, User, Agent, Finding, Subscription
# Hunt / CreditTxn are part of the cloud app's hunts+credits feature, which may not be committed on
# every branch this service can build. Import them defensively so the dashboard deploys regardless;
# any section whose model (or DB table) is absent degrades to zeros instead of crashing the service.
try:
    from .db import Hunt
except Exception:   # noqa: BLE001
    Hunt = None
try:
    from .db import CreditTxn
except Exception:   # noqa: BLE001
    CreditTxn = None
from .auth import (
    verify_password, create_session_token, decode_session_token,
    verify_totp, is_locked, record_failure, record_success, consume_backup_code,
)

app = FastAPI(title="HUNTR Admin", docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def _boot_notifier():
    """Start the founder-alert poller (one worker wins the advisory lock)."""
    try:
        from .notify_poll import start
        start()
    except Exception as e:   # noqa: BLE001
        print(f"[notify] start failed: {e}")
# NO CORS middleware on purpose: the page and its data endpoint are same-origin (admin.huntr.run),
# so nothing else is allowed to script this app in a logged-in admin's browser.

_SUB_MRR = {"founder": 29.0, "monthly": 49.0, "yearly": 490.0 / 12.0,
            "pro": 49.0, "hunter": 49.0, "apex": 99.0, "team": 99.0}

# A real bcrypt hash of a random string, spent on unknown/non-admin logins so the response time
# doesn't reveal whether an email exists (and is an admin). Computed once at import.
from .auth import hash_password as _hp  # noqa: E402
_DUMMY_HASH = _hp(secrets.token_hex(16))


@app.middleware("http")
async def _security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return resp


def _admin_emails() -> set[str]:
    return {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}


def _bearer(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "auth required")
    return authorization.removeprefix("Bearer ").strip()


def admin_user(token: str = Depends(_bearer), db: Session = Depends(get_db)) -> User:
    decoded = decode_session_token(token)
    if not decoded:
        raise HTTPException(401, "invalid session")
    uid, tv = decoded
    user = db.query(User).filter(User.id == uid).first()
    if not user or int(user.token_version or 0) != tv:
        raise HTTPException(401, "invalid session")
    allow = _admin_emails()
    if not allow or (user.email or "").lower() not in allow:
        raise HTTPException(404, "not found")  # opaque: don't confirm the dashboard exists
    return user


# ── login (self-contained; reuses the main app's password + TOTP + lockout) ──────────────────────
class LoginIn(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)
    code: str | None = Field(default=None, max_length=16)   # TOTP or backup code


@app.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    allow = _admin_emails()
    generic = HTTPException(401, "invalid credentials")
    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    # Only admins can ever authenticate here — a non-admin email is treated exactly like a wrong one.
    if not user or not allow or (user.email or "").lower() not in allow:
        # Still spend a hash to avoid a trivial user-enumeration timing gap.
        verify_password(body.password, _DUMMY_HASH)
        raise generic
    if is_locked(user):
        raise HTTPException(429, "too many attempts — try again later")
    if not verify_password(body.password, user.password_hash):
        record_failure(user); db.commit()
        raise generic
    if user.totp_enabled:
        code = (body.code or "").strip()
        if not code:
            raise HTTPException(401, "2fa code required")
        step = verify_totp(user.totp_secret or "", code, user.totp_last_step)
        if step is not None:
            user.totp_last_step = step
        else:
            ok, new_backup = consume_backup_code(code, user.backup_codes)
            if ok:
                user.backup_codes = new_backup
            else:
                record_failure(user); db.commit()
                raise generic
    record_success(user)
    db.commit()
    return {"token": create_session_token(user.id, int(user.token_version or 0))}


@app.get("/health", include_in_schema=False)
def health():
    return JSONResponse({"ok": True})


@app.get("/notify/status", include_in_schema=False)
def notify_status(_: User = Depends(admin_user)):
    try:
        from .notify_poll import status
        return JSONResponse(status())
    except Exception as e:   # noqa: BLE001
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/notify/test", include_in_schema=False)
def notify_test(_: User = Depends(admin_user)):
    try:
        from .notify_poll import send_test
        return JSONResponse({"sent": bool(send_test())})
    except Exception as e:   # noqa: BLE001
        return JSONResponse({"sent": False, "error": str(e)}, status_code=500)


# ── metrics (read-only aggregates) ───────────────────────────────────────────────────────────────
def _since(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days)


def _daily_series(rows, days: int = 30) -> list[dict]:
    cutoff = _since(days).date()
    buckets = Counter()
    for ts in rows:
        if ts is None:
            continue
        d = ts.date()
        if d >= cutoff:
            buckets[d] += 1
    out = []
    for i in range(days, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).date()
        out.append({"date": d.isoformat(), "count": int(buckets.get(d, 0))})
    return out


@app.get("/metrics.json")
def metrics(db: Session = Depends(get_db), _: User = Depends(admin_user)):
    now = datetime.utcnow()

    def q(fn, default):
        """Run one query; on any failure (model imported as None, or a table/column missing on this
        DB) roll the session back so it stays usable and return `default`. Keeps one absent feature
        from 500-ing the whole dashboard."""
        try:
            return fn()
        except Exception:   # noqa: BLE001
            try:
                db.rollback()
            except Exception:   # noqa: BLE001
                pass
            return default

    total_users = q(lambda: db.query(func.count(User.id)).scalar() or 0, 0)
    new_24h = q(lambda: db.query(func.count(User.id)).filter(User.created_at >= _since(1)).scalar() or 0, 0)
    new_7d = q(lambda: db.query(func.count(User.id)).filter(User.created_at >= _since(7)).scalar() or 0, 0)
    new_30d = q(lambda: db.query(func.count(User.id)).filter(User.created_at >= _since(30)).scalar() or 0, 0)
    signup_dates = q(lambda: [r[0] for r in db.query(User.created_at).filter(User.created_at >= _since(30)).all()], [])
    plans = q(lambda: {(p or "free"): int(c) for p, c in
                       db.query(User.plan, func.count(User.id)).group_by(User.plan).all()}, {})

    onboarded = q(lambda: db.query(func.count(User.id)).filter(User.onboarded == True).scalar() or 0, 0)  # noqa: E712
    installed_cli = q(lambda: db.query(func.count(func.distinct(Agent.user_id))).scalar() or 0, 0)
    ran_hunt = q(lambda: db.query(func.count(func.distinct(Hunt.user_id))).scalar() or 0, 0)
    got_finding = q(lambda: db.query(func.count(func.distinct(Finding.user_id))).scalar() or 0, 0)
    paying_users = q(lambda: db.query(func.count(func.distinct(CreditTxn.user_id)))
                     .filter((CreditTxn.reason.like("purchase%")) | (CreditTxn.reason.like("plan%"))).scalar() or 0, 0)

    def _sum_delta(*like):
        def _run():
            cond = None
            for lk in like:
                cond = CreditTxn.reason.like(lk) if cond is None else (cond | CreditTxn.reason.like(lk))
            return int(db.query(func.coalesce(func.sum(CreditTxn.delta), 0)).filter(cond).scalar() or 0)
        return q(_run, 0)

    credits_purchased = _sum_delta("purchase%", "plan%")
    credits_bonus = _sum_delta("bonus%", "grant%")
    credits_consumed = q(lambda: abs(int(db.query(func.coalesce(func.sum(CreditTxn.delta), 0))
                                         .filter(CreditTxn.delta < 0).scalar() or 0)), 0)
    credits_outstanding = q(lambda: int(db.query(func.coalesce(func.sum(User.credits), 0)).scalar() or 0), 0)

    subs_by_tier = q(lambda: {(t or "?"): int(c) for t, c in
                              db.query(Subscription.tier, func.count(Subscription.user_id))
                              .filter(Subscription.status == "active").group_by(Subscription.tier).all()}, {})
    est_mrr = round(sum(_SUB_MRR.get((t or "").lower(), 0.0) * c for t, c in subs_by_tier.items()), 2)

    total_hunts = q(lambda: db.query(func.count(Hunt.id)).scalar() or 0, 0)
    hunts_by_status = q(lambda: {(s or "?"): int(c) for s, c in
                                 db.query(Hunt.status, func.count(Hunt.id)).group_by(Hunt.status).all()}, {})
    hunts_running = int(hunts_by_status.get("running", 0) + hunts_by_status.get("queued", 0))
    hunts_24h = q(lambda: db.query(func.count(Hunt.id)).filter(Hunt.created_at >= _since(1)).scalar() or 0, 0)
    hunts_7d = q(lambda: db.query(func.count(Hunt.id)).filter(Hunt.created_at >= _since(7)).scalar() or 0, 0)
    hunts_30d = q(lambda: db.query(func.count(Hunt.id)).filter(Hunt.created_at >= _since(30)).scalar() or 0, 0)
    avg_findings = q(lambda: round(float(db.query(func.coalesce(func.avg(Hunt.findings), 0)).scalar() or 0), 2), 0)
    hunt_dates = q(lambda: [r[0] for r in db.query(Hunt.created_at).filter(Hunt.created_at >= _since(30)).all()], [])

    total_findings = q(lambda: db.query(func.count(Finding.id)).scalar() or 0, 0)
    findings_by_severity = q(lambda: {(s or "?"): int(c) for s, c in
                                      db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()}, {})
    findings_by_status = q(lambda: {(s or "?"): int(c) for s, c in
                                    db.query(Finding.status, func.count(Finding.id)).group_by(Finding.status).all()}, {})
    bounty_total = q(lambda: round(float(db.query(func.coalesce(func.sum(Finding.amount), 0)).scalar() or 0), 2), 0)

    active_agents_7d = q(lambda: db.query(func.count(Agent.id)).filter(Agent.last_seen >= _since(7)).scalar() or 0, 0)
    wau = q(lambda: db.query(func.count(func.distinct(Hunt.user_id))).filter(Hunt.created_at >= _since(7)).scalar() or 0, 0)
    mau = q(lambda: db.query(func.count(func.distinct(Hunt.user_id))).filter(Hunt.created_at >= _since(30)).scalar() or 0, 0)

    referrals = Counter()
    for (prof,) in q(lambda: db.query(User.profile).filter(User.profile.isnot(None)).all(), []):
        try:
            src = (json.loads(prof) or {}).get("referral")
        except Exception:
            src = None
        referrals[(src or "unknown").strip()[:40] or "unknown"] += 1

    return {
        "generated_at": now.isoformat() + "Z",
        "signups": {"total": total_users, "new_24h": new_24h, "new_7d": new_7d, "new_30d": new_30d,
                    "series_30d": _daily_series(signup_dates, 30), "by_plan": plans},
        "activation": {"signups": total_users, "onboarded": onboarded, "installed_cli": installed_cli,
                       "ran_hunt": ran_hunt, "got_finding": got_finding, "paid": paying_users},
        "revenue": {"paying_users": paying_users, "est_revenue_usd": credits_purchased,
                    "est_mrr_usd": est_mrr, "subs_by_tier": subs_by_tier,
                    "credits_purchased": credits_purchased, "credits_bonus": credits_bonus,
                    "credits_consumed": credits_consumed, "credits_outstanding": credits_outstanding},
        "hunts": {"total": total_hunts, "running_now": hunts_running, "last_24h": hunts_24h,
                  "last_7d": hunts_7d, "last_30d": hunts_30d, "avg_findings": avg_findings,
                  "by_status": hunts_by_status, "series_30d": _daily_series(hunt_dates, 30)},
        "findings": {"total": total_findings, "by_severity": findings_by_severity,
                     "by_status": findings_by_status, "bounty_total_usd": bounty_total},
        "engagement": {"active_agents_7d": active_agents_7d, "wau": wau, "mau": mau},
        "acquisition": {"referrals": dict(referrals.most_common(12))},
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def page():
    return HTMLResponse(_PAGE)


_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HUNTR · Admin</title>
<style>
  :root{
    --bg:#0A0B0D; --fg:#ECEEF2; --mut:#9AA0AD; --faint:#6F7684;
    --line:rgba(255,255,255,.08); --line2:rgba(255,255,255,.15);
    --brand:#A78BFA; --brand3:#DDD6FE; --cyan:#22D3EE; --green:#4ADE80; --green2:#86EFAC;
    --bad:#FF5D6C; --warn:#E7B84B;
    --glass:rgba(20,23,31,.55); --glass-top:rgba(255,255,255,.055);
    --blur:blur(20px) saturate(140%);
    --grad:linear-gradient(100deg,#A78BFA,#22D3EE 52%,#4ADE80);
    --mono:ui-monospace,"SF Mono",SFMono-Regular,"JetBrains Mono","Fira Code",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,ui-sans-serif,system-ui,sans-serif;
    --s1:8px; --s2:12px; --s3:16px; --s4:22px; --s5:32px;
    --r:14px; --rs:10px;
  }
  *{box-sizing:border-box} html,body{margin:0}
  body{background:#0A0B0D;color:var(--fg);font:14px/1.5 var(--sans);
    -webkit-font-smoothing:antialiased;position:relative;min-height:100vh}
  body::before{content:"";position:fixed;inset:-30%;z-index:-1;pointer-events:none;
    background:
      radial-gradient(420px 420px at 12% 12%, rgba(167,139,250,.34), transparent 60%),
      radial-gradient(480px 480px at 88% 6%, rgba(34,211,238,.26), transparent 60%),
      radial-gradient(520px 520px at 70% 96%, rgba(74,222,128,.20), transparent 62%);
    filter:blur(14px);animation:drift 28s ease-in-out infinite alternate}
  @keyframes drift{from{transform:translate3d(-1.5%,-1%,0) scale(1)}to{transform:translate3d(1.5%,1.5%,0) scale(1.06)}}
  @media (prefers-reduced-motion:reduce){body::before{animation:none}}
  .wrap{max-width:1180px;margin:0 auto;padding:var(--s4) var(--s3) 72px}

  /* header */
  .top{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap;
    padding:12px 16px;border-radius:var(--r);background:var(--glass);
    backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
    border:1px solid var(--line);box-shadow:inset 0 1px 0 var(--glass-top),0 20px 50px -34px #000}
  .brand{font-weight:680;font-size:16px;letter-spacing:-.01em;display:flex;align-items:center;gap:9px}
  .brand .dot{width:9px;height:9px;border-radius:99px;background:var(--grad);
    box-shadow:0 0 0 3px rgba(34,211,238,.15)}
  .brand .hl{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}
  .asof{color:var(--faint);font:11.5px/1 var(--mono);letter-spacing:.02em}
  .sp{flex:1}
  .btn{background:rgba(255,255,255,.04);color:var(--fg);border:1px solid var(--line2);
    border-radius:var(--rs);padding:8px 13px;font:12.5px/1 var(--sans);cursor:pointer;
    backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);transition:.18s border-color,.18s background}
  .btn:hover{border-color:var(--cyan);background:rgba(34,211,238,.09)}
  .btn:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}

  /* section label */
  .sec{display:flex;align-items:center;gap:10px;margin:var(--s5) 2px var(--s2)}
  .sec h2{margin:0;font:600 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--mut)}
  .sec .rule{flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}

  /* grids */
  .kpis{display:grid;gap:var(--s2);grid-template-columns:repeat(4,1fr)}
  .cols{display:grid;gap:var(--s2);grid-template-columns:repeat(4,1fr)}
  @media(max-width:900px){.kpis,.cols{grid-template-columns:repeat(2,1fr)}}
  @media(max-width:560px){.kpis,.cols{grid-template-columns:1fr}}

  /* glass panel base */
  .glass{position:relative;background:var(--glass);border:1px solid var(--line);
    border-radius:var(--r);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
    box-shadow:inset 0 1px 0 var(--glass-top),0 22px 55px -36px #000;overflow:hidden}
  .glass::before{content:"";position:absolute;left:0;right:0;top:0;height:2px;
    background:var(--accent,var(--grad));opacity:.9}

  /* KPI tile */
  .tile{padding:14px 15px 15px}
  .tile .lab{font:600 10.5px/1 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--mut);
    display:flex;align-items:center;justify-content:space-between;gap:8px}
  .tile .num{font:600 29px/1.05 var(--mono);letter-spacing:-.01em;margin-top:11px;
    font-variant-numeric:tabular-nums}
  .tile .sub{font:11.5px/1.3 var(--sans);color:var(--faint);margin-top:8px}
  .chip{font:600 10.5px/1 var(--mono);padding:4px 7px;border-radius:99px;white-space:nowrap}
  .chip.up{color:var(--green);background:rgba(74,222,128,.12)}
  .chip.flat{color:var(--mut);background:rgba(255,255,255,.05)}
  .tile.accent-g::before{background:linear-gradient(90deg,var(--green),var(--green2))}
  .tile.accent-c::before{background:linear-gradient(90deg,var(--cyan),#67E8F9)}

  /* chart panel */
  .chart{padding:13px 15px 8px}
  .chart .ch{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin-bottom:2px}
  .chart .ct{font:600 11px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--mut)}
  .chart .cv{font:600 13px/1 var(--mono);color:var(--fg);font-variant-numeric:tabular-nums}
  .chart .cv small{color:var(--faint);font-weight:500}
  .chart svg{width:100%;height:auto;display:block}

  /* funnel */
  .funnel{padding:16px 18px}
  .funnel .row{display:grid;grid-template-columns:132px 1fr 112px;align-items:center;gap:14px;padding:7px 0}
  .funnel .row+.row{border-top:1px solid var(--line)}
  .funnel .lab{font:12.5px/1 var(--sans);color:var(--fg)}
  .funnel .track{height:9px;border-radius:99px;background:rgba(255,255,255,.06);overflow:hidden}
  .funnel .track>i{display:block;height:100%;border-radius:99px;background:var(--grad);
    box-shadow:0 0 14px -2px rgba(34,211,238,.4)}
  .funnel .meta{text-align:right;font:var(--mono);font-variant-numeric:tabular-nums;white-space:nowrap}
  .funnel .meta b{font-weight:600;font-size:13px}
  .funnel .meta span{color:var(--faint);font-size:11.5px;margin-left:6px}

  /* breakdown tables */
  .bd{padding:14px 15px}
  .bd .bt{font:600 10.5px/1 var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--mut);margin-bottom:10px}
  .bd table{width:100%;border-collapse:collapse}
  .bd td{padding:6px 0;font-size:12.5px;vertical-align:middle}
  .bd td.k{color:var(--fg);white-space:nowrap;padding-right:10px;text-transform:capitalize}
  .bd td.b{width:52%}
  .bd td.v{text-align:right;font:var(--mono);font-variant-numeric:tabular-nums;color:var(--fg);width:40px}
  .bd .mini{height:6px;border-radius:99px;background:rgba(255,255,255,.06);overflow:hidden}
  .bd .mini>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--brand),var(--cyan))}
  .bd .empty{color:var(--faint);font-size:12.5px;padding:8px 0}

  .note{color:var(--faint);font-size:11px;margin-top:14px;text-align:center}
  .muted{color:var(--mut)} .err{color:var(--bad);min-height:18px;font-size:13px}

  /* login */
  .login{max-width:360px;margin:14vh auto 0;padding:0 16px}
  .login .glass{padding:26px}
  .login .glass::before{opacity:1}
  .login .brand{font-size:18px;margin-bottom:3px}
  .login .hint{color:var(--mut);font-size:12.5px;margin-bottom:12px}
  .login input{width:100%;margin:7px 0;padding:12px;border-radius:var(--rs);border:1px solid var(--line2);
    background:rgba(10,11,13,.5);color:var(--fg);font:14px var(--sans);
    backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
  .login input::placeholder{color:var(--faint)}
  .login input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px rgba(34,211,238,.18)}
  .login button{width:100%;margin-top:11px;padding:12px;border-radius:var(--rs);border:0;cursor:pointer;
    background:var(--grad);color:#07131A;font:680 14px var(--sans)}
  .login button:hover{filter:brightness(1.08)}
</style></head>
<body>

<div id="login" class="login" style="display:none">
  <div class="glass">
    <div class="brand"><span class="dot"></span><span class="hl">HUNTR</span>&nbsp;<span class="muted">Admin</span></div>
    <div class="hint">Founder access only.</div>
    <input id="li_email" type="email" placeholder="email" autocomplete="username">
    <input id="li_pw" type="password" placeholder="password" autocomplete="current-password">
    <input id="li_code" type="text" inputmode="numeric" placeholder="2FA code (if enabled)" autocomplete="one-time-code">
    <button onclick="doLogin()">Sign in</button>
    <div class="err" id="li_err" style="margin-top:10px"></div>
  </div>
</div>

<div id="shell" class="wrap" style="display:none">
  <div class="top">
    <div class="brand"><span class="dot"></span><span class="hl">HUNTR</span>&nbsp;<span class="muted">Admin</span></div>
    <span class="asof" id="asof">loading…</span>
    <span class="sp"></span>
    <button class="btn" onclick="testAlert()">✉ Test email</button>
    <button class="btn" onclick="load()">↻ Refresh</button>
    <button class="btn" onclick="logout()">Sign out</button>
  </div>
  <div id="err" class="err" style="margin-top:12px"></div>

  <div id="app" style="display:none">
    <div class="sec"><h2>Signups &amp; growth</h2><div class="rule"></div></div>
    <div class="kpis">
      <div class="glass tile"><div class="lab">Total users<span class="chip up" id="u_24">+0</span></div><div class="num" id="u_total">—</div><div class="sub" id="u_30">0 in 30d</div></div>
      <div class="glass tile accent-c"><div class="lab">New · 7 days</div><div class="num" id="u_7">—</div><div class="sub">signups this week</div></div>
      <div class="glass tile accent-g"><div class="lab">Paying users</div><div class="num" id="r_pay">—</div><div class="sub" id="r_rev">~$0 est</div></div>
      <div class="glass tile accent-g"><div class="lab">Est. MRR</div><div class="num" id="r_mrr">—</div><div class="sub" id="r_subs">0 active subs</div></div>
    </div>
    <div class="glass chart" style="margin-top:var(--s2)">
      <div class="ch"><span class="ct">Signups / day · 30d</span><span class="cv" id="spark_u_v">—</span></div>
      <svg id="spark_u" viewBox="0 0 600 100" preserveAspectRatio="none"></svg>
    </div>

    <div class="sec"><h2>Activation funnel</h2><div class="rule"></div></div>
    <div class="glass funnel" id="funnel"></div>

    <div class="sec"><h2>Usage · hunts</h2><div class="rule"></div></div>
    <div class="kpis">
      <div class="glass tile"><div class="lab">Total hunts</div><div class="num" id="h_total">—</div><div class="sub" id="h_run">0 running now</div></div>
      <div class="glass tile accent-c"><div class="lab">Hunts · 7 days</div><div class="num" id="h_7">—</div><div class="sub" id="h_24">0 in 24h</div></div>
      <div class="glass tile"><div class="lab">Avg findings / hunt</div><div class="num" id="h_avg">—</div><div class="sub">across all hunts</div></div>
      <div class="glass tile accent-g"><div class="lab">WAU / MAU</div><div class="num" id="e_wau">—</div><div class="sub" id="e_agents">0 active agents</div></div>
    </div>
    <div class="glass chart" style="margin-top:var(--s2)">
      <div class="ch"><span class="ct">Hunts / day · 30d</span><span class="cv" id="spark_h_v">—</span></div>
      <svg id="spark_h" viewBox="0 0 600 100" preserveAspectRatio="none"></svg>
    </div>

    <div class="sec"><h2>Breakdowns</h2><div class="rule"></div></div>
    <div class="cols">
      <div class="glass bd"><div class="bt">Hunts by status</div><table id="t_hstatus"></table></div>
      <div class="glass bd"><div class="bt">Findings by severity</div><table id="t_sev"></table></div>
      <div class="glass bd"><div class="bt">Plans</div><table id="t_plan"></table></div>
      <div class="glass bd"><div class="bt">Referral source</div><table id="t_ref"></table></div>
    </div>

    <div class="sec"><h2>Money · credits</h2><div class="rule"></div></div>
    <div class="kpis">
      <div class="glass tile"><div class="lab">Outstanding credits</div><div class="num" id="c_out">—</div><div class="sub">unspent balance = liability</div></div>
      <div class="glass tile accent-g"><div class="lab">Credits purchased</div><div class="num" id="c_buy">—</div><div class="sub">lifetime</div></div>
      <div class="glass tile"><div class="lab">Credits consumed</div><div class="num" id="c_used">—</div><div class="sub">spent on hunts</div></div>
      <div class="glass tile accent-g"><div class="lab">Bounties logged</div><div class="num" id="f_bounty">—</div><div class="sub">by users, via HUNTR</div></div>
    </div>
    <div class="note">Dollar figures are estimates (1 credit ≈ $1). Creem is the source of truth for revenue.</div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const TK = 'huntr_admin';
const tok = () => localStorage.getItem(TK);
const fmt = n => (n==null?'—':(typeof n==='number'? n.toLocaleString() : n));
const usd = n => '$'+(Number(n)||0).toLocaleString();

function showLogin(msg){ $('#login').style.display=''; $('#shell').style.display='none';
  if(msg) $('#li_err').textContent=msg; }
function showShell(){ $('#login').style.display='none'; $('#shell').style.display=''; }

async function doLogin(){
  $('#li_err').textContent='';
  const body={email:$('#li_email').value.trim(),password:$('#li_pw').value,code:$('#li_code').value.trim()||null};
  try{
    const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const j=await r.json().catch(()=>({}));
    if(!r.ok){ $('#li_err').textContent=j.detail||('Error '+r.status); return; }
    localStorage.setItem(TK,j.token); showShell(); load();
  }catch(e){ $('#li_err').textContent='Failed: '+e.message; }
}
function logout(){ localStorage.removeItem(TK); showLogin(''); }
async function testAlert(){
  $('#err').style.color='var(--mut)'; $('#err').textContent='Sending test email…';
  try{
    const r=await fetch('/notify/test',{method:'POST',headers:{'Authorization':'Bearer '+tok()}});
    const j=await r.json().catch(()=>({}));
    if(j.sent){ $('#err').style.color='var(--green)'; $('#err').textContent='✓ Test email sent — check your inbox (and spam/Promotions).'; }
    else { $('#err').style.color='var(--bad)'; $('#err').textContent='Not sent: '+(j.error||'check RESEND_API_KEY is set on the service'); }
  }catch(e){ $('#err').style.color='var(--bad)'; $('#err').textContent='Test failed: '+e.message; }
}

function spark(el, series){
  if(!series||!series.length){ el.innerHTML=''; return 0; }
  const w=600,h=100,pl=3,pr=3,pt=12,pb=12;
  const vals=series.map(d=>d.count), max=Math.max(1,...vals), n=series.length;
  const sx=(w-pl-pr)/((n-1)||1);
  const X=i=>pl+i*sx, Y=v=>h-pb-(v/max)*(h-pt-pb);
  const pts=series.map((d,i)=>[X(i),Y(d.count)]);
  const line=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ');
  const area=line+` L ${X(n-1).toFixed(1)} ${h-pb} L ${X(0).toFixed(1)} ${h-pb} Z`;
  const lp=pts[n-1];
  el.innerHTML=
    '<defs>'+
      '<linearGradient id="spkA" x1="0" y1="0" x2="0" y2="1">'+
        '<stop offset="0" stop-color="rgba(167,139,250,.32)"/>'+
        '<stop offset="1" stop-color="rgba(167,139,250,0)"/></linearGradient>'+
      '<linearGradient id="spkL" x1="0" y1="0" x2="1" y2="0">'+
        '<stop offset="0" stop-color="#A78BFA"/>'+
        '<stop offset="0.55" stop-color="#22D3EE"/>'+
        '<stop offset="1" stop-color="#4ADE80"/></linearGradient>'+
    '</defs>'+
    `<line x1="${pl}" y1="${(h-pb).toFixed(1)}" x2="${w-pr}" y2="${(h-pb).toFixed(1)}" stroke="rgba(255,255,255,.07)" vector-effect="non-scaling-stroke"/>`+
    `<path d="${area}" fill="url(#spkA)"/>`+
    `<path d="${line}" fill="none" stroke="url(#spkL)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>`+
    `<circle cx="${lp[0].toFixed(1)}" cy="${lp[1].toFixed(1)}" r="7" fill="rgba(74,222,128,.22)"/>`+
    `<circle cx="${lp[0].toFixed(1)}" cy="${lp[1].toFixed(1)}" r="3.2" fill="#4ADE80"/>`;
  return vals[n-1];
}
function tbl(el, obj, order){
  const keys = order ? order.filter(k=>k in (obj||{})) : Object.keys(obj||{}).sort((a,b)=>(obj[b]-obj[a]));
  const max = Math.max(1,...keys.map(k=>obj[k]||0));
  el.innerHTML = keys.length? keys.map(k=>`<tr><td class="k">${k}</td>`
     +`<td class="b"><div class="mini"><i style="width:${Math.round((obj[k]||0)/max*100)}%"></i></div></td>`
     +`<td class="v">${fmt(obj[k]||0)}</td></tr>`).join('')
     : `<tr><td class="empty">no data</td></tr>`;
}
function funnel(a){
  const steps=[['Signed up',a.signups],['Onboarded',a.onboarded],['Installed CLI',a.installed_cli],
    ['Ran a hunt',a.ran_hunt],['Got a finding',a.got_finding],['Paid',a.paid]];
  const top=Math.max(1,a.signups);
  $('#funnel').innerHTML = steps.map(([lab,v])=>{
    const pct=Math.round((v||0)/top*100);
    return `<div class="row"><span class="lab">${lab}</span>`
      +`<span class="track"><i style="width:${pct}%"></i></span>`
      +`<span class="meta"><b>${fmt(v||0)}</b><span>${pct}%</span></span></div>`;
  }).join('');
}

async function load(){
  if(!tok()){ showLogin(''); return; }
  showShell();
  try{
    const r = await fetch('/metrics.json', {headers:{'Authorization':'Bearer '+tok()}});
    if(r.status===401){ logout(); showLogin('Session expired — sign in again.'); return; }
    if(r.status===404){ $('#err').textContent='This account is not an admin.'; return; }
    if(!r.ok){ $('#err').textContent='Error '+r.status; return; }
    const m = await r.json();
    $('#err').textContent=''; $('#app').style.display='';
    $('#asof').textContent = 'as of '+new Date(m.generated_at).toLocaleString();
    $('#u_total').textContent=fmt(m.signups.total);
    $('#u_24').textContent='+'+fmt(m.signups.new_24h);
    $('#u_24').className = 'chip '+((m.signups.new_24h||0)>0?'up':'flat');
    $('#u_7').textContent=fmt(m.signups.new_7d);
    $('#u_30').textContent=fmt(m.signups.new_30d)+' in the last 30d';
    const lu=spark($('#spark_u'), m.signups.series_30d);
    $('#spark_u_v').innerHTML=fmt(lu)+' <small>today</small>';
    tbl($('#t_plan'), m.signups.by_plan);
    $('#r_pay').textContent=fmt(m.revenue.paying_users);
    $('#r_rev').textContent='~'+usd(m.revenue.est_revenue_usd)+' lifetime';
    $('#r_mrr').textContent=usd(m.revenue.est_mrr_usd);
    $('#r_subs').textContent=fmt(Object.values(m.revenue.subs_by_tier).reduce((a,b)=>a+b,0))+' active subs';
    $('#c_out').textContent=fmt(m.revenue.credits_outstanding);
    $('#c_buy').textContent=fmt(m.revenue.credits_purchased);
    $('#c_used').textContent=fmt(m.revenue.credits_consumed);
    funnel(m.activation);
    $('#h_total').textContent=fmt(m.hunts.total);
    $('#h_run').textContent=fmt(m.hunts.running_now)+' running now';
    $('#h_7').textContent=fmt(m.hunts.last_7d);
    $('#h_24').textContent=fmt(m.hunts.last_24h)+' in 24h';
    $('#h_avg').textContent=fmt(m.hunts.avg_findings);
    const lh=spark($('#spark_h'), m.hunts.series_30d);
    $('#spark_h_v').innerHTML=fmt(lh)+' <small>today</small>';
    tbl($('#t_hstatus'), m.hunts.by_status);
    $('#e_wau').textContent=fmt(m.engagement.wau)+' / '+fmt(m.engagement.mau);
    $('#e_agents').textContent=fmt(m.engagement.active_agents_7d)+' active agents';
    tbl($('#t_sev'), m.findings.by_severity, ['critical','high','medium','low','info']);
    $('#f_bounty').textContent=usd(m.findings.bounty_total_usd);
    tbl($('#t_ref'), m.acquisition.referrals);
  }catch(e){ $('#err').textContent='Failed to load: '+e.message; }
}
load();
</script>
</body></html>"""
