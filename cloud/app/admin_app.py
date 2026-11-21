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

from .db import get_db, User, Agent, Finding, Hunt, CreditTxn, Subscription
from .auth import (
    verify_password, create_session_token, decode_session_token,
    verify_totp, is_locked, record_failure, record_success, consume_backup_code,
)

app = FastAPI(title="HUNTR Admin", docs_url=None, redoc_url=None, openapi_url=None)
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

    total_users = db.query(func.count(User.id)).scalar() or 0
    new_24h = db.query(func.count(User.id)).filter(User.created_at >= _since(1)).scalar() or 0
    new_7d = db.query(func.count(User.id)).filter(User.created_at >= _since(7)).scalar() or 0
    new_30d = db.query(func.count(User.id)).filter(User.created_at >= _since(30)).scalar() or 0
    signup_dates = [r[0] for r in db.query(User.created_at).filter(User.created_at >= _since(30)).all()]
    plan_rows = db.query(User.plan, func.count(User.id)).group_by(User.plan).all()
    plans = {(p or "free"): int(c) for p, c in plan_rows}

    onboarded = db.query(func.count(User.id)).filter(User.onboarded == True).scalar() or 0  # noqa: E712
    installed_cli = db.query(func.count(func.distinct(Agent.user_id))).scalar() or 0
    ran_hunt = db.query(func.count(func.distinct(Hunt.user_id))).scalar() or 0
    got_finding = db.query(func.count(func.distinct(Finding.user_id))).scalar() or 0
    paying_users = (db.query(func.count(func.distinct(CreditTxn.user_id)))
                    .filter((CreditTxn.reason.like("purchase%")) | (CreditTxn.reason.like("plan%")))
                    .scalar() or 0)

    def _sum_delta(*like):
        cond = None
        for lk in like:
            cond = CreditTxn.reason.like(lk) if cond is None else (cond | CreditTxn.reason.like(lk))
        q = db.query(func.coalesce(func.sum(CreditTxn.delta), 0))
        return int(q.filter(cond).scalar() or 0) if cond is not None else 0

    credits_purchased = _sum_delta("purchase%", "plan%")
    credits_bonus = _sum_delta("bonus%", "grant%")
    credits_consumed = abs(int(db.query(func.coalesce(func.sum(CreditTxn.delta), 0))
                               .filter(CreditTxn.delta < 0).scalar() or 0))
    credits_outstanding = int(db.query(func.coalesce(func.sum(User.credits), 0)).scalar() or 0)

    sub_rows = (db.query(Subscription.tier, func.count(Subscription.user_id))
                .filter(Subscription.status == "active").group_by(Subscription.tier).all())
    subs_by_tier = {(t or "?"): int(c) for t, c in sub_rows}
    est_mrr = round(sum(_SUB_MRR.get((t or "").lower(), 0.0) * c for t, c in subs_by_tier.items()), 2)

    total_hunts = db.query(func.count(Hunt.id)).scalar() or 0
    hunt_status_rows = db.query(Hunt.status, func.count(Hunt.id)).group_by(Hunt.status).all()
    hunts_by_status = {(s or "?"): int(c) for s, c in hunt_status_rows}
    hunts_running = int(hunts_by_status.get("running", 0) + hunts_by_status.get("queued", 0))
    hunts_24h = db.query(func.count(Hunt.id)).filter(Hunt.created_at >= _since(1)).scalar() or 0
    hunts_7d = db.query(func.count(Hunt.id)).filter(Hunt.created_at >= _since(7)).scalar() or 0
    hunts_30d = db.query(func.count(Hunt.id)).filter(Hunt.created_at >= _since(30)).scalar() or 0
    avg_findings = round(float(db.query(func.coalesce(func.avg(Hunt.findings), 0)).scalar() or 0), 2)
    hunt_dates = [r[0] for r in db.query(Hunt.created_at).filter(Hunt.created_at >= _since(30)).all()]

    total_findings = db.query(func.count(Finding.id)).scalar() or 0
    sev_rows = db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
    findings_by_severity = {(s or "?"): int(c) for s, c in sev_rows}
    fstatus_rows = db.query(Finding.status, func.count(Finding.id)).group_by(Finding.status).all()
    findings_by_status = {(s or "?"): int(c) for s, c in fstatus_rows}
    bounty_total = round(float(db.query(func.coalesce(func.sum(Finding.amount), 0)).scalar() or 0), 2)

    active_agents_7d = db.query(func.count(Agent.id)).filter(Agent.last_seen >= _since(7)).scalar() or 0
    wau = db.query(func.count(func.distinct(Hunt.user_id))).filter(Hunt.created_at >= _since(7)).scalar() or 0
    mau = db.query(func.count(func.distinct(Hunt.user_id))).filter(Hunt.created_at >= _since(30)).scalar() or 0

    referrals = Counter()
    for (prof,) in db.query(User.profile).filter(User.profile.isnot(None)).all():
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
  :root{ --bg:#0a0710; --panel:#14101f; --panel2:#1b1530; --line:#2a2340;
         --ink:#ece9f5; --mut:#9b93b5; --accent:#b9a3ff; --pearl:#efe9ff;
         --good:#6ee7a8; --warn:#ffcf7a; --bad:#ff8a9c; }
  *{box-sizing:border-box} html,body{margin:0}
  body{background:radial-gradient(1200px 600px at 70% -10%, #241a3d 0%, var(--bg) 55%) fixed;
       color:var(--ink); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       padding:24px 16px 64px; max-width:1180px; margin:0 auto}
  h1{font-size:19px;margin:0;letter-spacing:.2px} h2{font-size:12px;text-transform:uppercase;
     letter-spacing:.14em;color:var(--mut);margin:26px 2px 10px;font-weight:600}
  .top{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .sub{color:var(--mut);font-size:12px}
  .grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(160px,1fr))}
  .card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
        border-radius:14px;padding:14px 15px}
  .kpi .n{font-size:26px;font-weight:650;letter-spacing:.2px}
  .kpi .l{color:var(--mut);font-size:12px;margin-top:2px}
  .kpi .d{font-size:11px;margin-top:6px;color:var(--mut)}
  .d .up{color:var(--good)} .wide{grid-column:1/-1}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td,th{padding:6px 8px;text-align:left;border-bottom:1px solid var(--line)}
  th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.08em}
  td.r,th.r{text-align:right;font-variant-numeric:tabular-nums}
  .bar{height:8px;border-radius:6px;background:var(--panel);overflow:hidden}
  .bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--pearl))}
  .funnel div{display:flex;align-items:center;gap:10px;margin:7px 0}
  .funnel .lab{width:120px;color:var(--mut);font-size:12px} .funnel .track{flex:1}
  .funnel .val{width:92px;text-align:right;font-variant-numeric:tabular-nums}
  svg{display:block;width:100%;height:60px}
  .muted{color:var(--mut)} .err{color:var(--bad);min-height:18px;font-size:13px}
  button{cursor:pointer}
  .btn{background:var(--panel2);color:var(--ink);border:1px solid var(--line);border-radius:9px;
       padding:6px 12px;font-size:12px}
  .note{color:var(--mut);font-size:11px;margin-top:4px}
  .login{max-width:320px;margin:12vh auto 0} .login .card{padding:22px}
  .login input{width:100%;margin:7px 0;padding:10px 11px;border-radius:9px;border:1px solid var(--line);
    background:var(--bg);color:var(--ink);font-size:14px}
  .login button{width:100%;margin-top:8px;padding:10px;border-radius:9px;border:1px solid var(--line);
    background:linear-gradient(90deg,var(--accent),var(--pearl));color:#1a1030;font-weight:650}
  .login h1{margin-bottom:4px}
</style></head>
<body>
  <div id="login" class="login" style="display:none">
    <div class="card">
      <h1>HUNTR <span class="muted">Admin</span></h1>
      <div class="sub" style="margin-bottom:8px">Founder access only.</div>
      <input id="li_email" type="email" placeholder="email" autocomplete="username">
      <input id="li_pw" type="password" placeholder="password" autocomplete="current-password">
      <input id="li_code" type="text" inputmode="numeric" placeholder="2FA code (if enabled)" autocomplete="one-time-code">
      <button onclick="doLogin()">Sign in</button>
      <div class="err" id="li_err" style="margin-top:8px"></div>
    </div>
  </div>

  <div id="shell" style="display:none">
  <div class="top">
    <h1>HUNTR <span class="muted">· Admin</span></h1>
    <span class="sub" id="asof">loading…</span>
    <span style="flex:1"></span>
    <button class="btn" onclick="load()">↻ Refresh</button>
    <button class="btn" onclick="logout()">Sign out</button>
  </div>
  <div id="err" class="err" style="margin-top:10px"></div>
  <div id="app" style="display:none">
    <h2>Signups &amp; growth</h2>
    <div class="grid">
      <div class="card kpi"><div class="n" id="u_total">—</div><div class="l">Total users</div>
        <div class="d"><span class="up" id="u_24">+0</span> last 24h</div></div>
      <div class="card kpi"><div class="n" id="u_7">—</div><div class="l">New · 7 days</div>
        <div class="d" id="u_30">0 in 30d</div></div>
      <div class="card kpi"><div class="n" id="r_pay">—</div><div class="l">Paying users</div>
        <div class="d" id="r_rev">~$0 est</div></div>
      <div class="card kpi"><div class="n" id="r_mrr">—</div><div class="l">Est. MRR</div>
        <div class="d" id="r_subs">0 active subs</div></div>
      <div class="card wide"><div class="l muted" style="margin-bottom:6px">Signups / day · 30d</div>
        <svg id="spark_u" viewBox="0 0 600 60" preserveAspectRatio="none"></svg></div>
    </div>
    <h2>Activation funnel</h2>
    <div class="card funnel" id="funnel"></div>
    <h2>Usage · hunts</h2>
    <div class="grid">
      <div class="card kpi"><div class="n" id="h_total">—</div><div class="l">Total hunts</div>
        <div class="d" id="h_run">0 running now</div></div>
      <div class="card kpi"><div class="n" id="h_7">—</div><div class="l">Hunts · 7 days</div>
        <div class="d" id="h_24">0 in 24h</div></div>
      <div class="card kpi"><div class="n" id="h_avg">—</div><div class="l">Avg findings / hunt</div></div>
      <div class="card kpi"><div class="n" id="e_wau">—</div><div class="l">WAU / MAU</div>
        <div class="d" id="e_agents">0 active agents</div></div>
      <div class="card wide"><div class="l muted" style="margin-bottom:6px">Hunts / day · 30d</div>
        <svg id="spark_h" viewBox="0 0 600 60" preserveAspectRatio="none"></svg></div>
    </div>
    <h2>Breakdowns</h2>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">
      <div class="card"><div class="l muted" style="margin-bottom:8px">Hunts by status</div><table id="t_hstatus"></table></div>
      <div class="card"><div class="l muted" style="margin-bottom:8px">Findings by severity</div><table id="t_sev"></table></div>
      <div class="card"><div class="l muted" style="margin-bottom:8px">Plans</div><table id="t_plan"></table></div>
      <div class="card"><div class="l muted" style="margin-bottom:8px">Referral source</div><table id="t_ref"></table></div>
    </div>
    <h2>Money · credits</h2>
    <div class="grid">
      <div class="card kpi"><div class="n" id="c_out">—</div><div class="l">Outstanding credits</div>
        <div class="note">unspent balance = liability</div></div>
      <div class="card kpi"><div class="n" id="c_buy">—</div><div class="l">Credits purchased</div></div>
      <div class="card kpi"><div class="n" id="c_used">—</div><div class="l">Credits consumed</div></div>
      <div class="card kpi"><div class="n" id="f_bounty">—</div><div class="l">Bounties logged</div></div>
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

function spark(el, series){
  if(!series||!series.length){return}
  const w=600,h=60,p=4, max=Math.max(1,...series.map(d=>d.count));
  const step = series.length>1 ? (w-2*p)/(series.length-1) : 0;
  const pts = series.map((d,i)=>[p+i*step, h-p-(d.count/max)*(h-2*p)]);
  const line = pts.map((pt,i)=>(i?'L':'M')+pt[0].toFixed(1)+' '+pt[1].toFixed(1)).join(' ');
  el.innerHTML = `<path d="${line} L ${w-p} ${h-p} L ${p} ${h-p} Z" fill="rgba(185,163,255,.14)"/>`
    + `<path d="${line}" fill="none" stroke="var(--accent)" stroke-width="2"/>`;
}
function tbl(el, obj, order){
  const keys = order ? order.filter(k=>k in (obj||{})) : Object.keys(obj||{}).sort((a,b)=>(obj[b]-obj[a]));
  const max = Math.max(1,...keys.map(k=>obj[k]||0));
  el.innerHTML = keys.length? keys.map(k=>`<tr><td>${k}</td>`
     +`<td style="width:45%"><div class="bar"><i style="width:${Math.round((obj[k]||0)/max*100)}%"></i></div></td>`
     +`<td class="r">${fmt(obj[k]||0)}</td></tr>`).join('')
     : `<tr><td class="muted">no data</td></tr>`;
}
function funnel(a){
  const steps=[['Signed up',a.signups],['Onboarded',a.onboarded],['Installed CLI',a.installed_cli],
    ['Ran a hunt',a.ran_hunt],['Got a finding',a.got_finding],['Paid',a.paid]];
  const top=Math.max(1,a.signups);
  $('#funnel').innerHTML = steps.map(([lab,v])=>{
    const pct=Math.round((v||0)/top*100);
    return `<div><span class="lab">${lab}</span><span class="track"><div class="bar">`
      +`<i style="width:${pct}%"></i></div></span>`
      +`<span class="val">${fmt(v||0)} <span class="muted">${pct}%</span></span></div>`;
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
    $('#u_7').textContent=fmt(m.signups.new_7d);
    $('#u_30').textContent=fmt(m.signups.new_30d)+' in 30d';
    spark($('#spark_u'), m.signups.series_30d);
    tbl($('#t_plan'), m.signups.by_plan);
    $('#r_pay').textContent=fmt(m.revenue.paying_users);
    $('#r_rev').textContent='~'+usd(m.revenue.est_revenue_usd)+' est';
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
    spark($('#spark_h'), m.hunts.series_30d);
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
