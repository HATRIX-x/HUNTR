"""
Billing — Creem checkout + webhook. Creem is the merchant of record (handles
cards, tax, invoices). We never see card data.

Flow:
  1. POST /v1/billing/checkout {plan}  (auth) → creates a Creem checkout session,
     returns {checkout_url}. The frontend redirects the user there.
  2. Creem hosts payment, then redirects to success_url and fires webhooks.
  3. POST /v1/billing/webhook  → verifies the creem-signature (HMAC-SHA256 of the
     raw body with CREEM_WEBHOOK_SECRET) and activates/downgrades the plan.

Plans map to Creem product_ids via env (create the products in the Creem
dashboard as *Subscription* products, then paste their ids):
  CREEM_PRODUCT_FOUNDER  (Founder, $29/mo)
  CREEM_PRODUCT_MONTHLY  (Monthly, $49/mo)
  CREEM_PRODUCT_YEARLY   (Yearly,  $490/yr)

Env:
  CREEM_API_KEY         — secret API key (test key for test-api, live key for api)
  CREEM_API_URL         — https://api.creem.io (default) or https://test-api.creem.io
  CREEM_WEBHOOK_SECRET  — from Creem → Developers → Webhooks
  APP_URL               — https://huntr.run (where the user returns after paying)

We reuse the existing generic columns to avoid a schema migration on the live DB:
  User.stripe_customer      → Creem customer id
  Subscription.stripe_sub_id → Creem subscription id
"""
import os, json, hmac, hashlib, urllib.request, urllib.error
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db, User, Subscription, CreditTxn
from ..deps import current_user, current_agent

router = APIRouter(prefix="/v1/billing", tags=["billing"])

CREEM_API_URL        = os.environ.get("CREEM_API_URL", "https://api.creem.io").rstrip("/")
CREEM_API_KEY        = os.environ.get("CREEM_API_KEY", "")
CREEM_WEBHOOK_SECRET = os.environ.get("CREEM_WEBHOOK_SECRET", "")
APP_URL              = os.environ.get("APP_URL", "https://huntr.run").rstrip("/")

PRODUCT_IDS = {
    "founder": os.environ.get("CREEM_PRODUCT_FOUNDER", ""),
    "monthly": os.environ.get("CREEM_PRODUCT_MONTHLY", ""),
    "yearly":  os.environ.get("CREEM_PRODUCT_YEARLY", ""),
}

# ── managed-credits products ────────────────────────────────────────────────
# One-time credit packs (Scout/Stalk/Takedown) and recurring credit plans
# (Hunter/Apex). Create these in the Creem dashboard and paste the product ids.
PACK_PRODUCT_IDS = {
    "scout":    os.environ.get("CREEM_PACK_SCOUT", ""),
    "stalk":    os.environ.get("CREEM_PACK_STALK", ""),
    "takedown": os.environ.get("CREEM_PACK_TAKEDOWN", ""),
}
PLAN_PRODUCT_IDS = {
    "hunter": os.environ.get("CREEM_PLAN_HUNTER", ""),
    "apex":   os.environ.get("CREEM_PLAN_APEX", ""),
}
# Credits granted per product. Packs grant once; plans grant this each billing
# cycle. This is the ONLY place the credit amounts live — Creem just charges.
CREDITS_FOR = {
    "scout": 30, "stalk": 115, "takedown": 360,   # one-time packs
    "hunter": 55, "apex": 180,                     # monthly plan allotment
}
# Launch promo: the first N buyers get double credits on their first pack, up
# to LAUNCH_BONUS_MAX bonus credits (so a first Takedown can't be had at half price).
LAUNCH_BONUS_CAP = int(os.environ.get("CREEM_LAUNCH_BONUS_CAP", "100"))
LAUNCH_BONUS_MAX = int(os.environ.get("CREEM_LAUNCH_BONUS_MAX", "100"))


def _product_id_for(plan: str) -> str:
    """Resolve a plan/pack/legacy slug to its Creem product id."""
    return (PACK_PRODUCT_IDS.get(plan) or PLAN_PRODUCT_IDS.get(plan)
            or PRODUCT_IDS.get(plan) or "")


def _all_slugs() -> set:
    return set(PACK_PRODUCT_IDS) | set(PLAN_PRODUCT_IDS) | set(PRODUCT_IDS)


def _key_for_product(pid: str):
    """Reverse-map a Creem product id back to its slug and kind."""
    if not pid:
        return None, None
    for k, v in PACK_PRODUCT_IDS.items():
        if v and v == pid:
            return k, "pack"
    for k, v in PLAN_PRODUCT_IDS.items():
        if v and v == pid:
            return k, "plan"
    for k, v in PRODUCT_IDS.items():
        if v and v == pid:
            return k, "sub"
    return None, None

# Events that grant access, and events that revoke it.
ACTIVATE_EVENTS   = {"checkout.completed", "subscription.active",
                     "subscription.paid", "subscription.trialing"}
DEACTIVATE_EVENTS = {"subscription.canceled", "subscription.cancelled",
                     "subscription.expired", "subscription.paused"}


def _plan_for_product(product_id: str):
    for plan, pid in PRODUCT_IDS.items():
        if pid and pid == product_id:
            return plan
    return None


# ── checkout ──────────────────────────────────────────────────────────────

class CheckoutIn(BaseModel):
    plan: str   # founder | monthly | yearly


@router.post("/checkout")
def create_checkout(body: CheckoutIn, user: User = Depends(current_user)):
    plan = (body.plan or "").lower()
    if plan not in _all_slugs():
        raise HTTPException(400, f"Unknown plan '{body.plan}'")
    product_id = _product_id_for(plan)
    if not product_id:
        raise HTTPException(500, f"Product for '{plan}' not configured (missing Creem product id)")
    if not CREEM_API_KEY:
        raise HTTPException(500, "CREEM_API_KEY not configured")

    payload = json.dumps({
        "product_id": product_id,
        "request_id": user.id,                       # our reference, echoed back
        "success_url": f"{APP_URL}/account/?upgraded=1",
        "metadata": {"user_id": user.id, "plan": plan},
        "customer": {"email": user.email},
    }).encode()

    req = urllib.request.Request(
        f"{CREEM_API_URL}/v1/checkouts",
        data=payload,
        headers={
            "x-api-key": CREEM_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Creem's API sits behind Cloudflare, which blocks the default
            # "Python-urllib/x.y" agent with a 403 "error code: 1010" before the
            # request reaches Creem. Send a normal browser-style UA so the
            # legitimate server-to-server call is allowed through.
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            ),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            res = json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300] if hasattr(e, "read") else str(e)
        print(f"[billing] creem checkout failed ({e.code}): {detail}")
        raise HTTPException(502, "Payment provider error — please try again shortly.")
    except Exception as e:
        print(f"[billing] creem unreachable: {e}")
        raise HTTPException(502, "Payment provider unreachable — please try again shortly.")

    url = res.get("checkout_url")
    if not url or not str(url).startswith("https://"):
        print(f"[billing] creem returned no usable checkout_url: {str(res)[:300]}")
        raise HTTPException(502, "Payment provider error — please try again shortly.")
    return {"checkout_url": url}


@router.get("/status")
def billing_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    return {
        "plan":      user.plan,
        "credits":   int(user.credits or 0),
        "status":    sub.status if sub else "none",
        "renews_at": str(sub.renews_at) if sub and sub.renews_at else None,
    }


@router.get("/credits")
def credits_balance(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Current balance plus the most recent ledger entries."""
    txns = (db.query(CreditTxn)
              .filter(CreditTxn.user_id == user.id)
              .order_by(CreditTxn.id.desc()).limit(25).all())
    return {
        "balance": int(user.credits or 0),
        "free_hunt_used": bool(user.free_hunt_used),
        "ledger": [
            {"delta": t.delta, "balance_after": t.balance_after,
             "reason": t.reason, "at": str(t.created_at)}
            for t in txns
        ],
    }


class ConsumeIn(BaseModel):
    amount: int                 # credits to deduct (the hunt's up-front estimate)
    ref: str = ""               # hunt id — idempotency key, so a retry never double-charges
    reason: str = "hunt"


def _charge(db: Session, user: User, amount: int, ref: str, reason: str) -> dict:
    """Deduct credits atomically. Never goes negative (402 when short), and is
    idempotent on (user, ref, reason) so a retried hunt never double-charges."""
    amt = int(amount or 0)
    if amt <= 0:
        raise HTTPException(400, "amount must be a positive integer")
    if ref:
        dup = db.query(CreditTxn).filter_by(user_id=user.id, ref=ref, reason=reason).first()
        if dup:
            return {"ok": True, "charged": 0, "balance": int(user.credits or 0),
                    "note": "already charged"}
    # lock the row on Postgres so two concurrent hunts can't overspend
    q = db.query(User).filter(User.id == user.id)
    try:
        u = q.with_for_update().first()
    except Exception:
        u = q.first()               # sqlite / drivers without row locks
    bal = int(u.credits or 0)
    if bal < amt:
        raise HTTPException(402, f"Insufficient credits: need {amt}, have {bal}")
    u.credits = bal - amt
    db.add(CreditTxn(user_id=u.id, delta=-amt, balance_after=u.credits,
                     reason=reason, ref=ref or None))
    db.commit()
    return {"ok": True, "charged": amt, "balance": int(u.credits)}


def _refund(db: Session, user: User, amount: int, ref: str, reason: str) -> dict:
    """Return credits (e.g. the unused portion of an up-front estimate when a
    hunt finished cheaper). Idempotent on (user, ref, reason)."""
    amt = int(amount or 0)
    if amt <= 0:
        return {"ok": True, "refunded": 0, "balance": int(user.credits or 0)}
    if ref:
        dup = db.query(CreditTxn).filter_by(user_id=user.id, ref=ref, reason=reason).first()
        if dup:
            return {"ok": True, "refunded": 0, "balance": int(user.credits or 0),
                    "note": "already refunded"}
    bal = int(user.credits or 0) + amt
    user.credits = bal
    db.add(CreditTxn(user_id=user.id, delta=amt, balance_after=bal,
                     reason=reason, ref=ref or None))
    db.commit()
    return {"ok": True, "refunded": amt, "balance": bal}


@router.post("/consume")
def consume_credits(body: ConsumeIn, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    """Deduct credits for a hunt (approach A: charge the estimate up front)."""
    return _charge(db, user, body.amount, body.ref, body.reason)


# ── agent-authed gate (the engine calls these at hunt start / end) ──────────

@router.get("/agent/balance")
def agent_balance(ctx=Depends(current_agent)):
    """Engine checks the user's balance before sizing/starting a hunt."""
    _agent, user = ctx
    return {"balance": int(user.credits or 0)}


@router.post("/agent/consume")
def agent_consume(body: ConsumeIn, ctx=Depends(current_agent),
                  db: Session = Depends(get_db)):
    """The gate: the engine deducts a hunt's estimated credits up front and
    aborts the hunt on a 402. This is what makes a managed hunt loss-proof —
    compute never runs unless the credits were already taken."""
    _agent, user = ctx
    return _charge(db, user, body.amount, body.ref, body.reason)


@router.post("/agent/refund")
def agent_refund(body: ConsumeIn, ctx=Depends(current_agent),
                 db: Session = Depends(get_db)):
    """Reconcile: return the unused portion of the up-front estimate when a
    hunt stops early or finishes cheaper than estimated."""
    _agent, user = ctx
    return _refund(db, user, body.amount, body.ref, body.reason + ":refund")


# ── webhook ───────────────────────────────────────────────────────────────

def _verify_signature(raw: bytes, signature: str) -> bool:
    if not CREEM_WEBHOOK_SECRET or not signature:
        return False
    expected = hmac.new(CREEM_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip())


def _parse_period_end(obj: dict):
    for key in ("current_period_end", "current_period_end_date",
                "next_billing_date", "renews_at", "period_end"):
        val = obj.get(key)
        if not val:
            continue
        try:
            if isinstance(val, (int, float)):
                return datetime.fromtimestamp(val, tz=timezone.utc)
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except Exception:
            continue
    return None


@router.post("/webhook")
async def creem_webhook(
    request: Request,
    db: Session = Depends(get_db),
    creem_signature: str = Header(None, alias="creem-signature"),
):
    raw = await request.body()
    # Creem docs are inconsistent on the header name; accept the x- variant too.
    sig = creem_signature or request.headers.get("x-creem-signature", "")
    if not _verify_signature(raw, sig):
        raise HTTPException(400, "Invalid signature")

    try:
        event = json.loads(raw.decode() or "{}")
    except ValueError:
        raise HTTPException(400, "Invalid JSON")
    etype = event.get("eventType") or event.get("type") or ""
    obj   = event.get("object") or event.get("data") or {}
    meta  = obj.get("metadata") or {}

    # resolve the user: metadata.user_id first, then customer email
    user = None
    uid = meta.get("user_id") or obj.get("request_id")
    if uid:
        user = db.query(User).filter(User.id == uid).first()
    if not user:
        cust = obj.get("customer") or {}
        email = cust.get("email") if isinstance(cust, dict) else None
        if email:
            user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"received": True, "note": "no matching user"}

    if etype in ACTIVATE_EVENTS:
        # The PRODUCT decides what was bought — never trust metadata alone, and
        # never default an unknown product (any other Creem item) to paid.
        prod = obj.get("product") or {}
        pid = prod.get("id") if isinstance(prod, dict) else prod
        key, kind = _key_for_product(pid)
        if not key:
            # fall back to metadata.plan only when no product id was present
            mp = meta.get("plan")
            if mp and not pid and mp in _all_slugs():
                key = mp
                kind = ("pack" if mp in PACK_PRODUCT_IDS
                        else "plan" if mp in PLAN_PRODUCT_IDS else "sub")
        if not key:
            print(f"[billing] {etype} for unknown product {pid!r} — ignored")
            return {"received": True, "note": "unknown product"}

        if kind == "pack":
            _credit_pack(db, user, key, obj)
        elif kind == "plan":
            _credit_plan(db, user, key, obj)
        else:
            _activate(db, user, key, obj)   # legacy subscription
    elif etype in DEACTIVATE_EVENTS:
        _deactivate(db, user)

    return {"received": True}


# ── credit ledger ───────────────────────────────────────────────────────────

def _order_ref(obj: dict) -> str:
    """Idempotency key for a one-time purchase (unique per order/checkout)."""
    o = obj.get("order") or {}
    return (str(o.get("id")) if isinstance(o, dict) and o.get("id") else None) \
        or obj.get("checkout_id") or obj.get("id") or ""


def _cycle_ref(obj: dict) -> str:
    """Idempotency key for a subscription that must re-credit each billing
    cycle — the subscription id plus the current period end."""
    sub_id = obj.get("id") or ""
    pe = _parse_period_end(obj)
    return f"{sub_id}:{pe.isoformat() if pe else ''}"


def _add_credits(db: Session, user: User, amount: int, reason: str, ref: str) -> int:
    """Append a ledger entry and move the balance. Idempotent on (user, ref,
    reason): a replayed webhook returns the existing balance without re-crediting."""
    if amount == 0:
        return int(user.credits or 0)
    if ref:
        dup = db.query(CreditTxn).filter_by(user_id=user.id, ref=ref, reason=reason).first()
        if dup:
            return int(user.credits or 0)
    bal = int(user.credits or 0) + int(amount)
    user.credits = bal
    db.add(CreditTxn(user_id=user.id, delta=int(amount), balance_after=bal,
                     reason=reason, ref=ref or None))
    db.commit()
    return bal


def _credit_pack(db: Session, user: User, key: str, obj: dict):
    """One-time pack purchase → grant credits, plus the launch 2× on a user's
    first pack (capped at LAUNCH_BONUS_MAX) while the global promo cap still has room."""
    base = CREDITS_FOR.get(key, 0)
    ref = _order_ref(obj)
    _add_credits(db, user, base, f"purchase:{key}", ref)
    if not user.first_pack_bonus_used:
        granted = db.query(User).filter(User.first_pack_bonus_used.is_(True)).count()
        if granted < LAUNCH_BONUS_CAP:
            user.first_pack_bonus_used = True
            _add_credits(db, user, min(base, LAUNCH_BONUS_MAX), "bonus:launch", ref)
        db.commit()


def _credit_plan(db: Session, user: User, key: str, obj: dict):
    """Recurring credit plan → set the plan tier and grant this cycle's credits
    (idempotent per billing cycle, so renewals top up once each)."""
    _activate(db, user, key, obj)                 # sets user.plan + subscription
    _add_credits(db, user, CREDITS_FOR.get(key, 0), f"plan:{key}", _cycle_ref(obj))


def _activate(db: Session, user: User, plan: str, obj: dict):
    user.plan = plan
    cust = obj.get("customer") or {}
    cust_id = cust.get("id") if isinstance(cust, dict) else (cust or None)
    if cust_id:
        user.stripe_customer = cust_id          # reused column = Creem customer id

    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    if not sub:
        sub = Subscription(user_id=user.id)
        db.add(sub)
    sub.tier          = plan
    sub.status        = "active"
    sub.stripe_sub_id = obj.get("id")           # reused column = Creem subscription id
    sub.renews_at     = _parse_period_end(obj)
    db.commit()


def _deactivate(db: Session, user: User):
    user.plan = "free"
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    if sub:
        sub.status = "cancelled"
    db.commit()
