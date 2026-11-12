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

from ..db import get_db, User, Subscription
from ..deps import current_user

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
    if plan not in PRODUCT_IDS:
        raise HTTPException(400, f"Unknown plan '{body.plan}'")
    product_id = PRODUCT_IDS[plan]
    if not product_id:
        raise HTTPException(500, f"CREEM_PRODUCT_{plan.upper()} not configured")
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
        raise HTTPException(502, f"Creem checkout failed ({e.code}): {detail}")
    except Exception as e:
        raise HTTPException(502, f"Creem unreachable: {e}")

    url = res.get("checkout_url")
    if not url:
        raise HTTPException(502, f"Creem returned no checkout_url: {res}")
    return {"checkout_url": url}


@router.get("/status")
def billing_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    return {
        "plan":      user.plan,
        "status":    sub.status if sub else "none",
        "renews_at": str(sub.renews_at) if sub and sub.renews_at else None,
    }


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

    event = json.loads(raw.decode() or "{}")
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
        plan = meta.get("plan")
        if not plan:
            prod = obj.get("product") or {}
            pid = prod.get("id") if isinstance(prod, dict) else prod
            plan = _plan_for_product(pid) or "monthly"
        _activate(db, user, plan, obj)
    elif etype in DEACTIVATE_EVENTS:
        _deactivate(db, user)

    return {"received": True}


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
