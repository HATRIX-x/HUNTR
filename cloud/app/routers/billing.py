"""
Billing routes — Stripe checkout + webhook.
Plans: free | pro ($29/mo) | team ($79/mo)
"""
import os, json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db, User, Subscription
from ..deps import current_user

router = APIRouter(prefix="/v1/billing", tags=["billing"])

STRIPE_SECRET_KEY      = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET  = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
APP_URL                = os.environ.get("APP_URL", "https://huntr.app")

PRICE_IDS = {
    "pro":  os.environ.get("STRIPE_PRICE_PRO",  ""),   # set in .env
    "team": os.environ.get("STRIPE_PRICE_TEAM", ""),
}


def _stripe():
    try:
        import stripe as s
        s.api_key = STRIPE_SECRET_KEY
        return s
    except ImportError:
        raise HTTPException(500, "stripe package not installed — pip install stripe")


# ── checkout ────────────────────────────────────────────────────────────

class CheckoutIn(BaseModel):
    plan: str   # pro | team


@router.post("/checkout")
def create_checkout(
    body: CheckoutIn,
    user: User = Depends(current_user),
    db:   Session = Depends(get_db),
):
    if body.plan not in PRICE_IDS:
        raise HTTPException(400, f"Unknown plan '{body.plan}'")
    price_id = PRICE_IDS[body.plan]
    if not price_id:
        raise HTTPException(500, f"STRIPE_PRICE_{body.plan.upper()} not configured")

    stripe = _stripe()

    # get or create Stripe customer
    customer_id = user.stripe_customer
    if not customer_id:
        customer = stripe.Customer.create(email=user.email, metadata={"user_id": user.id})
        customer_id = customer.id
        user.stripe_customer = customer_id
        db.commit()

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=f"{APP_URL}/dashboard?upgraded=1",
        cancel_url=f"{APP_URL}/dashboard?cancelled=1",
        metadata={"user_id": user.id, "plan": body.plan},
    )
    return {"checkout_url": session.url, "session_id": session.id}


@router.get("/portal")
def billing_portal(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Returns a Stripe billing portal URL so users can manage/cancel."""
    if not user.stripe_customer:
        raise HTTPException(400, "No billing account found")
    stripe = _stripe()
    session = stripe.billing_portal.Session.create(
        customer=user.stripe_customer,
        return_url=f"{APP_URL}/dashboard",
    )
    return {"portal_url": session.url}


@router.get("/status")
def billing_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    return {
        "plan":      user.plan,
        "status":    sub.status    if sub else "none",
        "renews_at": str(sub.renews_at) if sub and sub.renews_at else None,
    }


# ── webhook ─────────────────────────────────────────────────────────────

@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None),
    db: Session = Depends(get_db),
):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(500, "STRIPE_WEBHOOK_SECRET not configured")

    stripe = _stripe()
    body = await request.body()

    try:
        event = stripe.Webhook.construct_event(body, stripe_signature, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "Invalid signature")

    etype = event["type"]
    data  = event["data"]["object"]

    if etype == "checkout.session.completed":
        user_id = data.get("metadata", {}).get("user_id")
        plan    = data.get("metadata", {}).get("plan", "pro")
        sub_id  = data.get("subscription")
        if user_id:
            _activate_plan(db, user_id, plan, sub_id)

    elif etype in ("customer.subscription.updated", "customer.subscription.created"):
        _sync_subscription(db, data)

    elif etype in ("customer.subscription.deleted", "invoice.payment_failed"):
        customer_id = data.get("customer")
        user = db.query(User).filter(User.stripe_customer == customer_id).first()
        if user:
            user.plan = "free"
            sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
            if sub:
                sub.status = "cancelled" if "deleted" in etype else "past_due"
            db.commit()

    return {"received": True}


def _activate_plan(db: Session, user_id: str, plan: str, stripe_sub_id: str):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return
    user.plan = plan
    sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
    if not sub:
        sub = Subscription(user_id=user_id)
        db.add(sub)
    sub.tier          = plan
    sub.status        = "active"
    sub.stripe_sub_id = stripe_sub_id
    db.commit()


def _sync_subscription(db: Session, data: dict):
    stripe_sub_id = data.get("id")
    customer_id   = data.get("customer")
    status        = data.get("status")   # active | past_due | cancelled | ...

    user = db.query(User).filter(User.stripe_customer == customer_id).first()
    if not user:
        return

    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    if not sub:
        sub = Subscription(user_id=user.id)
        db.add(sub)

    sub.stripe_sub_id = stripe_sub_id
    sub.status        = status

    renews = data.get("current_period_end")
    if renews:
        sub.renews_at = datetime.fromtimestamp(renews, tz=timezone.utc)

    if status == "active":
        items = data.get("items", {}).get("data", [])
        for item in items:
            price_id = item.get("price", {}).get("id", "")
            if price_id == PRICE_IDS.get("team"):
                user.plan = "team"; break
            elif price_id == PRICE_IDS.get("pro"):
                user.plan = "pro";  break
    elif status in ("canceled", "unpaid", "past_due"):
        user.plan = "free"

    db.commit()
