#!/usr/bin/env python3
"""
stripe_setup.py — create HUNTR Stripe products and prices.

Usage:
  STRIPE_SECRET_KEY=sk_test_... python tools/stripe_setup.py

Prints the price IDs to paste into .env / fly secrets.
"""
import os, sys

try:
    import stripe
except ImportError:
    sys.exit("pip install stripe")

key = os.environ.get("STRIPE_SECRET_KEY", "")
if not key:
    sys.exit("Set STRIPE_SECRET_KEY env var first.")

stripe.api_key = key

def get_or_create_product(name, description):
    existing = stripe.Product.search(query=f'name:"{name}"', limit=1)
    if existing.data:
        p = existing.data[0]
        print(f"  product exists: {p.id}  ({name})")
        return p.id
    p = stripe.Product.create(name=name, description=description)
    print(f"  created product: {p.id}  ({name})")
    return p.id

def get_or_create_price(product_id, unit_amount, nickname):
    existing = stripe.Price.list(product=product_id, active=True, limit=10)
    for pr in existing.data:
        if pr.unit_amount == unit_amount and pr.recurring and pr.recurring.interval == "month":
            print(f"  price exists: {pr.id}  ({nickname} ${unit_amount//100}/mo)")
            return pr.id
    pr = stripe.Price.create(
        product=product_id,
        unit_amount=unit_amount,
        currency="usd",
        recurring={"interval": "month"},
        nickname=nickname,
    )
    print(f"  created price: {pr.id}  ({nickname} ${unit_amount//100}/mo)")
    return pr.id

print("\n── HUNTR Stripe setup ──\n")

print("Pro plan:")
pro_pid = get_or_create_product("HUNTR Pro", "Cloud dashboard, corpus sync, finding history")
pro_price = get_or_create_price(pro_pid, 2900, "HUNTR Pro Monthly")

print("\nTeam plan:")
team_pid = get_or_create_product("HUNTR Team", "Up to 5 hunters, shared findings, program suggestions")
team_price = get_or_create_price(team_pid, 7900, "HUNTR Team Monthly")

print("\n── Add these to your .env and fly secrets ──\n")
print(f"STRIPE_PRICE_PRO={pro_price}")
print(f"STRIPE_PRICE_TEAM={team_price}")
print()
print("fly secrets set \\")
print(f"  STRIPE_PRICE_PRO={pro_price} \\")
print(f"  STRIPE_PRICE_TEAM={team_price}")
print()
print("Next: set up webhook endpoint in Stripe dashboard →")
print("  Endpoint URL: https://huntr-cloud.fly.dev/v1/billing/webhook")
print("  Events: checkout.session.completed, customer.subscription.updated,")
print("          customer.subscription.deleted, invoice.payment_failed")
print("  Then: fly secrets set STRIPE_WEBHOOK_SECRET=whsec_...")
