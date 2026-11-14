"""
FastAPI dependencies — resolve the current user from session or agent token.
"""
from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session

from .db import get_db, User, Agent
from .auth import decode_session_token, verify_agent_token


def _bearer(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")
    return authorization.removeprefix("Bearer ").strip()


def current_user(token: str = Depends(_bearer), db: Session = Depends(get_db)) -> User:
    decoded = decode_session_token(token)
    if not decoded:
        raise HTTPException(401, "Invalid or expired session token")
    user_id, tv = decoded
    user = db.query(User).filter(User.id == user_id).first()
    # token_version mismatch = session revoked (password change, 2FA change, sign-out-everywhere)
    if not user or int(user.token_version or 0) != tv:
        raise HTTPException(401, "Invalid or expired session token")
    return user


def current_agent(token: str = Depends(_bearer), db: Session = Depends(get_db)) -> tuple[Agent, User]:
    """Resolve an agent from its raw token. Returns (agent, user)."""
    from .auth import hash_agent_token
    if len(token) > 256:
        raise HTTPException(401, "Invalid agent token")
    token_hash = hash_agent_token(token)
    agent = db.query(Agent).filter(Agent.token_hash == token_hash).first()
    if not agent:
        raise HTTPException(401, "Invalid agent token")
    user = db.query(User).filter(User.id == agent.user_id).first()
    if not user:
        raise HTTPException(401, "Agent's user not found")
    # update last_seen (throttled — not a DB write on every sync call)
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    ls = agent.last_seen
    if ls is not None and ls.tzinfo is None:
        ls = ls.replace(tzinfo=timezone.utc)
    if ls is None or now - ls > timedelta(minutes=1):
        agent.last_seen = now
        db.commit()
    return agent, user


def pro_required(user: User = Depends(current_user)) -> User:
    # any non-free plan (founder | monthly | yearly | pro | team) is entitled
    if user.plan == "free":
        raise HTTPException(403, "A paid plan is required")
    return user
