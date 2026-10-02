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
    user_id = decode_session_token(token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired session token")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user


def current_agent(token: str = Depends(_bearer), db: Session = Depends(get_db)) -> tuple[Agent, User]:
    """Resolve an agent from its raw token. Returns (agent, user)."""
    from .auth import hash_agent_token
    token_hash = hash_agent_token(token)
    agent = db.query(Agent).filter(Agent.token_hash == token_hash).first()
    if not agent:
        raise HTTPException(401, "Invalid agent token")
    user = db.query(User).filter(User.id == agent.user_id).first()
    if not user:
        raise HTTPException(401, "Agent's user not found")
    # update last_seen
    from datetime import datetime, timezone
    agent.last_seen = datetime.now(timezone.utc)
    db.commit()
    return agent, user


def pro_required(user: User = Depends(current_user)) -> User:
    if user.plan not in ("pro", "team"):
        raise HTTPException(403, "Pro plan required")
    return user
