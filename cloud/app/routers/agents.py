"""
Agent registration and token management.
"""
import ulid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db, Agent, User
from ..auth import generate_agent_token, hash_agent_token
from ..deps import current_user

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class RegisterIn(BaseModel):
    name: str = "default"
    os:   str | None = None
    version: str | None = None


class RegisterOut(BaseModel):
    agent_id:    str
    agent_token: str   # raw — show once, never stored


@router.post("/register", response_model=RegisterOut)
def register(body: RegisterIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raw_token  = generate_agent_token()
    token_hash = hash_agent_token(raw_token)
    agent = Agent(
        id         = str(ulid.new()),
        user_id    = user.id,
        name       = body.name,
        token_hash = token_hash,
        os         = body.os,
        version    = body.version,
        last_seen  = datetime.now(timezone.utc),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return RegisterOut(agent_id=agent.id, agent_token=raw_token)


@router.get("/")
def list_agents(user: User = Depends(current_user), db: Session = Depends(get_db)):
    agents = db.query(Agent).filter(Agent.user_id == user.id).all()
    return [{"id": a.id, "name": a.name, "os": a.os,
             "version": a.version, "last_seen": a.last_seen} for a in agents]


@router.delete("/{agent_id}")
def revoke(agent_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id, Agent.user_id == user.id).first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    db.delete(agent)
    db.commit()
    return {"ok": True}
