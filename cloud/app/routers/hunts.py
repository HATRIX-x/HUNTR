"""
Cloud hunts — trigger a hunt from the account, run it in a worker container.

  POST /v1/hunts              (user)  enqueue a hunt → {hunt_id, status}
  GET  /v1/hunts              (user)  list my hunts
  GET  /v1/hunts/{id}         (user)  one hunt's status
  POST /v1/agents/hunt-status (agent) worker reports completion

The worker authenticates to the cloud (credit gate + finding sync) as an
EPHEMERAL agent minted per hunt and deleted when the hunt finishes, so cloud
hunts never consume the user's real operator-token slots.
"""
import os
import json
import asyncio
import ulid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..db import get_db, SessionLocal, Hunt, Agent, User
from ..auth import generate_agent_token, hash_agent_token, decode_session_token
from ..deps import current_user, current_agent
from .. import queue

router = APIRouter(prefix="/v1", tags=["hunts"])

CLOUD_URL   = os.environ.get("CLOUD_API_URL", os.environ.get("APP_URL", "https://api.huntr.run")).rstrip("/")
MIN_CREDITS = int(os.environ.get("HUNT_MIN_CREDITS", "12"))   # a light hunt's estimate
_MODES = {"black", "grey", "white"}


class HuntIn(BaseModel):
    target:      str = Field(min_length=1, max_length=400)
    program:     str = Field("", max_length=200)
    mode:        str = Field("grey")
    scope_types: str = Field("web,api", max_length=64)


def _hunt_out(h: Hunt) -> dict:
    return {
        "hunt_id": h.id, "target": h.target, "program": h.program, "mode": h.mode,
        "status": h.status, "stage": h.stage or "", "pct": int(h.pct or 0),
        "findings": int(h.findings or 0), "error": h.error,
        "vnc": bool(h.vnc_host and h.vnc_port),
        "created_at": str(h.created_at), "updated_at": str(h.updated_at),
    }


@router.post("/hunts")
def create_hunt(body: HuntIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not queue.enabled():
        raise HTTPException(503, "Hunt queue unavailable — try again shortly.")
    mode = (body.mode or "grey").lower()
    if mode not in _MODES:
        raise HTTPException(400, f"mode must be one of {sorted(_MODES)}")
    # Pre-check credits so we never queue a hunt that would instantly block.
    if int(user.credits or 0) < MIN_CREDITS:
        raise HTTPException(402, f"Not enough credits — a hunt needs at least {MIN_CREDITS}. Top up to run one.")

    hunt_id = ulid.new().str
    # Ephemeral worker agent for this hunt (not the public register path, so it
    # bypasses the operator-token cap; deleted on completion).
    raw_token = generate_agent_token()
    agent = Agent(id=ulid.new().str, user_id=user.id, name=f"cloud:{hunt_id}",
                  token_hash=hash_agent_token(raw_token))
    db.add(agent)

    # program keys the finding sync; default it to the target so the dashboard
    # can always correlate a hunt to its findings.
    program = body.program.strip() or body.target.strip()
    hunt = Hunt(id=hunt_id, user_id=user.id, target=body.target.strip(),
                program=program, mode=mode,
                scope_types=body.scope_types or "web,api",
                status="queued", agent_id=agent.id)
    db.add(hunt)
    db.commit()

    try:
        queue.enqueue({
            "hunt_id": hunt_id, "user_id": user.id,
            "target": hunt.target, "program": hunt.program, "mode": hunt.mode,
            "scope_types": hunt.scope_types,
            "agent_token": raw_token, "cloud_url": CLOUD_URL,
        })
    except Exception as e:
        hunt.status = "error"; hunt.error = f"enqueue failed: {e}"
        db.commit()
        raise HTTPException(502, "Could not queue the hunt — try again shortly.")
    return {"hunt_id": hunt_id, "status": "queued"}


@router.get("/hunts")
def list_hunts(user: User = Depends(current_user), db: Session = Depends(get_db)):
    hunts = (db.query(Hunt).filter(Hunt.user_id == user.id)
               .order_by(Hunt.created_at.desc()).limit(100).all())
    return {"hunts": [_hunt_out(h) for h in hunts]}


@router.get("/hunts/{hunt_id}")
def get_hunt(hunt_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    h = db.query(Hunt).filter(Hunt.id == hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    out = _hunt_out(h)
    try:
        out["logs"] = json.loads(h.logs) if h.logs else []
    except Exception:
        out["logs"] = []
    return out


_TERMINAL = {"done", "error", "blocked", "cancelled"}


@router.post("/hunts/{hunt_id}/cancel")
def cancel_hunt(hunt_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Mark a hunt cancelled. A queued hunt is skipped on pickup; a running hunt
    sees the flag on its next progress tick and stops (worker side)."""
    h = db.query(Hunt).filter(Hunt.id == hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    if h.status in _TERMINAL:
        return {"ok": True, "status": h.status}   # already finished — idempotent
    h.status = "cancelled"
    db.commit()
    return {"ok": True, "status": "cancelled"}


class HuntProgressIn(BaseModel):
    hunt_id: str
    stage:   str = ""
    pct:     int = 0
    findings: int = 0
    tail:    List[str] = []   # recent engine log lines for the live tail


@router.post("/agents/hunt-progress")
def hunt_progress(body: HuntProgressIn, ctx=Depends(current_agent), db: Session = Depends(get_db)):
    """Worker → cloud: periodic live progress during a hunt (drives the dashboard)."""
    agent, user = ctx
    h = db.query(Hunt).filter(Hunt.id == body.hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    if h.status == "cancelled":
        return {"ok": True, "cancel": True}        # tell the worker to stop
    if h.status in ("queued", "running"):
        h.status = "running"
    h.stage = (body.stage or "")[:80]
    h.pct = max(0, min(100, int(body.pct or 0)))
    if body.findings:
        h.findings = int(body.findings)
    if body.tail:
        h.logs = json.dumps([str(s)[:300] for s in body.tail[-60:]])
    db.commit()
    return {"ok": True, "cancel": False}


class HuntFindingsIn(BaseModel):
    hunt_id: str
    findings: List[dict] = []


@router.post("/agents/hunt-findings")
def hunt_findings(body: HuntFindingsIn, ctx=Depends(current_agent), db: Session = Depends(get_db)):
    """Worker → cloud: the hunt's findings with full report/poc/repro, for the
    dashboard's per-finding detail view."""
    _agent, user = ctx
    h = db.query(Hunt).filter(Hunt.id == body.hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    h.findings_json = json.dumps(body.findings)[:4_000_000]   # cap the blob
    h.findings = len(body.findings)
    db.commit()
    return {"ok": True, "count": len(body.findings)}


@router.get("/hunts/{hunt_id}/findings")
def hunt_findings_list(hunt_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    h = db.query(Hunt).filter(Hunt.id == hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    try:
        items = json.loads(h.findings_json) if h.findings_json else []
    except Exception:
        items = []
    return {"findings": items}


class HuntStatusIn(BaseModel):
    hunt_id: str
    status:  str
    findings: int = 0
    credit_blocked: bool = False


@router.post("/agents/hunt-status")
def hunt_status(body: HuntStatusIn, ctx=Depends(current_agent), db: Session = Depends(get_db)):
    """Worker → cloud: a hunt finished. Update the row and retire the ephemeral agent."""
    agent, user = ctx
    h = db.query(Hunt).filter(Hunt.id == body.hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    status = (body.status or "done").lower()
    h.status = "blocked" if body.credit_blocked else (
        status if status in {"queued", "running", "done", "error", "blocked", "cancelled"} else "done")
    h.findings = int(body.findings or 0)
    db.commit()
    # Retire the per-hunt ephemeral agent (best-effort).
    if h.agent_id:
        a = db.query(Agent).filter(Agent.id == h.agent_id).first()
        if a:
            db.delete(a); db.commit()
    return {"ok": True, "status": h.status}


class HuntVncIn(BaseModel):
    hunt_id: str
    host: str
    port: int


@router.post("/agents/hunt-vnc")
def hunt_vnc(body: HuntVncIn, ctx=Depends(current_agent), db: Session = Depends(get_db)):
    """Worker → cloud: register this hunt's live-view (x11vnc) address so the
    dashboard can proxy to it."""
    _agent, user = ctx
    h = db.query(Hunt).filter(Hunt.id == body.hunt_id, Hunt.user_id == user.id).first()
    if not h:
        raise HTTPException(404, "Hunt not found")
    h.vnc_host = (body.host or "")[:200]
    h.vnc_port = int(body.port)
    db.commit()
    return {"ok": True}


@router.websocket("/hunts/{hunt_id}/vnc")
async def hunt_vnc_ws(ws: WebSocket, hunt_id: str, token: str = ""):
    """Browser noVNC <-> worker x11vnc bridge (websockify-style). The browser
    connects with ?token=<session token> (a WebSocket can't send an auth header);
    we verify the user owns the hunt, then pump raw RFB bytes between the browser
    WebSocket and a TCP socket to the worker's VNC port."""
    await ws.accept(subprotocol="binary")
    db = SessionLocal()
    try:
        decoded = decode_session_token(token)
        if not decoded:
            await ws.close(code=4401); return
        user_id, _tv = decoded
        h = db.query(Hunt).filter(Hunt.id == hunt_id, Hunt.user_id == user_id).first()
        if not h or not (h.vnc_host and h.vnc_port):
            await ws.close(code=4404); return
        host, port = h.vnc_host, int(h.vnc_port)
    finally:
        db.close()

    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception:
        await ws.close(code=4502); return

    async def ws_to_tcp():
        try:
            while True:
                writer.write(await ws.receive_bytes()); await writer.drain()
        except Exception:
            pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)
        except Exception:
            pass

    t1 = asyncio.create_task(ws_to_tcp())
    t2 = asyncio.create_task(tcp_to_ws())
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            t.cancel()
        try: writer.close()
        except Exception: pass
        try: await ws.close()
        except Exception: pass
