"""
Sync routes — agent pushes findings and funnel events here.
Requires agent token (not user session).
"""
import re, ulid, time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db, Finding, FunnelEvent, CorpusEntry, Agent, User
from ..deps import current_agent

router = APIRouter(prefix="/v1/sync", tags=["sync"])

VALID_STAGES = {"flagged", "confirmed", "submitted", "accepted", "dupe", "rejected", "paid"}


# ── helpers ──────────────────────────────────────────────────────────────

def _normalize_endpoint(ep: str) -> str:
    """Replace numeric path segments with {id} for corpus storage."""
    return re.sub(r"/\d+", "/{id}", ep or "")


# ── finding sync ─────────────────────────────────────────────────────────

class FindingPayload(BaseModel):
    id:           str
    cls:          str
    endpoint:     str
    severity:     str        = "medium"
    title:        str        = ""
    verdict:      str        = "REVIEW"
    dup_prob:     float | None = None
    evidence_ref: str | None   = None
    report_score: int | None   = None
    created_at:   str | None   = None


class SyncFindingIn(BaseModel):
    type:    str = "finding"
    ts:      str = ""
    program: str = ""
    finding: FindingPayload


@router.post("/finding")
def sync_finding(
    body: SyncFindingIn,
    ctx: tuple[Agent, User] = Depends(current_agent),
    db: Session = Depends(get_db),
):
    agent, user = ctx
    f = body.finding

    # upsert — agent re-sends on retry; last write wins
    existing = db.query(Finding).filter(
        Finding.id == f.id, Finding.user_id == user.id
    ).first()

    if existing:
        existing.verdict      = f.verdict
        existing.severity     = f.severity
        existing.title        = f.title
        existing.dup_prob     = f.dup_prob
        existing.evidence_ref = f.evidence_ref
        existing.report_score = f.report_score
        existing.updated_at   = datetime.now(timezone.utc)
        db.commit()
        finding = existing
    else:
        finding = Finding(
            id           = f.id,
            user_id      = user.id,
            program      = body.program,
            cls          = f.cls,
            endpoint     = f.endpoint,
            severity     = f.severity,
            title        = f.title,
            verdict      = f.verdict,
            status       = "confirmed" if f.verdict == "SUBMIT" else "flagged",
            dup_prob     = f.dup_prob,
            evidence_ref = f.evidence_ref,
            report_score = f.report_score,
        )
        db.add(finding)
        db.commit()

        # contribute to corpus (anonymized — no host, no token, no user identity)
        if f.verdict in ("SUBMIT", "REVIEW") and (f.dup_prob or 0) < 60:
            ep_template = _normalize_endpoint(f.endpoint)
            corpus_entry = CorpusEntry(
                cls               = f.cls,
                endpoint_template = ep_template,
                weakness          = f.severity,
                signature         = f"cls:{f.cls}|ep:{ep_template}|sev:{f.severity}",
                source            = "agent",
            )
            db.add(corpus_entry)
            db.commit()

        # auto-add a funnel event
        funnel = FunnelEvent(
            user_id    = user.id,
            finding_id = finding.id,
            program    = body.program,
            stage      = "confirmed" if f.verdict == "SUBMIT" else "flagged",
        )
        db.add(funnel)
        db.commit()

    return {"ok": True, "finding_id": finding.id, "action": "updated" if existing else "created"}


# ── funnel sync ──────────────────────────────────────────────────────────

class SyncFunnelIn(BaseModel):
    type:       str = "funnel"
    ts:         str = ""
    finding_id: str
    stage:      str
    amount:     float | None = None
    program:    str = ""


@router.post("/funnel")
def sync_funnel(
    body: SyncFunnelIn,
    ctx: tuple[Agent, User] = Depends(current_agent),
    db: Session = Depends(get_db),
):
    agent, user = ctx
    if body.stage not in VALID_STAGES:
        raise HTTPException(400, f"Invalid stage '{body.stage}'. Valid: {VALID_STAGES}")

    # update finding status if it exists
    finding = db.query(Finding).filter(
        Finding.id == body.finding_id, Finding.user_id == user.id
    ).first()
    if finding:
        finding.status = body.stage
        if body.amount and body.stage == "paid":
            finding.amount = body.amount
        db.commit()

    event = FunnelEvent(
        user_id    = user.id,
        finding_id = body.finding_id if finding else None,
        program    = body.program,
        stage      = body.stage,
        amount     = body.amount,
    )
    db.add(event)
    db.commit()
    return {"ok": True, "event_id": event.id}
