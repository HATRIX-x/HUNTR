"""
Sync routes — agent pushes findings and funnel events here.
Requires agent token (not user session).
"""
import re, ulid, time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from urllib.parse import urlsplit
from sqlalchemy.orm import Session

from ..db import get_db, Finding, FunnelEvent, CorpusEntry, Agent, User
from ..deps import current_agent

router = APIRouter(prefix="/v1/sync", tags=["sync"])

VALID_STAGES = {"flagged", "confirmed", "submitted", "accepted", "dupe", "rejected", "paid"}


# ── helpers ──────────────────────────────────────────────────────────────

_UUID   = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEXISH = re.compile(r"/(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{16,}(?=/|$)")
_TOKENY = re.compile(r"/[A-Za-z0-9_\-]{24,}(?=/|$)")


def _normalize_endpoint(ep: str) -> str | None:
    """Reduce an endpoint to a host-free path template for the SHARED corpus.
    The corpus is served to every paying customer, so it must never carry the
    target host, query string (tokens, emails), or object identifiers — that
    would leak one customer's unreported vulnerability to everyone else.
    Returns None when nothing safe is left."""
    ep = (ep or "").strip()
    if not ep:
        return None
    # "GET https://host/path" → drop the method prefix
    parts = ep.split(None, 1)
    if len(parts) == 2 and parts[0].isalpha() and parts[0].isupper():
        ep = parts[1]
    try:
        path = urlsplit(ep).path if "://" in ep or ep.startswith("//") else ep.split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        return None
    if not path.startswith("/"):
        return None                                   # bare host / garbage — nothing safe
    path = _UUID.sub("{id}", path)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    path = _HEXISH.sub("/{id}", path)
    path = _TOKENY.sub("/{token}", path)
    path = re.sub(r"[^A-Za-z0-9_\-./{}]", "", path)[:200]
    return path or None


def scoped_id(user_id: str, fid: str) -> str:
    """Findings.id is a global primary key but agents number findings locally
    (F1, F2…), so two customers would collide on 'F1'. Namespace by user."""
    return f"{user_id}:{fid}"


# ── finding sync ─────────────────────────────────────────────────────────

class FindingPayload(BaseModel):
    id:           str          = Field(min_length=1, max_length=64)
    cls:          str          = Field(max_length=64)
    endpoint:     str          = Field(max_length=2048)
    severity:     str          = Field("medium", max_length=16)
    title:        str          = Field("", max_length=500)
    verdict:      str          = Field("REVIEW", max_length=16)
    dup_prob:     float | None = Field(None, ge=0, le=100)
    evidence_ref: str | None   = Field(None, max_length=256)
    report_score: int | None   = Field(None, ge=0, le=1000)
    created_at:   str | None   = Field(None, max_length=64)


class SyncFindingIn(BaseModel):
    type:    str = Field("finding", max_length=16)
    ts:      str = Field("", max_length=64)
    program: str = Field("", max_length=200)
    finding: FindingPayload


@router.post("/finding")
def sync_finding(
    body: SyncFindingIn,
    ctx: tuple[Agent, User] = Depends(current_agent),
    db: Session = Depends(get_db),
):
    agent, user = ctx
    f = body.finding
    sid = scoped_id(user.id, f.id)

    # upsert — agent re-sends on retry; last write wins.
    # (legacy rows were stored with the bare agent id — still match those)
    existing = db.query(Finding).filter(
        Finding.id.in_([sid, f.id]), Finding.user_id == user.id
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
            id           = sid,
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
        ep_template = _normalize_endpoint(f.endpoint)
        if ep_template and f.verdict in ("SUBMIT", "REVIEW") and (f.dup_prob or 0) < 60:
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

    return {"ok": True, "finding_id": f.id, "action": "updated" if existing else "created"}


# ── funnel sync ──────────────────────────────────────────────────────────

class SyncFunnelIn(BaseModel):
    type:       str = Field("funnel", max_length=16)
    ts:         str = Field("", max_length=64)
    finding_id: str = Field(max_length=64)
    stage:      str = Field(max_length=16)
    amount:     float | None = Field(None, ge=0, le=10_000_000)
    program:    str = Field("", max_length=200)


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
        Finding.id.in_([scoped_id(user.id, body.finding_id), body.finding_id]),
        Finding.user_id == user.id,
    ).first()
    if finding:
        finding.status = body.stage
        if body.amount and body.stage == "paid":
            finding.amount = body.amount
        db.commit()

    event = FunnelEvent(
        user_id    = user.id,
        finding_id = finding.id if finding else None,
        program    = body.program,
        stage      = body.stage,
        amount     = body.amount,
    )
    db.add(event)
    db.commit()
    return {"ok": True, "event_id": event.id}
