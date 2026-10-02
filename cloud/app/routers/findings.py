"""
Findings and funnel read routes — dashboard reads these.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..db import get_db, Finding, FunnelEvent, User
from ..deps import current_user

router = APIRouter(prefix="/v1", tags=["findings"])


@router.get("/findings")
def list_findings(
    program: str | None = Query(None),
    status:  str | None = Query(None),
    verdict: str | None = Query(None),
    limit:   int        = Query(100, le=500),
    offset:  int        = Query(0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.user_id == user.id)
    if program: q = q.filter(Finding.program == program)
    if status:  q = q.filter(Finding.status  == status)
    if verdict: q = q.filter(Finding.verdict == verdict)
    total = q.count()
    items = q.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "findings": [_finding_dict(f) for f in items],
    }


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    f = db.query(Finding).filter(Finding.id == finding_id, Finding.user_id == user.id).first()
    if not f:
        from fastapi import HTTPException
        raise HTTPException(404, "Finding not found")
    return _finding_dict(f)


@router.get("/funnel/stats")
def funnel_stats(
    program: str | None = Query(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.user_id == user.id)
    if program: q = q.filter(Finding.program == program)

    findings = q.all()
    by_status = {}
    by_severity = {}
    total_earned = 0.0

    for f in findings:
        by_status[f.status]     = by_status.get(f.status, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        if f.amount: total_earned += f.amount

    total = len(findings)
    accepted = by_status.get("accepted", 0) + by_status.get("paid", 0)
    submitted = by_status.get("submitted", 0) + accepted
    acceptance_rate = round(accepted / submitted * 100, 1) if submitted else 0

    return {
        "total_findings":   total,
        "by_status":        by_status,
        "by_severity":      by_severity,
        "acceptance_rate":  acceptance_rate,
        "total_earned":     total_earned,
    }


@router.get("/funnel/events")
def funnel_events(
    program: str | None  = Query(None),
    finding_id: str | None = Query(None),
    limit: int           = Query(200, le=1000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(FunnelEvent).filter(FunnelEvent.user_id == user.id)
    if program:    q = q.filter(FunnelEvent.program    == program)
    if finding_id: q = q.filter(FunnelEvent.finding_id == finding_id)
    events = q.order_by(FunnelEvent.ts.desc()).limit(limit).all()
    return [{"id": e.id, "finding_id": e.finding_id, "stage": e.stage,
             "amount": e.amount, "program": e.program, "ts": str(e.ts)} for e in events]


def _finding_dict(f: Finding) -> dict:
    return {
        "id":           f.id,
        "program":      f.program,
        "cls":          f.cls,
        "endpoint":     f.endpoint,
        "severity":     f.severity,
        "title":        f.title,
        "verdict":      f.verdict,
        "status":       f.status,
        "dup_prob":     f.dup_prob,
        "evidence_ref": f.evidence_ref,
        "report_score": f.report_score,
        "amount":       f.amount,
        "created_at":   str(f.created_at),
        "updated_at":   str(f.updated_at),
    }
