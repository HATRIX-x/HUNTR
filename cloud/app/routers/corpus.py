"""
Corpus sync — agents pull the anonymized dedup corpus on startup.
Pro plan only.
"""
import gzip, json
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from ..db import get_db, CorpusEntry, User
from ..deps import current_agent, pro_required

router = APIRouter(prefix="/v1/corpus", tags=["corpus"])


@router.get("/latest")
def get_corpus(
    db: Session = Depends(get_db),
    ctx: tuple = Depends(current_agent),
):
    """
    Returns gzipped JSONL of anonymized corpus entries.
    Each line: {"cls":"idor","endpoint_template":"/user/{id}","signature":"..."}
    No host, no user identity, no target info.
    """
    agent, user = ctx
    if user.plan not in ("pro", "team"):
        from fastapi import HTTPException
        raise HTTPException(403, "Pro plan required for corpus sync")

    entries = db.query(CorpusEntry).order_by(CorpusEntry.created_at.desc()).limit(50000).all()
    lines = []
    for e in entries:
        lines.append(json.dumps({
            "cls":               e.cls,
            "endpoint_template": e.endpoint_template,
            "weakness":          e.weakness,
            "signature":         e.signature,
            "source":            e.source,
        }))

    body = gzip.compress("\n".join(lines).encode())
    return Response(
        content=body,
        media_type="application/x-ndjson",
        headers={
            "Content-Encoding": "gzip",
            "X-Entry-Count": str(len(entries)),
        }
    )


@router.get("/stats")
def corpus_stats(db: Session = Depends(get_db), ctx: tuple = Depends(current_agent)):
    agent, user = ctx
    total = db.query(CorpusEntry).count()
    from sqlalchemy import func
    by_cls = db.query(CorpusEntry.cls, func.count()).group_by(CorpusEntry.cls).all()
    return {
        "total": total,
        "by_class": {cls: count for cls, count in by_cls},
    }
