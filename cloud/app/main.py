"""
HUNTR Cloud — FastAPI application entry point.

Run locally:
  uvicorn cloud.app.main:app --reload --port 8000

Prod (gunicorn + uvicorn workers):
  gunicorn cloud.app.main:app -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:8000
"""
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .db import init_db
from .routers import auth, agents, sync, findings, corpus, billing, web

IS_PROD = os.environ.get("ENV") == "production"

app = FastAPI(
    title="HUNTR Cloud",
    version="1.0.0",
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None,
    openapi_url=None if IS_PROD else "/openapi.json",   # don't publish the API map in prod
)

# CORS — the browser app authenticates with a Bearer header (never cookies), so
# credentials are off. Localhost origins are dev-only.
_PROD_ORIGINS = "https://huntr.run,https://www.huntr.run"
_DEV_ORIGINS  = ",http://localhost:3000,http://127.0.0.1:3000,http://127.0.0.1:8899"
_DEFAULT_ORIGINS = _PROD_ORIGINS + ("" if IS_PROD else _DEV_ORIGINS)
ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", _DEFAULT_ORIGINS).split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# Hard cap on request bodies (the largest legit payload is a synced finding).
MAX_BODY = int(os.environ.get("MAX_BODY_BYTES", 256 * 1024))

_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
# the legacy HTML pages in routers/web.py use inline <script>/<style> + Google Fonts
_PAGE_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
             "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
             "font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; "
             "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)
    resp = await call_next(request)
    h = resp.headers
    h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    ctype = h.get("content-type", "")
    h.setdefault("Content-Security-Policy", _PAGE_CSP if ctype.startswith("text/html") else _API_CSP)
    if request.url.path.startswith("/v1/"):
        h.setdefault("Cache-Control", "no-store")
    return resp


app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(sync.router)
app.include_router(findings.router)
app.include_router(corpus.router)
app.include_router(billing.router)
app.include_router(web.router)


@app.on_event("startup")
def startup():
    init_db()
    _scrub_corpus()


def _scrub_corpus():
    """One-shot cleanup: older builds stored full URLs (host + query) in the
    shared corpus. Re-template or drop any row that still carries them."""
    from .db import SessionLocal, CorpusEntry
    from .routers.sync import _normalize_endpoint
    db = SessionLocal()
    try:
        bad = db.query(CorpusEntry).filter(
            CorpusEntry.endpoint_template.contains("://")
            | CorpusEntry.endpoint_template.contains("?")
            | ~CorpusEntry.endpoint_template.startswith("/")
        ).all()
        for e in bad:
            t = _normalize_endpoint(e.endpoint_template)
            if not t:
                db.delete(e)
            else:
                e.endpoint_template = t
                e.signature = f"cls:{e.cls}|ep:{t}|sev:{e.weakness}"
        if bad:
            db.commit()
            print(f"[corpus] scrubbed {len(bad)} host-bearing entries")
    except Exception as ex:
        db.rollback()
        print(f"[corpus] scrub warning: {ex}")
    finally:
        db.close()


@app.get("/health")
def health():
    return {"ok": True, "service": "huntr-cloud"}
