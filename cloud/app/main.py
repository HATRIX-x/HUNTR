"""
HUNTR Cloud — FastAPI application entry point.

Run locally:
  uvicorn cloud.app.main:app --reload --port 8000

Prod (gunicorn + uvicorn workers):
  gunicorn cloud.app.main:app -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:8000
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db import init_db
from .routers import auth, agents, sync, findings, corpus

app = FastAPI(
    title="HUNTR Cloud",
    version="1.0.0",
    docs_url="/docs" if os.environ.get("ENV") != "production" else None,
    redoc_url=None,
)

# CORS — allow the dashboard (served from the same domain in prod)
ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:8899").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(sync.router)
app.include_router(findings.router)
app.include_router(corpus.router)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"ok": True, "service": "huntr-cloud"}
