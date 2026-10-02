"""
Database connection and schema init.
Reads DATABASE_URL from env (Postgres in prod, SQLite for local dev).
"""
import os
from sqlalchemy import (
    create_engine, Column, String, Float, Integer, Boolean,
    DateTime, Text, ForeignKey, JSON, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./huntr_dev.db")
# Fly.io sets postgres://; SQLAlchemy 2 needs postgresql+psycopg2:// explicitly
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# SQLite needs check_same_thread=False for FastAPI's thread pool
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── models ──────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id              = Column(String, primary_key=True)   # ulid
    email           = Column(String, unique=True, nullable=False)
    password_hash   = Column(String, nullable=False)
    plan            = Column(String, default="free")     # free | pro | team
    stripe_customer = Column(String, nullable=True)
    created_at      = Column(DateTime, server_default=func.now())

    agents   = relationship("Agent",   back_populates="user", cascade="all, delete")
    findings = relationship("Finding", back_populates="user", cascade="all, delete")


class Agent(Base):
    __tablename__ = "agents"
    id          = Column(String, primary_key=True)
    user_id     = Column(String, ForeignKey("users.id"), nullable=False)
    name        = Column(String, default="default")
    token_hash  = Column(String, nullable=False, unique=True)
    os          = Column(String, nullable=True)
    version     = Column(String, nullable=True)
    last_seen   = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="agents")


class Finding(Base):
    __tablename__ = "findings"
    id              = Column(String, primary_key=True)   # agent-assigned e.g. "F1"
    user_id         = Column(String, ForeignKey("users.id"), nullable=False)
    program         = Column(String, default="")
    cls             = Column(String, default="")          # idor, ssrf, …
    endpoint        = Column(String, default="")
    severity        = Column(String, default="medium")
    title           = Column(String, default="")
    verdict         = Column(String, default="REVIEW")    # SUBMIT | REVIEW | HOLD
    status          = Column(String, default="flagged")   # flagged|confirmed|submitted|accepted|dupe|rejected|paid
    dup_prob        = Column(Float, nullable=True)
    evidence_ref    = Column(String, nullable=True)       # pointer into agent's local .hunt/evidence/
    report_score    = Column(Integer, nullable=True)
    amount          = Column(Float, nullable=True)        # bounty paid
    created_at      = Column(DateTime, server_default=func.now())
    updated_at      = Column(DateTime, server_default=func.now(), onupdate=func.now())

    user         = relationship("User", back_populates="findings")
    funnel_events = relationship("FunnelEvent", back_populates="finding", cascade="all, delete")


class FunnelEvent(Base):
    __tablename__ = "funnel_events"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    user_id     = Column(String, ForeignKey("users.id"), nullable=False)
    finding_id  = Column(String, ForeignKey("findings.id"), nullable=True)
    program     = Column(String, default="")
    stage       = Column(String, nullable=False)   # flagged|confirmed|submitted|accepted|paid
    amount      = Column(Float, nullable=True)
    ts          = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="funnel_events")


class CorpusEntry(Base):
    __tablename__ = "corpus"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    cls              = Column(String, nullable=False)
    endpoint_template = Column(String, nullable=False)
    weakness         = Column(String, nullable=True)
    signature        = Column(String, nullable=True)
    source           = Column(String, default="agent")   # agent | disclosed
    created_at       = Column(DateTime, server_default=func.now())


class Subscription(Base):
    __tablename__ = "subscriptions"
    user_id        = Column(String, ForeignKey("users.id"), primary_key=True)
    stripe_sub_id  = Column(String, nullable=True)
    tier           = Column(String, default="free")
    status         = Column(String, default="active")
    renews_at      = Column(DateTime, nullable=True)


# ── helpers ─────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
