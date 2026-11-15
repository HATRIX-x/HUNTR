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
    # ── 2FA (TOTP) ──
    totp_secret     = Column(String, nullable=True)       # base32; set at setup
    totp_enabled    = Column(Boolean, default=False)      # True once confirmed
    backup_codes    = Column(Text, nullable=True)         # JSON array of sha256 hashes
    # ── onboarding profile ──
    onboarded       = Column(Boolean, default=False)      # True once the welcome flow is done
    profile         = Column(Text, nullable=True)         # JSON: role, platforms, experience, referral, goal
    # ── security state ──
    token_version   = Column(Integer, default=0)          # bump to revoke every outstanding session
    failed_logins   = Column(Integer, default=0)          # consecutive password/2FA failures
    locked_until    = Column(DateTime, nullable=True)     # lockout after too many failures
    totp_last_step  = Column(Integer, nullable=True)      # last accepted TOTP time-step (anti-replay)
    # ── managed-service credits ──
    credits               = Column(Integer, default=0)    # prepaid credit balance (1 credit = $1)
    first_pack_bonus_used = Column(Boolean, default=False) # launch 2× granted on first pack
    free_hunt_used        = Column(Boolean, default=False) # one-time free-hunt grant used

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


class Hunt(Base):
    """A cloud hunt: queued by the account, run by a worker container, reported
    back via /v1/agents/hunt-status. One row = one hunt the user triggered."""
    __tablename__ = "hunts"
    id          = Column(String, primary_key=True)           # ulid
    user_id     = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    target      = Column(String, nullable=False)
    program     = Column(String, default="")
    mode        = Column(String, default="grey")             # black | grey | white
    scope_types = Column(String, default="web,api")
    status      = Column(String, default="queued")           # queued|running|done|error|blocked|cancelled
    stage       = Column(String, default="")                 # engine stage label (live)
    pct         = Column(Integer, default=0)                  # 0-100 progress (live)
    findings    = Column(Integer, default=0)
    error       = Column(String, nullable=True)
    agent_id    = Column(String, nullable=True)              # ephemeral worker agent for this hunt
    vnc_host    = Column(String, nullable=True)              # worker's internal address for the live view
    vnc_port    = Column(Integer, nullable=True)
    logs        = Column(Text, nullable=True)               # JSON array of recent engine log lines (live tail)
    findings_json = Column(Text, nullable=True)             # JSON array of this hunt's findings incl. report/poc/repro
    created_at  = Column(DateTime, server_default=func.now())
    updated_at  = Column(DateTime, server_default=func.now(), onupdate=func.now())


class CreditTxn(Base):
    """Append-only ledger of every credit change — purchases, bonuses, hunt
    debits, grants, refunds. `ref` is an idempotency key (Creem order/cycle id
    or hunt id) so a replayed webhook or retried hunt never double-counts."""
    __tablename__ = "credit_txns"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    user_id       = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    delta         = Column(Integer, nullable=False)          # +credit / -debit
    balance_after = Column(Integer, nullable=False)
    reason        = Column(String, default="")              # purchase:scout | plan:hunter | bonus:launch | hunt:standard | grant:free | refund
    ref           = Column(String, nullable=True, index=True)  # idempotency key
    created_at    = Column(DateTime, server_default=func.now())


# ── helpers ─────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate():
    """Idempotent column adds for features layered onto an existing users table
    (create_all won't ALTER an existing table). Safe to run on every boot."""
    # (name, postgres_decl, sqlite_decl)
    adds = [
        ("totp_secret",  "VARCHAR",                 "VARCHAR"),
        ("totp_enabled", "BOOLEAN DEFAULT FALSE",   "INTEGER DEFAULT 0"),
        ("backup_codes", "TEXT",                    "TEXT"),
        ("onboarded",    "BOOLEAN DEFAULT FALSE",   "INTEGER DEFAULT 0"),
        ("profile",      "TEXT",                    "TEXT"),
        ("token_version",  "INTEGER DEFAULT 0",     "INTEGER DEFAULT 0"),
        ("failed_logins",  "INTEGER DEFAULT 0",     "INTEGER DEFAULT 0"),
        ("locked_until",   "TIMESTAMP",             "DATETIME"),
        ("totp_last_step", "INTEGER",               "INTEGER"),
        ("credits",               "INTEGER DEFAULT 0",     "INTEGER DEFAULT 0"),
        ("first_pack_bonus_used", "BOOLEAN DEFAULT FALSE", "INTEGER DEFAULT 0"),
        ("free_hunt_used",        "BOOLEAN DEFAULT FALSE", "INTEGER DEFAULT 0"),
    ]
    dialect = engine.dialect.name
    try:
        with engine.begin() as conn:
            if dialect == "sqlite":
                existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(users)")}
                for name, _pg, sq in adds:
                    if name not in existing:
                        conn.exec_driver_sql(f"ALTER TABLE users ADD COLUMN {name} {sq}")
            else:
                for name, pg, _sq in adds:
                    conn.exec_driver_sql(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {name} {pg}")
    except Exception as e:
        # never crash boot on a migration hiccup; log and continue
        print(f"[db] migrate warning: {e}")


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate()
