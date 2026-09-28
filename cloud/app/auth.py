"""
Auth utilities — password hashing, JWT sessions, agent token generation.
"""
import os, secrets, hashlib, time
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ALGORITHM      = "HS256"
SESSION_EXPIRE = int(os.environ.get("SESSION_EXPIRE_HOURS", 72))

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=False)


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def create_session_token(user_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRE)
    return jwt.encode({"sub": user_id, "exp": exp, "type": "session"}, SECRET_KEY, algorithm=ALGORITHM)


def decode_session_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "session":
            return None
        return payload["sub"]
    except jwt.PyJWTError:
        return None


def generate_agent_token() -> str:
    """Returns a raw token (store the hash, give the raw to the agent)."""
    return secrets.token_urlsafe(48)


def hash_agent_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_agent_token(raw: str, stored_hash: str) -> bool:
    return hash_agent_token(raw) == stored_hash
