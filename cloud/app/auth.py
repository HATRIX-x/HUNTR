"""
Auth utilities — password hashing, JWT sessions, agent token generation.
"""
import os, secrets, hashlib, time, json
from datetime import datetime, timedelta, timezone

import jwt
import bcrypt as _bcrypt
import pyotp

SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ALGORITHM      = "HS256"
SESSION_EXPIRE = int(os.environ.get("SESSION_EXPIRE_HOURS", 72))


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain[:72].encode(), _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain[:72].encode(), hashed.encode())


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


# ── 2FA (TOTP) ─────────────────────────────────────────────────────────────

def create_2fa_token(user_id: str) -> str:
    """Short-lived token issued after password check when 2FA is on; exchanged
    for a full session once the TOTP/backup code is verified."""
    exp = datetime.now(timezone.utc) + timedelta(minutes=10)
    return jwt.encode({"sub": user_id, "exp": exp, "type": "2fa_pending"}, SECRET_KEY, algorithm=ALGORITHM)


def decode_2fa_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "2fa_pending":
            return None
        return payload["sub"]
    except jwt.PyJWTError:
        return None


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="HUNTR")


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    code = str(code).strip().replace(" ", "").replace("-", "")
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


def _norm_code(c: str) -> str:
    return str(c).strip().lower().replace(" ", "").replace("-", "")


def gen_backup_codes(n: int = 8) -> list[str]:
    # human-friendly, e.g. "a1b2-c3d4"
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]


def hash_backup_codes(codes: list[str]) -> str:
    return json.dumps([hashlib.sha256(_norm_code(c).encode()).hexdigest() for c in codes])


def consume_backup_code(code: str, hashed_json: str | None):
    """Returns (ok, new_hashed_json). A matching code is removed (single use)."""
    try:
        hashed = json.loads(hashed_json) if hashed_json else []
    except Exception:
        hashed = []
    h = hashlib.sha256(_norm_code(code).encode()).hexdigest()
    if h in hashed:
        hashed.remove(h)
        return True, json.dumps(hashed)
    return False, hashed_json
