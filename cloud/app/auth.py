"""
Auth utilities — password hashing, JWT sessions, agent token generation.
"""
import os, secrets, hashlib, time, json
from datetime import datetime, timedelta, timezone

import jwt
import bcrypt as _bcrypt
import pyotp

_IS_PROD = os.environ.get("ENV") == "production"
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    if _IS_PROD:
        # A random per-process fallback is broken under gunicorn -w N (each worker
        # signs with a different key, so sessions randomly fail) and every deploy
        # silently logs everyone out. Refuse to boot instead.
        raise RuntimeError("SECRET_KEY must be set (>=32 chars) when ENV=production")
    SECRET_KEY = secrets.token_hex(32)
ALGORITHM      = "HS256"
SESSION_EXPIRE = int(os.environ.get("SESSION_EXPIRE_HOURS", 72))


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain[:72].encode(), _bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain[:72].encode(), hashed.encode())


def create_session_token(user_id: str, token_version: int = 0) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=SESSION_EXPIRE)
    return jwt.encode({"sub": user_id, "exp": exp, "iat": now, "type": "session",
                       "tv": int(token_version or 0)}, SECRET_KEY, algorithm=ALGORITHM)


def decode_session_token(token: str) -> tuple[str, int] | None:
    """Returns (user_id, token_version) or None. The caller must compare the
    version to the user's current token_version so revoked sessions die."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM],
                             options={"require": ["exp", "sub"]})
        if payload.get("type") != "session":
            return None
        return payload["sub"], int(payload.get("tv", 0))
    except (jwt.PyJWTError, ValueError, TypeError):
        return None


def generate_agent_token() -> str:
    """Returns a raw token (store the hash, give the raw to the agent)."""
    return secrets.token_urlsafe(48)


def hash_agent_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_agent_token(raw: str, stored_hash: str) -> bool:
    import hmac
    return hmac.compare_digest(hash_agent_token(raw), stored_hash)


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


def verify_totp(secret: str, code: str, last_step: int | None = None) -> int | None:
    """Returns the matched TOTP time-step, or None. A step <= last_step is
    rejected so an observed/phished code can't be replayed inside its window."""
    if not secret or not code:
        return None
    code = str(code).strip().replace(" ", "").replace("-", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    try:
        totp = pyotp.TOTP(secret)
        now_step = int(time.time()) // totp.interval
        for step in (now_step - 1, now_step, now_step + 1):
            if last_step is not None and step <= last_step:
                continue
            if hmac_eq(totp.generate_otp(step), code):
                return step
    except Exception:
        pass
    return None


def hmac_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


# ── brute-force lockout (DB-backed, so it holds across gunicorn workers) ────
MAX_FAILURES  = int(os.environ.get("AUTH_MAX_FAILURES", 5))
LOCK_MINUTES  = int(os.environ.get("AUTH_LOCK_MINUTES", 15))


def _aware(dt):
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_locked(user) -> bool:
    lu = _aware(getattr(user, "locked_until", None))
    return bool(lu and lu > datetime.now(timezone.utc))


def record_failure(user) -> None:
    """Exponential-ish lockout: every MAX_FAILURES consecutive failures locks the
    account for LOCK_MINUTES * (round number). Caller commits."""
    user.failed_logins = int(user.failed_logins or 0) + 1
    if user.failed_logins % MAX_FAILURES == 0:
        rounds = user.failed_logins // MAX_FAILURES
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES * min(rounds, 16))


def record_success(user) -> None:
    user.failed_logins = 0
    user.locked_until = None


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
    if not code:
        return False, hashed_json
    h = hashlib.sha256(_norm_code(code).encode()).hexdigest()
    if h in hashed:
        hashed.remove(h)
        return True, json.dumps(hashed)
    return False, hashed_json
