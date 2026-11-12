"""
Auth routes — signup, login, me.
"""
import json
import ulid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..db import get_db, User
from ..auth import (
    hash_password, verify_password, create_session_token,
    create_2fa_token, decode_2fa_token,
    new_totp_secret, totp_provisioning_uri, verify_totp,
    gen_backup_codes, hash_backup_codes, consume_backup_code,
)
from ..deps import current_user

router = APIRouter(prefix="/v1/auth", tags=["auth"])

# A small set of obviously-weak passwords to reject outright (defense in depth;
# the frontend strength meter is the first line, this is the enforced floor).
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "11111111", "00000000", "letmein1", "iloveyou",
    "admin123", "welcome1", "changeme", "passw0rd", "huntr123",
}


def _check_password(pw: str):
    """Enforce a real password policy server-side. Raises HTTP 400 on violation."""
    if len(pw) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    if len(pw) > 200:
        raise HTTPException(400, "Password is too long (200 characters max).")
    if pw.lower() in _COMMON_PASSWORDS:
        raise HTTPException(400, "That password is too common — choose something harder to guess.")
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if classes < 2:
        raise HTTPException(400, "Use a mix of at least two of: lowercase, uppercase, numbers, symbols.")


class SignupIn(BaseModel):
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class AuthOut(BaseModel):
    session_token: str
    user_id: str
    email: str
    plan: str


@router.post("/signup", response_model=AuthOut)
def signup(body: SignupIn, db: Session = Depends(get_db)):
    _check_password(body.password)
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(409, "Email already registered")
    user = User(
        id            = ulid.new().str,
        email         = body.email,
        password_hash = hash_password(body.password),
        plan          = "free",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return AuthOut(
        session_token = create_session_token(user.id),
        user_id       = user.id,
        email         = user.email,
        plan          = user.plan,
    )


def _auth_out(user: User) -> AuthOut:
    return AuthOut(
        session_token = create_session_token(user.id),
        user_id       = user.id,
        email         = user.email,
        plan          = user.plan,
    )


@router.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    # If 2FA is enabled, don't hand out a session yet — issue a short-lived
    # challenge token the client exchanges via /2fa/verify.
    if getattr(user, "totp_enabled", False):
        return {"twofa_required": True, "twofa_token": create_2fa_token(user.id)}
    return _auth_out(user)


@router.get("/me")
def me(user: User = Depends(current_user)):
    """Resolve the signed-in user from the Bearer session token."""
    try:
        profile = json.loads(user.profile) if getattr(user, "profile", None) else None
    except Exception:
        profile = None
    return {
        "user_id": user.id,
        "email": user.email,
        "plan": user.plan,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "twofa_enabled": bool(getattr(user, "totp_enabled", False)),
        "onboarded": bool(getattr(user, "onboarded", False)),
        "profile": profile,
    }


# ── onboarding profile ─────────────────────────────────────────────────────
class ProfileIn(BaseModel):
    role: str | None = None            # hunter | pentester | researcher | appsec | learning
    experience: str | None = None      # new | mid | senior | pro
    platforms: list[str] = []          # hackerone, bugcrowd, intigriti, private, own-assets
    goal: str | None = None            # more-bounties, save-time, coverage, learning
    referral: str | None = None        # x, friend, search, youtube, discord, other


_ALLOWED = {
    "role": {"hunter", "pentester", "researcher", "appsec", "learning"},
    "experience": {"new", "mid", "senior", "pro"},
    "platforms": {"hackerone", "bugcrowd", "intigriti", "private", "own-assets"},
    "goal": {"more-bounties", "save-time", "coverage", "learning"},
    "referral": {"x", "friend", "search", "youtube", "discord", "other"},
}


@router.post("/profile")
def save_profile(body: ProfileIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Persist the onboarding answers and mark the account onboarded.
    Values are whitelisted so the stored profile stays clean/analytics-ready."""
    data = {
        "role": body.role if body.role in _ALLOWED["role"] else None,
        "experience": body.experience if body.experience in _ALLOWED["experience"] else None,
        "platforms": [p for p in body.platforms if p in _ALLOWED["platforms"]][:5],
        "goal": body.goal if body.goal in _ALLOWED["goal"] else None,
        "referral": body.referral if body.referral in _ALLOWED["referral"] else None,
    }
    user.profile = json.dumps(data)
    user.onboarded = True
    db.add(user)
    db.commit()
    return {"ok": True, "onboarded": True, "profile": data}


# ── 2FA (TOTP) ─────────────────────────────────────────────────────────────

class TwoFAVerifyIn(BaseModel):
    twofa_token: str
    code: str


class CodeIn(BaseModel):
    code: str


@router.post("/2fa/verify")
def twofa_verify(body: TwoFAVerifyIn, db: Session = Depends(get_db)):
    """Exchange a 2fa_pending token + TOTP (or backup) code for a full session."""
    uid = decode_2fa_token(body.twofa_token)
    if not uid:
        raise HTTPException(401, "Your sign-in attempt expired — start again.")
    user = db.query(User).filter(User.id == uid).first()
    if not user or not user.totp_enabled:
        raise HTTPException(401, "Invalid request.")
    if verify_totp(user.totp_secret, body.code):
        return _auth_out(user)
    ok, remaining = consume_backup_code(body.code, user.backup_codes)
    if ok:
        user.backup_codes = remaining
        db.commit()
        return _auth_out(user)
    raise HTTPException(401, "Invalid code. Try your authenticator app or a backup code.")


@router.post("/2fa/setup")
def twofa_setup(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Begin enrollment: generate (and store) a secret, return the QR URI. 2FA is
    not active until /2fa/enable confirms a code."""
    if user.totp_enabled:
        raise HTTPException(409, "Two-factor authentication is already enabled.")
    secret = new_totp_secret()
    user.totp_secret = secret
    db.commit()
    return {"secret": secret, "otpauth_uri": totp_provisioning_uri(secret, user.email)}


@router.post("/2fa/enable")
def twofa_enable(body: CodeIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Confirm a code against the pending secret, turn 2FA on, return backup codes once."""
    if user.totp_enabled:
        raise HTTPException(409, "Two-factor authentication is already enabled.")
    if not user.totp_secret:
        raise HTTPException(400, "Start setup first.")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(401, "That code didn't match. Check your authenticator app and try again.")
    codes = gen_backup_codes()
    user.backup_codes = hash_backup_codes(codes)
    user.totp_enabled = True
    db.commit()
    return {"enabled": True, "backup_codes": codes}


@router.post("/2fa/disable")
def twofa_disable(body: CodeIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Turn 2FA off after verifying a current code (or a backup code)."""
    if not user.totp_enabled:
        return {"enabled": False}
    ok = verify_totp(user.totp_secret, body.code)
    if not ok:
        ok, remaining = consume_backup_code(body.code, user.backup_codes)
    if not ok:
        raise HTTPException(401, "Enter a valid code to turn off two-factor authentication.")
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.commit()
    return {"enabled": False}
