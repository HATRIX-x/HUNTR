"""
Auth routes — signup, login, me.
"""
import ulid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..db import get_db, User
from ..auth import hash_password, verify_password, create_session_token
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


@router.post("/login", response_model=AuthOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    return AuthOut(
        session_token = create_session_token(user.id),
        user_id       = user.id,
        email         = user.email,
        plan          = user.plan,
    )


@router.get("/me")
def me(user: User = Depends(current_user)):
    """Resolve the signed-in user from the Bearer session token."""
    return {
        "user_id": user.id,
        "email": user.email,
        "plan": user.plan,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
