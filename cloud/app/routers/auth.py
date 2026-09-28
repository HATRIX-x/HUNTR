"""
Auth routes — signup, login, me.
"""
import ulid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..db import get_db, User
from ..auth import hash_password, verify_password, create_session_token

router = APIRouter(prefix="/v1/auth", tags=["auth"])


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
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(409, "Email already registered")
    user = User(
        id            = str(ulid.new()),
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
def me(db: Session = Depends(get_db),
       token: str = Depends(lambda authorization=None: authorization)):
    # handled by current_user dep in callers; this is a convenience endpoint
    from ..deps import current_user
    from fastapi import Request
    return {"note": "use Authorization: Bearer <session_token>"}
