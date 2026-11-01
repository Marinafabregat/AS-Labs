from typing import Optional
from uuid import UUID
import secrets
from fastapi import Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlmodel import Session

from authz import account_attrs, can, enforce
from db import get_session
from models import User


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Kept so that existing password hashes keep verifying.
MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    return pwd_context.hash(password[:MAX_PASSWORD_BYTES])


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password[:MAX_PASSWORD_BYTES], hashed_password)


def _session_user_id(request: Request) -> Optional[UUID]:
    """Return the user id stored in the session, or None if it is missing or malformed."""
    raw = request.session.get("user_id")

    if not raw:
        return None

    try:
        return UUID(raw)
    except (TypeError, ValueError):
        return None


def get_current_user(
    request: Request,
    session: Session = Depends(get_session),
) -> User:
    """Authentication only: a valid session must point to an existing user."""
    user_id = _session_user_id(request)

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = session.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


def get_current_user_optional(
    request: Request,
    session: Session = Depends(get_session),
) -> Optional[User]:
    """
    An account that XACML does not allow to use the application (banned or
    suspended) is treated as anonymous on public pages.
    """
    user_id = _session_user_id(request)

    if user_id is None:
        return None

    user = session.get(User, user_id)

    if user is None:
        return None

    # XACML decides whether this account may act at all.
    if not can(user, "session", "account", account_attrs(user)):
        return None

    return user


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    enforce(user, "session", "account", account_attrs(user))
    return user

def get_or_create_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        request.session["csrf_token"] = token
    return token

def verify_csrf(request: Request, client_token: str):
    """Verify that the client-submitted token matches the session token."""
    session_token = request.session.get("csrf_token")
    if not session_token or not client_token or not secrets.compare_digest(session_token, client_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid.",
        )