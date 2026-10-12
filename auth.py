from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlmodel import Session, select

from casbin_enforcer import casbin_enforcer
from db import engine, get_session
from models import User, UserRole


pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    password = password[:72]
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    password = password[:72]
    return pwd_context.verify(password, hashed_password)


def get_current_user(request: Request, session: Session = Depends(get_session)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    try:
        user_uuid = UUID(user_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user session"
        )

    user = session.get(User, user_uuid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user


def get_current_user_optional(request: Request, session: Session = Depends(get_session)) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    try:
        user_uuid = UUID(user_id)
    except Exception:
        return None
    user = session.get(User, user_uuid)
    return user


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    if user.is_blacklisted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been blacklisted. Access denied."
        )
    return user


def require_permission(resource: str, action: str):
    def dependency(user: User = Depends(get_current_active_user)) -> User:
        if not casbin_enforcer.enforce(user.role.value, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {action} on {resource}"
            )
        return user
    return dependency


require_admin = require_permission("*", "*")
require_moderator = require_permission("item", "report")


def require_admin_user(user: User = Depends(get_current_active_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required."
        )
    return user


def require_moderator_user(user: User = Depends(get_current_active_user)) -> User:
    if user.role not in [UserRole.MODERATOR, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Moderator privileges required."
        )
    return user