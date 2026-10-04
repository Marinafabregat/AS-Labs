import os
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from sqlmodel import Session, select
from db import engine
from models import User,UserRole
from service import OAuth2PasswordBearerWithCookie
from typing import Optional
from service import oauth2_scheme
from uuid import UUID
from dotenv import load_dotenv

SECRET_KEY = os.getenv("PROJECT_SECRET_KEY", "backupsecretkeyforsapp")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

#oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="cookie")


#Handles Salting internally (in the argon doc))
def hash_password(password: str) -> str:
    password = password[:72]
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    password = password[:72]
    return pwd_context.verify(password, hashed_password)

def create_access_token(user: User, expires_delta: timedelta | None = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": str(user.id),
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
            
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    try:
        user_uuid = UUID(user_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user token"
        )
    with Session(engine) as session:
        user = session.get(User, user_uuid)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )
        return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    """
    Dependency to ensure the current user is an active Admin.
    """
    if user.is_blacklisted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Your account has been blacklisted."
        )
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Admin privileges required."
        )
    return user


def require_moderator(user: User = Depends(get_current_user)) -> User:
    """
    Dependency to ensure the current user is at least a Moderator 
    (allows both Moderators and Admins).
    """
    if user.is_blacklisted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Your account has been blacklisted."
        )
    # Admins inherit moderator powers, so we allow both MODERATOR and ADMINs
    if user.role not in [UserRole.MODERATOR, UserRole.ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Moderator privileges required."
        )
    return user

def get_current_active_user(user: User = Depends(get_current_user)) -> User: #check not blacklisted
    if user.is_blacklisted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Your account has been blacklisted. Access denied."
        )
    return user

def get_current_user_optional(token: str = Depends(oauth2_scheme)) -> Optional[User]:
    """Return user if valid JWT present, else None (no error)."""
    if not token:
        return None

    try:
        payload = decode_access_token(token)
        user_id_str = payload.get("sub")
        if not user_id_str:
            return None

        user_id = UUID(user_id_str)
    except (jwt.InvalidTokenError, ValueError):
        return None

    with Session(engine) as session:
        user = session.get(User, user_id)
        return user