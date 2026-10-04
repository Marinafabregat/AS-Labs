from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from auth import (
    create_access_token,
    get_current_active_user,
    get_current_user,
    hash_password,
    verify_password,
)
from db import get_session
from models import ModPetition, User, UserRole

router = APIRouter(prefix="/users", tags=["Users"])
templates = Jinja2Templates(directory="templates")


#  REGISTER 

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render the registration HTML form."""
    return templates.TemplateResponse(request, "register.html")


@router.post("/register")
async def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    delivery_address: Optional[str] = Form(None),
    session: Session = Depends(get_session),
):
    """Handle user registration."""
    existing_user = session.exec(
        select(User).where((User.username == username) | (User.email == email))
    ).first()

    if existing_user:
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "error": "Username or email is already registered.",
                "username": username,
                "email": email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    new_user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        delivery_address=delivery_address if delivery_address else None,
        role=UserRole.USER,
    )

    session.add(new_user)
    session.commit()

    return RedirectResponse(url="/users/login?registered=true", status_code=status.HTTP_302_FOUND)


# LOGIN & LOGOUT

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, registered: Optional[bool] = None):
    """Render the login HTML form."""
    return templates.TemplateResponse(
        request, "login.html", {"registered": registered}
    )


@router.post("/login")
async def login_user(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    """Authenticate user and store access token in secure HTTP-only cookie."""
    user = session.exec(select(User).where(User.username == username)).first()

    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if user.is_blacklisted:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Account is blacklisted. Access denied."},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    access_token = create_access_token(user)

    redirect_response = RedirectResponse(
        url="/users/profile", status_code=status.HTTP_302_FOUND
    )
    redirect_response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        samesite="lax",
    )
    return redirect_response


@router.get("/logout")
async def logout():
    """Clear session cookie and redirect to login."""
    response = RedirectResponse(url="/users/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response


# PROFILE & UPDATE

@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
):
    """Display profile page for authenticated, non-blacklisted user."""
    return templates.TemplateResponse(
        request, "profile.html", {"user": current_user}
    )


@router.post("/update")
async def update_profile(
    request: Request,
    email: str = Form(...),
    delivery_address: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Update profile details (email, address, or password)."""
    if email != current_user.email:
        email_check = session.exec(
            select(User).where(User.email == email, User.id != current_user.id)
        ).first()
        if email_check:
            return templates.TemplateResponse(
                request,
                "profile.html",
                {
                    "user": current_user,
                    "error": "Email is already in use by another account.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        current_user.email = email

    current_user.delivery_address = delivery_address if delivery_address else None

    if password and password.strip():
        current_user.hashed_password = hash_password(password)

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "user": current_user,
            "success": "Profile updated successfully!",
        },
    )


# --- MODERATOR PETITION ---

@router.get("/mod-petition", response_class=HTMLResponse)
async def mod_petition_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Render page to submit or view status of moderator petitions."""
    existing_petition = session.exec(
        select(ModPetition).where(ModPetition.user_id == current_user.id)
    ).first()

    return templates.TemplateResponse(
        request,
        "mod_petition.html",
        {
            "user": current_user,
            "petition": existing_petition,
        },
    )


@router.post("/mod-petition")
async def submit_mod_petition(
    request: Request,
    message: str = Form(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Submit a petition to become a moderator."""
    if current_user.role != UserRole.USER:
        return templates.TemplateResponse(
            request,
            "mod_petition.html",
            {
                "user": current_user,
                "error": "You are already a moderator or admin.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    existing_petition = session.exec(
        select(ModPetition).where(ModPetition.user_id == current_user.id)
    ).first()

    if existing_petition:
        return templates.TemplateResponse(
            request,
            "mod_petition.html",
            {
                "user": current_user,
                "petition": existing_petition,
                "error": "You have already submitted a moderator petition.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    petition = ModPetition(
        user_id=current_user.id,
        message=message,
    )
    session.add(petition)
    session.commit()

    return RedirectResponse(
        url="/users/mod-petition", status_code=status.HTTP_302_FOUND
    )


# --- DELETE ACCOUNT ---

@router.post("/delete")
async def delete_account(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Delete own account and clear active session."""
    session.delete(current_user)
    session.commit()

    response = RedirectResponse(url="/users/login?deleted=true", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response