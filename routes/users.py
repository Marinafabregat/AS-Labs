from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import aliased
from sqlmodel import Session, select

from auth import (
    get_current_active_user,
    get_current_user,
    get_current_user_optional,
    hash_password,
    verify_password,
)
from db import get_session
from models import Item, ItemReport, ModPetition, ReportStatus, User, UserReport, UserRole
from security_encryption import encrypt_pii, decrypt_pii
from template_context import templates

router = APIRouter(prefix="/users", tags=["Users"])


# REGISTER

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render the registration HTML form."""
    return templates.TemplateResponse(request, "users/register.html")

@router.post("/register")
async def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    """Handle user registration without PII delivery data."""
    existing_user = session.exec(
        select(User).where((User.username == username) | (User.email == email))
    ).first()

    if existing_user:
        return templates.TemplateResponse(
            request,
            "users/register.html",
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
        role=UserRole.USER,
    )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    request.session["user_id"] = str(new_user.id)
    return RedirectResponse(url="/users/profile", status_code=status.HTTP_302_FOUND)


# LOGIN & LOGOUT

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, registered: Optional[bool] = None):
    """Render the login HTML form."""
    return templates.TemplateResponse(
        request, "users/login.html", {"registered": registered}
    )


@router.post("/login")
async def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    """Authenticate user and store user_id in session."""
    user = session.exec(select(User).where(User.username == username)).first()

    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request,
            "users/login.html",
            {"error": "Invalid username or password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if user.is_blacklisted:
        return templates.TemplateResponse(
            request,
            "users/login.html",
            {"error": "Account is blacklisted. Access denied."},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    request.session["user_id"] = str(user.id)
    return RedirectResponse(url="/users/profile", status_code=status.HTTP_302_FOUND)


@router.get("/logout")
async def logout(request: Request):
    """Clear session and redirect to login."""
    request.session.clear()
    return RedirectResponse(url="/users/login", status_code=status.HTTP_302_FOUND)


# PROFILE & UPDATE

@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
):
    """Display profile page with decrypted PII delivery info for the user."""
    # Decrypt sensitive fields for template rendering view
    user_data = {
        **current_user.model_dump(),
        "delivery_address_line1": decrypt_pii(current_user.delivery_address_line1),
        "delivery_address_line2": decrypt_pii(current_user.delivery_address_line2),
        "postal_code": decrypt_pii(current_user.postal_code),
        "city": decrypt_pii(current_user.city),
        "country": decrypt_pii(current_user.country),
        "phone_number": decrypt_pii(current_user.phone_number),
    }

    return templates.TemplateResponse(
        request, "users/profile.html", {"user": user_data}
    )


@router.post("/update")
async def update_profile(
    request: Request,
    email: str = Form(...),
    address_line1: Optional[str] = Form(None),
    address_line2: Optional[str] = Form(None),
    postal_code: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    country: Optional[str] = Form(None),
    phone_number: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Update profile details and encrypt sensitive delivery PII before committing."""
    if email != current_user.email:
        email_check = session.exec(
            select(User).where(User.email == email, User.id != current_user.id)
        ).first()
        if email_check:
            return templates.TemplateResponse(
                request,
                "users/profile.html",
                {
                    "user": current_user,
                    "error": "Email is already in use by another account.",
                },
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        current_user.email = email

    # Encrypt each PII field before saving to DB
    current_user.delivery_address_line1 = encrypt_pii(address_line1)
    current_user.delivery_address_line2 = encrypt_pii(address_line2)
    current_user.postal_code = encrypt_pii(postal_code)
    current_user.city = encrypt_pii(city)
    current_user.country = encrypt_pii(country)
    current_user.phone_number = encrypt_pii(phone_number)

    if password and password.strip():
        current_user.hashed_password = hash_password(password)

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    # Prepare decrypted user view for template response
    user_data = {
        **current_user.model_dump(),
        "delivery_address_line1": address_line1,
        "delivery_address_line2": address_line2,
        "postal_code": postal_code,
        "city": city,
        "country": country,
        "phone_number": phone_number,
    }

    return templates.TemplateResponse(
        request,
        "users/profile.html",
        {
            "user": user_data,
            "success": "Profile and delivery info updated securely!",
        },
    )


# MODERATOR PETITION

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
        "users/mod_petition.html",
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
            "users/mod_petition.html",
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
            "users/mod_petition.html",
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


# DELETE ACCOUNT

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

# PUBLIC PROFILE & USER REPORTS

@router.get("/{user_id}", response_class=HTMLResponse)
async def public_profile(
    request: Request,
    user_id: UUID,
    current_user: Optional[User] = Depends(get_current_user_optional),
    session: Session = Depends(get_session),
):
    """Show public account details and active listings without exposing private data."""
    profile_user = session.get(User, user_id)
    if not profile_user:
        raise HTTPException(status_code=404, detail="User not found")

    items = session.exec(
        select(Item).where(
            Item.seller_id == profile_user.id,
            Item.is_blacklisted.is_(False),
        )
    ).all()

    return templates.TemplateResponse(
        request,
        "users/public_profile.html",
        {
            "user": current_user,
            "profile_user": profile_user,
            "items": items,
            "reported_success": request.query_params.get("reported") == "true",
        },
    )


@router.post("/{user_id}/report")
async def report_user(
    user_id: UUID,
    reason: str = Form(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Save a report about another user for moderator review."""
    target_user = session.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot report yourself")

    user_report = UserReport(
        target_user_id=target_user.id,
        reporter_id=current_user.id,
        reason=reason.strip() or "No reason provided",
    )
    session.add(user_report)
    session.commit()

    return RedirectResponse(
        url=f"/users/{target_user.id}?reported=true",
        status_code=status.HTTP_302_FOUND,
    )