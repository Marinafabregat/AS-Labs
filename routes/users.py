from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select, delete

from auth import (
    get_current_active_user,
    get_current_user_optional,
    hash_password,
    verify_password,
)
from authz import (
    can,
    enforce,
    item_attrs,
    login_attrs,
    report_create_attrs,
    role_of,
    user_pii_attrs,
    user_profile_attrs,
)
from db import get_session
from models import (
    Item,
    ModPetition,
    ReportStatus,
    User,
    UserReport,
    UserRole,
)
from security_encryption import decrypt_pii, encrypt_pii
from template_context import templates
import re


router = APIRouter(prefix="/users", tags=["Users"])

PII_FIELDS = (
    "delivery_address_line1",
    "delivery_address_line2",
    "postal_code",
    "city",
    "country",
    "phone_number",
)

MIN_PASSWORD_LENGTH = 8
MAX_REASON_LENGTH = 500
MAX_PETITION_MESSAGE_LENGTH = 1000


def _role_value(user: User) -> str:
    """Return the role as a string, whether it is an Enum or a plain string."""
    role = user.role
    return role.value if hasattr(role, "value") else str(role)


def _profile_view(user: User, pii: Optional[dict] = None) -> dict:
    """DTO for templates. Never includes the password hash or OAuth tokens."""
    pii_values = {field: None for field in PII_FIELDS}

    if pii:
        pii_values.update(pii)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": _role_value(user),
        "created_at": user.created_at,
        "has_password": user.hashed_password is not None,
        "oauth_provider": user.oauth_provider,
        "is_banned": user.is_banned,
        "is_blacklisted": user.is_blacklisted,
        **pii_values,
    }


def _latest_mod_petition(
    session: Session,
    user_id: UUID,
) -> Optional[ModPetition]:
    """Return the most recent moderator application of the user."""
    return session.exec(
        select(ModPetition)
        .where(ModPetition.user_id == user_id)
        .order_by(
            ModPetition.created_at.desc(),
            ModPetition.id.desc(),
        )
    ).first()


def _petition_attrs(user_id: UUID) -> dict:
    """Resource attributes for moderator application policies."""
    return {"owner_id": str(user_id)}


def _render_profile_error(
    request: Request,
    current_user: User,
    session: Session,
    message: str,
    submitted_pii: Optional[dict] = None,
):
    """Re-render the profile page with a validation error."""
    petition = _latest_mod_petition(session, current_user.id)

    if submitted_pii is None:
        pii = {
            field: decrypt_pii(getattr(current_user, field))
            for field in PII_FIELDS
        }
    else:
        pii = submitted_pii

    return templates.TemplateResponse(
        request=request,
        name="users/profile.html",
        context={
            "user": _profile_view(current_user, pii),
            "petition": petition,
            "has_mod_petition": petition is not None,
            "error": message,
        },
        status_code=status.HTTP_400_BAD_REQUEST,
    )


# ---------------------------------------------------------
# REGISTRATION
# ---------------------------------------------------------


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="users/register.html",
    )


@router.post("/register")
async def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    # XACML decides whether an anonymous subject may create an account.
    enforce(None, "create", "user", {})
    """Handle user registration without PII delivery data."""
    if (
      len(password) < 8
      or not re.search(r"[A-Z]", password)
      or not re.search(r"[0-9]", password)
      or not re.search(r"[\W_]", password)
    ):
        return templates.TemplateResponse(
            request,
            "users/register.html",
            {
                "error": (
                    "Password must be at least 8 characters long and include an"
                    " uppercase letter, a number, and a special character."
                ),
                "username": username,
                "email": email,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    existing_user = session.exec(
        select(User).where((User.username == username) | (User.email == email))
    ).first()

    username = username.strip()
    email = email.strip().lower()

    error = None

    if len(password) < MIN_PASSWORD_LENGTH:
        error = (
            f"La contraseña debe tener al menos "
            f"{MIN_PASSWORD_LENGTH} caracteres."
        )
    elif not username or "@" not in email:
        error = "Datos de registro no válidos."
    else:
        existing = session.exec(
            select(User).where(
                (User.username == username)
                | (User.email == email)
            )
        ).first()

        if existing:
            error = "Username or email is already registered."

    if error:
        return templates.TemplateResponse(
            request=request,
            name="users/register.html",
            context={
                "error": error,
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

    request.session.clear()
    request.session["user_id"] = str(new_user.id)

    return RedirectResponse(
        url="/users/profile",
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------
# LOGIN AND LOGOUT
# ---------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    registered: Optional[bool] = None,
):
    return templates.TemplateResponse(
        request=request,
        name="users/login.html",
        context={"registered": registered},
    )


@router.post("/login")
async def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    user = session.exec(
        select(User).where(User.username == username.strip())
    ).first()

    # Verifying the credentials is authentication, not authorization.
    if (
        not user
        or not user.hashed_password
        or not verify_password(password, user.hashed_password)
    ):
        return templates.TemplateResponse(
            request=request,
            name="users/login.html",
            context={"error": "Invalid username or password."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # XACML decides whether this account is allowed to start a session.
    # Banned or suspended accounts receive 403 from enforce().
    enforce(user, "login", "user", login_attrs(user))

    request.session.clear()
    request.session["user_id"] = str(user.id)

    return RedirectResponse(
        url="/users/profile",
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/logout")
async def logout(request: Request):
    # Ending one's own session does not require an authorization decision.
    request.session.clear()

    return RedirectResponse(
        url="/users/login",
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------
# PROFILE AND UPDATE
# ---------------------------------------------------------


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # XACML decides whether the user may read their own personal data.
    enforce(
        current_user,
        "read",
        "user_pii",
        user_pii_attrs(current_user),
    )

    pii = {
        field: decrypt_pii(getattr(current_user, field))
        for field in PII_FIELDS
    """Display profile page with decrypted PII delivery info for the user."""
    #decrypt sensitive fields
    user_data = {
        **current_user.model_dump(),
        "delivery_address_line1": decrypt_pii(current_user.delivery_address_line1),
        "delivery_address_line2": decrypt_pii(current_user.delivery_address_line2),
        "postal_code": decrypt_pii(current_user.postal_code),
        "city": decrypt_pii(current_user.city),
        "country": decrypt_pii(current_user.country),
        "phone_number": decrypt_pii(current_user.phone_number),
    } }

    petition = _latest_mod_petition(session, current_user.id)

    context = {
        "user": _profile_view(current_user, pii),
        "petition": petition,
        "has_mod_petition": petition is not None,
    }

    if request.query_params.get("updated") == "true":
        context["success"] = "Perfil actualizado correctamente."

    return templates.TemplateResponse(
        request=request,
        name="users/profile.html",
        context=context,
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
    current_password: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # XACML decides whether the user may update their personal data.
    enforce(
        current_user,
        "update",
        "user_pii",
        user_pii_attrs(current_user),
    )

    email = email.strip().lower()
    new_password = password if password and password.strip() else None

    if password and password.strip():
        if (
              len(password) < 8
              or not re.search(r"[A-Z]", password)
              or not re.search(r"[0-9]", password)
              or not re.search(r"[\W_]", password)
            ):
                return templates.TemplateResponse(
                    request,
                    "users/profile.html",
                    {
                        "error": (
                            "Password must be at least 8 characters long and include an"
                            " uppercase letter, a number, and a special character."
                        ),
                        "user": current_user,
                    },
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
        
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

    email_changed = email != current_user.email

    # Changing email or password requires the current password.
    if (email_changed or new_password) and current_user.hashed_password:
        if (
            not current_password
            or not verify_password(
                current_password,
                current_user.hashed_password,
            )
        ):
            return _render_profile_error(
                request,
                current_user,
                session,
                "Confirma tu contraseña actual para cambiar el email o la contraseña.",
                submitted_pii,
            )

    if "@" not in email:
        return _render_profile_error(
            request,
            current_user,
            session,
            "Email no válido.",
            submitted_pii,
        )

    if new_password and len(new_password) < MIN_PASSWORD_LENGTH:
        return _render_profile_error(
            request,
            current_user,
            session,
            (
                f"La contraseña debe tener al menos "
                f"{MIN_PASSWORD_LENGTH} caracteres."
            ),
            submitted_pii,
        )

    if email_changed:
        taken = session.exec(
            select(User).where(
                User.email == email,
                User.id != current_user.id,
            )
        ).first()

        if taken:
            return _render_profile_error(
                request,
                current_user,
                session,
                "Email no disponible.",
                submitted_pii,
            )

        current_user.email = email

    if new_password:
        current_user.hashed_password = hash_password(new_password)

    for field, value in submitted_pii.items():
        setattr(
            current_user,
            field,
            encrypt_pii((value or "").strip() or None),
        )

    session.add(current_user)
    session.commit()

    return RedirectResponse(
        url="/users/profile?updated=true",
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------
# MODERATOR APPLICATIONS
# ---------------------------------------------------------


@router.get("/mod-petition", response_class=HTMLResponse)
async def mod_petition_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    enforce(
        current_user,
        "read",
        "mod_petition",
        _petition_attrs(current_user.id),
    )

    existing_petition = _latest_mod_petition(
        session,
        current_user.id,
    )

    return templates.TemplateResponse(
        request=request,
        name="users/mod_petition.html",
        context={
            "user": _profile_view(current_user),
            "petition": existing_petition,
            "cancelled": (
                request.query_params.get("cancelled") == "true"
            ),
        },
    )


@router.post("/mod-petition")
async def submit_mod_petition(
    request: Request,
    message: str = Form(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # XACML decides whether this subject may submit an application.
    # The "user" role check lives in the policy, not in this function.
    enforce(
        current_user,
        "create",
        "mod_petition",
        _petition_attrs(current_user.id),
    )

    existing_petition = _latest_mod_petition(
        session,
        current_user.id,
    )

    # Business rule: do not allow a second application while one is pending.
    if existing_petition and not existing_petition.Reviewed:
        return templates.TemplateResponse(
            request=request,
            name="users/mod_petition.html",
            context={
                "user": _profile_view(current_user),
                "petition": existing_petition,
                "error": (
                    "You already have a pending moderator application."
                ),
            },
            status_code=status.HTTP_409_CONFLICT,
        )

    cleaned_message = message.strip()[:MAX_PETITION_MESSAGE_LENGTH]

    if not cleaned_message:
        return templates.TemplateResponse(
            request=request,
            name="users/mod_petition.html",
            context={
                "user": _profile_view(current_user),
                "petition": existing_petition,
                "error": (
                    "Please provide a message explaining your application."
                ),
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    new_petition = ModPetition(
        user_id=current_user.id,
        message=cleaned_message,
    )

    session.add(new_petition)
    session.commit()

    return RedirectResponse(
        url="/users/mod-petition",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/mod-petition/cancel")
async def cancel_mod_petition(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    petition = _latest_mod_petition(session, current_user.id)

    # Authorize first, so the response does not reveal whether a petition exists.
    enforce(
        current_user,
        "delete",
        "mod_petition",
        _petition_attrs(current_user.id),
    )

    if petition is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Moderator application not found.",
        )

    # Business rule: a reviewed application cannot be cancelled.
    if petition.Reviewed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A reviewed application cannot be cancelled.",
        )

    session.delete(petition)
    session.commit()

    return RedirectResponse(
        url="/users/mod-petition?cancelled=true",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# ---------------------------------------------------------
# ACCOUNT DELETION
# ---------------------------------------------------------


@router.post("/delete")
async def delete_account(
    request: Request,
    password: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    enforce(
        current_user,
        "delete",
        "user_pii",
        user_pii_attrs(current_user),
    )

    if current_user.hashed_password:
        if not password or not verify_password(
            password,
            current_user.hashed_password,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
            )

    # Remove reports where the user is either the target or the reporter.
    session.exec(
        delete(UserReport).where(
            (UserReport.target_user_id == current_user.id)
            | (UserReport.reporter_id == current_user.id)
        )
    )

    session.delete(current_user)
    session.commit()

    request.session.clear()

    return RedirectResponse(
        url="/users/login?deleted=true",
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------
# PUBLIC PROFILE AND USER REPORTS
# ---------------------------------------------------------


@router.get("/{user_id}", response_class=HTMLResponse)
async def public_profile(
    request: Request,
    user_id: UUID,
    current_user: Optional[User] = Depends(get_current_user_optional),
    session: Session = Depends(get_session),
):
    profile_user = session.get(User, user_id)

    # Same 404 whether the user does not exist or the viewer may not see it,
    # so the endpoint cannot be used to enumerate accounts.
    if not profile_user or not can(
        current_user,
        "read",
        "user_profile",
        user_profile_attrs(profile_user),
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    all_seller_items = session.exec(
        select(Item).where(Item.seller_id == profile_user.id)
    ).all()

    # XACML decides which of the seller's items the visitor may see.
    items = [
        item
        for item in all_seller_items
        if can(
            current_user,
            "read",
            "item",
            item_attrs(item),
        )
    ]

    # Public DTO: no email, personal data or hash.
    public_view = {
        "id": profile_user.id,
        "username": profile_user.username,
        "created_at": profile_user.created_at,
    }

    return templates.TemplateResponse(
        request=request,
        name="users/public_profile.html",
        context={
            "user": current_user,
            "profile_user": public_view,
            "items": items,
            "reported_success": (
                request.query_params.get("reported") == "true"
            ),
        },
    )


@router.post("/{user_id}/report")
async def report_user(
    user_id: UUID,
    reason: str = Form(...),
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    target_user = session.get(User, user_id)

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Authorize first, so the response does not reveal the target's state.
    report_attrs = report_create_attrs(target_user.id, role_of(target_user))

    enforce(
        current_user,
        "create",
        "report",
        report_attrs,
    )

    cleaned_reason = reason.strip()

    if not cleaned_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a reason for the report.",
        )

    # XACML decides whether this report is escalated straight to admins.
    escalated = can(
        current_user,
        "create_escalated",
        "report",
        report_attrs,
    )

    report_status = (
        ReportStatus.FOR_ADMIN
        if escalated
        else ReportStatus.PENDING
    )

    new_report = UserReport(
        target_user_id=target_user.id,
        reporter_id=current_user.id,
        reason=cleaned_reason[:MAX_REASON_LENGTH],
        status=report_status,
    )

    session.add(new_report)

    # Only block the target account if the policy allows escalation.
    if escalated:
        target_user.is_blacklisted = True
        session.add(target_user)

    session.commit()

    return RedirectResponse(
        url=f"/users/{target_user.id}?reported=true",
        status_code=status.HTTP_302_FOUND,
    )