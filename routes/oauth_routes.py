import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from auth import get_current_active_user, get_current_user_optional
from authz import can, enforce, login_attrs, user_pii_attrs
from db import get_session
from models import User
from oauth import oauth
from security_encryption import encrypt_secret
from template_context import templates


log = logging.getLogger("oauth")
router = APIRouter(prefix="/auth", tags=["Auth"])

# Generic on purpose: XACML returns Permit or Deny, not the reason.
LOGIN_DENIED_MESSAGE = (
    "Access to this account is restricted. Contact an administrator."
)


def _may_login(user: User) -> bool:
    """Ask XACML whether this account may start a session."""
    return can(user, "login", "user", login_attrs(user))


def _login_denied(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="auth/login.html",
        context={"error": LOGIN_DENIED_MESSAGE},
        status_code=status.HTTP_403_FORBIDDEN,
    )


def _profile_link_redirect(error: Optional[str] = None):
    """Return to the user panel, optionally reporting a link error code."""
    url = "/users/profile"

    if error:
        url = f"{url}?link_error={error}"

    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="auth/login.html",
    )


@router.get("/google")
async def google_login(request: Request):
    # Starts the OAuth redirect. It exposes no data; the decision happens
    # in the callback, once the Google identity is known.
    redirect_uri = (
        os.getenv("GOOGLE_REDIRECT_URI")
        or str(request.url_for("google_callback"))
    )
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/link")
async def google_link(
    request: Request,
    current_user: User = Depends(get_current_active_user),
):
    # Linking is only possible from an authenticated panel session.
    enforce(
        current_user,
        "update",
        "user_pii",
        user_pii_attrs(current_user),
    )

    if current_user.oauth_provider == "google":
        return RedirectResponse(url="/users/profile", status_code=status.HTTP_302_FOUND)

    # The callback uses this flag to link instead of starting a new login.
    request.session["oauth_link_user_id"] = str(current_user.id)

    redirect_uri = (
        os.getenv("GOOGLE_REDIRECT_URI")
        or str(request.url_for("google_callback"))
    )
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/callback")
async def google_callback(
    request: Request,
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    # The intent is single-use: remove it even if the exchange fails.
    link_user_id = request.session.pop("oauth_link_user_id", None)
    is_link = link_user_id is not None

    # A link request only makes sense for the account that started it.
    if is_link and (
        current_user is None or str(current_user.id) != link_user_id
    ):
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    # Identity verification (token and email) is authentication, so it stays here.
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as exc:
        log.warning("OAuth error: %s", exc)
        if is_link:
            return _profile_link_redirect("oauth_error")
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"error": "No se pudo completar el inicio de sesión con Google."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    userinfo = token.get("userinfo")

    if not userinfo:
        userinfo = await oauth.google.parse_id_token(request, token)

    if not userinfo or "email" not in userinfo:
        if is_link:
            return _profile_link_redirect("oauth_error")
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"error": "Could not retrieve user info from Google"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # An unverified Google email must not be linked to an existing account.
    if not userinfo.get("email_verified", False):
        if is_link:
            return _profile_link_redirect("email_not_verified")
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"error": "Tu cuenta de Google no tiene el email verificado."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    email = userinfo["email"].strip().lower()
    oauth_id = userinfo["sub"]

    # Linking started from the user panel: only for the same email.
    if is_link:
        enforce(
            current_user,
            "update",
            "user_pii",
            user_pii_attrs(current_user),
        )

        if email != current_user.email.strip().lower():
            return _profile_link_redirect("email_mismatch")

        # Data integrity: one Google identity can be linked to one account only.
        other = session.exec(
            select(User).where(
                User.oauth_id == oauth_id,
                User.id != current_user.id,
            )
        ).first()

        if other:
            return _profile_link_redirect("already_linked")

        current_user.oauth_provider = "google"
        current_user.oauth_id = oauth_id
        current_user.oauth_access_token = encrypt_secret(token.get("access_token"))
        current_user.oauth_refresh_token = encrypt_secret(token.get("refresh_token"))

        session.add(current_user)
        session.commit()

        return RedirectResponse(
            url="/users/profile?linked=true",
            status_code=status.HTTP_302_FOUND,
        )

    # Case 1: a known Google identity.
    user = session.exec(select(User).where(User.oauth_id == oauth_id)).first()

    if user:
        if not _may_login(user):
            return _login_denied(request)

        user.oauth_access_token = encrypt_secret(token.get("access_token"))
        user.oauth_refresh_token = encrypt_secret(token.get("refresh_token"))
        session.add(user)
        session.commit()

        request.session.clear()
        request.session["user_id"] = str(user.id)
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    # Case 2: an existing account with the same email. Linking is only allowed
    # from the authenticated user panel, so do not link here.
    existing_user = session.exec(select(User).where(User.email == email)).first()

    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={
                "error": (
                    "Ya existe una cuenta con este email. Inicia sesión con "
                    "tu contraseña y vincula Google desde tu perfil."
                )
            },
            status_code=status.HTTP_409_CONFLICT,
        )

    # Case 3: a new account. Registration is an anonymous "create" decision.
    enforce(None, "create", "user", {})

    username_base = email.split("@")[0][:40]
    username = username_base
    counter = 1

    while session.exec(select(User).where(User.username == username)).first():
        username = f"{username_base}{counter}"
        counter += 1

    user = User(
        username=username,
        email=email,
        hashed_password=None,
        oauth_provider="google",
        oauth_id=oauth_id,
        oauth_access_token=encrypt_secret(token.get("access_token")),
        oauth_refresh_token=encrypt_secret(token.get("refresh_token")),
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    request.session.clear()
    request.session["user_id"] = str(user.id)
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.post("/unlink")
async def unlink_google(
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # Changing one's own linked identity is an owner-only decision.
    enforce(
        current_user,
        "update",
        "user_pii",
        user_pii_attrs(current_user),
    )

    if current_user.oauth_provider is None:
        return RedirectResponse(url="/users/profile", status_code=status.HTTP_302_FOUND)

    # Business rule: without a password the account would become unreachable.
    if current_user.hashed_password is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puedes desvincular Google: la cuenta no tiene contraseña.",
        )

    current_user.oauth_provider = None
    current_user.oauth_id = None
    current_user.oauth_access_token = None
    current_user.oauth_refresh_token = None

    session.add(current_user)
    session.commit()

    return RedirectResponse(url="/users/profile", status_code=status.HTTP_302_FOUND)


@router.get("/logout")
async def logout(request: Request):
    # Ending one's own session needs no authorization decision.
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)