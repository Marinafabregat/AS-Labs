import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from auth import get_current_active_user
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


@router.get("/callback")
async def google_callback(
    request: Request,
    session: Session = Depends(get_session),
):
    # Identity verification (token and email) is authentication, so it stays here.
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as exc:
        log.warning("OAuth error: %s", exc)
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
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"error": "Could not retrieve user info from Google"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # An unverified Google email must not be linked to an existing account.
    if not userinfo.get("email_verified", False):
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"error": "Tu cuenta de Google no tiene el email verificado."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    email = userinfo["email"].strip().lower()
    oauth_id = userinfo["sub"]

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

    # Case 2: an existing account with the same email. Linking needs confirmation.
    existing_user = session.exec(select(User).where(User.email == email)).first()

    if existing_user:
        if not _may_login(existing_user):
            return _login_denied(request)

        request.session["pending_oauth_link"] = {
            "email": email,
            "oauth_id": oauth_id,
            "access_token": encrypt_secret(token.get("access_token")),
            "refresh_token": encrypt_secret(token.get("refresh_token")),
            "name": userinfo.get("name", ""),
            "picture": userinfo.get("picture", ""),
        }
        return RedirectResponse(url="/auth/link", status_code=status.HTTP_302_FOUND)

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


@router.get("/link", response_class=HTMLResponse)
async def link_account_page(request: Request):
    # Shows only the pending link data stored in this visitor's own session.
    oauth_data = request.session.get("pending_oauth_link")

    if not oauth_data:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="auth/link.html",
        context={"oauth_data": oauth_data},
    )


@router.get("/cancel")
async def cancel_link(request: Request):
    request.session.pop("pending_oauth_link", None)
    return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)


@router.post("/link")
async def link_account_confirm(
    request: Request,
    session: Session = Depends(get_session),
):
    oauth_data = request.session.pop("pending_oauth_link", None)

    if not oauth_data:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    user = session.exec(
        select(User).where(User.email == oauth_data["email"])
    ).first()

    if not user:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    # Linking ends in a session, so it requires the same "login" decision.
    if not _may_login(user):
        return _login_denied(request)

    # Data integrity: one Google identity can be linked to one account only.
    other = session.exec(
        select(User).where(
            User.oauth_id == oauth_data["oauth_id"],
            User.id != user.id,
        )
    ).first()

    if other:
        return templates.TemplateResponse(
            request=request,
            name="auth/login.html",
            context={"error": "Esta cuenta de Google ya está vinculada a otro usuario."},
            status_code=status.HTTP_409_CONFLICT,
        )

    user.oauth_provider = "google"
    user.oauth_id = oauth_data["oauth_id"]
    # Tokens were already encrypted in the callback.
    user.oauth_access_token = oauth_data["access_token"]
    user.oauth_refresh_token = oauth_data["refresh_token"]

    if not user.username:
        user.username = oauth_data["name"] or oauth_data["email"].split("@")[0]

    session.add(user)
    session.commit()

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