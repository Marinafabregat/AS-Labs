from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select
from auth import get_current_user, get_session
from models import User
from oauth import oauth
from template_context import templates

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Show login page with both Google OAuth and password options."""
    return templates.TemplateResponse(request, "auth/login.html")


@router.get("/google")
async def google_login(request: Request):
    """Redirect to Google OAuth."""
    redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/callback")
async def google_callback(request: Request, session: Session = Depends(get_session)):
    """Handle Google OAuth callback."""
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": f"OAuth error: {str(e)}"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await oauth.google.parse_id_token(request, token)

    if not userinfo or "email" not in userinfo:
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": "Could not retrieve user info from Google"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    email = userinfo["email"]
    oauth_id = userinfo["sub"]

    # Check if user exists with this OAuth ID
    user = session.exec(select(User).where(User.oauth_id == oauth_id)).first()

    if user:
        # Update tokens
        user.oauth_access_token = token.get("access_token")
        user.oauth_refresh_token = token.get("refresh_token")
        session.add(user)
        session.commit()
        session.refresh(user)
        request.session["user_id"] = str(user.id)
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

    # Check if user exists with this email (for linking)
    existing_user = session.exec(select(User).where(User.email == email)).first()

    if existing_user:
        # Store OAuth info in session for linking confirmation
        request.session["pending_oauth_link"] = {
            "email": email,
            "oauth_id": oauth_id,
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "name": userinfo.get("name", ""),
            "picture": userinfo.get("picture", ""),
        }
        return RedirectResponse(url="/auth/link", status_code=status.HTTP_302_FOUND)

    # Create new OAuth-only user
    username_base = email.split("@")[0]
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
        oauth_access_token=token.get("access_token"),
        oauth_refresh_token=token.get("refresh_token"),
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    request.session["user_id"] = str(user.id)
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.get("/link", response_class=HTMLResponse)
async def link_account_page(request: Request):
    """Show account linking confirmation page."""
    oauth_data = request.session.get("pending_oauth_link")
    if not oauth_data:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request, "auth/link.html", {"oauth_data": oauth_data})


@router.post("/link")
async def link_account_confirm(request: Request, session: Session = Depends(get_session)):
    """Confirm linking Google account to existing user."""
    oauth_data = request.session.get("pending_oauth_link")
    if not oauth_data:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    email = oauth_data["email"]
    user = session.exec(select(User).where(User.email == email)).first()

    if user:
        user.oauth_provider = "google"
        user.oauth_id = oauth_data["oauth_id"]
        user.oauth_access_token = oauth_data["access_token"]
        user.oauth_refresh_token = oauth_data["refresh_token"]
        if not user.username:
            user.username = oauth_data["name"] or email.split("@")[0]
        session.add(user)
        session.commit()
        session.refresh(user)

    request.session.pop("pending_oauth_link", None)
    request.session["user_id"] = str(user.id)
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@router.get("/unlink")
async def unlink_google(request: Request, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    """Unlink Google account from current user."""
    if current_user.oauth_provider == "google" and current_user.hashed_password is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot unlink Google: no password set for account"
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
    """Clear session and redirect to home."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)