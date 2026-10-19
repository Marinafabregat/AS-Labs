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

router = APIRouter(prefix="/admin", tags=["Admin"])

# ADMIN REPORTS


def _require_admin(current_user: User) -> None:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )

@router.get("/admin-reports", response_class=HTMLResponse)
async def admin_reports_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Show escalated user and item reports for administrator review."""
    _require_admin(current_user)

    target_user = aliased(User)
    user_reporter = aliased(User)
    user_reports = session.exec(
        select(UserReport, target_user, user_reporter)
        .join(target_user, UserReport.target_user_id == target_user.id)
        .join(user_reporter, UserReport.reporter_id == user_reporter.id)
        .where(UserReport.status == ReportStatus.FOR_ADMIN)
        .order_by(UserReport.created_at.desc())
    ).all()

    item_seller = aliased(User)
    item_reporter = aliased(User)
    item_reports = session.exec(
        select(ItemReport, Item, item_seller, item_reporter)
        .join(Item, ItemReport.item_id == Item.id)
        .join(item_seller, Item.seller_id == item_seller.id)
        .join(item_reporter, ItemReport.reporter_id == item_reporter.id)
        .where(ItemReport.status == ReportStatus.FOR_ADMIN)
        .order_by(ItemReport.created_at.desc())
    ).all()

    return templates.TemplateResponse(
        request,
        "users/admin_reports.html",
        {
            "user": current_user,
            "user_reports": user_reports,
            "item_reports": item_reports,
        },
    )

@router.post("/admin-reports/users/{user_id}/delete")
async def admin_delete_user(
    user_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Delete a reported user and update associated reports."""
    _require_admin(current_user)
    target_user = session.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    session.delete(target_user)
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
    )

@router.post("/admin-reports/items/{item_id}/delete")
async def admin_delete_item(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Delete a reported item from the platform."""
    _require_admin(current_user)
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    session.delete(item)
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
    )
