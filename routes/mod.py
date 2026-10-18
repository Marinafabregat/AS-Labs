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

router = APIRouter(prefix="/mod", tags=["mod"])

# MODERATOR REPORTS

def _require_moderator(current_user: User) -> None:
    if current_user.role != UserRole.MODERATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Moderator privileges required.",
        )

# TODO: Implement admin report review page and actions for escalated reports.
def _require_admin(current_user: User) -> None:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )


@router.get("/moderator-reports", response_class=HTMLResponse)
async def moderator_reports_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Show pending user and item reports to moderators."""
    _require_moderator(current_user)

    target_user = aliased(User)
    user_reporter = aliased(User)
    user_reports = session.exec(
        select(UserReport, target_user, user_reporter)
        .join(target_user, UserReport.target_user_id == target_user.id)
        .join(user_reporter, UserReport.reporter_id == user_reporter.id)
        .where(
            UserReport.status.in_(
                [ReportStatus.PENDING, ReportStatus.FOR_ADMIN]
            )
        )
        .order_by(UserReport.created_at.desc())
    ).all()

    item_seller = aliased(User)
    item_reporter = aliased(User)
    item_reports = session.exec(
        select(ItemReport, Item, item_seller, item_reporter)
        .join(Item, ItemReport.item_id == Item.id)
        .join(item_seller, Item.seller_id == item_seller.id)
        .join(item_reporter, ItemReport.reporter_id == item_reporter.id)
        .where(
            ItemReport.status.in_(
                [ReportStatus.PENDING, ReportStatus.FOR_ADMIN]
            )
        )
        .order_by(ItemReport.created_at.desc())
    ).all()

    return templates.TemplateResponse(
        request,
        "users/moderator_reports.html",
        {
            "user": current_user,
            "user_reports": user_reports,
            "item_reports": item_reports,
        },
    )

@router.post("/moderator-reports/users/{report_id}/dismiss")
async def dismiss_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    _require_moderator(current_user)
    report = session.get(UserReport, report_id)
    if not report or report.status != ReportStatus.PENDING:
        raise HTTPException(status_code=404, detail="Pending user report not found")

    report.status = ReportStatus.DISMISSED
    session.add(report)
    session.commit()
    return RedirectResponse(
        url="/mod/moderator-reports", status_code=status.HTTP_302_FOUND
    )


@router.post("/moderator-reports/users/{report_id}/accept")
async def accept_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    _require_moderator(current_user)
    report = session.get(UserReport, report_id)
    if not report or report.status != ReportStatus.PENDING:
        raise HTTPException(status_code=404, detail="Pending user report not found")

    target_user = session.get(User, report.target_user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Reported user not found")

    report.status = ReportStatus.FOR_ADMIN
    target_user.is_blacklisted = True
    session.add(report)
    session.add(target_user)
    session.commit()
    return RedirectResponse(
        url="/mod/moderator-reports", status_code=status.HTTP_302_FOUND
    )


@router.post("/moderator-reports/items/{report_id}/accept")
async def accept_item_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    _require_moderator(current_user)
    report = session.get(ItemReport, report_id)
    if not report or report.status != ReportStatus.PENDING:
        raise HTTPException(status_code=404, detail="Pending item report not found")

    item = session.get(Item, report.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Reported item not found")

    report.status = ReportStatus.FOR_ADMIN
    item.is_blacklisted = True
    session.add(report)
    session.add(item)
    session.commit()
    return RedirectResponse(
        url="/mod/moderator-reports", status_code=status.HTTP_302_FOUND
    )


@router.post("/moderator-reports/items/{report_id}/dismiss")
async def dismiss_item_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    _require_moderator(current_user)
    report = session.get(ItemReport, report_id)
    if not report or report.status != ReportStatus.PENDING:
        raise HTTPException(status_code=404, detail="Pending item report not found")

    item = session.get(Item, report.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Reported item not found")

    report.status = ReportStatus.DISMISSED
    still_reported = session.exec(
        select(ItemReport.id).where(
            ItemReport.item_id == item.id,
            ItemReport.status.in_(
                [ReportStatus.PENDING, ReportStatus.FOR_ADMIN]
            ),
            ItemReport.id != report.id,
        )
    ).first()
    if not still_reported:
        item.is_blacklisted = False

    session.add(report)
    session.add(item)
    session.commit()
    return RedirectResponse(
        url="/mod/moderator-reports", status_code=status.HTTP_302_FOUND
    )
