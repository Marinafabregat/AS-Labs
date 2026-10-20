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

# MODERATOR REPORTS


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
    """Show moderator petitions and escalated reports for administrator review."""
    _require_admin(current_user)

    mod_petitions = session.exec(
        select(ModPetition, User)
        .join(User, ModPetition.user_id == User.id)
        .where(ModPetition.Reviewed.is_(False))
        .order_by(ModPetition.created_at.asc())
    ).all()

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

    banned_users = session.exec(
        select(User)
        .where(User.is_banned.is_(True))
        .order_by(User.username.asc())
    ).all()

    return templates.TemplateResponse(
        request,
        "users/admin_reports.html",
        {
            "user": current_user,
            "mod_petitions": mod_petitions,
            "user_reports": user_reports,
            "item_reports": item_reports,
            "banned_users": banned_users,
        },
    )

@router.post("/admin-reports/users/{report_id}/ban")
async def admin_ban_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Confirm the permanent ban of a user escalated by a moderator."""
    _require_admin(current_user)
    report = session.get(UserReport, report_id)
    if not report or report.status != ReportStatus.FOR_ADMIN:
        raise HTTPException(
            status_code=404, detail="Escalated user report not found"
        )

    target_user = session.get(User, report.target_user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Reported user not found")

    target_user.is_banned = True
    target_user.is_blacklisted = True

    active_reports = session.exec(
        select(UserReport).where(
            UserReport.target_user_id == target_user.id,
            UserReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()
    for active_report in active_reports:
        active_report.status = ReportStatus.RESOLVED
        session.add(active_report)

    session.add(target_user)
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
    )


@router.post("/admin-reports/users/{report_id}/revert")
async def admin_revert_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Revert a moderator's temporary blacklist after admin review."""
    _require_admin(current_user)
    report = session.get(UserReport, report_id)
    if not report or report.status != ReportStatus.FOR_ADMIN:
        raise HTTPException(
            status_code=404, detail="Escalated user report not found"
        )

    target_user = session.get(User, report.target_user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Reported user not found")

    if target_user.is_banned:
        raise HTTPException(
            status_code=409,
            detail="This user is permanently banned. Unban them first.",
        )

    escalated_reports = session.exec(
        select(UserReport).where(
            UserReport.target_user_id == target_user.id,
            UserReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()
    for escalated_report in escalated_reports:
        escalated_report.status = ReportStatus.DISMISSED
        session.add(escalated_report)

    target_user.is_blacklisted = False
    session.add(target_user)
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
    )


@router.post("/admin-reports/users/{user_id}/unban")
async def admin_unban_user(
    user_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Lift a permanent ban and clear any pending temporary blacklist."""
    _require_admin(current_user)
    target_user = session.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not target_user.is_banned:
        raise HTTPException(status_code=409, detail="User is not permanently banned")

    target_user.is_banned = False
    target_user.is_blacklisted = False

    active_reports = session.exec(
        select(UserReport).where(
            UserReport.target_user_id == target_user.id,
            UserReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()
    for active_report in active_reports:
        active_report.status = ReportStatus.DISMISSED
        session.add(active_report)

    session.add(target_user)
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
    )


@router.post("/mod-petitions/{petition_id}/approve")
async def approve_mod_petition(
    petition_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Approve a moderator petition and promote its applicant."""
    _require_admin(current_user)
    petition = session.get(ModPetition, petition_id)
    if not petition:
        raise HTTPException(status_code=404, detail="Moderator petition not found")
    if petition.Reviewed:
        raise HTTPException(status_code=409, detail="Moderator petition already reviewed")

    applicant = session.get(User, petition.user_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    if applicant.role != UserRole.USER:
        raise HTTPException(
            status_code=409,
            detail="Only regular users can be promoted to moderator",
        )

    applicant.role = UserRole.MODERATOR
    petition.Reviewed = True
    petition.approved = True
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
    )

@router.post("/mod-petitions/{petition_id}/reject")
async def reject_mod_petition(
    petition_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Reject a pending moderator petition."""
    _require_admin(current_user)
    petition = session.get(ModPetition, petition_id)
    if not petition:
        raise HTTPException(status_code=404, detail="Moderator petition not found")
    if petition.Reviewed:
        raise HTTPException(status_code=409, detail="Moderator petition already reviewed")

    petition.Reviewed = True
    petition.approved = False
    session.commit()
    return RedirectResponse(
        url="/admin/admin-reports", status_code=status.HTTP_302_FOUND
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

@router.post("/admin-reports/items/{report_id}/revert")
async def admin_revert_item_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    """Revert a moderator's temporary blacklist on a reported item."""
    _require_admin(current_user)
    report = session.get(ItemReport, report_id)
    if not report or report.status != ReportStatus.FOR_ADMIN:
        raise HTTPException(
            status_code=404, detail="Escalated item report not found"
        )

    item = session.get(Item, report.item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Reported item not found")

    escalated_reports = session.exec(
        select(ItemReport).where(
            ItemReport.item_id == item.id,
            ItemReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()
    for escalated_report in escalated_reports:
        escalated_report.status = ReportStatus.DISMISSED
        session.add(escalated_report)

    item.is_blacklisted = False
    session.add(item)
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
