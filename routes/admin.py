from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import aliased
from sqlmodel import Session, select

from auth import get_current_active_user
from authz import (
    admin_target_attrs,
    enforce,
    item_attrs,
    item_report_attrs,
    petition_review_attrs,
    role_of,
    user_report_attrs,
)
from db import get_session
from models import (
    Item,
    ItemReport,
    ModPetition,
    ReportStatus,
    User,
    UserReport,
    UserRole,
)
from template_context import templates


router = APIRouter(prefix="/admin", tags=["Admin"])

ADMIN_REPORTS_URL = "/admin/admin-reports"


def _redirect_admin() -> RedirectResponse:
    return RedirectResponse(
        url=ADMIN_REPORTS_URL,
        status_code=status.HTTP_302_FOUND,
    )


def _load_user_report(session: Session, report_id: int) -> UserReport:
    report = session.get(UserReport, report_id)

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User report not found",
        )

    return report


def _load_item_report(session: Session, report_id: int) -> ItemReport:
    report = session.get(ItemReport, report_id)

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item report not found",
        )

    return report


def _load_user(session: Session, user_id: UUID) -> User:
    user = session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


def _load_item(session: Session, item_id: int) -> Item:
    item = session.get(Item, item_id)

    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found",
        )

    return item


def _load_seller(session: Session, item: Item) -> User:
    seller = session.get(User, item.seller_id)

    if not seller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Seller not found",
        )

    return seller


def _load_petition(session: Session, petition_id: int) -> ModPetition:
    petition = session.get(ModPetition, petition_id)

    if not petition:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Moderator petition not found",
        )

    return petition


def _ensure_escalated_user_report(report: UserReport) -> None:
    if report.status != ReportStatus.FOR_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Escalated user report not found",
        )


def _ensure_escalated_item_report(report: ItemReport) -> None:
    if report.status != ReportStatus.FOR_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Escalated item report not found",
        )


def _ensure_not_reviewed(petition: ModPetition) -> None:
    if petition.Reviewed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Moderator petition already reviewed",
        )

# ADMIN DASHBOARD

@router.get("/admin-reports", response_class=HTMLResponse)
async def admin_reports_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # XACML decides whether the user may open the admin area.
    enforce(current_user, "view", "admin_action", {})

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
        .join(
            target_user,
            UserReport.target_user_id == target_user.id,
        )
        .join(
            user_reporter,
            UserReport.reporter_id == user_reporter.id,
        )
        .where(UserReport.status == ReportStatus.FOR_ADMIN)
        .order_by(UserReport.created_at.desc())
    ).all()

    item_seller = aliased(User)
    item_reporter = aliased(User)

    item_reports = session.exec(
        select(ItemReport, Item, item_seller, item_reporter)
        .join(Item, ItemReport.item_id == Item.id)
        .join(
            item_seller,
            Item.seller_id == item_seller.id,
        )
        .join(
            item_reporter,
            ItemReport.reporter_id == item_reporter.id,
        )
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

# USER REPORTS: BAN / REVERT / UNBAN

@router.post("/admin-reports/users/{report_id}/ban")
async def admin_ban_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_user_report(session, report_id)
    target_user = _load_user(session, report.target_user_id)

    # 1. XACML decides whether this admin may act on the escalated report.
    enforce(
        current_user,
        "escalated_decide",
        "report",
        user_report_attrs(report, role_of(target_user)),
    )

    # 2. Business state check, only after authorization.
    _ensure_escalated_user_report(report)

    # 3. XACML decides whether this admin may ban this specific account.
    enforce(
        current_user,
        "ban",
        "admin_action",
        admin_target_attrs(target_user.id),
    )

    target_user.is_banned = True
    target_user.is_blacklisted = True

    active_reports = session.exec(
        select(UserReport).where(
            UserReport.target_user_id == target_user.id,
            UserReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()

    for active in active_reports:
        active.status = ReportStatus.RESOLVED
        session.add(active)

    session.add(target_user)
    session.commit()

    return _redirect_admin()


@router.post("/admin-reports/users/{report_id}/revert")
async def admin_revert_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_user_report(session, report_id)
    target_user = _load_user(session, report.target_user_id)

    enforce(
        current_user,
        "escalated_decide",
        "report",
        user_report_attrs(report, role_of(target_user)),
    )

    _ensure_escalated_user_report(report)

    enforce(
        current_user,
        "revert",
        "admin_action",
        admin_target_attrs(target_user.id),
    )

    if target_user.is_banned:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This user is permanently banned. Unban them first.",
        )

    escalated_reports = session.exec(
        select(UserReport).where(
            UserReport.target_user_id == target_user.id,
            UserReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()

    for escalated in escalated_reports:
        escalated.status = ReportStatus.DISMISSED
        session.add(escalated)

    target_user.is_blacklisted = False

    session.add(target_user)
    session.commit()

    return _redirect_admin()


@router.post("/admin-reports/users/{user_id}/unban")
async def admin_unban_user(
    user_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    target_user = _load_user(session, user_id)

    # XACML decides first, so the response does not reveal the ban state.
    enforce(
        current_user,
        "unban",
        "admin_action",
        admin_target_attrs(target_user.id),
    )

    if not target_user.is_banned:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is not permanently banned",
        )

    target_user.is_banned = False
    target_user.is_blacklisted = False

    active_reports = session.exec(
        select(UserReport).where(
            UserReport.target_user_id == target_user.id,
            UserReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()

    for active in active_reports:
        active.status = ReportStatus.DISMISSED
        session.add(active)

    session.add(target_user)
    session.commit()

    return _redirect_admin()

# MODERATOR APPLICATIONS

@router.post("/mod-petitions/{petition_id}/approve")
async def approve_mod_petition(
    petition_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    petition = _load_petition(session, petition_id)
    applicant = _load_user(session, petition.user_id)

    # XACML checks that this is an admin and that the applicant is a
    # regular user. The "applicant_role" attribute is what enforces that.
    enforce(
        current_user,
        "review",
        "mod_petition",
        petition_review_attrs(applicant),
    )

    _ensure_not_reviewed(petition)

    applicant.role = UserRole.MODERATOR
    petition.Reviewed = True
    petition.approved = True

    session.add_all([applicant, petition])
    session.commit()

    return _redirect_admin()


@router.post("/mod-petitions/{petition_id}/reject")
async def reject_mod_petition(
    petition_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    petition = _load_petition(session, petition_id)
    applicant = _load_user(session, petition.user_id)

    enforce(
        current_user,
        "review",
        "mod_petition",
        petition_review_attrs(applicant),
    )

    _ensure_not_reviewed(petition)

    petition.Reviewed = True
    petition.approved = False

    session.add(petition)
    session.commit()

    return _redirect_admin()

# DELETE USERS AND ITEMS

@router.post("/admin-reports/users/{user_id}/delete")
async def admin_delete_user(
    user_id: UUID,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    target_user = _load_user(session, user_id)

    # XACML denies admins from deleting their own account.
    enforce(
        current_user,
        "delete_user",
        "admin_action",
        admin_target_attrs(target_user.id),
    )

    session.delete(target_user)
    session.commit()

    return _redirect_admin()


@router.post("/admin-reports/items/{report_id}/revert")
async def admin_revert_item_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_item_report(session, report_id)
    item = _load_item(session, report.item_id)
    seller = _load_seller(session, item)

    enforce(
        current_user,
        "escalated_decide",
        "report",
        item_report_attrs(report, item, role_of(seller)),
    )

    _ensure_escalated_item_report(report)

    escalated_reports = session.exec(
        select(ItemReport).where(
            ItemReport.item_id == item.id,
            ItemReport.status == ReportStatus.FOR_ADMIN,
        )
    ).all()

    for escalated in escalated_reports:
        escalated.status = ReportStatus.DISMISSED
        session.add(escalated)

    item.is_blacklisted = False

    session.add(item)
    session.commit()

    return _redirect_admin()


@router.post("/admin-reports/items/{item_id}/delete")
async def admin_delete_item(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    item = _load_item(session, item_id)

    enforce(
        current_user,
        "delete",
        "item",
        item_attrs(item),
    )

    session.delete(item)
    session.commit()

    return _redirect_admin()