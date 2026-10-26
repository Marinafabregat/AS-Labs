from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import aliased
from sqlmodel import Session, select

from auth import get_current_active_user
from authz import enforce, item_report_attrs, role_of, user_report_attrs
from db import get_session
from models import Item, ItemReport, ReportStatus, User, UserReport
from template_context import templates


router = APIRouter(prefix="/mod", tags=["mod"])

MOD_REPORTS_URL = "/mod/moderator-reports"


def _redirect_to_reports() -> RedirectResponse:
    return RedirectResponse(
        url=MOD_REPORTS_URL,
        status_code=status.HTTP_302_FOUND,
    )


# ---------------------------------------------------------
# LOADERS
# Loaders only check existence. The status check runs AFTER enforce(),
# so the response for unauthorized users does not reveal the state.
# ---------------------------------------------------------


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


def _load_target_user(session: Session, report: UserReport) -> User:
    target_user = session.get(User, report.target_user_id)

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reported user not found",
        )

    return target_user


def _load_item(session: Session, report: ItemReport) -> Item:
    item = session.get(Item, report.item_id)

    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reported item not found",
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


def _ensure_pending_user_report(report: UserReport) -> None:
    if report.status != ReportStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending user report not found",
        )


def _ensure_pending_item_report(report: ItemReport) -> None:
    if report.status != ReportStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending item report not found",
        )


# ---------------------------------------------------------
# MODERATOR DASHBOARD
# ---------------------------------------------------------


@router.get(
    "/moderator-reports",
    response_class=HTMLResponse,
)
async def moderator_reports_page(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    # XACML decides whether the user may see the moderation queue.
    enforce(
        current_user,
        "read",
        "report",
        {"status": "pending"},
    )

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
        .join(
            item_seller,
            Item.seller_id == item_seller.id,
        )
        .join(
            item_reporter,
            ItemReport.reporter_id == item_reporter.id,
        )
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


# ---------------------------------------------------------
# USER REPORTS
# ---------------------------------------------------------


@router.post("/moderator-reports/users/{report_id}/dismiss")
async def dismiss_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_user_report(session, report_id)
    target_user = _load_target_user(session, report)

    # XACML checks conflict of interest and staff-target rules.
    enforce(
        current_user,
        "decide",
        "report",
        user_report_attrs(report, role_of(target_user)),
    )

    _ensure_pending_user_report(report)

    report.status = ReportStatus.DISMISSED

    session.add(report)
    session.commit()

    return _redirect_to_reports()


@router.post("/moderator-reports/users/{report_id}/accept")
async def accept_user_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_user_report(session, report_id)
    target_user = _load_target_user(session, report)

    enforce(
        current_user,
        "decide",
        "report",
        user_report_attrs(report, role_of(target_user)),
    )

    _ensure_pending_user_report(report)

    # Escalating to admins also blocks the target account.
    report.status = ReportStatus.FOR_ADMIN
    target_user.is_blacklisted = True

    session.add_all([report, target_user])
    session.commit()

    return _redirect_to_reports()


# ---------------------------------------------------------
# ITEM REPORTS
# ---------------------------------------------------------


@router.post("/moderator-reports/items/{report_id}/accept")
async def accept_item_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_item_report(session, report_id)
    item = _load_item(session, report)
    seller = _load_seller(session, item)

    enforce(
        current_user,
        "decide",
        "report",
        item_report_attrs(report, item, role_of(seller)),
    )

    _ensure_pending_item_report(report)

    report.status = ReportStatus.FOR_ADMIN
    item.is_blacklisted = True

    session.add_all([report, item])
    session.commit()

    return _redirect_to_reports()


@router.post("/moderator-reports/items/{report_id}/dismiss")
async def dismiss_item_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    report = _load_item_report(session, report_id)
    item = _load_item(session, report)
    seller = _load_seller(session, item)

    enforce(
        current_user,
        "decide",
        "report",
        item_report_attrs(report, item, role_of(seller)),
    )

    _ensure_pending_item_report(report)

    report.status = ReportStatus.DISMISSED

    # Business rule: keep the item hidden if another escalated report
    # still exists for it.
    still_reported = session.exec(
        select(ItemReport.id).where(
            ItemReport.item_id == item.id,
            ItemReport.status == ReportStatus.FOR_ADMIN,
            ItemReport.id != report.id,
        )
    ).first()

    if not still_reported:
        item.is_blacklisted = False

    session.add_all([report, item])
    session.commit()

    return _redirect_to_reports()