from uuid import UUID

from sqlmodel import Session, select

from models import ReportStatus, UserReport


def is_user_reported(session: Session, user_id: UUID) -> bool:
    return (
        session.exec(
            select(UserReport.id).where(
                UserReport.target_user_id == user_id,
                UserReport.status.in_(
                    [ReportStatus.PENDING, ReportStatus.FOR_ADMIN]
                ),
            )
        ).first()
        is not None
    )
