import os
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine, select

from models import (
    Category,
    Item,
    ItemReport,
    Like,
    ModPetition,
    Purchase,
    ReportStatus,
    User,
    UserReport,
)

PROJECT_ROOT = Path(__file__).resolve().parent
IN_DOCKER = os.path.exists("/app")
LOCAL_DB_FILE = PROJECT_ROOT / "database.db"


def _resolve_sqlite_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    # An /app/... path only makes sense inside the Docker container
    if env_url and (IN_DOCKER or not env_url.startswith("sqlite:////app/")):
        return env_url
    db_file = Path("/app/database.db") if IN_DOCKER else LOCAL_DB_FILE
    return f"sqlite:///{db_file}"


sqlite_url = _resolve_sqlite_url()
connect_args = {"check_same_thread": False}

# Create the Engine
engine = create_engine(sqlite_url, echo=False, connect_args=connect_args)


def init_db():
    """
    Helper Method to create the initial Database
    and any associated tables.

    This should be called by the application on startup
    """
    SQLModel.metadata.create_all(engine)

    # Lightweight migration for databases created before the ban feature.
    inspector = inspect(engine)
    if "user" in inspector.get_table_names():
        user_columns = {column["name"] for column in inspector.get_columns("user")}
        if "is_banned" not in user_columns:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE user "
                        "ADD COLUMN is_banned BOOLEAN NOT NULL DEFAULT 0"
                    )
                )

    with Session(engine) as session:
        blacklisted_items = session.exec(
            select(Item).where(Item.is_blacklisted.is_(True))
        ).all()
        for item in blacklisted_items:
            active_escalation = session.exec(
                select(ItemReport.id).where(
                    ItemReport.item_id == item.id,
                    ItemReport.status == ReportStatus.FOR_ADMIN,
                )
            ).first()
            if not active_escalation:
                item.is_blacklisted = False
                session.add(item)

        blacklisted_users = session.exec(
            select(User).where(
                User.is_blacklisted.is_(True),
                User.is_banned.is_(False),
            )
        ).all()
        for user in blacklisted_users:
            active_escalation = session.exec(
                select(UserReport.id).where(
                    UserReport.target_user_id == user.id,
                    UserReport.status == ReportStatus.FOR_ADMIN,
                )
            ).first()
            if not active_escalation:
                user.is_blacklisted = False
                session.add(user)

        session.commit()


def get_session():
    """Generator for the Session object, used as dependency in requests
    """
    with Session(engine) as session:
        yield session