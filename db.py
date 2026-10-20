from sqlmodel import SQLModel, create_engine, Session, select
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
from sqlalchemy import inspect, text
import os

# Define our SQLite
if os.getenv("DATABASE_URL"):
    sqlite_url = os.getenv("DATABASE_URL")
else:
    # Automatically check if we are inside Docker (where /app typically exists)
    if os.path.exists("/app"):
        sqlite_file_name = "/app/database.db"
    else:
        sqlite_file_name = "database.db"  # Local fallback
    sqlite_url = f"sqlite:///{sqlite_file_name}"
        
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