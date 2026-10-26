# This file defines the database structure: the objects the application
# stores and loads. Access decisions are NOT made here; see authz.py.

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from sqlalchemy import UniqueConstraint
from sqlmodel import SQLModel, Field, Relationship


class UserRole(str, Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class ReportStatus(str, Enum):
    PENDING = "pending"        # Waiting for a moderator
    FOR_ADMIN = "for_admin"    # Escalated to an administrator
    RESOLVED = "resolved"      # Closed with a sanction
    DISMISSED = "dismissed"    # Closed without action


class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: Optional[str] = Field(default=None, index=True, unique=True)
    email: str = Field(nullable=False, unique=True, index=True)
    hashed_password: Optional[str] = Field(default=None)
    role: UserRole = Field(default=UserRole.USER)

    # is_blacklisted: the account is currently blocked (temporary or permanent).
    # is_banned: an administrator confirmed a permanent ban.
    is_blacklisted: bool = Field(default=False)
    is_banned: bool = Field(default=False)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Personal data (PII), stored encrypted with Fernet (see security_encryption.py).
    delivery_address_line1: Optional[str] = None
    delivery_address_line2: Optional[str] = None
    postal_code: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    phone_number: Optional[str] = None

    # OAuth fields. Tokens are encrypted at rest.
    oauth_provider: Optional[str] = Field(default=None)
    oauth_id: Optional[str] = Field(default=None, index=True)
    oauth_access_token: Optional[str] = Field(default=None)
    oauth_refresh_token: Optional[str] = Field(default=None)

    # Relationships
    posted_items: List["Item"] = Relationship(
        back_populates="seller",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    purchases: List["Purchase"] = Relationship(
        back_populates="buyer",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    Likes: List["Like"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    mod_petitions: List["ModPetition"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    reports_made: List["ItemReport"] = Relationship(
        back_populates="reporter",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Category(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)

    items: List["Item"] = Relationship(back_populates="category")


class Item(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    description: str
    price: float = Field(default=0.0, ge=0.0)

    # Filename on disk inside uploads/. Served only through /items/images/.
    image_filename: Optional[str] = Field(default=None)

    # Moderation soft-hide flag. Hidden items are visible only to staff.
    is_blacklisted: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Foreign keys
    seller_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    category_id: Optional[int] = Field(
        default=None, foreign_key="category.id", ondelete="SET NULL"
    )

    # Relationships
    seller: Optional[User] = Relationship(back_populates="posted_items")
    category: Optional[Category] = Relationship(back_populates="items")
    Likes: List["Like"] = Relationship(
        back_populates="item",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    purchases: List["Purchase"] = Relationship(
        back_populates="item",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )
    reports: List["ItemReport"] = Relationship(
        back_populates="item",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"},
    )


class Purchase(SQLModel, table=True):
    # An item can be sold only once, so uniqueness is enforced on item_id.
    # Enforcing it at database level closes the race condition where two
    # buyers pass the "already sold" check at the same time.
    __table_args__ = (
        UniqueConstraint("item_id", name="uq_item_sold_once"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    buyer_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    item_id: int = Field(foreign_key="item.id", ondelete="CASCADE")
    purchased_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Historical price, kept even if the item price changes later.
    price_paid: float

    buyer: Optional[User] = Relationship(back_populates="purchases")
    item: Optional[Item] = Relationship(back_populates="purchases")


class Like(SQLModel, table=True):
    # Users can like items to save them for later.
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    item_id: int = Field(foreign_key="item.id", ondelete="CASCADE")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    user: Optional[User] = Relationship(back_populates="Likes")
    item: Optional[Item] = Relationship(back_populates="Likes")


class ItemReport(SQLModel, table=True):
    # Created by users to flag items. Moderators decide, admins review escalations.
    id: Optional[int] = Field(default=None, primary_key=True)
    item_id: int = Field(foreign_key="item.id", ondelete="CASCADE")
    reporter_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    reason: str
    status: ReportStatus = Field(default=ReportStatus.PENDING)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    item: Optional[Item] = Relationship(back_populates="reports")
    reporter: Optional[User] = Relationship(back_populates="reports_made")


class UserReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    reporter_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    reason: str
    status: ReportStatus = Field(default=ReportStatus.PENDING)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModPetition(SQLModel, table=True):
    # Application from a user who wants to become a moderator.
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    message: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    Reviewed: bool = Field(default=False)
    approved: Optional[bool] = None

    user: Optional[User] = Relationship(back_populates="mod_petitions")