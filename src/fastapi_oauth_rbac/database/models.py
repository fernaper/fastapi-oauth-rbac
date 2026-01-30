import uuid

from typing import List, Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    Table,
    DateTime,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime, timezone


class Base(DeclarativeBase):
    pass


# Association tables
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', ForeignKey('permissions.id'), primary_key=True),
)

user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', ForeignKey('users.id'), primary_key=True),
    Column('role_id', ForeignKey('roles.id'), primary_key=True),
)


class Permission(Base):
    __tablename__ = 'permissions'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255))

    # Hierarchy
    parent_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey('permissions.id')
    )
    parent: Mapped[Optional['Permission']] = relationship(
        'Permission', remote_side=[id], backref='children'
    )


class Role(Base):
    __tablename__ = 'roles'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255))
    is_default: Mapped[bool] = mapped_column(default=False)

    # Hierarchy
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey('roles.id'))
    parent: Mapped[Optional['Role']] = relationship(
        'Role', remote_side=[id], backref='children'
    )

    permissions: Mapped[List[Permission]] = relationship(
        secondary=role_permissions
    )


class UserBaseMixin:
    """Base mixin for User model to allow extensibility."""

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    is_verified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )

    # OAuth fields
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(50))
    oauth_id: Mapped[Optional[str]] = mapped_column(String(255))

    # Revocation support
    is_revoked: Mapped[bool] = mapped_column(default=False)


class User(Base, UserBaseMixin):
    __tablename__ = 'users'

    roles: Mapped[List[Role]] = relationship(secondary=user_roles)
