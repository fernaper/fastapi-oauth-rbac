import uuid

from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Uuid,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    declared_attr,
)
from sqlalchemy.schema import ForeignKeyConstraint
from datetime import datetime, timezone


class Base(DeclarativeBase):
    pass


# Association tables
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, primary_key=True),
    Column('permission_id', Integer, primary_key=True),
    ForeignKeyConstraint(
        ['role_id'], ['roles.id'], name='fk_role_permissions_role_id'
    ),
    ForeignKeyConstraint(
        ['permission_id'],
        ['permissions.id'],
        name='fk_role_permissions_permission_id',
    ),
)

user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Uuid, primary_key=True),
    Column('role_id', Integer, primary_key=True),
    ForeignKeyConstraint(
        ['user_id'], ['users.id'], name='fk_user_roles_user_id'
    ),
    ForeignKeyConstraint(
        ['role_id'], ['roles.id'], name='fk_user_roles_role_id'
    ),
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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(100), index=True)

    # Hierarchy
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey('roles.id'))
    parent: Mapped[Optional['Role']] = relationship(
        'Role', remote_side=[id], backref='children'
    )

    permissions: Mapped[List[Permission]] = relationship(
        Permission,
        secondary=role_permissions,
        primaryjoin=lambda: Role.id == role_permissions.c.role_id,
        secondaryjoin=lambda: Permission.id == role_permissions.c.permission_id,
        overlaps="permissions",
    )


class UserBaseMixin:
    """Base mixin for User model to allow extensibility."""

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    is_verified: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # OAuth fields
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(50))
    oauth_id: Mapped[Optional[str]] = mapped_column(String(255))

    # Revocation support
    is_revoked: Mapped[bool] = mapped_column(default=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(100), index=True)

    @declared_attr
    def roles(cls) -> Mapped[List[Role]]:
        return relationship(
            Role,
            secondary=user_roles,
            primaryjoin=lambda: cls.id == user_roles.c.user_id,
            secondaryjoin=lambda: Role.id == user_roles.c.role_id,
            overlaps="roles",
        )


class User(Base, UserBaseMixin):
    __tablename__ = 'users'


class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    actor_email: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[Optional[str]] = mapped_column(String(255))
    details: Mapped[Optional[str]] = mapped_column(String(1000))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
