import pytest

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)
from sqlalchemy.orm import selectinload
from sqlalchemy import select
from fastapi_oauth_rbac.database.models import Base, User, Role, Permission
from fastapi_oauth_rbac.rbac.manager import RBACManager
from fastapi_oauth_rbac.core.security import hash_password, verify_password


@pytest.mark.asyncio
async def test_password_hashing():
    password = 'secret_password'
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True


@pytest.mark.asyncio
async def test_async_rbac_hierarchy():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # CRITICAL: expire_on_commit=False
    AsyncSessionLocal = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncSessionLocal() as db:
        view_p = Permission(name='view')
        manage_p = Permission(name='manage', children=[view_p])
        db.add_all([view_p, manage_p])

        role = Role(name='manager', permissions=[manage_p])
        user = User(email='async@example.com', roles=[role])
        db.add_all([role, user])
        await db.commit()

        # Re-fetch user with EVERYTHING loaded for the manager
        stmt = (
            select(User)
            .where(User.id == user.id)
            .options(selectinload(User.roles).selectinload(Role.permissions))
        )
        result = await db.execute(stmt)
        user = result.scalar_one()

        rbac = RBACManager(db)
        perms = await rbac.get_user_permissions(user)
        assert 'manage' in perms
        assert 'view' in perms
        assert await rbac.has_permission(user, 'view') is True

    await engine.dispose()


@pytest.mark.asyncio
async def test_has_role():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    AsyncSessionLocal = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )
    async with AsyncSessionLocal() as db:
        role = Role(name='admin')
        user = User(email='admin@test.com', roles=[role])
        db.add_all([role, user])
        await db.commit()

        stmt = (
            select(User)
            .where(User.id == user.id)
            .options(selectinload(User.roles))
        )
        result = await db.execute(stmt)
        user = result.scalar_one()

        rbac = RBACManager(db)
        assert await rbac.has_role(user, 'admin') is True
    await engine.dispose()
