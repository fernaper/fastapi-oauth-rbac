import pytest

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from fastapi_oauth_rbac.database.models import Base, User, Role, Permission
from fastapi_oauth_rbac.rbac.manager import RBACManager


@pytest.mark.asyncio
async def test_rbac_hierarchy():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncSessionLocal() as db:
        # Create permissions: Admin > Manage > View
        view_p = Permission(name='view')
        manage_p = Permission(name='manage', children=[view_p])
        admin_p = Permission(name='admin', children=[manage_p])
        db.add_all([view_p, manage_p, admin_p])

        role = Role(name='manager_role', permissions=[manage_p])
        user = User(email='mgr@example.com', roles=[role])
        db.add_all([role, user])
        await db.commit()
        await db.refresh(user, ['roles'])

        rbac = RBACManager(db)

        # Manager should have 'manage' and 'view'
        perms = await rbac.get_user_permissions(user)
        assert 'manage' in perms
        assert 'view' in perms
        assert 'admin' not in perms

        assert await rbac.has_permission(user, 'view') is True
        assert await rbac.has_permission(user, 'admin') is False
