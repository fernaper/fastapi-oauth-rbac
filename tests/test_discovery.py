import pytest

from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from fastapi_oauth_rbac import FastAPIOAuthRBAC
from fastapi_oauth_rbac.rbac.dependencies import requires_permission
from fastapi_oauth_rbac.database.models import Permission, Base


@pytest.mark.asyncio
async def test_dynamic_permission_discovery():
    app = FastAPI()

    # Define a route with a custom permission
    @app.get('/custom', dependencies=[requires_permission('custom:action')])
    async def custom_route():
        return {'ok': True}

    # Initialize library
    auth = FastAPIOAuthRBAC(app)  # We'll call setup_defaults manually

    # The permission "custom:action" should be discovered
    discovered = auth._discover_route_permissions()
    assert 'custom:action' in discovered

    # Now verify it gets created in the DB during setup
    from fastapi_oauth_rbac.database.session import engine, AsyncSessionLocal

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        await auth.setup_defaults(session)

        # Check if it exists
        stmt = select(Permission).where(Permission.name == 'custom:action')
        result = await session.execute(stmt)
        perm = result.scalar_one_or_none()
        assert perm is not None
        assert 'Automatically discovered' in perm.description


@pytest.mark.asyncio
async def test_role_registration():
    app = FastAPI()
    auth = FastAPIOAuthRBAC(app)

    # Register a custom role
    auth.add_role(
        'editor', 'Can edit things', ['content:edit', 'content:read']
    )

    from fastapi_oauth_rbac.database.session import engine, AsyncSessionLocal
    from fastapi_oauth_rbac.database.models import Role

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        await auth.setup_defaults(session)

        # Check if role exists
        stmt = (
            select(Role)
            .where(Role.name == 'editor')
            .options(selectinload(Role.permissions))
        )
        result = await session.execute(stmt)
        role = result.scalar_one_or_none()

        assert role is not None
        assert len(role.permissions) == 2
        perm_names = {p.name for p in role.permissions}
        assert 'content:edit' in perm_names
        assert 'content:read' in perm_names
