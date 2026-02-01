import pytest
import os
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from fastapi_oauth_rbac import FastAPIOAuthRBAC, Settings, get_current_user


@pytest.mark.asyncio
async def test_dynamic_database_configuration():
    # Setup two different databases (in-memory)
    db_url_1 = 'sqlite+aiosqlite:///:memory:'
    db_url_2 = 'sqlite+aiosqlite:///:memory:'

    app1 = FastAPI()
    settings1 = Settings(
        DATABASE_URL=db_url_1, ADMIN_EMAIL='admin1@example.com'
    )
    auth1 = FastAPIOAuthRBAC(app1, settings=settings1)
    auth1.include_auth_router(prefix='/auth1')

    app2 = FastAPI()
    settings2 = Settings(
        DATABASE_URL=db_url_2, ADMIN_EMAIL='admin2@example.com'
    )
    auth2 = FastAPIOAuthRBAC(app2, settings=settings2)
    auth2.include_auth_router(prefix='/auth2')

    from fastapi_oauth_rbac.database.models import Base

    # Manually trigger table creation and setup (usually happens in lifespan)
    async with auth1.db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with auth1.db_sessionmaker() as session:
        await auth1.setup_defaults(session)

    async with auth2.db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with auth2.db_sessionmaker() as session:
        await auth2.setup_defaults(session)

    # Verify that app1 HAS the admin1 user but NOT admin2
    async with auth1.db_sessionmaker() as session:
        from fastapi_oauth_rbac.database.models import User
        from sqlalchemy import select

        result = await session.execute(
            select(User).where(User.email == 'admin1@example.com')
        )
        assert result.scalar_one_or_none() is not None

        result = await session.execute(
            select(User).where(User.email == 'admin2@example.com')
        )
        assert result.scalar_one_or_none() is None

    # Verify that app2 HAS the admin2 user but NOT admin1
    async with auth2.db_sessionmaker() as session:
        result = await session.execute(
            select(User).where(User.email == 'admin2@example.com')
        )
        assert result.scalar_one_or_none() is not None

        result = await session.execute(
            select(User).where(User.email == 'admin1@example.com')
        )
        assert result.scalar_one_or_none() is None

    print(
        '\nSUCCESS: Instances successfully use isolated databases based on injected settings.'
    )
