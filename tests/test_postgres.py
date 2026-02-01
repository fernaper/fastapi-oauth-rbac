import pytest
import asyncio
import os
import subprocess
import time
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import select
from fastapi_oauth_rbac import FastAPIOAuthRBAC, Settings, Base

# Container configuration
POSTGRES_USER = "testuser"
POSTGRES_PASSWORD = "testpassword"
POSTGRES_DB = "testdb"
POSTGRES_PORT = 5433
CONTAINER_NAME = "rbac_test_postgres"

@pytest.fixture(scope="session")
def postgres_container():
    # Stop and remove if already exists
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm", CONTAINER_NAME], capture_output=True)

    # Start fresh container
    cmd = [
        "docker", "run", "--name", CONTAINER_NAME,
        "-e", f"POSTGRES_USER={POSTGRES_USER}",
        "-e", f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}",
        "-e", f"POSTGRES_DB={POSTGRES_DB}",
        "-p", f"{POSTGRES_PORT}:5432",
        "-d", "postgres:latest"
    ]
    subprocess.run(cmd, check=True)

    # Wait for postgres to be ready
    max_retries = 30
    ready = False
    for i in range(max_retries):
        try:
            res = subprocess.run(
                ["docker", "exec", CONTAINER_NAME, "pg_isready", "-U", POSTGRES_USER],
                capture_output=True, check=True
            )
            if b"accepting connections" in res.stdout:
                ready = True
                break
        except:
            pass
        time.sleep(1)
    
    if not ready:
        pytest.fail("PostgreSQL container failed to start")
    
    yield f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@localhost:{POSTGRES_PORT}/{POSTGRES_DB}"

    # Cleanup
    subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
    subprocess.run(["docker", "rm", CONTAINER_NAME], capture_output=True)

@pytest.mark.asyncio
async def test_postgres_initialization(postgres_container):
    db_url = postgres_container
    print(f"\nConnecting to {db_url}")
    
    app = FastAPI()
    settings = Settings(DATABASE_URL=db_url)
    
    # This is where the NoForeignKeysError usually happens (during relationship resolution)
    try:
        auth = FastAPIOAuthRBAC(app, settings=settings)
        auth.include_auth_router()
        
        # Trigger table creation
        async with auth.db_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            
        # Try a simple database operation to ensure relationships are loaded
        async with auth.db_sessionmaker() as session:
            from fastapi_oauth_rbac.database.models import User, Role
            from sqlalchemy.orm import selectinload
            
            # Create a role and a user
            role = Role(name="test_role")
            user = User(email="test@example.com", roles=[role])
            session.add_all([role, user])
            await session.commit()
            
            # Query with relationship loading
            stmt = select(User).options(selectinload(User.roles))
            result = await session.execute(stmt)
            fetched_user = result.scalar_one()
            assert len(fetched_user.roles) == 1
            assert fetched_user.roles[0].name == "test_role"
            
        print("SUCCESS: PostgreSQL initialization and relationship query worked!")
        
    except Exception as e:
        print(f"FAILED: {e}")
        raise e


@pytest.mark.asyncio
async def test_postgres_subclassed_user(postgres_container):
    from typing import List, Optional
    from sqlalchemy.orm import relationship, Mapped, mapped_column, declared_attr, DeclarativeBase, selectinload
    from sqlalchemy import String, DateTime, func, Table, Column, Integer, ForeignKey, Uuid, select
    from fastapi_oauth_rbac.database.models import UserBaseMixin
    from datetime import datetime

    db_url = postgres_container
    app = FastAPI()
    settings = Settings(DATABASE_URL=db_url)

    from sqlalchemy.orm import DeclarativeBase
    class TestBase(DeclarativeBase):
        pass

    from sqlalchemy import Table, Column, Integer, ForeignKey, Uuid
    from sqlalchemy.schema import ForeignKeyConstraint

    # Re-declare Role and user_roles in the new metadata to avoid conflicts
    test_user_roles = Table(
        'user_roles',
        TestBase.metadata,
        Column('user_id', Uuid, primary_key=True),
        Column('role_id', Integer, primary_key=True),
        ForeignKeyConstraint(['user_id'], ['users.id']),
        ForeignKeyConstraint(['role_id'], ['roles.id']),
    )

    class TestRole(TestBase):
        __tablename__ = 'roles'
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(String(50), unique=True)

    # Mimic user's subclassing using the library's mixin
    class CustomUser(TestBase, UserBaseMixin):
        __tablename__ = 'users'
        __table_args__ = {'extend_existing': True}
        username: Mapped[str] = mapped_column(
            String(50), unique=True, index=True, nullable=False
        )
        updated_at: Mapped[Optional[datetime]] = mapped_column(
            DateTime(timezone=True), onupdate=func.now()
        )
        
        # We MUST use the library's mixin logic, but since we are using a different 
        # Table object (test_user_roles) and different Role class (TestRole),
        # we have to point the relationship to THEM.
        @declared_attr
        def roles(cls) -> Mapped[List[TestRole]]:
            return relationship(
                TestRole,
                secondary=test_user_roles,
                primaryjoin=lambda: cls.id == test_user_roles.c.user_id,
                secondaryjoin=lambda: TestRole.id == test_user_roles.c.role_id,
            )

    try:
        auth = FastAPIOAuthRBAC(app, settings=settings)
        
        async with auth.db_engine.begin() as conn:
            await conn.run_sync(TestBase.metadata.create_all)

        async with auth.db_sessionmaker() as session:
            role = TestRole(name="custom_role")
            user = CustomUser(
                email="custom@example.com", username="custom_user", roles=[role]
            )
            session.add_all([role, user])
            await session.commit()

            stmt = select(CustomUser).options(selectinload(CustomUser.roles))
            result = await session.execute(stmt)
            fetched_user = result.scalar_one()
            assert fetched_user.username == "custom_user"
            assert len(fetched_user.roles) == 1

        print("SUCCESS: Subclassed User worked in PostgreSQL!")

    except Exception as e:
        print(f"FAILED Subclassed User: {e}")
        raise e
