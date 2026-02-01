from fastapi import Request
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from ..core.config import settings


# Create async engine
engine = create_async_engine(settings.DATABASE_URL, echo=False)

# Create async session factory (default for backward compatibility)
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db(request: Request):
    """
    Dependency that provides an async database session.
    It prioritizes the sessionmaker configured in the FastAPIOAuthRBAC instance.
    """
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    sessionmaker = (
        rbac_instance.db_sessionmaker if rbac_instance else AsyncSessionLocal
    )

    async with sessionmaker() as session:
        try:
            yield session
        finally:
            await session.close()
