from fastapi import Request
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)


async def get_db(request: Request):
    """
    Dependency that provides an async database session.
    It prioritizes the sessionmaker configured in the FastAPIOAuthRBAC instance.
    """
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    if not rbac_instance:
        raise RuntimeError(
            'FastAPIOAuthRBAC not initialized on app.state.oauth_rbac. '
            'Ensure you called include_auth_router() or set the state manually.'
        )

    sessionmaker = rbac_instance.db_sessionmaker

    async with sessionmaker() as session:
        try:
            yield session
        finally:
            await session.close()
