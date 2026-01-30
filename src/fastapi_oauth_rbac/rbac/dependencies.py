from typing import List, Optional, Callable, Union
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from ..core.security import decode_token
from ..core.config import settings
from ..database.models import User, Role, Permission
from ..database.session import get_db
from .manager import RBACManager
from .logic import Requirement, And, Permission as PermissionLogic

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/login', auto_error=False)


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    user = await get_current_user_optional(request, token, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    return user


async def get_current_user_optional(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    if not token:
        # Check cookies as fallback for dashboard
        token = request.cookies.get('access_token')

    if not token:
        return None

    try:
        payload = decode_token(token)
        email: str = payload.get('sub')
        if email is None:
            return None
    except Exception:
        return None

    # Async query with eager loading of roles and permissions
    stmt = (
        select(User)
        .where(User.email == email)
        .options(
            selectinload(User.roles)
            .selectinload(Role.permissions)
            .selectinload(Permission.children)
        )
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user and settings.AUTH_REVOCATION_ENABLED and user.is_revoked:
        return None

    return user


class PermissionChecker:
    def __init__(self, requirement: Union[str, List[str], Requirement]):
        if isinstance(requirement, str):
            self.requirement = PermissionLogic(requirement)
        elif isinstance(requirement, list):
            self.requirement = And(*requirement)
        else:
            self.requirement = requirement

    async def __call__(
        self,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ):
        rbac = RBACManager(db)
        user_perms = await rbac.get_user_permissions(user)

        if not self.requirement.evaluate(user_perms):
            detail = f"Permission denied. Required: {self.requirement}"
            if isinstance(self.requirement, PermissionLogic):
                detail = f"Permission denied: {self.requirement.name}"

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=detail,
            )
        return user


def requires_permission(requirement: Union[str, List[str], Requirement]):
    return Depends(PermissionChecker(requirement))
