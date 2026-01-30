from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, Optional, List

from ..database.models import User, Role
from ..rbac.dependencies import get_db, get_current_user
from ..core.security import (
    verify_password,
    hash_password,
    create_access_token,
    decode_token,
)
from ..auth.oauth import GoogleOAuth
from ..rbac.manager import RBACManager
from ..core.config import settings

auth_router = APIRouter(tags=['Authentication'])


class SignupRequest(BaseModel):
    email: EmailStr
    password: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@auth_router.post('/signup')
async def signup(data: SignupRequest, db: AsyncSession = Depends(get_db)):
    if not settings.SIGNUP_ENABLED:
        raise HTTPException(status_code=400, detail='Signup is disabled')

    stmt = select(User).where(User.email == data.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail='Email already registered')

    stmt_role = select(Role).where(Role.name == 'user')
    result_role = await db.execute(stmt_role)
    user_role = result_role.scalar_one_or_none()

    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        roles=[user_role] if user_role else [],
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {'message': 'User created successfully', 'email': user.email}


@auth_router.post('/login')
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(User)
        .where(User.email == form_data.username)
        .options(selectinload(User.roles))
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if (
        not user
        or not user.hashed_password
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect email or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    if user.is_revoked:
        user.is_revoked = False
        await db.commit()
        await db.refresh(user, ['roles'])

    # Get RBAC settings from app state
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    if (
        rbac_instance
        and rbac_instance.require_verified
        and not user.is_verified
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='USER_NOT_VERIFIED',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    # Fetch permissions for scopes
    rbac = RBACManager(db)
    permissions = await rbac.get_user_permissions(user)

    access_token = create_access_token(
        data={'sub': user.email, 'scopes': list(permissions)}
    )

    # Set cookie for dashboard access
    response.set_cookie(
        key='access_token',
        value=access_token,
        httponly=False,  # Allow JS to clear it on logout for now
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path='/',
    )

    return {'access_token': access_token, 'token_type': 'bearer'}


@auth_router.post('/logout')
async def logout(
    global_logout: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if global_logout:
        current_user.is_revoked = True
        await db.commit()
    return {'message': 'Logged out successfully'}


@auth_router.get('/me')
async def read_users_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rbac = RBACManager(db)
    permissions = await rbac.get_user_permissions(current_user)
    return {
        'email': current_user.email,
        'is_active': current_user.is_active,
        'is_verified': current_user.is_verified,
        'roles': [r.name for r in current_user.roles],
        'permissions': list(permissions),
    }


@auth_router.get('/verify')
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(token)
        email = payload.get('sub')
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail='User not found')

        user.is_active = True
        await db.commit()
        return {'message': 'Email verified successfully'}
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid or expired token')


@auth_router.post('/forgot-password')
async def forgot_password(email: EmailStr, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    if not result.scalar_one_or_none():
        return {
            'message': 'If the email is registered, you will receive a reset link'
        }

    token = create_access_token(data={'sub': email, 'type': 'reset_password'})
    return {'message': 'Reset token generated', 'debug_token': token}


@auth_router.post('/reset-password')
async def reset_password(
    data: ResetPasswordRequest, db: AsyncSession = Depends(get_db)
):
    try:
        payload = decode_token(data.token)
        if payload.get('type') != 'reset_password':
            raise ValueError('Invalid token type')

        email = payload.get('sub')
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail='User not found')

        user.hashed_password = hash_password(data.new_password)
        await db.commit()
        return {'message': 'Password reset successfully'}
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid or expired token')


@auth_router.get('/google/callback')
async def google_callback(
    request: Request, code: str, db: AsyncSession = Depends(get_db)
):
    try:
        user_data = await GoogleOAuth.get_user_data(code, 'YOUR_REDIRECT_URI')
        email = user_data.get('email')

        stmt = (
            select(User)
            .where(User.email == email)
            .options(selectinload(User.roles))
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            stmt_role = select(Role).where(Role.name == 'user')
            result_role = await db.execute(stmt_role)
            user_role = result_role.scalar_one_or_none()

            user = User(
                email=email,
                oauth_provider='google',
                oauth_id=user_data.get('sub'),
                roles=[user_role] if user_role else [],
                is_verified=True,  # OAuth users are usually considered verified
            )
            db.add(user)
            await db.commit()
            await db.refresh(user, ['roles'])

        # Verification check for OAuth too
        rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
        if (
            rbac_instance
            and rbac_instance.require_verified
            and not user.is_verified
        ):
            # For Google, maybe they should be verified by default?
            # But let's follow the strict rule if set.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='USER_NOT_VERIFIED',
            )

        rbac = RBACManager(db)
        permissions = await rbac.get_user_permissions(user)
        access_token = create_access_token(
            data={'sub': user.email, 'scopes': list(permissions)}
        )

        # Set cookie for dashboard access
        response = Response(
            content='{"access_token": "'
            + access_token
            + '", "token_type": "bearer"}',
            media_type='application/json',
        )
        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=False,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            path='/',
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@auth_router.post('/logout')
async def logout(response: Response):
    response.delete_cookie(key='access_token', path='/')
    return {'message': 'Logged out'}
