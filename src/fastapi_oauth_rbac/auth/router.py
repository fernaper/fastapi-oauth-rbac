import json

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Body,
    Request,
    Response,
)
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Optional

from ..auth.oauth import GoogleOAuth
from ..core.config import settings as default_settings
from ..core.security import (
    verify_password,
    hash_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from ..database.models import User, Role
from ..rbac.dependencies import (
    get_db,
    get_current_user,
    get_current_user_optional,
)
from ..rbac.manager import RBACManager
from ..core.audit import AuditManager

auth_router = APIRouter(tags=['Authentication'])


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class GoogleAuthRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None


@auth_router.post('/signup')
async def signup(
    request: Request, data: SignupRequest, db: AsyncSession = Depends(get_db)
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings

    if not s.SIGNUP_ENABLED:
        raise HTTPException(status_code=400, detail='Signup is disabled')

    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = select(user_model).where(user_model.email == data.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail='Email already registered')

    stmt_role = select(Role).where(Role.name == 'user')
    result_role = await db.execute(stmt_role)
    user_role = result_role.scalar_one_or_none()

    user = user_model(
        email=data.email,
        hashed_password=hash_password(data.password),
        roles=[user_role] if user_role else [],
        tenant_id=data.tenant_id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Audit Log (Self signup or system action)
    audit = AuditManager(db)

    enabled = rbac_instance.settings.AUDIT_ENABLED if rbac_instance else True
    await audit.log(
        actor_email=user.email,
        action='USER_SIGNUP',
        target=user.email,
        details=f'Tenant: {user.tenant_id}',
        enabled=enabled,
    )

    # 1. Trigger Hook
    if rbac_instance:
        await rbac_instance.hooks.trigger('post_signup', user)

    # 2. Handle Verification Email
    if s.VERIFY_EMAIL_ENABLED and rbac_instance:
        token = create_access_token(
            data={'sub': user.email, 'type': 'verify_email'}, settings=s
        )
        await rbac_instance.email_exporter.send_verification_email(user, token)

    return {'message': 'User created successfully', 'email': user.email}


@auth_router.post('/login')
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings
    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = (
        select(user_model)
        .where(user_model.email == form_data.username)
        .options(selectinload(user_model.roles))
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

    if (
        rbac_instance
        and rbac_instance.settings.REQUIRE_VERIFIED_LOGIN
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
        data={'sub': user.email, 'scopes': list(permissions)}, settings=s
    )
    refresh_token = create_refresh_token(data={'sub': user.email}, settings=s)

    # Set cookie for dashboard access
    response.set_cookie(
        key='access_token',
        value=access_token,
        httponly=False,  # Allow JS to clear it on logout for now
        max_age=s.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path='/',
    )
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        httponly=True,  # Refresh token should be more secure
        max_age=s.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path='/',
    )

    # Trigger Login Hook
    if rbac_instance:
        await rbac_instance.hooks.trigger('post_login', user)
        # Audit Log
        audit = AuditManager(db)
        await audit.log(
            actor_email=user.email,
            action='USER_LOGIN',
            target=user.email,
            ip_address=request.client.host if request.client else None,
            enabled=rbac_instance.settings.AUDIT_ENABLED,
        )

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
    }


@auth_router.post('/logout')
async def logout(
    response: Response,
    global_logout: bool = False,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    """
    Clears the access token cookie and optionally performs a global logout
    (invalidating all sessions for this user).
    """
    response.delete_cookie(key='access_token', path='/')

    if global_logout and current_user:
        current_user.is_revoked = True
        await db.commit()

    return {'message': 'Logged out successfully'}


@auth_router.post('/refresh')
async def refresh_token(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Body(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Renew the access token using a refresh token.
    The refresh token can be provided in the body or via cookie.
    """
    token = refresh_token or request.cookies.get('refresh_token')
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Refresh token missing',
        )

    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings
    user_model = rbac_instance.user_model if rbac_instance else User

    try:
        payload = decode_token(token, settings=s)
        if payload.get('type') != 'refresh':
            raise ValueError('Invalid token type')
        email = payload.get('sub')
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid refresh token',
        )

    stmt = (
        select(user_model)
        .where(user_model.email == email)
        .options(selectinload(user_model.roles))
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or (s.AUTH_REVOCATION_ENABLED and user.is_revoked):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='User not found or session revoked',
        )

    # Fetch permissions for scopes
    rbac = RBACManager(db)
    permissions = await rbac.get_user_permissions(user)

    new_access_token = create_access_token(
        data={'sub': user.email, 'scopes': list(permissions)}, settings=s
    )
    new_refresh_token = create_refresh_token(
        data={'sub': user.email}, settings=s
    )

    # Update cookies
    response.set_cookie(
        key='access_token',
        value=new_access_token,
        httponly=False,
        max_age=s.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path='/',
    )
    response.set_cookie(
        key='refresh_token',
        value=new_refresh_token,
        httponly=True,
        max_age=s.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path='/',
    )

    return {
        'access_token': new_access_token,
        'refresh_token': new_refresh_token,
        'token_type': 'bearer',
    }


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
async def verify_email(
    request: Request, token: str, db: AsyncSession = Depends(get_db)
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings

    try:
        payload = decode_token(token, settings=s)
        email = payload.get('sub')

        user_model = rbac_instance.user_model if rbac_instance else User

        stmt = select(user_model).where(user_model.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail='User not found')

        user.is_verified = True
        await db.commit()

        # Trigger Hook
        if rbac_instance:
            await rbac_instance.hooks.trigger('post_email_verify', user)

        return {'message': 'Email verified successfully'}
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid or expired token')


@auth_router.post('/forgot-password')
async def forgot_password(
    request: Request, email: EmailStr, db: AsyncSession = Depends(get_db)
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings
    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = select(user_model).where(user_model.email == email)
    result = await db.execute(stmt)
    if not result.scalar_one_or_none():
        return {
            'message': 'If the email is registered, you will receive a reset link'
        }

    token = create_access_token(
        data={'sub': email, 'type': 'reset_password'}, settings=s
    )

    if rbac_instance:
        # Fetch user again to be sure (already done by exist check above but we need to pass it to exporter)
        stmt = select(user_model).where(user_model.email == email)
        res = await db.execute(stmt)
        u = res.scalar_one()
        await rbac_instance.email_exporter.send_password_reset_email(u, token)

    return {
        'message': 'If the email is registered, you will receive a reset link',
        'debug_token': token,
    }


@auth_router.post('/reset-password')
async def reset_password(
    request: Request,
    data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings

    try:
        payload = decode_token(data.token, settings=s)
        if payload.get('type') != 'reset_password':
            raise ValueError('Invalid token type')

        email = payload.get('sub')

        user_model = rbac_instance.user_model if rbac_instance else User

        stmt = select(user_model).where(user_model.email == email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail='User not found')

        user.hashed_password = hash_password(data.new_password)
        await db.commit()

        # Trigger Hook
        if rbac_instance:
            await rbac_instance.hooks.trigger('post_password_reset', user)

        return {'message': 'Password reset successfully'}
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid or expired token')


async def _process_google_login(
    request: Request, code: str, redirect_uri: str, db: AsyncSession
):
    """
    Shared logic for processing Google Login (Code Exchange -> User Provisioning -> Token Issuance).
    Returns a Response object with tokens and cookies set.
    """
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings

    user_data = await GoogleOAuth.get_user_data(
        code,
        redirect_uri,
        client_id=s.GOOGLE_OAUTH_CLIENT_ID,
        client_secret=s.GOOGLE_OAUTH_CLIENT_SECRET,
    )
    email = user_data.get('email')

    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = (
        select(user_model)
        .where(user_model.email == email)
        .options(selectinload(user_model.roles))
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        stmt_role = select(Role).where(Role.name == 'user')
        result_role = await db.execute(stmt_role)
        user_role = result_role.scalar_one_or_none()

        user = user_model(
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
    if (
        rbac_instance
        and rbac_instance.settings.REQUIRE_VERIFIED_LOGIN
        and not user.is_verified
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='USER_NOT_VERIFIED',
        )

    rbac = RBACManager(db)
    permissions = await rbac.get_user_permissions(user)
    access_token = create_access_token(
        data={'sub': user.email, 'scopes': list(permissions)}, settings=s
    )

    # Set cookie for dashboard access
    response = Response(
        content=json.dumps(
            {
                'access_token': access_token,
                'token_type': 'bearer',
                'user': {
                    'email': user.email,
                    'roles': [r.name for r in user.roles],
                },
            }
        ),
        media_type='application/json',
    )
    response.set_cookie(
        key='access_token',
        value=access_token,
        httponly=False,
        max_age=s.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path='/',
    )

    # Audit Log
    if rbac_instance:
        audit = AuditManager(db)
        await audit.log(
            actor_email=user.email,
            action='USER_LOGIN_GOOGLE',
            target=user.email,
            enabled=rbac_instance.settings.AUDIT_ENABLED,
        )

    return response


@auth_router.get('/google/callback')
async def google_callback(
    request: Request, code: str, db: AsyncSession = Depends(get_db)
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings

    try:
        redirect_uri = s.GOOGLE_OAUTH_REDIRECT_URI or str(
            request.url_for('google_callback')
        )
        return await _process_google_login(request, code, redirect_uri, db)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@auth_router.post('/google/exchange')
async def google_exchange(
    request: Request,
    data: GoogleAuthRequest,
    db: AsyncSession = Depends(get_db),
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    s = rbac_instance.settings if rbac_instance else default_settings

    try:
        # For SPA, usually the redirect_uri is the origin or configured one
        redirect_uri = data.redirect_uri or s.GOOGLE_OAUTH_REDIRECT_URI
        if not redirect_uri:
            raise HTTPException(
                status_code=400, detail='Redirect URI is required'
            )

        return await _process_google_login(
            request, data.code, redirect_uri, db
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
