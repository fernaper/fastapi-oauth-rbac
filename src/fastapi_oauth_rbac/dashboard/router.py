import os
import uuid

from typing import Optional, List

from fastapi import APIRouter, Depends, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, or_, and_, distinct
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, aliased

from ..core.security import hash_password
from ..core.audit import AuditManager
from ..database.models import AuditLog, Permission, Role, User
from ..rbac.dependencies import (
    get_db,
    get_current_user_optional,
    requires_permission,
)
from ..rbac.manager import RBACManager

dashboard_router = APIRouter(tags=['Dashboard'])


@dashboard_router.get('/audit', response_class=HTMLResponse)
async def audit_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    pageSize: int = 15,
    page: int = 0,
    filter: Optional[str] = None,
):
    # 1. Check permissions
    if not current_user:
        return RedirectResponse(
            url=request.url_for('dashboard_index'),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    rbac = RBACManager(db)
    if not await rbac.has_permission(current_user, 'dashboard.audit:read'):
        return templates.TemplateResponse(
            'access_denied.html.jinja',
            {'request': request, 'user_email': current_user.email},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # 2. Fetch logs
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())

    if filter:
        stmt = stmt.where(
            or_(
                AuditLog.actor_email.ilike(f'%{filter}%'),
                AuditLog.action.ilike(f'%{filter}%'),
                AuditLog.target.ilike(f'%{filter}%'),
                AuditLog.details.ilike(f'%{filter}%'),
            )
        )

    # Total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    count_result = await db.execute(count_stmt)
    total_logs = count_result.scalar()

    # Pagination
    stmt = stmt.offset(page * pageSize).limit(pageSize)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    # Get user permissions for UI toggles
    user_perms = await rbac.get_user_permissions(current_user)

    return templates.TemplateResponse(
        'audit.html.jinja',
        {
            'request': request,
            'logs': logs,
            'page': page,
            'pageSize': pageSize,
            'total_logs': total_logs,
            'filter': filter,
            'user': current_user,
            'user_email': current_user.email,
            'user_perms': user_perms,
            'custom_css': '',
        },
    )


# Set up templates directory
current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, 'templates'))


@dashboard_router.get('/', response_class=HTMLResponse)
async def dashboard_index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    pageSize: int = 10,
    page: int = 0,
    filter: Optional[str] = None,
):
    # 1. Check if user is logged in
    if not current_user:
        return templates.TemplateResponse(
            'login.html.jinja', {'request': request}
        )

    # 2. Check if user has permission to view dashboard
    rbac = RBACManager(db)
    if not await rbac.has_permission(current_user, 'dashboard:read'):
        return templates.TemplateResponse(
            'access_denied.html.jinja',
            {'request': request, 'user_email': current_user.email},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # 3. Standard Dashboard Logic
    # Fetch users with roles and permissions
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    user_model = rbac_instance.user_model if rbac_instance else User

    # Base query for counts and filtering
    base_stmt = select(user_model)

    # Filter logic
    if filter:
        filters = []
        # Search by email (name)
        filters.append(user_model.email.ilike(f'%{filter}%'))

        # Search by status/verified
        if filter.lower() in ('active', 'inactive'):
            filters.append(
                user_model.is_active == (filter.lower() == 'active')
            )
        if filter.lower() in ('verified', 'unverified', 'pending'):
            filters.append(
                user_model.is_verified == (filter.lower() == 'verified')
            )

        # Filter by roles
        role_alias = aliased(Role)
        # We check if any role name matches the filter
        role_stmt = (
            select(user_model.id)
            .join(user_model.roles.of_type(role_alias))
            .where(role_alias.name.ilike(f'%{filter}%'))
        )
        filters.append(user_model.id.in_(role_stmt))

        base_stmt = base_stmt.where(or_(*filters))

    # Total users (always same)
    total_users_stmt = select(func.count()).select_from(user_model)
    total_users_result = await db.execute(total_users_stmt)
    total_users = total_users_result.scalar()

    # Filtered users count
    filtered_users_stmt = select(func.count()).select_from(
        base_stmt.subquery()
    )
    filtered_users_result = await db.execute(filtered_users_stmt)
    filtered_users = filtered_users_result.scalar()

    # Final query with pagination
    stmt = (
        base_stmt.options(
            selectinload(user_model.roles).selectinload(Role.permissions)
        )
        .order_by(user_model.id)
        .offset(page * pageSize)
        .limit(pageSize)
    )
    result = await db.execute(stmt)
    users = result.scalars().all()

    # Get user permissions for UI toggles
    user_perms = await rbac.get_user_permissions(current_user)

    # Fetch all roles for the "Edit Roles" modal
    stmt_all_roles = select(Role).order_by(Role.id)
    result_all_roles = await db.execute(stmt_all_roles)
    all_roles = result_all_roles.scalars().all()

    return templates.TemplateResponse(
        'index.html.jinja',
        {
            'request': request,
            'users': users,
            'all_roles': all_roles,
            'user_email': current_user.email,
            'user_perms': user_perms,
            'pageSize': pageSize,
            'page': page,
            'filter': filter or '',
            'total_users': total_users,
            'filtered_users': filtered_users,
            'custom_css': '',
        },
    )


@dashboard_router.post(
    '/user/verify/{user_id}',
    dependencies=[requires_permission('users:verify')],
)
async def verify_user_action(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    page: int = 0,
    pageSize: int = 10,
    filter: Optional[str] = None,
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = select(user_model).where(user_model.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail='User not found')

    user.is_verified = not user.is_verified
    await db.commit()

    # Audit Log
    audit = AuditManager(db)
    current_user = await get_current_user_optional(
        request,
        request.cookies.get('access_token'),
        db,
    )
    enabled = rbac_instance.settings.AUDIT_ENABLED if rbac_instance else True
    await audit.log(
        actor_email=current_user.email if current_user else 'system',
        action='USER_VERIFY_TOGGLE',
        target=user.email,
        details=f'Verified: {user.is_verified}',
        ip_address=request.client.host if request.client else None,
        enabled=enabled,
    )

    query = f'?page={page}&pageSize={pageSize}'
    if filter:
        query += f'&filter={filter}'

    return RedirectResponse(
        url=f'{request.url_for("dashboard_index")}{query}',
        status_code=status.HTTP_303_SEE_OTHER,
    )


@dashboard_router.post(
    '/user/toggle-active/{user_id}',
    dependencies=[requires_permission('users:verify')],
)
async def toggle_user_active(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    page: int = 0,
    pageSize: int = 10,
    filter: Optional[str] = None,
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = select(user_model).where(user_model.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail='User not found')

    user.is_active = not user.is_active
    await db.commit()

    # Audit Log
    audit = AuditManager(db)
    current_user = await get_current_user_optional(
        request,
        request.cookies.get('access_token'),
        db,
    )
    enabled = rbac_instance.settings.AUDIT_ENABLED if rbac_instance else True
    await audit.log(
        actor_email=current_user.email if current_user else 'system',
        action='USER_TOGGLE_ACTIVE',
        target=user.email,
        details=f'Active: {user.is_active}',
        ip_address=request.client.host if request.client else None,
        enabled=enabled,
    )

    query = f'?page={page}&pageSize={pageSize}'
    if filter:
        query += f'&filter={filter}'

    return RedirectResponse(
        url=f'{request.url_for("dashboard_index")}{query}',
        status_code=status.HTTP_303_SEE_OTHER,
    )


@dashboard_router.post(
    '/user/create', dependencies=[requires_permission('users:write')]
)
async def create_user_action(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    is_verified: bool = Form(False),
    db: AsyncSession = Depends(get_db),
):
    # Check if exists
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = select(user_model).where(user_model.email == email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail='User already exists')

    # Get default role
    stmt_role = select(Role).where(Role.name == 'user')
    result_role = await db.execute(stmt_role)
    user_role = result_role.scalar_one_or_none()

    new_user = user_model(
        email=email,
        hashed_password=hash_password(password),
        is_verified=is_verified,
        roles=[user_role] if user_role else [],
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Audit Log
    audit = AuditManager(db)
    current_user = await get_current_user_optional(
        request,
        request.cookies.get('access_token'),
        db,
    )
    enabled = rbac_instance.settings.AUDIT_ENABLED if rbac_instance else True
    await audit.log(
        actor_email=current_user.email if current_user else 'system',
        action='USER_CREATED_DASHBOARD',
        target=new_user.email,
        ip_address=request.client.host if request.client else None,
        enabled=enabled,
    )
    return RedirectResponse(
        url=request.url_for('dashboard_index'),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@dashboard_router.post(
    '/user/update-roles/{user_id}',
    dependencies=[requires_permission('roles:manage')],
)
async def update_user_roles(
    user_id: uuid.UUID,
    request: Request,
    role_ids: List[int] = Form([]),
    db: AsyncSession = Depends(get_db),
    page: int = 0,
    pageSize: int = 10,
    filter: Optional[str] = None,
):
    rbac_instance = getattr(request.app.state, 'oauth_rbac', None)
    user_model = rbac_instance.user_model if rbac_instance else User

    stmt = (
        select(user_model)
        .where(user_model.id == user_id)
        .options(selectinload(user_model.roles))
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail='User not found')

    # Fetch new roles
    if role_ids:
        stmt_roles = select(Role).where(Role.id.in_(role_ids))
        result_roles = await db.execute(stmt_roles)
        new_roles = result_roles.scalars().all()
        user.roles = list(new_roles)
    else:
        user.roles = []
    await db.commit()

    # Audit Log
    audit = AuditManager(db)
    current_user = await get_current_user_optional(
        request,
        request.cookies.get('access_token'),
        db,
    )
    enabled = rbac_instance.settings.AUDIT_ENABLED if rbac_instance else True
    await audit.log(
        actor_email=current_user.email if current_user else 'system',
        action='USER_ROLES_UPDATE',
        target=user.email,
        details=f'New role IDs: {role_ids}',
        ip_address=request.client.host if request.client else None,
        enabled=enabled,
    )

    return RedirectResponse(
        url=request.url_for('dashboard_index'),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@dashboard_router.get('/roles', response_class=HTMLResponse)
async def roles_index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    if not current_user:
        return templates.TemplateResponse(
            'login.html.jinja', {'request': request}
        )

    rbac = RBACManager(db)
    if not await rbac.has_permission(current_user, 'roles:manage'):
        return templates.TemplateResponse(
            'access_denied.html.jinja',
            {'request': request, 'user_email': current_user.email},
            status_code=status.HTTP_403_FORBIDDEN,
        )

    # Fetch roles with permissions
    stmt_roles = (
        select(Role).options(selectinload(Role.permissions)).order_by(Role.id)
    )
    result_roles = await db.execute(stmt_roles)
    roles = result_roles.scalars().all()

    # Fetch all permissions (discovered)
    stmt_perms = select(Permission).order_by(Permission.name)
    result_perms = await db.execute(stmt_perms)
    all_permissions = result_perms.scalars().all()

    user_perms = await rbac.get_user_permissions(current_user)

    return templates.TemplateResponse(
        'roles.html.jinja',
        {
            'request': request,
            'roles': roles,
            'all_permissions': all_permissions,
            'user_email': current_user.email,
            'user_perms': user_perms,
        },
    )


@dashboard_router.post(
    '/role/create', dependencies=[requires_permission('roles:manage')]
)
async def create_role_action(
    request: Request,
    name: str = Form(...),
    description: str = Form(None),
    permission_ids: List[int] = Form([]),
    db: AsyncSession = Depends(get_db),
):
    # Check if exists
    stmt = select(Role).where(Role.name == name)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail='Role already exists')

    role_perms = []
    if permission_ids:
        stmt_perms = select(Permission).where(
            Permission.id.in_(permission_ids)
        )
        result_perms = await db.execute(stmt_perms)
        role_perms = result_perms.scalars().all()

    new_role = Role(
        name=name,
        description=description,
        permissions=list(role_perms),
        is_default=False,
    )
    db.add(new_role)
    await db.commit()
    return RedirectResponse(
        url=request.url_for('roles_index'),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@dashboard_router.post(
    '/role/delete/{role_id}',
    dependencies=[requires_permission('roles:manage')],
)
async def delete_role_action(
    role_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    stmt = select(Role).where(Role.id == role_id)
    result = await db.execute(stmt)
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(status_code=404, detail='Role not found')

    if role.is_default:
        raise HTTPException(
            status_code=400,
            detail='Cannot delete default roles',
        )

    await db.delete(role)
    await db.commit()
    return RedirectResponse(
        url=request.url_for('roles_index'),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@dashboard_router.post(
    '/role/update-permissions/{role_id}',
    dependencies=[requires_permission('roles:manage')],
)
async def update_role_permissions(
    role_id: int,
    request: Request,
    permission_ids: List[int] = Form([]),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(Role)
        .where(Role.id == role_id)
        .options(selectinload(Role.permissions))
    )
    result = await db.execute(stmt)
    role = result.scalar_one_or_none()

    if not role:
        raise HTTPException(status_code=404, detail='Role not found')

    if role.is_default:
        raise HTTPException(
            status_code=400, detail='Cannot edit default roles'
        )

    # Fetch new permissions
    if permission_ids:
        stmt_perms = select(Permission).where(
            Permission.id.in_(permission_ids)
        )
        result_perms = await db.execute(stmt_perms)
        new_perms = result_perms.scalars().all()
        role.permissions = list(new_perms)
    else:
        role.permissions = []

    await db.commit()
    return RedirectResponse(
        url=request.url_for('roles_index'),
        status_code=status.HTTP_303_SEE_OTHER,
    )
