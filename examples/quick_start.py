from fastapi import FastAPI, Depends
from fastapi_oauth_rbac import FastAPIOAuthRBAC
from fastapi_oauth_rbac.rbac.dependencies import (
    get_current_user,
    requires_permission,
)
from fastapi_oauth_rbac.rbac.logic import Or, Not
from fastapi_oauth_rbac.database.models import User

# Minimal code needed!
app = FastAPI(title='Async Quick Start')

# 1. Initialize Library
# auto_setup is now internal and mandatory in lifespan.
# We enable the dashboard and require verification for login.
auth = FastAPIOAuthRBAC(app, enable_dashboard=True, require_verified=True)

# 2. Register Custom Roles (Optional)
auth.add_role('editor', 'Can manage content', ['content:update', 'content:read'])
auth.add_role('content_manager', 'Can manage all content', ['content:*'])

# 3. Include the authentication router
auth.include_auth_router()


@app.get('/me')
async def read_me(current_user: User = Depends(get_current_user)):
    return {
        'email': current_user.email,
        'roles': [r.name for r in current_user.roles],
    }


@app.get('/edit', dependencies=[requires_permission('content:edit')])
async def edit_content():
    return {'message': 'You can edit this!'}


@app.get('/admin-only', dependencies=[requires_permission('roles:manage')])
async def admin_only():
    return {'message': 'Welcome, Master of Roles!'}


@app.get(
    '/multi-perm',
    dependencies=[requires_permission(['users:read', 'dashboard:read'])],
)
async def multi_perm():
    """Requires BOTH users:read AND dashboard:read (List input means AND)"""
    return {'message': 'You have both required permissions!'}


@app.get(
    '/complex-logic',
    dependencies=[
        requires_permission(Or('users:write', Not('is_guest:access')))
    ],
)
async def complex_logic():
    """Requires (users:write OR NOT is_guest:access)"""
    return {'message': 'You passed the complex logic check!'}


@app.get('/content/view', dependencies=[requires_permission('content:read')])
async def content_view():
    """Matches 'content:*' wildcard granted to content_manager"""
    return {'message': 'Access granted to content:read via wildcard!'}


if __name__ == '__main__':
    import uvicorn

    # Default DATABASE_URL from config.py will be used (sqlite+aiosqlite)
    uvicorn.run(app, host='0.0.0.0', port=8001)
