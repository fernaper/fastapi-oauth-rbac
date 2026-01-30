import asyncio
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from fastapi_oauth_rbac import FastAPIOAuthRBAC, User, Role, Permission, Base
from fastapi_oauth_rbac.rbac.dependencies import (
    get_current_user,
    requires_permission,
)
from fastapi_oauth_rbac.core.security import hash_password

app = FastAPI(title='Multi-tenancy Example')

# 1. Setup Async Database
DATABASE_URL = 'sqlite+aiosqlite:///./multi_tenant.db'
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# 2. Initialize Library
auth = FastAPIOAuthRBAC(app)
auth.include_auth_router()


@app.on_event('startup')
async def startup():
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # 3. Setup Roles and Permissions

        # Global Permission
        read_perm = Permission(
            name='data:read', description='Global read permission'
        )

        # Tenant Scoped Permission
        secret_perm = Permission(
            name='org:secret', description='Organization secret access'
        )
        db.add_all([read_perm, secret_perm])
        await db.commit()

        # Global Role: Everyone can read
        viewer_role = Role(
            name='Viewer', permissions=[read_perm], tenant_id=None
        )

        # Scoped Role: Only for Org A
        org_a_manager = Role(
            name='OrgManager', permissions=[secret_perm], tenant_id='org_a'
        )

        # Scoped Role: Only for Org B (with same name but different tenant and permissions)
        org_b_manager = Role(
            name='OrgManager', permissions=[], tenant_id='org_b'
        )

        db.add_all([viewer_role, org_a_manager, org_b_manager])
        await db.commit()

        # 4. Create Users for different tenants

        # Alice belongs to Org A
        alice = User(
            email='alice@org_a.com',
            hashed_password=hash_password('password123'),
            tenant_id='org_a',
            roles=[viewer_role, org_a_manager],
        )

        # Bob belongs to Org B
        bob = User(
            email='bob@org_b.com',
            hashed_password=hash_password('password123'),
            tenant_id='org_b',
            roles=[
                viewer_role,
                org_a_manager,
            ],  # Notice Bob is assigned Org A's manager role by mistake
        )

        db.add_all([alice, bob])
        await db.commit()


@app.get('/tenant-info')
async def get_info(user: User = Depends(get_current_user)):
    """Show current user tenant and roles."""
    return {
        'email': user.email,
        'tenant_id': user.tenant_id,
        'assigned_roles': [r.name for r in user.roles],
    }


@app.get('/global-data', dependencies=[requires_permission('data:read')])
async def global_data():
    """Accessible by anyone with Viewer role."""
    return {'message': 'This is global data.'}


@app.get('/org-secrets', dependencies=[requires_permission('org:secret')])
async def org_secrets(user: User = Depends(get_current_user)):
    """
    Only Alice should be able to see this.
    Bob has the 'OrgManager' role assigned, but since that role is scoped
    to 'org_a' and Bob is in 'org_b', the RBAC manager will filter it out.
    """
    return {'message': f'Welcome to the secret vault of {user.tenant_id}'}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8001)
