from fastapi import FastAPI, APIRouter, Depends
from typing import Type, Optional, Callable, AsyncGenerator, List, Set
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from .rbac.dependencies import get_current_user
from .database.models import Base, User, Role, Permission
from .database.session import AsyncSessionLocal, engine, get_db
from .core.config import settings
from .core.security import hash_password


class FastAPIOAuthRBAC:
    def __init__(
        self,
        app: FastAPI,
        user_model: Optional[Type] = None,
        require_verified: bool = settings.REQUIRE_VERIFIED_LOGIN,
        enable_dashboard: bool = settings.DASHBOARD_ENABLED,
        dashboard_path: str = settings.DASHBOARD_PATH,
    ):
        self.app = app
        self.registered_roles = {}  # name -> {"description": str, "permissions": List[str]}
        self.require_verified = require_verified
        self.enable_dashboard = enable_dashboard
        self.dashboard_path = dashboard_path

        # Default dependency override
        self.app.dependency_overrides[get_db] = get_db

        # Always setup lifespan for defaults
        original_lifespan = app.router.lifespan_context

        @asynccontextmanager
        async def lifespan_wrapper(
            app: FastAPI,
        ) -> AsyncGenerator[None, None]:
            # 1. Init DB (if using SQLite or explicitly requested,
            # though usually people use Alembic)
            # For now keep it as a convenience, maybe add a flag for it later
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            # 2. Setup defaults (Mandatory)
            async with AsyncSessionLocal() as session:
                await self.setup_defaults(session)

            # 3. Call original lifespan if it exists
            if original_lifespan:
                async with original_lifespan(app) as state:
                    yield state
            else:
                yield

        app.router.lifespan_context = lifespan_wrapper

        # Register dashboard if enabled
        if self.enable_dashboard:
            self._register_dashboard()

    def include_auth_router(self, prefix: str = '/auth'):
        from .auth.router import auth_router

        # Pass our settings to the router (via app state or similar)
        self.app.state.oauth_rbac = self
        self.app.include_router(auth_router, prefix=prefix)

    def _register_dashboard(self):
        """Registers the internal Jinja2 dashboard."""
        from .dashboard.router import dashboard_router

        self.app.include_router(dashboard_router, prefix=self.dashboard_path)

    def add_role(self, name: str, description: str, permissions: List[str]):
        """Registers a role to be created during setup."""
        self.registered_roles[name] = {
            'description': description,
            'permissions': permissions,
        }

    def _discover_route_permissions(self) -> Set[str]:
        """Scans FastAPI routes for required permissions."""
        from .rbac.dependencies import PermissionChecker

        discovered = set()
        for route in self.app.routes:
            if hasattr(route, 'dependencies'):
                for dep in route.dependencies:
                    if isinstance(dep.dependency, PermissionChecker):
                        discovered.update(
                            dep.dependency.requirement.get_permission_names()
                        )

            if hasattr(route, 'dependant'):
                to_check = [route.dependant]
                while to_check:
                    curr = to_check.pop()
                    if isinstance(curr.call, PermissionChecker):
                        discovered.update(
                            curr.call.requirement.get_permission_names()
                        )
                    to_check.extend(curr.dependencies)
        return discovered

    async def setup_defaults(self, db: AsyncSession):
        """Creates standard roles, permissions, and initial admin user with bulk queries."""
        # 1. Collect all required permissions
        basic_perms = {
            'users:read': 'Can read user information',
            'users:write': 'Can create/update users',
            'users:delete': 'Can delete users',
            'users:verify': 'Can verify/deactivate users',
            'roles:manage': 'Can manage roles and permissions',
            'dashboard:view': 'Can view the internal dashboard',
        }

        # Discover permissions from routes
        discovered_perms = self._discover_route_permissions()

        # 1. Define Standard Roles
        standard_roles = {
            'user': ('Standard user access', [], None),
            'user_manager': (
                'Can manage users but not roles',
                ['users:write', 'users:verify', 'dashboard:view'],
                'user',
            ),
            'user_admin': (
                'Can manage users and roles',
                ['users:*', 'roles:manage'],
                'user_manager',
            ),
            'admin': ('Full system access', ['*'], 'user_admin'),
        }

        # Permissions from registered and standard roles
        extra_perms = set()
        for role_info in self.registered_roles.values():
            extra_perms.update(role_info['permissions'])
        for _, perms, _ in standard_roles.values():
            extra_perms.update(perms)

        # 1.5 Ensure wildcards for all discovered prefixes and global wildcard
        all_base_perms = (
            set(basic_perms.keys()) | discovered_perms | extra_perms
        )

        wildcard_perms = {'*'}  # Always allow global wildcard
        for perm in all_base_perms:
            if ':' in perm:
                prefix = perm.split(':')[0]
                wildcard_perms.add(f'{prefix}:*')

        all_perm_names = all_base_perms | wildcard_perms

        # 2. Bulk fetch existing permissions
        stmt = select(Permission).where(Permission.name.in_(all_perm_names))
        result = await db.execute(stmt)
        existing_perms = {p.name: p for p in result.scalars().all()}

        # 3. Bulk create missing permissions
        missing_perms = []
        for name in all_perm_names:
            if name not in existing_perms:
                desc = basic_perms.get(
                    name, f'Automatically discovered permission: {name}'
                )
                if name == '*':
                    desc = 'Global wildcard (Full system access)'
                elif name.endswith(':*'):
                    desc = f'Prefix wildcard for {name[:-2]}'

                new_perm = Permission(name=name, description=desc)
                db.add(new_perm)
                missing_perms.append(new_perm)

        if missing_perms:
            await db.flush()
            for p in missing_perms:
                existing_perms[p.name] = p

        # 5. Handle Roles (Registered + Standard)
        all_roles_to_setup = standard_roles.copy()
        for name, info in self.registered_roles.items():
            all_roles_to_setup[name] = (
                info['description'],
                info['permissions'],
                info.get('parent_role'),
            )

        # Bulk fetch existing roles
        stmt = (
            select(Role)
            .where(Role.name.in_(all_roles_to_setup.keys()))
            .options(selectinload(Role.permissions))
        )
        result = await db.execute(stmt)
        existing_roles = {r.name: r for r in result.scalars().all()}

        # 6. Create/Update roles (First pass: create roles and permissions)
        for name, (desc, perms, _) in all_roles_to_setup.items():
            role_perms = [
                existing_perms[p] for p in perms if p in existing_perms
            ]
            if name not in existing_roles:
                new_role = Role(
                    name=name,
                    description=desc,
                    permissions=role_perms,
                    is_default=name in standard_roles,
                )
                db.add(new_role)
                existing_roles[name] = new_role
            else:
                # Update permissions for existing roles (optional, but good for dev)
                existing_roles[name].permissions = role_perms
                existing_roles[name].is_default = name in standard_roles

        await db.flush()

        # 7. Second pass: handle Role Hierarchy
        for name, (_, _, parent_name) in all_roles_to_setup.items():
            if parent_name and parent_name in existing_roles:
                existing_roles[name].parent_id = existing_roles[
                    parent_name
                ].id

        await db.flush()

        # 6. Initial Admin User
        admin_email = settings.ADMIN_EMAIL
        stmt = select(User).where(User.email == admin_email)
        result = await db.execute(stmt)
        if not result.scalar_one_or_none():
            admin_role = existing_roles.get('admin')

            admin_user = User(
                email=admin_email,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                is_verified=True,
                roles=[admin_role] if admin_role else [],
            )
            db.add(admin_user)

        await db.commit()
