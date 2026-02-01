import secrets
import string

from typing import Type, Optional, AsyncGenerator, List, Set
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, Depends
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .core.config import settings as default_settings, Settings
from .core.security import hash_password
from .core.hooks import hooks
from .core.email import BaseEmailExporter, ConsoleEmailExporter
from .database.models import Base, User, Role, Permission
from .database.session import get_db


class FastAPIOAuthRBAC:
    def __init__(
        self,
        app: FastAPI,
        user_model: Optional[Type] = None,
        settings: Optional[Settings] = None,
        email_exporter: Optional[BaseEmailExporter] = None,
    ):
        self.app = app
        self.settings = settings or default_settings
        self.user_model = user_model or User
        self.registered_roles = {}  # name -> {"description": str, "permissions": List[str]}
        self.email_exporter = email_exporter or ConsoleEmailExporter()
        self.hooks = hooks

        # Initialize Database Resources
        self.db_engine = create_async_engine(
            self.settings.DATABASE_URL, echo=False
        )
        self.db_sessionmaker = async_sessionmaker(
            bind=self.db_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

        # Default dependency override
        self.app.dependency_overrides[get_db] = get_db

        # Always setup lifespan for defaults
        original_lifespan = app.router.lifespan_context

        @asynccontextmanager
        async def lifespan_wrapper(
            app: FastAPI,
        ) -> AsyncGenerator[None, None]:
            # 1. Init DB
            async with self.db_engine.begin() as conn:
                # FIRST: Create the custom user model's tables if it has its own metadata
                user_metadata = getattr(self.user_model, 'metadata', None)
                if user_metadata:
                    # If it's the same as Base.metadata, we'll handle it below with filtering
                    if user_metadata is not Base.metadata:
                        await conn.run_sync(user_metadata.create_all)
                
                # SECOND: Create library tables, carefully skipping 'users' if overridden
                tables_to_create = []
                for name, table in Base.metadata.tables.items():
                    if name == 'audit_logs' and not self.settings.AUDIT_ENABLED:
                        continue
                    
                    # If using a custom model, skip the library's default 'users' table definition
                    # to let the custom one (which might have more columns) take precedence.
                    if name == 'users' and self.user_model is not User:
                        continue
                        
                    tables_to_create.append(table)
                
                if tables_to_create:
                    await conn.run_sync(
                        Base.metadata.create_all, tables=tables_to_create
                    )
                
                # THIRD: If the custom model uses Base.metadata, we must ensure it's created 
                # after the others to avoid FK issues, but with its specific table object.
                if user_metadata is Base.metadata and self.user_model is not User:
                    user_table = getattr(self.user_model, '__table__', None)
                    if user_table is not None:
                        await conn.run_sync(user_table.create, checkfirst=True)

            # 2. Setup defaults (Mandatory)
            async with self.db_sessionmaker() as session:
                await self.setup_defaults(session)

            # 3. Call original lifespan if it exists
            if original_lifespan:
                async with original_lifespan(app) as state:
                    yield state
            else:
                yield

        app.router.lifespan_context = lifespan_wrapper

    def include_auth_router(self, prefix: str = '/auth'):
        from .auth.router import auth_router

        # Pass our settings to the router (via app state or similar)
        self.app.state.oauth_rbac = self
        self.app.include_router(auth_router, prefix=prefix)

    def include_dashboard(self, path: Optional[str] = None):
        """Registers the internal Jinja2 dashboard."""
        from .dashboard.router import dashboard_router

        dashboard_path = path or self.settings.DASHBOARD_PATH
        self.app.include_router(dashboard_router, prefix=dashboard_path)

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
            'dashboard:read': 'Can view the internal dashboard',
            'dashboard.audit:read': 'Can view system audit logs',
        }

        # Discover permissions from routes
        discovered_perms = self._discover_route_permissions()

        # 1. Define Standard Roles
        standard_roles = {
            'user': ('Standard user access', [], None),
            'user_manager': (
                'Can manage users but not roles',
                ['users:write', 'users:verify', 'dashboard:read'],
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
                existing_roles[name].parent_id = existing_roles[parent_name].id

        await db.flush()

        # 6. Initial Admin User
        admin_email = self.settings.ADMIN_EMAIL
        stmt = select(self.user_model).where(
            self.user_model.email == admin_email
        )
        result = await db.execute(stmt)
        if not result.scalar_one_or_none():
            admin_role = existing_roles.get('admin')
            admin_password = self.settings.ADMIN_PASSWORD
            if not admin_password:
                # Generate a secure random password
                alphabet = string.ascii_letters + string.digits
                admin_password = ''.join(
                    secrets.choice(alphabet) for _ in range(12)
                )
                print('\n' + '=' * 60)
                print('🚀 SECURITY INITIALIZATION')
                print('=' * 60)
                print(f'Admin user created: {admin_email}')
                print(f'Generated password: {admin_password}')
                print('\n' + '⚠️  IMPORTANT:')
                print('Save this password securely!')
                print('To change it, you can use the CLI:')
                print(
                    '  python -m fastapi_oauth_rbac.main set-password "admin@example.com" "new_password"'
                )
                print('=' * 60 + '\n')

            admin_user = self.user_model(
                email=admin_email,
                hashed_password=hash_password(admin_password),
                is_verified=True,
                roles=[admin_role] if admin_role else [],
                **self.settings.ADMIN_EXTRA_DATA,
            )
            db.add(admin_user)

        await db.commit()

    async def set_user_password(self, email: str, password: str):
        """Helper to update a user's password directly."""
        async with self.db_sessionmaker() as session:
            stmt = select(self.user_model).where(
                self.user_model.email == email
            )
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            if not user:
                print(f'User {email} not found.')
                return False

            user.hashed_password = hash_password(password)
            await session.commit()
            print(f'Successfully updated password for {email}.')
            return True


if __name__ == '__main__':
    import argparse
    import asyncio

    async def main():
        parser = argparse.ArgumentParser(
            description='FastAPIOAuthRBAC CLI Utility'
        )
        subparsers = parser.add_subparsers(dest='command', help='Commands')

        # set-password command
        pwd_parser = subparsers.add_parser(
            'set-password', help='Update a user password'
        )
        pwd_parser.add_argument('email', help='Email of the user')
        pwd_parser.add_argument('password', help='New password to set')

        args = parser.parse_args()

        if args.command == 'set-password':
            # We need a dummy app to initialize the class
            from fastapi import FastAPI

            auth = FastAPIOAuthRBAC(FastAPI())
            await auth.set_user_password(args.email, args.password)
        else:
            parser.print_help()

    asyncio.run(main())
