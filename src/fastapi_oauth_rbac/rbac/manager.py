from typing import List, Set, Dict

from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from ..database.models import (
    User,
    Role,
    Permission,
    role_permissions,
)


class RBACManager:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_permissions(self, user: User) -> Set[str]:
        """
        Fetches all permissions for a user, including those inherited from roles.
        Resolves hierarchy for both roles and permissions in memory.
        """
        user_role_ids = {role.id for role in user.roles}
        if not user_role_ids:
            return set()

        # 1. Fetch all roles to resolve role hierarchy in memory
        stmt_roles = select(Role)
        result_roles = await self.db.execute(stmt_roles)
        all_db_roles = result_roles.scalars().all()

        role_map: Dict[int, Role] = {r.id: r for r in all_db_roles}
        role_hierarchy: Dict[int, Set[int]] = {}  # parent_id -> children_ids
        for r in all_db_roles:
            if r.parent_id:
                role_hierarchy.setdefault(r.parent_id, set()).add(r.id)

        # 2. Expand user roles recursively
        final_role_ids = set()
        to_process_roles = list(user_role_ids)

        while to_process_roles:
            role_id = to_process_roles.pop()
            if role_id not in final_role_ids:
                final_role_ids.add(role_id)
                role = role_map.get(role_id)
                if role and role.parent_id:
                    # Parent roles are also inherited
                    to_process_roles.append(role.parent_id)

        # 3. Fetch all permissions to resolve permission hierarchy in memory
        stmt_perms = select(Permission)
        result_perms = await self.db.execute(stmt_perms)
        all_db_permissions = result_perms.scalars().all()

        perm_map: Dict[int, Permission] = {p.id: p for p in all_db_permissions}
        perm_hierarchy: Dict[str, Set[str]] = {}

        for p in all_db_permissions:
            if p.parent_id:
                parent = perm_map.get(p.parent_id)
                if parent:
                    perm_hierarchy.setdefault(parent.name, set()).add(p.name)

        # 4. Get base permissions from all resolved roles
        stmt_user_perms = (
            select(Permission.name)
            .join(role_permissions)
            .where(role_permissions.c.role_id.in_(final_role_ids))
        )
        result_user_perms = await self.db.execute(stmt_user_perms)
        user_base_perm_names = set(result_user_perms.scalars().all())

        # 5. Resolve permission hierarchy
        final_perms = set()
        to_process_perms = list(user_base_perm_names)

        while to_process_perms:
            perm_name = to_process_perms.pop()
            if perm_name not in final_perms:
                final_perms.add(perm_name)
                children = perm_hierarchy.get(perm_name, set())
                to_process_perms.extend(children)

        # 6. Expand wildcards for frontend visibility (e.g. '*' or 'users:*')
        all_known_names = {p.name for p in all_db_permissions}
        expanded_perms = set()
        for p in final_perms:
            expanded_perms.add(p)  # Keep original (including wildcard)
            if p == '*':
                expanded_perms.update(all_known_names)
            elif p.endswith(':*'):
                prefix = p[:-2]
                expanded_perms.update(
                    {n for n in all_known_names if n.startswith(prefix + ':')}
                )

        return expanded_perms

    async def has_permission(self, user: User, permission_name: str) -> bool:
        user_perms = await self.get_user_permissions(user)
        # Exact match
        if permission_name in user_perms:
            return True
        # Global wildcard
        if '*' in user_perms:
            return True
        # Prefix wildcard
        for up in user_perms:
            if up.endswith(':*'):
                prefix = up[:-2]
                if permission_name.startswith(prefix + ':'):
                    return True
        return False

    async def has_any_permission(
        self, user: User, permission_names: List[str]
    ) -> bool:
        for perm in permission_names:
            if await self.has_permission(user, perm):
                return True
        return False

    async def has_role(self, user: User, role_name: str) -> bool:
        # Note: has_role now checks if user HAS or INHERITS a role
        user_role_ids = {role.id for role in user.roles}
        stmt_roles = select(Role)
        result_roles = await self.db.execute(stmt_roles)
        all_db_roles = result_roles.scalars().all()

        role_map: Dict[int, Role] = {r.id: r for r in all_db_roles}
        final_role_ids = set()
        to_process_roles = list(user_role_ids)

        while to_process_roles:
            role_id = to_process_roles.pop()
            if role_id not in final_role_ids:
                final_role_ids.add(role_id)
                role = role_map.get(role_id)
                if role and role.parent_id:
                    to_process_roles.append(role.parent_id)

        return any(role_map[rid].name == role_name for rid in final_role_ids)
