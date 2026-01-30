from typing import List, Set, Dict

from sqlalchemy import select, or_
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
        Resolves hierarchy for both roles and permissions using iterative DB lookups.
        """
        user_role_ids = {role.id for role in user.roles}
        if not user_role_ids:
            return set()

        # 1. Resolve role hierarchy (ancestors)
        final_role_ids = set(user_role_ids)
        to_process_roles = list(user_role_ids)

        while to_process_roles:
            stmt = select(Role.parent_id).where(
                Role.id.in_(to_process_roles),
                or_(Role.tenant_id == user.tenant_id, Role.tenant_id == None),
            )
            result = await self.db.execute(stmt)
            parents = {p for p in result.scalars().all() if p is not None}
            new_parents = parents - final_role_ids
            final_role_ids.update(new_parents)
            to_process_roles = list(new_parents)

        # 2. Get base permissions from all resolved roles
        stmt_user_perms = (
            select(Permission)
            .join(role_permissions)
            .where(role_permissions.c.role_id.in_(final_role_ids))
        )
        result_user_perms = await self.db.execute(stmt_user_perms)
        user_base_perms = result_user_perms.scalars().all()

        # 3. Resolve permission hierarchy (descendants)
        final_perms = {p.name for p in user_base_perms}
        to_process_perm_ids = [p.id for p in user_base_perms]
        processed_perm_ids = set(to_process_perm_ids)

        while to_process_perm_ids:
            stmt = select(Permission).where(
                Permission.parent_id.in_(to_process_perm_ids)
            )
            result = await self.db.execute(stmt)
            children = result.scalars().all()

            new_perm_ids = []
            for child in children:
                if child.id not in processed_perm_ids:
                    processed_perm_ids.add(child.id)
                    final_perms.add(child.name)
                    new_perm_ids.append(child.id)
            to_process_perm_ids = new_perm_ids

        # 4. Expand wildcards for frontend visibility (e.g. '*' or 'users:*')
        has_wildcard = any(p == '*' or p.endswith(':*') for p in final_perms)
        if has_wildcard:
            stmt_all = select(Permission.name)
            result_all = await self.db.execute(stmt_all)
            all_known_names = set(result_all.scalars().all())

            expanded_perms = set()
            for p in final_perms:
                expanded_perms.add(p)
                if p == '*':
                    expanded_perms.update(all_known_names)
                elif p.endswith(':*'):
                    prefix = p[:-2]
                    expanded_perms.update(
                        {
                            n
                            for n in all_known_names
                            if n.startswith(prefix + ':')
                        }
                    )
            return expanded_perms

        return final_perms

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
