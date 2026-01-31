# 🛡️ NIST RBAC Model

**FastAPIOAuthRBAC** implements the **NIST (National Institute of Standards and Technology)** standard for Role-Based Access Control. This model is more powerful than simple "admin/user" flags and allows for complex, hierarchical permission management.

## 🧱 Core Concepts

1.  **Users**: The entities (humans or systems) that access the application.
2.  **Roles**: Named job functions (e.g., `Manager`, `Developer`) that encapsulate a set of permissions.
3.  **Permissions**: Granular capabilities (e.g., `users:read`, `roles:manage`) that represent the right to perform an action.
4.  **Role Hierarchy**: The concept that a "senior" role automatically inherits all permissions from its "junior" roles.

## 🔼 Role Hierarchy

In this library, hierarchies are stored in the database. When you check for a permission, the system recursively looks up through the role hierarchy to see if any assigned role (or its parents) possesses that permission.

### Example Hierarchy
- `SuperAdmin` (Inherits from `Admin`)
- `Admin` (Inherits from `User`)
- `User` (Base role)

If a route requires the `user:profile:edit` permission, and that permission is assigned to the `User` role, then `Admin` and `SuperAdmin` users will also have access.

## ✍️ Defining Permissions

Permissions are strings following the `resource:action` pattern (though any string works).

- `articles:create`
- `billing.invoice:read`
- `system:reboot`

### Wildcards
The library supports robust wildcard matching using the `*` character.

- `*`: Global wildcard. Grants access to every permission in the system.
- `resource:*`: Prefix wildcard. Grants access to all actions within a specific resource (e.g., `users:*` matches `users:read`, `users:write`, etc.).

## 🛠️ Implementation in Code

Use the `requires_permission` dependency. It accepts a single string or a list of strings (interpreted as "require ALL of these").

```python
from fastapi import Depends
from fastapi_oauth_rbac import requires_permission

@app.post("/roles", dependencies=[Depends(requires_permission(["roles:manage", "system:audit"]))])
async def create_new_role():
    # Only users with BOTH permissions (directly or via hierarchy) can enter
    ...
```

---
[🏠 Index](README.md) | [🖥️ Dashboard](dashboard.md) | [📖 API Reference](api-reference.md)
