# 🏢 Multi-tenancy
**FastAPIOAuthRBAC** supports basic multi-tenancy via `tenant_id` scoping. This allows you to host multiple organizations or projects within the same database while keeping their roles and permissions separated.

## How it works

1.  **Model Scoping**: Both `User` and `Role` models have an optional `tenant_id` string field.
2.  **Global vs. Tenant Roles**: 
    *   Roles with `tenant_id = None` are **Global**. They are visible and inheritable by all users.
    *   Roles with a specific `tenant_id` are **Scoped**. They are only visible to users sharing that same `tenant_id`.
3.  **Automatic Filtering**: The `RBACManager` filters role hierarchy resolution automatically based on the current user's `tenant_id`.

## Usage

### Setting up a Tenant User

When creating a user, simply assign a `tenant_id`:

```python
user = User(email="user@org1.com", tenant_id="org_123")
db.add(user)
```

### Creating Scoped Roles

```python
org1_role = Role(name="OrgManager", tenant_id="org_123", permissions=[...])
db.add(org1_role)
```

## Dashboard Support
The dashboard current treats all users and roles equally (it shows everything). In a multi-tenant production environment, you would typically filter the user list in the dashboard based on the logged-in admin's `tenant_id`.
