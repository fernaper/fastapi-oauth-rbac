# 📖 API Reference

This document provides a reference for the primary classes and decorators provided by **FastAPIOAuthRBAC**.

## `FastAPIOAuthRBAC` Class

The main entry point for the library.

### Initialization
```python
FastAPIOAuthRBAC(
    app: FastAPI,
    user_model: Optional[Type] = None,
    require_verified: bool = settings.REQUIRE_VERIFIED_LOGIN,
    enable_dashboard: bool = settings.DASHBOARD_ENABLED,
    dashboard_path: str = settings.DASHBOARD_PATH,
)
```
- `app`: The FastAPI instance to attach to.
- `user_model`: (Optional) Your custom SQLAlchemy user model. Defaults to internal `User`.
- `require_verified`: Whether to enforce email verification for logins.
- `enable_dashboard`: Toggle the visual admin dashboard.
- `dashboard_path`: The base path for the dashboard (defaults to `/auth/dashboard`).

### Methods
- `include_auth_router()`: Mounts the authentication endpoints (`/login`, `/signup`, `/logout`, `/me`).
- `include_dashboard()`: Mounts the admin dashboard.

## 🪝 Event Hooks
The library provides an event system to react to core identity events.

```python
auth = FastAPIOAuthRBAC(app)

@auth.hooks.register("post_signup")
async def welcome_user(user, **kwargs):
    print(f"Welcome {user.email}!")
```

Available events: `post_signup`, `post_login`, `post_password_reset`, `post_email_verify`.

## 📧 Email Exporters
To send real emails, subclass `BaseEmailExporter` and pass it during initialization.

```python
from fastapi_oauth_rbac import BaseEmailExporter

class MyEmailService(BaseEmailExporter):
    async def send_verification_email(self, user, token):
        # Your custom logic (SendGrid, etc)
        ...

auth = FastAPIOAuthRBAC(app, email_exporter=MyEmailService())
```

## 🔄 Refresh Tokens
The library supports JWT refresh tokens for secure session renewal.

- **/refresh**: Endpoint to exchange a valid refresh token for a new access token and a new rotated refresh token.
- **Cookies**: Refresh tokens are stored in `httponly` cookies for enhanced security.
- **Configuration**: `REFRESH_TOKEN_EXPIRE_DAYS` (default: 7).

## 📜 Audit Logging
Administrative actions performed through the dashboard are automatically logged.

- **Actions Logged**: `USER_VERIFY_TOGGLE`, `USER_ROLES_UPDATE`.
- **Database Table**: `audit_logs` (stores actor, action, target, details, and IP).

## 🏢 Multi-tenancy
Users and roles can be scoped to a specific tenant.

- **tenant_id**: Both `User` and `Role` models include an optional `tenant_id` field.
- **Scoping**: When resolving permissions, the `RBACManager` only considers global roles (null `tenant_id`) or roles matching the user's `tenant_id`.

## 🧱 Dependencies

These functions are designed to be used with FastAPI's `Depends()`.

### `get_current_user`
Retrieves the currently authenticated user from the JWT token. Raises `401 Unauthorized` if the token is missing or invalid.

```python
from fastapi import Depends
from fastapi_oauth_rbac import get_current_user, User

@app.get("/users/me")
async def read_me(user: User = Depends(get_current_user)):
    return user
```

### `requires_permission(requirement: str | List[str])`
Enforces that the authenticated user must satisfy the specified permission requirements.

```python
from fastapi_oauth_rbac import requires_permission

# Using as a router-level dependency (Recommended)
@app.get("/config", dependencies=[Depends(requires_permission("system.config:read"))])
async def get_config():
    ...
```

> [!NOTE]
> `requires_permission` returns a dependency function, so it must be wrapped in `Depends()` when used in `dependencies=[]` or as a function argument.

## 🛠️ CLI Utility

The library provides a simple CLI utility for administrative tasks.

### Set User Password
If you need to manually update a user's password from the terminal:

```bash
# From your project root (ensure src is in your PYTHONPATH)
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
python -m fastapi_oauth_rbac.main set-password "user@example.com" "new_secure_password"
```

## Internal Models (SQLAlchemy)

The library uses the following models for its internal state:
- `User`: Identity data and status.
- `Role`: Named role with hierarchy supports.
- `Permission`: Granular capability string.

---
[🏠 Index](README.md) | [🛡️ RBAC Model](rbac.md) | [🏗️ Architecture](architecture.md)
