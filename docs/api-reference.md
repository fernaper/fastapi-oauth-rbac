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
