# fastapi-oauth-rbac

A comprehensive FastAPI library for Authentication and NIST-style Role-Based Access Control (RBAC).

## Quick Start
Get up and running in seconds with fully asynchronous database support and automatic NIST setup.

```python
from fastapi import FastAPI
from fastapi_oauth_rbac import FastAPIOAuthRBAC

app = FastAPI()

# 1. Initialize Library with auto_setup=True
# This handles:
# - Async DB engine and session creation (via DATABASE_URL env)
# - Database table creation
# - Standard roles (admin, user, viewer) and permissions setup
# - Initial superuser creation (via ADMIN_EMAIL/ADMIN_PASSWORD env)
# - FastAPI Lifespan management
auth = FastAPIOAuthRBAC(app, auto_setup=True)

# 2. Include the authentication router (signup, login, logout, me, etc.)
auth.include_auth_router()
```

## Features
- **Asynchronous**: Built from the ground up to support async database drivers (`aiosqlite`, `asyncpg`).
- **Lifespan Support**: Uses the modern FastAPI lifespan pattern for clean resource management.
- **Plug-and-Play**: Automated role and permission setup with a single flag.
- **Full Auth Flow**: Signup, Login, Logout (Global), `/me` endpoint, and more.
- **NIST RBAC**: Advanced Role-Based Access Control with hierarchy.

## Configuration
The following environment variables can be used to configure the library:
- `DATABASE_URL`: SQLAlchemy database URL.
- `JWT_SECRET_KEY`: Secret key for JWT signing.
- `GOOGLE_OAUTH_CLIENT_ID`: Google OAuth client ID.
- `GOOGLE_OAUTH_CLIENT_SECRET`: Google OAuth client secret.
- `AUTH_REVOCATION_ENABLED`: Set to `true` to enable user-level token revocation.

## License
MIT
