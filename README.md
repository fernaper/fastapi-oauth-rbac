# FastAPIOAuthRBAC

[![PyPI version](https://badge.fury.io/py/fastapi-oauth-rbac.svg)](https://badge.fury.io/py/fastapi-oauth-rbac) [![Downloads](https://static.pepy.tech/badge/fastapi-oauth-rbac)](https://pepy.tech/project/fastapi-oauth-rbac) [![Downloads Month](https://static.pepy.tech/badge/fastapi-oauth-rbac/month)](https://pepy.tech/project/fastapi-oauth-rbac)

A comprehensive FastAPI library for Authentication and NIST-style Role-Based Access Control (RBAC).

---

## 📖 Complete Documentation

The documentation has been significantly improved and split into easy-to-digest resources:

- **[Documentation Index](docs/README.md)** - Start here for the full overview.
- **[🚀 Getting Started](docs/getting-started.md)** - Installation and basic usage.
- **[⚙️ Configuration](docs/configuration.md)** - Environment variables and setup.
- **[🛡️ NIST RBAC Model](docs/rbac.md)** - Learn about roles, hierarchies, and permissions.
- **[🖥️ Admin Dashboard](docs/dashboard.md)** - Guide to the visual administration panel.
- **[💻 Frontend Integration](docs/frontend-integration.md)** - Vanilla JS & React guides.

---

## 🛠️ Examples

Check out the `examples/` directory for practical implementations:
- `basic_app.py`: Standard implementation.
- `multi_tenancy.py`: [NEW] Scoping users and roles to tenants.
- `advanced_extension.py`: [NEW] Custom User models, Hooks, and Email services.
- `testing_example.py`: [NEW] How to test your protected routes.

---

## Quick Start (Minimal)

```python
from fastapi import FastAPI
from fastapi_oauth_rbac import FastAPIOAuthRBAC

app = FastAPI()
auth = FastAPIOAuthRBAC(app)
auth.include_auth_router()
auth.include_dashboard()
```

## Features
- **Asynchronous**: Full support for `aiosqlite`, `asyncpg`, etc.
- **NIST RBAC**: Advanced Role-Based Access Control with hierarchy.
- **Full Auth Flow**: Login, Signup, OAuth (Google), and Global Logout.
- **Premium Dashboard**: Manage users and roles through a beautiful glassmorphism UI.

## License
MIT
