# 🚀 Getting Started

This guide will help you get up and running with **FastAPIOAuthRBAC** in your FastAPI project.

## 📋 Prerequisites

- Python 3.9+
- A running database (SQLite, PostgreSQL, MySQL) supported by SQLAlchemy.
- A FastAPI application.

## ⚙️ Installation

You can install the library directly from your preferred package manager:

```bash
# Basic installation (no DB driver)
pip install fastapi-oauth-rbac

# With SQLite support
pip install "fastapi-oauth-rbac[sqlite]"

# With PostgreSQL support
pip install "fastapi-oauth-rbac[postgres]"

# Using uv
uv add fastapi-oauth-rbac --extra sqlite
```

## 🛠️ Basic Integration

Getting started is as simple as initializing the `FastAPIOAuthRBAC` class. By default, it uses environment variables for configuration and handles database initialization and default role creation automatically.

```python
from fastapi import FastAPI
from fastapi_oauth_rbac import FastAPIOAuthRBAC

app = FastAPI()

# Initialize the library
auth = FastAPIOAuthRBAC(app)

# Add the essential authentication routes (login, logout, signup, /me)
auth.include_auth_router()

# Add the Admin Dashboard (Optional)
auth.include_dashboard()
```

## 👤 Custom User Model

You can provide your own SQLAlchemy model (e.g., to add extra fields like `phone_number` or `avatar`). Your model should ideally inherit from `UserBaseMixin` or at least include its fields.

```python
from fastapi_oauth_rbac import UserBaseMixin, Base

class MyUser(Base, UserBaseMixin):
    __tablename__ = "my_custom_users"
    phone: str = Column(String)

# Pass it during initialization
auth = FastAPIOAuthRBAC(app, user_model=MyUser)
```

## 🔒 Protecting Routes

Use the `requires_permission` dependency to enforce RBAC on your endpoints.

```python
from fastapi import Depends
from fastapi_oauth_rbac import requires_permission

@app.get("/admin-data", dependencies=[Depends(requires_permission("users:manage"))])
async def get_sensitive_data():
    return {"message": "Only those with 'users:manage' permission can see this!"}
```

## 📚 Next Steps

- Go to **[Configuration](configuration.md)** to learn about environment variables.
- Learn about the **[NIST RBAC Model](rbac.md)** used by this library.
- Explore the **[API Reference](api-reference.md)** for more advanced usage.

---
[🏠 Index](README.md) | [⚙️ Configuration](configuration.md)
