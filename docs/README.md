# FastAPIOAuthRBAC Documentation

Welcome to the comprehensive documentation for **FastAPIOAuthRBAC**. This library provides a robust, asynchronous implementation of NIST-style Role-Based Access Control (RBAC) and Authentication for FastAPI applications.

## 📚 Documentation Resources

| Resource | Description |
| :--- | :--- |
| 🚀 **[Getting Started](getting-started.md)** | Installation and your first "Hello World" with RBAC. |
| ⚙️ **[Configuration](configuration.md)** | Environment variables, Database, and OAuth providers. |
| 🛡️ **[NIST RBAC Model](rbac.md)** | Deep dive into roles, hierarchies, and permissions. |
| 🖥️ **[Admin Dashboard](dashboard.md)** | How to manage users and roles visually. |
| 📖 **[API Reference](api-reference.md)** | Detailed documentation of classes, hooks, and methods. |
| 🏗️ **[Architecture](architecture.md)** | Internal design, database schema, and security flow. |
| 🧪 **[Testing](testing.md)** | How to test your application with RBAC helpers. |
| 🏢 **[Multi-tenancy](multi-tenancy.md)** | Scoping users and roles to tenants. |

---

## 💡 Quick Overview

FastAPIOAuthRBAC is designed to be plug-and-play. The library handles database initialization, standard role creation (Admin, User, Viewer), and initial superuser provisioning automatically via the FastAPI lifespan.

```python
from fastapi import FastAPI
from fastapi_oauth_rbac import FastAPIOAuthRBAC

app = FastAPI()
auth = FastAPIOAuthRBAC(app)
auth.include_auth_router()
```

---
[🏠 Back to Root](../README.md)
