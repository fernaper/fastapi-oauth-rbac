# ⚙️ Configuration

**FastAPIOAuthRBAC** is designed to be configured primarily through environment variables.

> [!IMPORTANT]
> All environment variables must be prefixed with `FORBAC_` (e.g., `FORBAC_DATABASE_URL`, `FORBAC_ADMIN_EMAIL`).

## 🛠️ Settings Injection

While environment variables are the easiest way to configure the library, you can also inject a `Settings` object during initialization. This is useful for dynamic configurations or testing.

```python
from fastapi_oauth_rbac import FastAPIOAuthRBAC, Settings

# Load settings from environment (default behavior)
auth = FastAPIOAuthRBAC(app)

# OR provide explicit values
custom_settings = Settings(
    DATABASE_URL="postgresql+asyncpg://user:pass@localhost/db",
    JWT_SECRET_KEY="my-super-secret-key",
    SIGNUP_ENABLED=False
)
auth = FastAPIOAuthRBAC(app, settings=custom_settings)
```

## 🔑 Core Configuration

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | SQLAlchemy connection string. Supports async drivers. | `sqlite+aiosqlite:///./sql_app.db` |
| `JWT_SECRET_KEY` | Secret key for signing JWT tokens. **Keep this secret!** | `very-secret-change-me` |
| `JWT_ALGORITHM` | Algorithm used for JWT singing. | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Lifetime of the access token in minutes. | `30` |

## 🛡️ Admin Provisioning

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ADMIN_EMAIL` | The email for the initial superuser. | `admin@example.com` |
| `ADMIN_PASSWORD` | The password for the initial superuser. | `admin123` |

## 🌐 OAuth2 / OpenID Connect

Integrate third-party login providers easily.

### Google OAuth
| Variable | Description |
| :--- | :--- |
| `GOOGLE_OAUTH_CLIENT_ID` | Your Google Cloud Console Client ID. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Your Google Cloud Console Client Secret. |

## ⚙️ Flow & Security Settings

| Variable | Description | Default |
| :--- | :--- | :--- |
| `SIGNUP_ENABLED` | Allow new users to register via the signup endpoint. | `True` |
| `VERIFY_EMAIL_ENABLED` | Whether to send verification emails (Implementation pending). | `False` |
| `REQUIRE_VERIFIED_LOGIN` | Enforce email verification for all logins. | `False` |
| `AUTH_REVOCATION_ENABLED` | Enable user-level token revocation (Logout Global). | `False` |
| `AUDIT_ENABLED` | Toggle automatic audit logging for system actions. | `True` |

## ⚡ Dashboard Settings

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DASHBOARD_ENABLED` | Enable the visual administration dashboard. | `True` |
| `DASHBOARD_PATH` | Relative path where the dashboard will be hosted. | `/auth/dashboard` |

---
[🏠 Index](README.md) | [🚀 Getting Started](getting-started.md) | [🛡️ RBAC Model](rbac.md)
