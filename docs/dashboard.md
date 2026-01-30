# 🖥️ Admin Dashboard

**FastAPIOAuthRBAC** comes with a built-in, premium visual dashboard to manage your system's access control without writing a single line of code or SQL.

## 🚀 Accessing the Dashboard

By default, the dashboard is available at:
`http://your-app-url/auth/dashboard/`

> [!NOTE]
> Access to the dashboard itself is protected. Only users with the `dashboard:view` permission (included in the default `Admin` role) can log in.

## 👥 User Management

The User Management screen allows you to:
- **Provision New Users**: Create accounts directly from the UI.
- **Assign Roles**: Add or remove roles from any user via a modal.
- **Toggle Status**: Instantly deactivate/activate accounts.
- **Manual Verification**: Toggle the "Verified" status of users (bypassing email flows).

## 🛡️ Role Management

The Role Management screen allows you to:
- **Create Custom Roles**: Define roles specific to your organization.
- **Configure Permissions**: A granular grid interface to select exactly which permissions a role possesses.
- **Inheritance View**: See which roles inherit from others.
- **System Roles**: View protected system roles (like `Admin`) that cannot be deleted to prevent accidental lockouts.

## 🎨 Customizing the UI

The dashboard is built with Vanilla CSS and Jinja2 templates, designed to look premium out of the box with a "glassmorphism" aesthetic.

You can customize the prefix using the `DASHBOARD_PATH` environment variable.

---
[🏠 Index](README.md) | [🛡️ RBAC Model](rbac.md) | [🏗️ Architecture](architecture.md)
