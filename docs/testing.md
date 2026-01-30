# 🧪 Testing
Testing authenticated routes is simple with the included `AuthTestClient`.

## Basic Usage

```python
from fastapi.testclient import TestClient
from fastapi_oauth_rbac.testing import AuthTestClient
from my_app import app

client = TestClient(app)
auth_client = AuthTestClient(client)

def test_protected_route():
    # Login as a user with specific permissions
    auth_client.login_as("user@example.com", scopes=["users:read"])
    
    response = client.get("/users/me")
    assert response.status_code == 200
```

## Manual Headers
If you prefer to manage headers yourself:

```python
from fastapi_oauth_rbac.testing import AuthTestClient

auth = AuthTestClient(None)
headers = auth.get_auth_headers("admin@example.com", scopes=["*"])

response = client.get("/admin/config", headers=headers)
```
