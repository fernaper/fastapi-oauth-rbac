from typing import List, Optional, Dict

from fastapi.testclient import TestClient

from .core.security import create_access_token


class AuthTestClient:
    """Helper to create and manage authenticated test clients."""

    def __init__(self, client: TestClient):
        self.client = client

    def get_auth_headers(
        self, email: str, scopes: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """Generates a JWT and returns the Authorization header."""
        token = create_access_token(
            data={'sub': email, 'scopes': scopes or []}
        )
        return {'Authorization': f'Bearer {token}'}

    def login_as(self, email: str, scopes: Optional[List[str]] = None):
        """Sets the authorization header on the internal client."""
        headers = self.get_auth_headers(email, scopes)
        self.client.headers.update(headers)
        return self.client
