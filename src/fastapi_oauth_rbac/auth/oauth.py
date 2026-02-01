import httpx

from typing import Dict, Any

from ..core.config import settings as default_settings, Settings


class GoogleOAuth:
    TOKEN_URL = 'https://oauth2.googleapis.com/token'
    USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo'

    @classmethod
    async def get_user_data(
        cls, code: str, redirect_uri: str, client_id: str, client_secret: str
    ) -> Dict[str, Any]:
        if not client_id or not client_secret:
            raise ValueError('Google OAuth credentials not configured')

        async with httpx.AsyncClient() as client:
            # Exchange code for token
            token_res = await client.post(
                cls.TOKEN_URL,
                data={
                    'code': code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': redirect_uri,
                    'grant_type': 'authorization_code',
                },
            )
            token_res.raise_for_status()
            token_data = token_res.json()
            access_token = token_data.get('access_token')

            # Get user info
            user_res = await client.get(
                cls.USERINFO_URL,
                headers={'Authorization': f'Bearer {access_token}'},
            )
            user_res.raise_for_status()
            return user_res.json()
