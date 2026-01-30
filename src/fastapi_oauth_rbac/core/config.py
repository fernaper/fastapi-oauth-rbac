from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = 'sqlite+aiosqlite:///./sql_app.db'
    JWT_SECRET_KEY: str = 'secret'
    JWT_ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # OAuth Settings
    GOOGLE_OAUTH_CLIENT_ID: Optional[str] = None
    GOOGLE_OAUTH_CLIENT_SECRET: Optional[str] = None
    GOOGLE_OAUTH_REDIRECT_URI: Optional[str] = None

    # RBAC Settings
    AUTH_REVOCATION_ENABLED: bool = False

    # Default Admin (for quick start)
    ADMIN_EMAIL: str = 'admin@example.com'
    ADMIN_PASSWORD: Optional[str] = None

    # Auth Flow Settings
    SIGNUP_ENABLED: bool = True
    VERIFY_EMAIL_ENABLED: bool = False
    REQUIRE_VERIFIED_LOGIN: bool = False

    # Dashboard Settings
    DASHBOARD_ENABLED: bool = True
    DASHBOARD_PATH: str = '/auth/dashboard'

    model_config = SettingsConfigDict(
        env_file='.env',
        extra='ignore',
        env_prefix='FORBAC_',
    )


settings = Settings()
