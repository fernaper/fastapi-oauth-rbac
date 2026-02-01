from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt
from pwdlib import PasswordHash

from .config import settings as default_settings, Settings

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
) -> str:
    s = settings or default_settings
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=s.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(
        to_encode, s.JWT_SECRET_KEY, algorithm=s.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
) -> str:
    s = settings or default_settings
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=s.REFRESH_TOKEN_EXPIRE_DAYS
        )
    to_encode.update({'exp': expire, 'type': 'refresh'})
    encoded_jwt = jwt.encode(
        to_encode,
        s.JWT_SECRET_KEY,
        algorithm=s.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_token(token: str, settings: Optional[Settings] = None) -> dict:
    s = settings or default_settings
    return jwt.decode(token, s.JWT_SECRET_KEY, algorithms=[s.JWT_ALGORITHM])
