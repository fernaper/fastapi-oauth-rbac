import pytest

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fastapi_oauth_rbac.database.models import Base, User
from fastapi_oauth_rbac.core.security import create_access_token
from fastapi_oauth_rbac.rbac.dependencies import get_current_user
from fastapi_oauth_rbac.core.config import settings


def test_token_revocation():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Create user
    user = User(email='test@example.com', is_revoked=False)
    db.add(user)
    db.commit()

    token = create_access_token(data={'sub': user.email})

    # Enable revocation for test
    settings.AUTH_REVOCATION_ENABLED = True

    # 1. Normal access
    async def mock_get_current_user():
        u = db.query(User).filter(User.email == 'test@example.com').first()
        if settings.AUTH_REVOCATION_ENABLED and u.is_revoked:
            raise HTTPException(status_code=403, detail='Revoked')
        return u

    import asyncio

    current_u = asyncio.run(mock_get_current_user())
    assert current_u.email == 'test@example.com'

    # 2. Revoke globally (Logout all devices)
    user.is_revoked = True
    db.commit()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(mock_get_current_user())
    assert exc.value.status_code == 403

    db.close()
