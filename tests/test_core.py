from fastapi_oauth_rbac.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
)


def test_password_hashing():
    password = 'secret_password'
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password('wrong_password', hashed) is False


def test_jwt_token():
    data = {'sub': 'test@example.com'}
    token = create_access_token(data)
    decoded = decode_token(token)
    assert decoded['sub'] == 'test@example.com'
    assert 'exp' in decoded
