from datetime import timedelta

import jwt
import pytest

from src.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_hashing_and_verification():
    """Verify password hashing produces bcrypt hashes and validates matches."""
    plain = "AnalystSecretPassword2026!"
    hashed = hash_password(plain)

    # Hash should not equal plaintext
    assert hashed != plain
    assert hashed.startswith("$2b$")

    # Correct password verifies
    assert verify_password(plain, hashed) is True

    # Wrong password fails verification
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_token_generation_and_decoding():
    """Verify JWT access token creation, claims, and payload decoding."""
    user_id = 42
    role = "analyst"
    token, expires_in = create_access_token(
        subject=user_id,
        role=role,
        expires_delta=timedelta(minutes=30),
    )

    assert isinstance(token, str)
    assert len(token) > 20
    assert expires_in == 1800

    payload = decode_access_token(token)
    assert payload["sub"] == "42"
    assert payload["role"] == "analyst"
    assert "exp" in payload
    assert "iat" in payload


def test_jwt_expired_token_raises_error():
    """Verify that expired JWT tokens raise ExpiredSignatureError."""
    token, _ = create_access_token(
        subject=100,
        role="analyst",
        expires_delta=timedelta(seconds=-10),  # Already expired in the past
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_jwt_invalid_signature_raises_error():
    """Verify that tampered tokens raise PyJWTError."""
    token, _ = create_access_token(subject=100)
    tampered_token = token[:-5] + "XXXXX"

    with pytest.raises(jwt.PyJWTError):
        decode_access_token(tampered_token)
