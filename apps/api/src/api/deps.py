from collections.abc import Callable

import jwt
from fastapi import Depends, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.errors import AppException
from src.core.security import decode_access_token
from src.db.session import get_db
from src.models.user import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False,
)


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validates JWT bearer token and retrieves authenticated user from database."""
    if not token:
        raise AppException(
            message="Authentication credentials were not provided.",
            code="UNAUTHORIZED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise AppException(
                message="Invalid authentication token payload.",
                code="INVALID_TOKEN",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
    except jwt.ExpiredSignatureError as exc:
        raise AppException(
            message="Authentication token has expired.",
            code="TOKEN_EXPIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from exc
    except jwt.PyJWTError as exc:
        raise AppException(
            message="Could not validate credentials.",
            code="INVALID_TOKEN",
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from exc

    # Lookup user by ID
    query = select(User).where(User.id == int(user_id))
    user = db.execute(query).scalar_one_or_none()

    if not user:
        raise AppException(
            message="User associated with token does not exist.",
            code="USER_NOT_FOUND",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    return user


def get_current_active_user(
    user: User = Depends(get_current_user),
) -> User:
    """Verifies that the authenticated user account is active."""
    if not user.is_active:
        raise AppException(
            message="User account is deactivated.",
            code="INACTIVE_USER",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    return user


def require_role(required_role: UserRole) -> Callable[[User], User]:
    """Dependency factory enforcing specific role authorization."""

    def role_dependency(
        user: User = Depends(get_current_active_user),
    ) -> User:
        if user.role != required_role:
            raise AppException(
                message=f"Access forbidden: requires '{required_role.value}' role.",
                code="FORBIDDEN",
                status_code=status.HTTP_403_FORBIDDEN,
                details={"required_role": required_role.value, "user_role": user.role.value},
            )
        return user

    return role_dependency


# Pre-configured role dependencies
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ANALYST)
