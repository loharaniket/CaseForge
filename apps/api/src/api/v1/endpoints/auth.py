from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.api.deps import get_current_active_user, get_db, require_admin
from src.core.errors import AppException
from src.core.security import create_access_token, hash_password, verify_password
from src.models.user import User, UserRole
from src.schemas.auth import LoginRequest, TokenResponse
from src.schemas.user import UserCreate, UserRegistrationRequest, UserResponse

router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Analyst Login",
    description="Authenticates an analyst using email and password, returning a signed JWT Bearer token and user profile.",
    responses={
        200: {"description": "Authentication successful"},
        401: {"description": "Invalid credentials provided"},
        403: {"description": "Account is inactive"},
    },
)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticates credentials and issues a JWT token."""
    query = select(User).where(User.email == payload.email.lower())
    user = db.execute(query).scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise AppException(
            message="Invalid email or password.",
            code="INVALID_CREDENTIALS",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if not user.is_active:
        raise AppException(
            message="User account is deactivated. Contact a SOC administrator.",
            code="INACTIVE_USER",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    token, expires_in = create_access_token(
        subject=user.id,
        role=user.role.value,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Current User Profile",
    description="Returns the profile of the currently authenticated analyst.",
    responses={
        200: {"description": "Authenticated user profile"},
        401: {"description": "Missing or invalid token"},
    },
)
def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Returns the authenticated analyst identity."""
    return UserResponse.model_validate(current_user)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Analyst Account",
    description="Provisions a new analyst account. Always creates UserRole.ANALYST to prevent privilege escalation.",
)
def register(
    payload: UserRegistrationRequest,
    db: Session = Depends(get_db),
) -> UserResponse:
    """Registers a new user with analyst privileges."""
    # Check for existing email
    query = select(User).where(User.email == payload.email.lower())
    existing = db.execute(query).scalar_one_or_none()
    if existing:
        raise AppException(
            message="An account with this email address already exists.",
            code="EMAIL_ALREADY_REGISTERED",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={"email": payload.email},
        )

    new_user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=UserRole.ANALYST,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse.model_validate(new_user)


@router.post(
    "/admin/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision User (Admin Only)",
    description="Protected endpoint for administrators to provision analysts or fellow administrators.",
    responses={
        201: {"description": "User account provisioned successfully"},
        400: {"description": "Email already registered or invalid payload"},
        401: {"description": "Authentication required"},
        403: {"description": "Administrator privileges required"},
    },
)
def admin_create_user(
    payload: UserCreate,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Provisions a user with the requested role (restricted to administrators)."""
    query = select(User).where(User.email == payload.email.lower())
    existing = db.execute(query).scalar_one_or_none()
    if existing:
        raise AppException(
            message="An account with this email address already exists.",
            code="EMAIL_ALREADY_REGISTERED",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={"email": payload.email},
        )

    new_user = User(
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse.model_validate(new_user)


@router.get(
    "/admin-only",
    summary="Admin Authorization Probe",
    description="Protected endpoint accessible only by users with the admin role.",
    responses={
        200: {"description": "Authorized as administrator"},
        403: {"description": "Insufficient permissions"},
    },
)
def admin_only_route(
    admin_user: User = Depends(require_admin),
) -> dict:
    """Admin-only protected route for authorization testing."""
    return {
        "message": "Admin authorization granted.",
        "admin_email": admin_user.email,
    }
