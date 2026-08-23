from pydantic import BaseModel, EmailStr, Field

from src.schemas.user import UserResponse


class LoginRequest(BaseModel):
    """Analyst login request payload."""

    email: EmailStr = Field(..., description="Registered analyst email")
    password: str = Field(..., min_length=1, description="Analyst password")

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "analyst@threattrace.local",
                "password": "SecurePassword123!",
            }
        }
    }


class TokenResponse(BaseModel):
    """JWT bearer token response."""

    access_token: str = Field(..., description="Signed JWT Bearer token")
    token_type: str = Field(default="bearer", description="Token authentication scheme")
    expires_in: int = Field(..., description="Token validity lifetime in seconds")
    user: UserResponse = Field(..., description="Authenticated analyst profile")

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 28800,
                "user": {
                    "id": 1,
                    "email": "analyst@threattrace.local",
                    "full_name": "SOC Lead Analyst",
                    "role": "analyst",
                    "is_active": True,
                    "created_at": "2026-08-23T00:00:00Z",
                },
            }
        }
    }
