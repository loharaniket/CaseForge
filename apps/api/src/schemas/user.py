from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from src.models.user import UserRole


class UserBase(BaseModel):
    """Base user properties."""

    email: EmailStr = Field(..., description="Analyst email address")
    full_name: str = Field(..., min_length=1, max_length=255, description="Full legal name")
    role: UserRole = Field(default=UserRole.ANALYST, description="Authorization role")


class UserCreate(UserBase):
    """User account registration schema."""

    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Plaintext password (hashed before database persistence)",
    )


class UserResponse(UserBase):
    """Public user response schema — never exposes password or hash."""

    id: int = Field(..., description="User unique identifier")
    is_active: bool = Field(..., description="Account active status")
    created_at: datetime = Field(..., description="Account creation timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "email": "analyst@threattrace.local",
                "full_name": "SOC Lead Analyst",
                "role": "analyst",
                "is_active": True,
                "created_at": "2026-08-23T00:00:00Z",
            }
        },
    )
