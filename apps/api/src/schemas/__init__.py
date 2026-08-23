"""Pydantic request and response schemas."""

from src.schemas.auth import LoginRequest, TokenResponse
from src.schemas.email import AttachmentMetadataResponse, ParsedEmailResponse
from src.schemas.error import ErrorDetail, ErrorResponse
from src.schemas.health import DatabaseStatus, HealthResponse, HealthStatus, LivenessResponse
from src.schemas.ready import ReadyResponse, ReadyStatus
from src.schemas.upload import EmailUploadResponse
from src.schemas.user import UserCreate, UserResponse, UserRole

__all__ = [
    "AttachmentMetadataResponse",
    "DatabaseStatus",
    "EmailUploadResponse",
    "ErrorDetail",
    "ErrorResponse",
    "HealthResponse",
    "HealthStatus",
    "LivenessResponse",
    "LoginRequest",
    "ParsedEmailResponse",
    "ReadyResponse",
    "ReadyStatus",
    "TokenResponse",
    "UserCreate",
    "UserResponse",
    "UserRole",
]
