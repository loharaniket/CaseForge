"""Pydantic request and response schemas."""

from src.schemas.auth import LoginRequest, TokenResponse
from src.schemas.email import AttachmentMetadataResponse, ParsedEmailResponse
from src.schemas.error import ErrorDetail, ErrorResponse
from src.schemas.forensics import (
    AuthenticationResultSchema,
    HeaderForensicsResponse,
    ProtocolAuthDetailSchema,
    RelayHopSchema,
)
from src.schemas.health import DatabaseStatus, HealthResponse, HealthStatus, LivenessResponse
from src.schemas.ioc import CaseIOCListResponse, IOCRecordSchema
from src.schemas.ready import ReadyResponse, ReadyStatus
from src.schemas.risk import RiskAssessmentResponse, RiskBreakdownSchema
from src.schemas.threat import ThreatAssessmentResponse
from src.schemas.upload import EmailUploadResponse
from src.schemas.user import UserCreate, UserResponse, UserRole

__all__ = [
    "AttachmentMetadataResponse",
    "AuthenticationResultSchema",
    "CaseIOCListResponse",
    "DatabaseStatus",
    "EmailUploadResponse",
    "ErrorDetail",
    "ErrorResponse",
    "HeaderForensicsResponse",
    "HealthResponse",
    "HealthStatus",
    "IOCRecordSchema",
    "LivenessResponse",
    "LoginRequest",
    "ParsedEmailResponse",
    "ProtocolAuthDetailSchema",
    "ReadyResponse",
    "ReadyStatus",
    "RelayHopSchema",
    "RiskAssessmentResponse",
    "RiskBreakdownSchema",
    "ThreatAssessmentResponse",
    "TokenResponse",
    "UserCreate",
    "UserResponse",
    "UserRole",
]
