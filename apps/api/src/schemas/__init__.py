"""Pydantic request and response schemas."""

from src.schemas.auth import LoginRequest, TokenResponse
from src.schemas.email import AttachmentMetadataResponse, ParsedEmailResponse
from src.schemas.error import ErrorDetail, ErrorResponse
from src.schemas.evidence import (
    CaseEvidenceListResponse,
    CaseEvidenceVerificationResponse,
    EvidenceRecordSchema,
    EvidenceVerificationResultSchema,
)
from src.schemas.forensics import (
    AuthenticationResultSchema,
    HeaderForensicsResponse,
    ProtocolAuthDetailSchema,
    RelayHopSchema,
)
from src.schemas.geo import CaseGeoInfrastructureResponse, GeoLocationResultSchema
from src.schemas.graph import (
    CaseThreatGraphResponse,
    GraphNodeSchema,
    GraphRelationshipSchema,
)
from src.schemas.health import DatabaseStatus, HealthResponse, HealthStatus, LivenessResponse
from src.schemas.intel import CaseThreatIntelResponse, ReputationResultSchema
from src.schemas.ioc import CaseIOCListResponse, IOCRecordSchema
from src.schemas.ip_intel import CaseIPIntelligenceResponse, IPIntelligenceRecordSchema
from src.schemas.ready import ReadyResponse, ReadyStatus
from src.schemas.report import InvestigationReportDataResponse
from src.schemas.risk import RiskAssessmentResponse, RiskBreakdownSchema
from src.schemas.threat import ThreatAssessmentResponse
from src.schemas.timeline import ForensicTimelineResponse, TimelineEventSchema
from src.schemas.upload import EmailUploadResponse
from src.schemas.user import (
    UserCreate,
    UserRegistrationRequest,
    UserResponse,
    UserRole,
)

__all__ = [
    "AttachmentMetadataResponse",
    "AuthenticationResultSchema",
    "CaseEvidenceListResponse",
    "CaseEvidenceVerificationResponse",
    "CaseGeoInfrastructureResponse",
    "CaseIPIntelligenceResponse",
    "CaseIOCListResponse",
    "IPIntelligenceRecordSchema",
    "CaseThreatGraphResponse",
    "CaseThreatIntelResponse",
    "DatabaseStatus",
    "EmailUploadResponse",
    "ErrorDetail",
    "ErrorResponse",
    "EvidenceRecordSchema",
    "EvidenceVerificationResultSchema",
    "ForensicTimelineResponse",
    "GeoLocationResultSchema",
    "GraphNodeSchema",
    "GraphRelationshipSchema",
    "HeaderForensicsResponse",
    "HealthResponse",
    "HealthStatus",
    "IOCRecordSchema",
    "InvestigationReportDataResponse",
    "LivenessResponse",
    "LoginRequest",
    "ParsedEmailResponse",
    "ProtocolAuthDetailSchema",
    "ReadyResponse",
    "ReadyStatus",
    "RelayHopSchema",
    "ReputationResultSchema",
    "RiskAssessmentResponse",
    "RiskBreakdownSchema",
    "ThreatAssessmentResponse",
    "TimelineEventSchema",
    "TokenResponse",
    "UserCreate",
    "UserRegistrationRequest",
    "UserResponse",
    "UserRole",
]
