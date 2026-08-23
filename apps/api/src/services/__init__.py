"""Service layer abstractions and provider implementations."""

from src.services.detection_service import (
    DetectionService,
    default_detection_service,
    get_detection_service,
)
from src.services.detector import (
    RuleBasedThreatDetector,
    ThreatCategory,
    ThreatDetectionResult,
    ThreatDetector,
    default_rule_detector,
)
from src.services.forensics import (
    AuthenticationResult,
    AuthenticationStatus,
    AuthStatus,
    EmailAuthenticationAnalyzer,
    HeaderForensicsResult,
    HeaderForensicsService,
    NormalizedEmailAuthentication,
    ProtocolAuthResult,
    RelayHop,
    default_auth_analyzer,
    default_forensics_service,
    get_forensics_service,
    normalize_auth_status,
)
from src.services.parser import (
    AttachmentMetadata,
    EmailParser,
    EMLParser,
    ParsedEmailData,
    default_eml_parser,
    extract_urls,
)
from src.services.parser_service import (
    ParserService,
    default_parser_service,
    get_parser_service,
)
from src.services.risk import (
    RiskCalculationResult,
    RiskScoreBreakdown,
    RiskScoringService,
    RiskSeverity,
    default_risk_service,
    get_risk_service,
)
from src.services.storage import (
    EvidenceStorage,
    LocalEvidenceStorage,
    get_evidence_storage,
)

__all__ = [
    "AttachmentMetadata",
    "AuthStatus",
    "AuthenticationResult",
    "AuthenticationStatus",
    "DetectionService",
    "EMLParser",
    "EmailAuthenticationAnalyzer",
    "EmailParser",
    "EvidenceStorage",
    "HeaderForensicsResult",
    "HeaderForensicsService",
    "LocalEvidenceStorage",
    "NormalizedEmailAuthentication",
    "ParsedEmailData",
    "ParserService",
    "ProtocolAuthResult",
    "RelayHop",
    "RiskCalculationResult",
    "RiskScoreBreakdown",
    "RiskScoringService",
    "RiskSeverity",
    "RuleBasedThreatDetector",
    "ThreatCategory",
    "ThreatDetectionResult",
    "ThreatDetector",
    "default_auth_analyzer",
    "default_detection_service",
    "default_eml_parser",
    "default_forensics_service",
    "default_parser_service",
    "default_risk_service",
    "default_rule_detector",
    "extract_urls",
    "get_detection_service",
    "get_evidence_storage",
    "get_forensics_service",
    "get_parser_service",
    "get_risk_service",
    "normalize_auth_status",
]
