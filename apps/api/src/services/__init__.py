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
from src.services.storage import (
    EvidenceStorage,
    LocalEvidenceStorage,
    get_evidence_storage,
)

__all__ = [
    "AttachmentMetadata",
    "DetectionService",
    "EMLParser",
    "EmailParser",
    "EvidenceStorage",
    "LocalEvidenceStorage",
    "ParsedEmailData",
    "ParserService",
    "RuleBasedThreatDetector",
    "ThreatCategory",
    "ThreatDetectionResult",
    "ThreatDetector",
    "default_detection_service",
    "default_eml_parser",
    "default_parser_service",
    "default_rule_detector",
    "extract_urls",
    "get_detection_service",
    "get_evidence_storage",
    "get_parser_service",
]
