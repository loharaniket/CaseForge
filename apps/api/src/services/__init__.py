"""Service layer abstractions and provider implementations."""

from src.services.parser import (
    AttachmentMetadata,
    EmailParser,
    EMLParser,
    ParsedEmailData,
    default_eml_parser,
)
from src.services.parser_service import ParserService, default_parser_service, get_parser_service
from src.services.storage import EvidenceStorage, LocalEvidenceStorage, get_evidence_storage

__all__ = [
    "AttachmentMetadata",
    "EMLParser",
    "EmailParser",
    "EvidenceStorage",
    "LocalEvidenceStorage",
    "ParsedEmailData",
    "ParserService",
    "default_eml_parser",
    "default_parser_service",
    "get_evidence_storage",
    "get_parser_service",
]
