from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EvidenceType(StrEnum):
    """Supported types of cryptographic investigation evidence."""

    ORIGINAL_EMAIL = "ORIGINAL_EMAIL"
    INVESTIGATION_REPORT = "INVESTIGATION_REPORT"
    ATTACHMENT = "ATTACHMENT"


class EvidenceIntegrityStatus(StrEnum):
    """Cryptographic verification status outcomes."""

    VERIFIED = "VERIFIED"
    CORRUPTED = "CORRUPTED"
    MISSING = "MISSING"


@dataclass
class EvidenceRecordResult:
    """Structured representation of a persisted evidence integrity record."""

    id: str
    case_id: str
    evidence_type: str
    sha256_hash: str
    file_name: str | None = None
    file_size_bytes: int = 0
    calculated_at_iso: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "evidence_type": self.evidence_type,
            "sha256_hash": self.sha256_hash,
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "calculated_at_iso": self.calculated_at_iso,
            "metadata": self.metadata,
        }


@dataclass
class EvidenceVerificationResult:
    """Detailed result of cryptographic evidence verification."""

    case_id: str
    evidence_type: str
    status: EvidenceIntegrityStatus
    is_valid: bool
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    file_name: str | None = None
    verified_at_iso: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "evidence_type": self.evidence_type,
            "status": self.status.value
            if isinstance(self.status, EvidenceIntegrityStatus)
            else str(self.status),
            "is_valid": self.is_valid,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "file_name": self.file_name,
            "verified_at_iso": self.verified_at_iso,
            "details": self.details,
        }
