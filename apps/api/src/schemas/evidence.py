from typing import Any

from pydantic import BaseModel, Field


class EvidenceRecordSchema(BaseModel):
    """Schema representing a cryptographic SHA-256 evidence record."""

    id: str = Field(description="Unique record UUID")
    case_id: str = Field(description="Associated investigation case UUID")
    evidence_type: str = Field(
        description="Type of evidence: ORIGINAL_EMAIL, INVESTIGATION_REPORT, ATTACHMENT"
    )
    sha256_hash: str = Field(description="Deterministic cryptographic SHA-256 hex digest")
    file_name: str | None = Field(default=None, description="Original evidence or report filename")
    file_size_bytes: int = Field(default=0, description="Raw evidence payload size in bytes")
    status: str = Field(default="UNVERIFIED", description="Current evidence status")
    calculated_at_iso: str = Field(description="ISO 8601 timestamp of hash calculation")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata payload")


class CaseEvidenceListResponse(BaseModel):
    """API response model for case evidence integrity records."""

    case_id: str
    total_evidence_records: int
    records: list[EvidenceRecordSchema]


class EvidenceVerificationResultSchema(BaseModel):
    """Schema representing verification outcome of a single evidence artifact."""

    case_id: str
    evidence_type: str
    status: str = Field(description="VERIFIED, INTEGRITY_MISMATCH, or UNAVAILABLE")
    is_valid: bool = Field(description="True if cryptographic hash exactly matches evidence")
    expected_sha256: str | None = Field(default=None, description="Persisted baseline hash")
    actual_sha256: str | None = Field(
        default=None, description="Freshly calculated hash from actual data"
    )
    file_name: str | None = Field(default=None)
    verified_at_iso: str
    details: dict[str, Any] = Field(default_factory=dict)


class CaseEvidenceVerificationResponse(BaseModel):
    """API response model for cryptographic verification across case evidence."""

    case_id: str
    total_verified: int
    all_valid: bool
    results: list[EvidenceVerificationResultSchema]
