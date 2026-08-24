import hashlib
import hmac
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case
from src.models.evidence import EvidenceRecord
from src.services.evidence.types import (
    EvidenceIntegrityStatus,
    EvidenceRecordResult,
    EvidenceType,
    EvidenceVerificationResult,
)
from src.services.storage import EvidenceStorage, default_storage

logger = logging.getLogger("threattrace")


class EvidenceIntegrityService:
    """Service providing deterministic cryptographic SHA-256 evidence hashing and integrity verification."""

    def __init__(self, storage: EvidenceStorage | None = None) -> None:
        self.storage = storage or default_storage

    def calculate_hash(self, data: bytes) -> str:
        """Computes deterministic cryptographic SHA-256 hash of byte payload."""
        if data is None:
            raise ValueError("Cannot calculate hash for null data")
        return hashlib.sha256(data).hexdigest()

    def verify_hash(self, expected_hash: str, actual_data: bytes | None) -> bool:
        """Performs constant-time comparison between expected SHA-256 hash and actual byte payload."""
        if not expected_hash or actual_data is None:
            return False
        actual_hash = self.calculate_hash(actual_data)
        return hmac.compare_digest(expected_hash.strip().lower(), actual_hash.strip().lower())

    def record_evidence_hash(
        self,
        case_id: str,
        evidence_type: EvidenceType | str,
        data: bytes,
        file_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        db: Session | None = None,
    ) -> EvidenceRecordResult:
        """Computes SHA-256 hash for raw evidence and idempotently records/updates it in database."""
        ev_type = str(
            evidence_type.value if isinstance(evidence_type, EvidenceType) else evidence_type
        )
        sha256_hash = self.calculate_hash(data)
        file_size = len(data)
        now = datetime.now(UTC)

        if db is not None:
            # Query existing record for idempotency (case_id + evidence_type + file_name)
            query = select(EvidenceRecord).where(
                EvidenceRecord.case_id == case_id,
                EvidenceRecord.evidence_type == ev_type,
            )
            if file_name:
                query = query.where(EvidenceRecord.file_name == file_name)

            existing = db.execute(query).scalar_one_or_none()

            if existing:
                existing.sha256_hash = sha256_hash
                existing.file_size_bytes = file_size
                existing.file_name = file_name or existing.file_name
                existing.metadata_json = metadata or existing.metadata_json
                existing.calculated_at = now
                existing.updated_at = now
                record_id = existing.id
            else:
                new_record = EvidenceRecord(
                    case_id=case_id,
                    evidence_type=ev_type,
                    sha256_hash=sha256_hash,
                    file_name=file_name,
                    file_size_bytes=file_size,
                    metadata_json=metadata or {},
                    calculated_at=now,
                )
                db.add(new_record)
                db.flush()
                record_id = new_record.id

            logger.info(
                f"Recorded SHA-256 evidence integrity hash for case '{case_id}' "
                f"type='{ev_type}' sha256={sha256_hash[:16]}..."
            )
            return EvidenceRecordResult(
                id=record_id,
                case_id=case_id,
                evidence_type=ev_type,
                sha256_hash=sha256_hash,
                file_name=file_name,
                file_size_bytes=file_size,
                calculated_at_iso=now.isoformat(),
                metadata=metadata or {},
            )

        # Ephemeral record if DB session is omitted (e.g. standalone test)
        return EvidenceRecordResult(
            id=f"ephemeral-{case_id}",
            case_id=case_id,
            evidence_type=ev_type,
            sha256_hash=sha256_hash,
            file_name=file_name,
            file_size_bytes=file_size,
            calculated_at_iso=now.isoformat(),
            metadata=metadata or {},
        )

    def get_case_evidence_records(self, case_id: str, db: Session) -> list[EvidenceRecordResult]:
        """Retrieves all persisted evidence integrity records for a case."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' not found.")

        records = (
            db.execute(
                select(EvidenceRecord)
                .where(EvidenceRecord.case_id == case_id)
                .order_by(EvidenceRecord.calculated_at.asc())
            )
            .scalars()
            .all()
        )

        results: list[EvidenceRecordResult] = []
        for r in records:
            results.append(
                EvidenceRecordResult(
                    id=r.id,
                    case_id=r.case_id,
                    evidence_type=r.evidence_type,
                    sha256_hash=r.sha256_hash,
                    file_name=r.file_name,
                    file_size_bytes=r.file_size_bytes,
                    calculated_at_iso=r.calculated_at.isoformat()
                    if r.calculated_at
                    else datetime.now(UTC).isoformat(),
                    metadata=r.metadata_json or {},
                )
            )
        return results

    def verify_case_evidence(
        self,
        case_id: str,
        evidence_type: EvidenceType | str,
        db: Session,
        target_record_id: str | None = None,
    ) -> EvidenceVerificationResult:
        """Cryptographically verifies stored evidence hash against underlying storage or generated asset."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' not found.")

        ev_type = str(
            evidence_type.value if isinstance(evidence_type, EvidenceType) else evidence_type
        )

        # 1. Fetch expected record
        query = select(EvidenceRecord).where(
            EvidenceRecord.case_id == case_id,
            EvidenceRecord.evidence_type == ev_type,
        )
        if target_record_id:
            query = query.where(EvidenceRecord.id == target_record_id)

        record = db.execute(query).scalar_one_or_none()

        expected_hash = (
            record.sha256_hash
            if record
            else case.sha256_hash
            if ev_type == EvidenceType.ORIGINAL_EMAIL
            else None
        )
        file_name = (
            record.file_name
            if record
            else case.file_name
            if ev_type == EvidenceType.ORIGINAL_EMAIL
            else None
        )

        if not expected_hash:
            return EvidenceVerificationResult(
                case_id=case_id,
                evidence_type=ev_type,
                file_name=file_name,
                expected_sha256=None,
                actual_sha256=None,
                status=EvidenceIntegrityStatus.MISSING,
                is_valid=False,
                details={
                    "reason": f"No baseline cryptographic hash registered for evidence type '{ev_type}'."
                },
            )

        # 2. Retrieve actual evidence payload based on type
        actual_bytes: bytes | None = None
        details: dict[str, Any] = {}

        if ev_type == EvidenceType.ORIGINAL_EMAIL:
            actual_bytes = self.storage.get(case.storage_key)
            if actual_bytes is None:
                return EvidenceVerificationResult(
                    case_id=case_id,
                    evidence_type=ev_type,
                    file_name=file_name,
                    expected_sha256=expected_hash,
                    actual_sha256=None,
                    status=EvidenceIntegrityStatus.MISSING,
                    is_valid=False,
                    details={
                        "reason": f"Original evidence file '{case.storage_key}' is missing from storage."
                    },
                )

        elif ev_type == EvidenceType.INVESTIGATION_REPORT:
            # Check if report artifact was persisted in storage
            storage_key = (
                record.metadata_json.get("storage_key")
                if (record and record.metadata_json)
                else None
            )
            if storage_key:
                actual_bytes = self.storage.get(storage_key)

            if actual_bytes is None:
                # Fallback to generating report dynamically
                from src.services.report.service import default_report_service

                try:
                    actual_bytes, _ = default_report_service.generate_case_pdf(
                        case_id=case_id, db=db
                    )
                except Exception as e:
                    return EvidenceVerificationResult(
                        case_id=case_id,
                        evidence_type=ev_type,
                        file_name=file_name
                        or f"ThreatTrace_Investigation_Report_{case_id[:8]}.pdf",
                        expected_sha256=expected_hash,
                        actual_sha256=None,
                        status=EvidenceIntegrityStatus.MISSING,
                        is_valid=False,
                        details={
                            "reason": f"Failed to retrieve or generate report for verification: {str(e)}"
                        },
                    )

        if actual_bytes is None:
            return EvidenceVerificationResult(
                case_id=case_id,
                evidence_type=ev_type,
                file_name=file_name,
                expected_sha256=expected_hash,
                actual_sha256=None,
                status=EvidenceIntegrityStatus.MISSING,
                is_valid=False,
                details={"reason": "Actual evidence payload could not be retrieved."},
            )

        # 3. Compute actual hash and verify
        actual_hash = self.calculate_hash(actual_bytes)
        is_valid = self.verify_hash(expected_hash, actual_bytes)

        status = EvidenceIntegrityStatus.VERIFIED if is_valid else EvidenceIntegrityStatus.CORRUPTED
        details["algorithm"] = "SHA-256"
        details["payload_size_bytes"] = len(actual_bytes)

        if not is_valid:
            details["tamper_warning"] = (
                "CRITICAL: Cryptographic checksum mismatch detected. Evidence integrity or custody may be compromised."
            )

        return EvidenceVerificationResult(
            case_id=case_id,
            evidence_type=ev_type,
            file_name=file_name,
            expected_sha256=expected_hash,
            actual_sha256=actual_hash,
            status=status,
            is_valid=is_valid,
            details=details,
        )

    def verify_all_case_evidence(
        self, case_id: str, db: Session
    ) -> list[EvidenceVerificationResult]:
        """Cryptographically verifies all registered evidence records for an investigation case."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' not found.")

        records = (
            db.execute(select(EvidenceRecord).where(EvidenceRecord.case_id == case_id))
            .scalars()
            .all()
        )

        results: list[EvidenceVerificationResult] = []

        if not records:
            # Always verify baseline original email evidence if present
            results.append(
                self.verify_case_evidence(
                    case_id=case_id, evidence_type=EvidenceType.ORIGINAL_EMAIL, db=db
                )
            )
            return results

        for r in records:
            ver_res = self.verify_case_evidence(
                case_id=case_id,
                evidence_type=r.evidence_type,
                db=db,
                target_record_id=r.id,
            )
            results.append(ver_res)

        return results


# Global default instance & dependency injector
default_evidence_service = EvidenceIntegrityService()


def get_evidence_integrity_service() -> EvidenceIntegrityService:
    """FastAPI dependency injector for EvidenceIntegrityService."""
    return default_evidence_service
