from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case, CaseStatus
from src.models.evidence import EvidenceRecord
from src.models.user import User, UserRole
from src.services.evidence.service import EvidenceIntegrityService
from src.services.evidence.types import EvidenceIntegrityStatus, EvidenceType
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def temp_storage(tmp_path: Path) -> LocalEvidenceStorage:
    """Fixture providing an isolated local evidence storage directory."""
    return LocalEvidenceStorage(storage_dir=tmp_path / "evidence_vault")


@pytest.fixture
def evidence_service(temp_storage: LocalEvidenceStorage) -> EvidenceIntegrityService:
    """Fixture providing an instance of EvidenceIntegrityService with temp storage."""
    return EvidenceIntegrityService(storage=temp_storage)


@pytest.fixture
def sample_analyst(db_session: Session) -> User:
    """Fixture providing a test analyst user."""
    user = User(
        email="evidence_analyst@threattrace.io",
        hashed_password="hashed_pw_for_test",
        full_name="Evidence Forensic Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_deterministic_sha256_hashing_identical_input(evidence_service: EvidenceIntegrityService):
    """Test identical input payload always produces identical cryptographic SHA-256 digest."""
    payload = b"Received: from mail.threattrace.io\nSubject: Critical Security Advisory\n\nSecurity Notice"
    hash1 = evidence_service.calculate_hash(payload)
    hash2 = evidence_service.calculate_hash(payload)

    assert hash1 == hash2
    assert len(hash1) == 64
    assert isinstance(hash1, str)
    # Validate against known hex pattern
    assert all(c in "0123456789abcdef" for c in hash1)


def test_modified_input_produces_completely_different_hash(
    evidence_service: EvidenceIntegrityService,
):
    """Test single byte modification produces completely distinct SHA-256 hash (avalanche effect)."""
    original = b"Received: from trusted-server.corp.com\nSubject: Invoice #1024\nAmount: $1000"
    tampered = b"Received: from trusted-server.corp.com\nSubject: Invoice #1024\nAmount: $9000"

    hash_original = evidence_service.calculate_hash(original)
    hash_tampered = evidence_service.calculate_hash(tampered)

    assert hash_original != hash_tampered
    # Assert significant character divergence (avalanche)
    diff_chars = sum(1 for c1, c2 in zip(hash_original, hash_tampered, strict=True) if c1 != c2)
    assert diff_chars > 20


def test_verify_hash_constant_time_checks(evidence_service: EvidenceIntegrityService):
    """Test constant-time verify_hash accurately identifies authentic and modified data."""
    payload = b"Evidence Payload For Verification Testing"
    expected_hash = evidence_service.calculate_hash(payload)

    # Authentic match
    assert evidence_service.verify_hash(expected_hash, payload) is True
    # Case insensitivity support
    assert evidence_service.verify_hash(expected_hash.upper(), payload) is True
    # Modified data mismatch
    assert evidence_service.verify_hash(expected_hash, b"Tampered Payload") is False
    # None / Empty inputs
    assert evidence_service.verify_hash("", payload) is False
    assert evidence_service.verify_hash(expected_hash, None) is False


def test_record_evidence_hash_db_persistence_and_idempotency(
    evidence_service: EvidenceIntegrityService,
    db_session: Session,
    sample_analyst: User,
):
    """Test recording evidence hash creates database record and is idempotent upon re-execution."""
    case = Case(
        user_id=sample_analyst.id,
        file_name="suspicious.eml",
        file_size_bytes=1024,
        sha256_hash="0000000000000000000000000000000000000000000000000000000000000000",
        storage_key="test_key.eml",
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    test_data = b"Original EML message content from forensic collection"

    # 1. First record creation
    rec1 = evidence_service.record_evidence_hash(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        data=test_data,
        file_name="suspicious.eml",
        metadata={"vault": "primary"},
        db=db_session,
    )
    db_session.commit()

    assert rec1.case_id == case.id
    assert rec1.evidence_type == EvidenceType.ORIGINAL_EMAIL
    assert rec1.file_size_bytes == len(test_data)
    assert rec1.sha256_hash == evidence_service.calculate_hash(test_data)

    # 2. Query database directly
    stored = db_session.query(EvidenceRecord).filter_by(case_id=case.id).all()
    assert len(stored) == 1
    assert stored[0].sha256_hash == rec1.sha256_hash

    # 3. Idempotent re-recording does not duplicate record
    rec2 = evidence_service.record_evidence_hash(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        data=test_data,
        file_name="suspicious.eml",
        metadata={"vault": "updated_tag"},
        db=db_session,
    )
    db_session.commit()

    stored_after = db_session.query(EvidenceRecord).filter_by(case_id=case.id).all()
    assert len(stored_after) == 1
    assert rec2.id == rec1.id
    assert stored_after[0].metadata_json["vault"] == "updated_tag"


def test_verify_case_evidence_original_email_verified(
    evidence_service: EvidenceIntegrityService,
    temp_storage: LocalEvidenceStorage,
    db_session: Session,
    sample_analyst: User,
):
    """Test verify_case_evidence returns VERIFIED when raw storage file matches registered hash."""
    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    storage_key, sha256 = temp_storage.save(eml_bytes, "credential_phishing.eml")

    case = Case(
        user_id=sample_analyst.id,
        file_name="credential_phishing.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    evidence_service.record_evidence_hash(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        data=eml_bytes,
        file_name="credential_phishing.eml",
        db=db_session,
    )
    db_session.commit()

    res = evidence_service.verify_case_evidence(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        db=db_session,
    )

    assert res.case_id == case.id
    assert res.evidence_type == EvidenceType.ORIGINAL_EMAIL
    assert res.status == EvidenceIntegrityStatus.VERIFIED
    assert res.is_valid is True
    assert res.expected_sha256 == sha256
    assert res.actual_sha256 == sha256


def test_verify_case_evidence_corrupted_payload_detected(
    evidence_service: EvidenceIntegrityService,
    temp_storage: LocalEvidenceStorage,
    db_session: Session,
    sample_analyst: User,
):
    """Test verify_case_evidence returns CORRUPTED and warns when disk bytes are altered."""
    original_bytes = b"Legitimate evidence payload before unauthorized modification"
    storage_key, sha256 = temp_storage.save(original_bytes, "unaltered.eml")

    case = Case(
        user_id=sample_analyst.id,
        file_name="unaltered.eml",
        file_size_bytes=len(original_bytes),
        sha256_hash=sha256,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    evidence_service.record_evidence_hash(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        data=original_bytes,
        file_name="unaltered.eml",
        db=db_session,
    )
    db_session.commit()

    # Tamper with the evidence on disk
    target_path = temp_storage.base_dir / storage_key
    target_path.write_bytes(b"Tampered / Injected unauthorized byte sequence")

    res = evidence_service.verify_case_evidence(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        db=db_session,
    )

    assert res.case_id == case.id
    assert res.status == EvidenceIntegrityStatus.INTEGRITY_MISMATCH
    assert res.is_valid is False
    assert res.expected_sha256 == sha256
    assert res.actual_sha256 != sha256
    assert "tamper_warning" in res.details


def test_verify_case_evidence_missing_storage_file(
    evidence_service: EvidenceIntegrityService,
    temp_storage: LocalEvidenceStorage,
    db_session: Session,
    sample_analyst: User,
):
    """Test verify_case_evidence handles missing storage file gracefully with MISSING status."""
    case = Case(
        user_id=sample_analyst.id,
        file_name="ghost_evidence.eml",
        file_size_bytes=512,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_key="non_existent_file.eml",
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    res = evidence_service.verify_case_evidence(
        case_id=case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        db=db_session,
    )

    assert res.status == EvidenceIntegrityStatus.UNAVAILABLE
    assert res.is_valid is False
    assert res.actual_sha256 is None


def test_evidence_service_nonexistent_case_raises_not_found(
    evidence_service: EvidenceIntegrityService,
    db_session: Session,
):
    """Test evidence operations for nonexistent case UUID raise NotFoundError."""
    with pytest.raises(NotFoundError):
        evidence_service.get_case_evidence_records(
            case_id="00000000-0000-0000-0000-000000000000", db=db_session
        )

    with pytest.raises(NotFoundError):
        evidence_service.verify_case_evidence(
            case_id="00000000-0000-0000-0000-000000000000",
            evidence_type=EvidenceType.ORIGINAL_EMAIL,
            db=db_session,
        )
