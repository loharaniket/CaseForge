from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException
from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.user import User, UserRole
from src.services.parser import EMLParser
from src.services.parser_service import ParserService
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def test_user(db_session: Session) -> User:
    """Fixture providing a persisted analyst user."""
    user = User(
        email="analyst.persistence@threattrace.io",
        hashed_password=hash_password("PersistencePass123!"),
        full_name="Persistence Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def storage(tmp_path: Path) -> LocalEvidenceStorage:
    """Fixture providing isolated temporary evidence storage."""
    return LocalEvidenceStorage(storage_dir=str(tmp_path / "evidence"))


def test_successful_case_persistence_transaction(
    db_session: Session, test_user: User, storage: LocalEvidenceStorage
):
    """Test full upload -> parse -> DB persistence flow with state transitions."""
    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "phishing_email.eml")

    # 1. Create Case in initial state
    case = Case(
        user_id=test_user.id,
        file_name="phishing_email.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    # 2. Run ParserService
    parser_service = ParserService(parser=EMLParser(), storage=storage)
    parsed_email = parser_service.parse_case(case.id, db_session)

    # 3. Verify Database state
    db_session.refresh(case)
    assert case.status == CaseStatus.PARSED
    assert case.error_message is None

    persisted_email = db_session.execute(
        select(ParsedEmail).where(ParsedEmail.case_id == case.id)
    ).scalar_one_or_none()

    assert persisted_email is not None
    assert persisted_email.id == parsed_email.id
    assert persisted_email.case_id == case.id
    assert "security-alerts@suspicious-domain-phish.com" in (persisted_email.from_address or "")
    assert len(persisted_email.extracted_urls) >= 2


def test_parser_failure_triggers_atomic_rollback(
    db_session: Session, test_user: User, storage: LocalEvidenceStorage
):
    """Test that a parser failure rolls back any partial DB records and updates case to FAILED."""
    eml_bytes = b"Some raw bytes"
    storage_key, sha256_hash = storage.save(eml_bytes, "broken.eml")

    case = Case(
        user_id=test_user.id,
        file_name="broken.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    # Create mock parser that raises an exception during parsing
    mock_parser = MagicMock()
    mock_parser.parse.side_effect = RuntimeError("Simulated unhandled parser crash")

    parser_service = ParserService(parser=mock_parser, storage=storage)

    with pytest.raises(AppException) as exc_info:
        parser_service.parse_case(case.id, db_session)

    assert exc_info.value.code == "PARSING_FAILED"

    # Verify no orphan ParsedEmail records exist in DB
    persisted_email = db_session.execute(
        select(ParsedEmail).where(ParsedEmail.case_id == case.id)
    ).scalar_one_or_none()
    assert persisted_email is None

    # Verify case status transitioned to FAILED and error message was recorded
    db_session.refresh(case)
    assert case.status == CaseStatus.FAILED
    assert "Simulated unhandled parser crash" in (case.error_message or "")


def test_duplicate_processing_idempotency(
    db_session: Session, test_user: User, storage: LocalEvidenceStorage
):
    """Test calling parse_case multiple times on the same case returns the existing record idempotently."""
    eml_bytes = (FIXTURES_DIR / "normal_email.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "normal_email.eml")

    case = Case(
        user_id=test_user.id,
        file_name="normal_email.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)

    # First parse
    first_parsed = parser_service.parse_case(case.id, db_session)
    # Second parse
    second_parsed = parser_service.parse_case(case.id, db_session)

    assert first_parsed.id == second_parsed.id

    # Verify only 1 record exists in table
    records = (
        db_session.execute(select(ParsedEmail).where(ParsedEmail.case_id == case.id))
        .scalars()
        .all()
    )
    assert len(records) == 1


def test_malformed_email_persistence(
    db_session: Session, test_user: User, storage: LocalEvidenceStorage
):
    """Test malformed email payloads persist safely without raising uncaught exceptions."""
    eml_bytes = (FIXTURES_DIR / "malformed_email.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "malformed_email.eml")

    case = Case(
        user_id=test_user.id,
        file_name="malformed_email.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    parsed = parser_service.parse_case(case.id, db_session)

    db_session.refresh(case)
    assert case.status == CaseStatus.PARSED
    assert parsed.case_id == case.id
    assert "http://malformed-embedded-link.com/payload" in parsed.extracted_urls


def test_all_extracted_fields_persisted_correctly(
    db_session: Session, test_user: User, storage: LocalEvidenceStorage
):
    """Test that all forensic fields, attachment metadata, and headers are persisted accurately."""
    eml_bytes = (FIXTURES_DIR / "attachment_email.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "attachment_email.eml")

    case = Case(
        user_id=test_user.id,
        file_name="attachment_email.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    parsed = parser_service.parse_case(case.id, db_session)

    assert parsed.subject == "Invoicing Statement for August 2026 #INV-99018"
    assert "Accounts Receivable" in (parsed.from_name or "")
    assert "invoicing@vendor-supply.com" in (parsed.from_address or "")
    assert len(parsed.recipients) >= 1
    assert "https://vendor-supply.com/payments" in parsed.extracted_urls
    assert len(parsed.attachments_metadata) == 1
    assert parsed.attachments_metadata[0]["filename"] == "invoice_august_2026.pdf"
    assert parsed.attachments_metadata[0]["sha256"] != ""
    assert isinstance(parsed.raw_headers, dict)
    assert "from" in [k.lower() for k in parsed.raw_headers.keys()]
