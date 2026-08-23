from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException
from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.threat import ThreatAssessment
from src.models.user import User, UserRole
from src.services.detection_service import DetectionService
from src.services.detector.rule_based import RuleBasedThreatDetector
from src.services.parser.eml_parser import EMLParser
from src.services.parser_service import ParserService
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def test_analyst(db_session: Session) -> User:
    """Fixture providing a test analyst."""
    user = User(
        email="threat.analyst@threattrace.io",
        hashed_password=hash_password("ThreatPass123!"),
        full_name="Threat Analyst",
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
    return LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))


def test_threat_assessment_db_persistence(
    db_session: Session, test_analyst: User, storage: LocalEvidenceStorage
):
    """Test full threat detection analysis and database persistence."""
    eml_bytes = (FIXTURES_DIR / "bec_executive_wire.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "bec.eml")

    case = Case(
        user_id=test_analyst.id,
        file_name="bec.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    detection_service = DetectionService(
        detector=RuleBasedThreatDetector(),
        parser_service=parser_service,
    )

    assessment = detection_service.analyze_case(case.id, db_session)

    assert assessment.case_id == case.id
    assert assessment.classification == "BEC"
    assert assessment.confidence >= 0.80
    assert len(assessment.reasons) > 0
    assert assessment.model_version == "rule-based-heuristic-v1.0.0-dev"

    # Verify query from database
    persisted = db_session.execute(
        select(ThreatAssessment).where(ThreatAssessment.case_id == case.id)
    ).scalar_one_or_none()

    assert persisted is not None
    assert persisted.id == assessment.id
    assert persisted.classification == "BEC"


def test_threat_assessment_idempotency(
    db_session: Session, test_analyst: User, storage: LocalEvidenceStorage
):
    """Test re-analyzing a case returns the existing persisted assessment without creating duplicates."""
    eml_bytes = (FIXTURES_DIR / "normal_email.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "normal.eml")

    case = Case(
        user_id=test_analyst.id,
        file_name="normal.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    detection_service = DetectionService(
        detector=RuleBasedThreatDetector(),
        parser_service=parser_service,
    )

    first = detection_service.analyze_case(case.id, db_session)
    second = detection_service.analyze_case(case.id, db_session)

    assert first.id == second.id

    rows = (
        db_session.execute(select(ThreatAssessment).where(ThreatAssessment.case_id == case.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1


def test_threat_assessment_on_failed_case_raises_error(
    db_session: Session, test_analyst: User, storage: LocalEvidenceStorage
):
    """Test analyzing a case that failed parsing raises appropriate AppException."""
    case = Case(
        user_id=test_analyst.id,
        file_name="failed.eml",
        file_size_bytes=100,
        sha256_hash="dummyhash",
        storage_key="missing.eml",
        status=CaseStatus.FAILED,
        error_message="Simulated corrupt MIME boundary error",
    )
    db_session.add(case)
    db_session.commit()

    detection_service = DetectionService(
        detector=RuleBasedThreatDetector(),
        parser_service=ParserService(storage=storage),
    )

    with pytest.raises(AppException) as exc_info:
        detection_service.analyze_case(case.id, db_session)

    assert exc_info.value.code == "CASE_PARSING_FAILED"
