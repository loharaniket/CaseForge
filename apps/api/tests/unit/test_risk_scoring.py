from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.risk import RiskAssessment
from src.models.user import User, UserRole
from src.services.detection_service import DetectionService
from src.services.detector.rule_based import RuleBasedThreatDetector
from src.services.parser.eml_parser import EMLParser
from src.services.parser_service import ParserService
from src.services.risk.service import RiskScoringService
from src.services.risk.types import RiskSeverity
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def risk_service() -> RiskScoringService:
    return RiskScoringService()


def test_minimum_score_calculation(risk_service: RiskScoringService):
    """Test minimum score (all 0.0) yields 0.0 and LOW severity."""
    result = risk_service.calculate_score(
        ai_score=0.0,
        header_score=0.0,
        domain_score=0.0,
        ip_score=0.0,
        url_score=0.0,
    )
    assert result.total_score == 0.0
    assert result.severity == RiskSeverity.LOW
    assert len(result.missing_components) == 0


def test_maximum_score_calculation(risk_service: RiskScoringService):
    """Test maximum score (all 100.0) yields 100.0 and CRITICAL severity."""
    result = risk_service.calculate_score(
        ai_score=100.0,
        header_score=100.0,
        domain_score=100.0,
        ip_score=100.0,
        url_score=100.0,
    )
    assert result.total_score == 100.0
    assert result.severity == RiskSeverity.CRITICAL


def test_exact_weighted_calculation(risk_service: RiskScoringService):
    """Test exact formula: AI=40%, Headers=25%, Domain=15%, IP=10%, URL=10%."""
    # (80 * 0.40) + (60 * 0.25) + (40 * 0.15) + (20 * 0.10) + (10 * 0.10)
    # = 32.0 + 15.0 + 6.0 + 2.0 + 1.0 = 56.0
    result = risk_service.calculate_score(
        ai_score=80.0,
        header_score=60.0,
        domain_score=40.0,
        ip_score=20.0,
        url_score=10.0,
    )
    assert result.total_score == 56.0
    assert result.severity == RiskSeverity.HIGH
    assert result.breakdown.ai == 80.0
    assert result.breakdown.header_forensics == 60.0
    assert result.breakdown.domain_reputation == 40.0
    assert result.breakdown.ip_reputation == 20.0
    assert result.breakdown.url_analysis == 10.0


def test_missing_components_deterministic_handling(risk_service: RiskScoringService):
    """Test missing/None inputs default to 0.0 and are tracked in missing_components."""
    # Only AI is available (90.0 * 0.40 = 36.0)
    result = risk_service.calculate_score(
        ai_score=90.0,
        header_score=None,
        domain_score=None,
        ip_score=None,
        url_score=None,
    )
    assert result.total_score == 36.0
    assert result.severity == RiskSeverity.MEDIUM
    assert "header_forensics" in result.missing_components
    assert "domain_reputation" in result.missing_components
    assert "ip_reputation" in result.missing_components
    assert "url_analysis" in result.missing_components
    assert "ai_analysis" not in result.missing_components


def test_severity_threshold_boundaries(risk_service: RiskScoringService):
    """Test strict threshold boundaries: 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL."""
    # LOW boundaries
    assert risk_service.determine_severity(0.0) == RiskSeverity.LOW
    assert risk_service.determine_severity(24.99) == RiskSeverity.LOW

    # MEDIUM boundaries
    assert risk_service.determine_severity(25.0) == RiskSeverity.MEDIUM
    assert risk_service.determine_severity(49.99) == RiskSeverity.MEDIUM

    # HIGH boundaries
    assert risk_service.determine_severity(50.0) == RiskSeverity.HIGH
    assert risk_service.determine_severity(74.99) == RiskSeverity.HIGH

    # CRITICAL boundaries
    assert risk_service.determine_severity(75.0) == RiskSeverity.CRITICAL
    assert risk_service.determine_severity(100.0) == RiskSeverity.CRITICAL


def test_floating_point_rounding_stability(risk_service: RiskScoringService):
    """Test fractional float calculations round deterministically to 2 decimal places."""
    # (33.33 * 0.40) + (66.67 * 0.25) + (12.34 * 0.15) + (55.55 * 0.10) + (99.99 * 0.10)
    # = 13.332 + 16.6675 + 1.851 + 5.555 + 9.999 = 47.4045 -> 47.40
    result = risk_service.calculate_score(
        ai_score=33.33,
        header_score=66.67,
        domain_score=12.34,
        ip_score=55.55,
        url_score=99.99,
    )
    assert result.total_score == 47.40
    assert result.severity == RiskSeverity.MEDIUM


def test_risk_scoring_db_persistence_and_idempotency(db_session: Session, tmp_path: Path):
    """Test full flow: Case -> Parse -> Threat -> Calculate Risk -> Persist in DB -> Idempotency."""
    user = User(
        email="risk.analyst@threattrace.io",
        hashed_password=hash_password("RiskPass123!"),
        full_name="Risk Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    storage = LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))
    eml_bytes = (FIXTURES_DIR / "bec_executive_wire.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "bec_risk.eml")

    case = Case(
        user_id=user.id,
        file_name="bec_risk.eml",
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
    risk_service = RiskScoringService(detection_service=detection_service)

    # First calculation
    assessment = risk_service.calculate_case_risk(case.id, db_session)
    assert assessment.case_id == case.id
    assert assessment.total_score > 0.0
    assert assessment.severity in ("MEDIUM", "HIGH", "CRITICAL")
    assert assessment.weights_applied["ai_analysis"] == 0.40

    # Idempotent second query
    second = risk_service.calculate_case_risk(case.id, db_session)
    assert second.id == assessment.id

    rows = (
        db_session.execute(select(RiskAssessment).where(RiskAssessment.case_id == case.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1
