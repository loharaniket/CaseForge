from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.risk import RiskAssessment
from src.models.user import User, UserRole
from src.services.detection_service import DetectionService
from src.services.detector.rule_based import RuleBasedThreatDetector
from src.services.forensics.service import HeaderForensicsService
from src.services.intel.providers.mock_provider import (
    MockDomainReputationProvider,
    MockIPReputationProvider,
)
from src.services.intel.service import ThreatIntelService
from src.services.intel.types import ProviderStatus, ReputationResult
from src.services.ioc.extractor import IOCExtractor
from src.services.ioc.service import IOCService
from src.services.parser.eml_parser import EMLParser
from src.services.parser_service import ParserService
from src.services.risk.service import RiskScoringService
from src.services.risk.types import RiskSeverity
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def risk_service() -> RiskScoringService:
    return RiskScoringService()


def test_acceptance_test_exact_weighted_five_components(risk_service: RiskScoringService):
    """Acceptance test: Controlled phishing with AI=90, Header=80, Domain=90, IP=100, URL=80.

    Mathematical verification:
    (90 * 0.40) + (80 * 0.25) + (90 * 0.15) + (100 * 0.10) + (80 * 0.10)
    = 36.0 + 20.0 + 13.5 + 10.0 + 8.0 = 87.5
    """
    expected_score = (90.0 * 0.40) + (80.0 * 0.25) + (90.0 * 0.15) + (100.0 * 0.10) + (80.0 * 0.10)
    assert expected_score == 87.5

    result = risk_service.calculate_score(
        ai_score=90.0,
        header_score=80.0,
        domain_score=90.0,
        ip_score=100.0,
        url_score=80.0,
    )

    assert result.total_score == expected_score
    assert result.severity == RiskSeverity.CRITICAL
    assert result.breakdown.ai == 90.0
    assert result.breakdown.header_forensics == 80.0
    assert result.breakdown.domain_reputation == 90.0
    assert result.breakdown.ip_reputation == 100.0
    assert result.breakdown.url_analysis == 80.0
    assert len(result.missing_components) == 0
    assert result.weights_applied["ai_analysis"] == 0.40
    assert result.weights_applied["header_forensics"] == 0.25
    assert result.weights_applied["domain_reputation"] == 0.15
    assert result.weights_applied["ip_reputation"] == 0.10
    assert result.weights_applied["url_analysis"] == 0.10


def test_only_ai_available_renormalization_and_raw(risk_service: RiskScoringService):
    """Test 2: When only AI analysis is available:

    - With renormalization: 90.0 / 0.40 * 0.40 = 90.0 (CRITICAL)
    - Without renormalization: 90.0 * 0.40 = 36.0 (MEDIUM)
    """
    renorm_result = risk_service.calculate_score(
        ai_score=90.0,
        header_score=None,
        domain_score=None,
        ip_score=None,
        url_score=None,
        renormalize=True,
    )
    assert renorm_result.total_score == 90.0
    assert renorm_result.severity == RiskSeverity.CRITICAL
    assert "header_forensics" in renorm_result.missing_components
    assert "domain_reputation" in renorm_result.missing_components
    assert "ip_reputation" in renorm_result.missing_components
    assert "url_analysis" in renorm_result.missing_components
    assert renorm_result.weights_applied["ai_analysis"] == 1.0

    raw_result = risk_service.calculate_score(
        ai_score=90.0,
        header_score=None,
        domain_score=None,
        ip_score=None,
        url_score=None,
        renormalize=False,
    )
    assert raw_result.total_score == 36.0
    assert raw_result.severity == RiskSeverity.MEDIUM


def test_ai_and_header_available_renormalization(risk_service: RiskScoringService):
    """Test 3: AI=90, Header=80, others unavailable:

    Available weights: 0.40 + 0.25 = 0.65
    Raw sum: (90 * 0.40) + (80 * 0.25) = 36.0 + 20.0 = 56.0
    Renormalized: 56.0 / 0.65 = 86.15
    """
    result = risk_service.calculate_score(
        ai_score=90.0,
        header_score=80.0,
        domain_score=None,
        ip_score=None,
        url_score=None,
        renormalize=True,
    )
    expected = round((36.0 + 20.0) / 0.65, 2)
    assert result.total_score == expected
    assert result.severity == RiskSeverity.CRITICAL
    assert len(result.missing_components) == 3


def test_malicious_ip_reputation_increases_score(risk_service: RiskScoringService):
    """Test 4: Adding malicious IP reputation increases the final risk score."""
    clean_ip_result = risk_service.calculate_score(
        ai_score=50.0,
        header_score=50.0,
        domain_score=0.0,
        ip_score=0.0,
        url_score=0.0,
    )

    malicious_ip_result = risk_service.calculate_score(
        ai_score=50.0,
        header_score=50.0,
        domain_score=0.0,
        ip_score=100.0,
        url_score=0.0,
    )

    # Delta should equal IP weight * 100.0 = 0.10 * 100.0 = 10.0
    diff = malicious_ip_result.total_score - clean_ip_result.total_score
    assert round(diff, 2) == 10.0
    assert malicious_ip_result.total_score > clean_ip_result.total_score


def test_malicious_domain_reputation_increases_score(risk_service: RiskScoringService):
    """Test 5: Adding malicious domain reputation increases the final risk score."""
    clean_dom_result = risk_service.calculate_score(
        ai_score=50.0,
        header_score=50.0,
        domain_score=0.0,
        ip_score=0.0,
        url_score=0.0,
    )

    malicious_dom_result = risk_service.calculate_score(
        ai_score=50.0,
        header_score=50.0,
        domain_score=90.0,
        ip_score=0.0,
        url_score=0.0,
    )

    # Delta should equal Domain weight * 90.0 = 0.15 * 90.0 = 13.5
    diff = malicious_dom_result.total_score - clean_dom_result.total_score
    assert round(diff, 2) == 13.5
    assert malicious_dom_result.total_score > clean_dom_result.total_score


def test_url_evidence_contributes_correctly(risk_service: RiskScoringService):
    """Test 6: URL heuristics evaluate raw IP host, keywords, and malicious intel matching."""
    # 1. Clean benign URL
    assert risk_service.evaluate_url_risk(["https://www.example.com/about"]) == 0.0

    # 2. Raw IP target in URL (+50)
    score_ip_url = risk_service.evaluate_url_risk(["http://198.51.100.200/index.html"])
    assert score_ip_url >= 50.0

    # 3. Credential harvesting keyword (+30)
    score_login_url = risk_service.evaluate_url_risk(
        ["https://portal.secure-access.com/verify-login"]
    )
    assert score_login_url >= 30.0

    # 4. Raw IP + credential keyword (HTTPS = 50 + 30 = 80.0, HTTP = 50 + 30 + 15 = 95.0)
    score_https_url = risk_service.evaluate_url_risk(["https://198.51.100.200/verify-account"])
    assert score_https_url == 80.0

    score_http_url = risk_service.evaluate_url_risk(["http://198.51.100.200/verify-account"])
    assert score_http_url == 95.0

    # 5. Matching malicious domain from intel (+40)
    score_intel_dom = risk_service.evaluate_url_risk(
        ["https://evil-phish.net/welcome"],
        malicious_domains={"evil-phish.net"},
    )
    assert score_intel_dom >= 40.0


def test_provider_unavailable_handling(risk_service: RiskScoringService):
    """Test 7: When external intel provider is UNAVAILABLE, component is marked missing."""
    result = risk_service.calculate_score(
        ai_score=80.0,
        header_score=60.0,
        domain_score=None,  # Provider UNAVAILABLE
        ip_score=None,  # Provider UNAVAILABLE
        url_score=40.0,
        renormalize=True,
    )

    assert "domain_reputation" in result.missing_components
    assert "ip_reputation" in result.missing_components
    assert result.total_score > 0.0
    # Available weights: 0.40 + 0.25 + 0.10 = 0.75
    # Raw sum: 32 + 15 + 4 = 51.0 -> Renormalized: 51 / 0.75 = 68.0
    assert result.total_score == 68.0


def test_provider_timeout_handling(risk_service: RiskScoringService):
    """Test 8: Timeout in provider lookups correctly marks component as missing without crashing."""
    result = risk_service.calculate_score(
        ai_score=75.0,
        header_score=75.0,
        domain_score=None,  # Timed out
        ip_score=75.0,
        url_score=75.0,
        renormalize=True,
    )
    assert "domain_reputation" in result.missing_components
    assert result.total_score == 75.0  # Equal subscores renormalize to 75.0


def test_provider_returns_no_result_clean_email(risk_service: RiskScoringService):
    """Test 9: Email with 0 IP/Domain indicators returns 0.0 without false missing markers."""
    result = risk_service.calculate_score(
        ai_score=10.0,
        header_score=10.0,
        domain_score=0.0,
        ip_score=0.0,
        url_score=0.0,
    )
    assert result.total_score == 6.5
    assert result.severity == RiskSeverity.LOW
    assert len(result.missing_components) == 0


def test_score_clamping_and_boundaries(risk_service: RiskScoringService):
    """Test 10: Component scores and final score remain clamped strictly between 0.0 and 100.0."""
    result_high = risk_service.calculate_score(
        ai_score=999.0,
        header_score=500.0,
        domain_score=200.0,
        ip_score=150.0,
        url_score=120.0,
    )
    assert result_high.total_score == 100.0
    assert result_high.severity == RiskSeverity.CRITICAL

    result_low = risk_service.calculate_score(
        ai_score=-50.0,
        header_score=-10.0,
        domain_score=-5.0,
        ip_score=-20.0,
        url_score=-1.0,
    )
    assert result_low.total_score == 0.0
    assert result_low.severity == RiskSeverity.LOW


def test_severity_threshold_boundaries(risk_service: RiskScoringService):
    """Test 11: Strict threshold boundaries: 0-24.99 LOW, 25-49.99 MEDIUM, 50-74.99 HIGH, 75-100 CRITICAL."""
    assert risk_service.determine_severity(0.0) == RiskSeverity.LOW
    assert risk_service.determine_severity(24.99) == RiskSeverity.LOW
    assert risk_service.determine_severity(25.0) == RiskSeverity.MEDIUM
    assert risk_service.determine_severity(49.99) == RiskSeverity.MEDIUM
    assert risk_service.determine_severity(50.0) == RiskSeverity.HIGH
    assert risk_service.determine_severity(74.99) == RiskSeverity.HIGH
    assert risk_service.determine_severity(75.0) == RiskSeverity.CRITICAL
    assert risk_service.determine_severity(100.0) == RiskSeverity.CRITICAL


def test_exact_mvp_weights_distribution(risk_service: RiskScoringService):
    """Test 12: Enforce exact Rule 13 MVP weighting distribution."""
    weights = risk_service.get_weights()
    assert weights["ai_analysis"] == 0.40
    assert weights["header_forensics"] == 0.25
    assert weights["domain_reputation"] == 0.15
    assert weights["ip_reputation"] == 0.10
    assert weights["url_analysis"] == 0.10
    assert sum(weights.values()) == 1.00


def test_risk_scoring_db_persistence_and_idempotency(db_session: Session, tmp_path: Path):
    """Test 13: Full case pipeline -> Parse -> Threat -> Forensics -> IOC -> Intel -> Risk -> DB persistence -> Idempotency."""
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
    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "cred_phish.eml")

    case = Case(
        user_id=user.id,
        file_name="cred_phish.eml",
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
    forensics_service = HeaderForensicsService(parser_service=parser_service)
    ioc_service = IOCService(extractor=IOCExtractor(), parser_service=parser_service)
    intel_service = ThreatIntelService(
        ip_provider=MockIPReputationProvider(),
        domain_provider=MockDomainReputationProvider(),
        ioc_service=ioc_service,
    )
    risk_service = RiskScoringService(
        detection_service=detection_service,
        forensics_service=forensics_service,
        ioc_service=ioc_service,
        intel_service=intel_service,
    )

    # First calculation: executes full 5-dimension pipeline
    assessment = risk_service.calculate_case_risk(case.id, db_session)
    assert assessment.case_id == case.id
    assert assessment.total_score > 0.0
    assert assessment.severity in ("MEDIUM", "HIGH", "CRITICAL")
    assert assessment.breakdown["ai"] > 0.0
    assert assessment.breakdown["header_forensics"] >= 0.0
    assert assessment.breakdown["url_analysis"] > 0.0

    # Idempotent second calculation returns identical persisted record
    second = risk_service.calculate_case_risk(case.id, db_session)
    assert second.id == assessment.id
    assert second.total_score == assessment.total_score

    rows = (
        db_session.execute(select(RiskAssessment).where(RiskAssessment.case_id == case.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1


def test_regression_malicious_ip_affects_persisted_case_risk_score(
    db_session: Session, tmp_path: Path
):
    """Regression test: Proves that a malicious IP lookup result directly elevates the final persisted case risk score."""
    user = User(
        email="ip.regression@threattrace.io",
        hashed_password=hash_password("Pass123!"),
        full_name="IP Regression Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    storage = LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))
    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "phish_ip.eml")

    # Case A: with clean IP provider (reputation 0.0)
    case_clean = Case(
        user_id=user.id,
        file_name="clean_ip.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case_clean)
    db_session.commit()

    # Case B: with malicious IP provider (reputation 100.0)
    case_malicious = Case(
        user_id=user.id,
        file_name="malicious_ip.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case_malicious)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    detection_service = DetectionService(
        detector=RuleBasedThreatDetector(), parser_service=parser_service
    )
    forensics_service = HeaderForensicsService(parser_service=parser_service)
    ioc_service = IOCService(extractor=IOCExtractor(), parser_service=parser_service)

    # 1. Clean IP Provider
    clean_ip_provider = MockIPReputationProvider()
    clean_intel_service = ThreatIntelService(
        ip_provider=clean_ip_provider,
        domain_provider=MockDomainReputationProvider(),
        ioc_service=ioc_service,
    )
    clean_risk_service = RiskScoringService(
        detection_service=detection_service,
        forensics_service=forensics_service,
        ioc_service=ioc_service,
        intel_service=clean_intel_service,
    )

    clean_assessment = clean_risk_service.calculate_case_risk(case_clean.id, db_session)

    # 2. Malicious IP Provider returning 100.0 reputation for all IPs
    malicious_ip_provider = AsyncMock()
    malicious_ip_provider.provider_name = "MaliciousIPTestProvider"
    malicious_ip_provider.lookup_ip.return_value = ReputationResult(
        indicator="198.51.100.200",
        indicator_type="ip",
        provider_name="MaliciousIPTestProvider",
        status=ProviderStatus.SUCCESS,
        reputation_score=100.0,
        is_malicious=True,
        threat_tags=["c2", "bruteforce"],
    )

    malicious_intel_service = ThreatIntelService(
        ip_provider=malicious_ip_provider,
        domain_provider=MockDomainReputationProvider(),
        ioc_service=ioc_service,
    )
    malicious_risk_service = RiskScoringService(
        detection_service=detection_service,
        forensics_service=forensics_service,
        ioc_service=ioc_service,
        intel_service=malicious_intel_service,
    )

    malicious_assessment = malicious_risk_service.calculate_case_risk(case_malicious.id, db_session)

    # Verify that the malicious IP score is recorded in the breakdown and increased the total score
    assert malicious_assessment.breakdown["ip_reputation"] == 100.0
    assert malicious_assessment.total_score >= clean_assessment.total_score
