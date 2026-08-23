from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.forensics import HeaderForensics
from src.models.user import User, UserRole
from src.services.forensics.service import HeaderForensicsService
from src.services.forensics.types import AuthenticationStatus
from src.services.parser.eml_parser import EMLParser
from src.services.parser_service import ParserService
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def forensics_service() -> HeaderForensicsService:
    return HeaderForensicsService()


def test_parse_relay_chain_chronological_ordering(forensics_service: HeaderForensicsService):
    """Verify relay hops are parsed in chronological transmission order with valid delays."""
    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = forensics_service.analyze_headers(parsed)

    assert len(result.relay_hops) == 3
    assert result.relay_hops[0].hop_number == 1
    assert result.relay_hops[0].from_host == "outbound-mta.sender-domain.com"
    assert result.relay_hops[0].ip_address == "192.0.2.15"

    assert result.relay_hops[1].hop_number == 2
    assert result.relay_hops[1].from_host == "mx1.upstream-relay.net"
    assert result.relay_hops[1].ip_address == "203.0.113.45"
    assert result.relay_hops[1].delay_seconds == 7.0

    assert result.relay_hops[2].hop_number == 3
    assert result.relay_hops[2].delay_seconds == 8.0


def test_rfc1918_private_ip_filtering_and_public_origin_identification(
    forensics_service: HeaderForensicsService,
):
    """Verify internal RFC1918 IPs (10.x, 192.168.x) are flagged and first public MTA IP is chosen."""
    eml_bytes = (FIXTURES_DIR / "private_and_public_relay.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = forensics_service.analyze_headers(parsed)

    assert len(result.relay_hops) == 4
    # Hop 1: 10.0.0.15 (private)
    assert result.relay_hops[0].ip_address == "10.0.0.15"
    assert result.relay_hops[0].is_private_ip is True

    # Hop 2: 192.168.1.50 (private)
    assert result.relay_hops[1].ip_address == "192.168.1.50"
    assert result.relay_hops[1].is_private_ip is True

    # Hop 3: 203.0.113.88 (public)
    assert result.relay_hops[2].ip_address == "203.0.113.88"
    assert result.relay_hops[2].is_private_ip is False

    # Probable origin should be the first public external IP
    assert result.probable_origin_ip == "203.0.113.88"
    assert "203.0.113.88" in result.origin_ip_candidates


def test_authentication_results_parsing_spf_dkim_dmarc(
    forensics_service: HeaderForensicsService,
):
    """Verify SPF/DKIM/DMARC pass parsing."""
    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = forensics_service.analyze_headers(parsed)

    assert result.authentication.spf_status == AuthenticationStatus.PASS
    assert result.authentication.dkim_status == AuthenticationStatus.PASS
    assert result.authentication.dmarc_status == AuthenticationStatus.PASS
    assert result.forensics_risk_score == 0.0
    assert len(result.spoofing_indicators) == 0


def test_spoofing_detection_return_path_and_reply_to_mismatch(
    forensics_service: HeaderForensicsService,
):
    """Verify domain discrepancies between From, Return-Path, and Reply-To are detected as spoofing."""
    eml_bytes = (FIXTURES_DIR / "spoofed_return_path.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = forensics_service.analyze_headers(parsed)

    assert len(result.spoofing_indicators) >= 2
    assert any("Return-Path domain mismatch" in s for s in result.spoofing_indicators)
    assert any("Reply-To domain mismatch" in s for s in result.spoofing_indicators)
    assert result.authentication.spf_status == AuthenticationStatus.SOFTFAIL
    assert result.forensics_risk_score >= 50.0


def test_auth_failures_trigger_spoofing_and_high_risk_score(
    forensics_service: HeaderForensicsService,
):
    """Verify failed SPF, DKIM, and DMARC checks are captured and produce high risk score."""
    eml_bytes = (FIXTURES_DIR / "auth_failures_spf_dkim_dmarc.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = forensics_service.analyze_headers(parsed)

    assert result.authentication.spf_status == AuthenticationStatus.FAIL
    assert result.authentication.dkim_status == AuthenticationStatus.FAIL
    assert result.authentication.dmarc_status == AuthenticationStatus.FAIL
    assert len(result.spoofing_indicators) >= 3
    assert result.forensics_risk_score >= 75.0


def test_malformed_received_headers_resilience(
    forensics_service: HeaderForensicsService,
):
    """Verify parser safely handles malformed, empty, or corrupt header structures without exceptions."""
    eml_bytes = (FIXTURES_DIR / "malformed_email.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = forensics_service.analyze_headers(parsed)

    assert isinstance(result.relay_hops, list)
    assert isinstance(result.origin_ip_candidates, list)
    assert 0.0 <= result.forensics_risk_score <= 100.0


def test_header_forensics_db_persistence_and_idempotency(db_session: Session, tmp_path: Path):
    """Test full analysis and DB persistence for header forensics."""
    user = User(
        email="forensics.analyst@threattrace.io",
        hashed_password=hash_password("ForensicsPass123!"),
        full_name="Forensics Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    storage = LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))
    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "relay.eml")

    case = Case(
        user_id=user.id,
        file_name="relay.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    forensics_service = HeaderForensicsService(parser_service=parser_service)

    # First analysis
    record = forensics_service.analyze_case(case.id, db_session)
    assert record.case_id == case.id
    assert len(record.relay_hops) == 3
    assert record.spf_status == "pass"

    # Idempotent second call
    second = forensics_service.analyze_case(case.id, db_session)
    assert second.id == record.id

    rows = (
        db_session.execute(select(HeaderForensics).where(HeaderForensics.case_id == case.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1
