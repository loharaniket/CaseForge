from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.ioc import CaseIOC
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.models.user import User, UserRole
from src.services.report.generator import MockReportGenerator, PDFReportGenerator
from src.services.report.service import InvestigationReportService
from src.services.report.types import InvestigationReportData


@pytest.fixture
def sample_analyst(db_session: Session) -> User:
    user = User(
        email="report_analyst@threattrace.io",
        full_name="Senior SOC Analyst",
        hashed_password="hashedpassword123",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_pdf_report_generation_full_sections(db_session: Session, sample_analyst: User):
    """Verifies that PDFReportGenerator compiles a complete 18-section report without crashing."""
    service = InvestigationReportService(generator=PDFReportGenerator())

    case = Case(
        id="case-report-001",
        user_id=sample_analyst.id,
        file_name="payroll_phish.eml",
        file_size_bytes=8192,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_key="case-report-001.eml",
        status=CaseStatus.PARSED,
        created_at=datetime.now(UTC),
    )
    db_session.add(case)

    parsed = ParsedEmail(
        case_id=case.id,
        sender="payroll@spoofed-corp.com",
        from_name="HR Payroll Department",
        from_address="payroll@spoofed-corp.com",
        recipients=["employee@victim.com"],
        cc=["accounting@victim.com"],
        reply_to=["drop@evil-attacker.org"],
        subject="URGENT: Mandatory Direct Deposit Verification",
        date_raw="Sun, 23 Aug 2026 14:00:00 +0000",
        date_parsed=datetime.now(UTC),
        message_id="<pay123@spoofed-corp.com>",
        body_plain="Please update banking details immediately at http://evil-attacker.org/login",
        extracted_urls=["http://evil-attacker.org/login"],
        attachments_metadata=[
            {
                "filename": "DirectDepositForm.pdf.exe",
                "sha256": "4444555566667777888899990000aaaabbbbccccddddeeeeffff000011112222",
                "file_size_bytes": 145000,
            }
        ],
        raw_headers={"X-Mailer": "EvilSpam v1"},
        created_at=datetime.now(UTC),
    )
    db_session.add(parsed)

    threat = ThreatAssessment(
        case_id=case.id,
        classification="credential_phishing",
        confidence=0.95,
        reasons=[
            "Urgent payroll language",
            "Suspicious credential harvesting link",
            "Executable attachment disguised as PDF",
        ],
        model_version="rule-v1.0.0",
        created_at=datetime.now(UTC),
    )
    db_session.add(threat)

    forensics = HeaderForensics(
        case_id=case.id,
        relay_hops=[
            {
                "hop_number": 1,
                "by_host": "mail.victim.com",
                "from_host": "relay.evil-attacker.org",
                "ip": "198.51.100.77",
                "timestamp_raw": "Sun, 23 Aug 2026 14:00:10 +0000",
                "timestamp_iso": "2026-08-23T14:00:10Z",
                "delay_seconds": 10.0,
            }
        ],
        origin_ip_candidates=["198.51.100.77"],
        probable_origin_ip="198.51.100.77",
        spf_status="fail",
        dkim_status="none",
        dmarc_status="fail",
        authentication_details={"spf": {"explanation": "SPF validation failed"}},
        spoofing_indicators=["Return-path mismatch"],
        anomalies=["Non-standard X-Mailer header"],
        forensics_risk_score=90.0,
        created_at=datetime.now(UTC),
    )
    db_session.add(forensics)

    risk = RiskAssessment(
        case_id=case.id,
        total_score=88.5,
        severity="critical",
        breakdown={
            "ai_threat": 38.0,
            "header_forensics": 22.5,
            "domain_reputation": 14.0,
            "ip_reputation": 8.0,
            "url_analysis": 6.0,
        },
    )
    db_session.add(risk)

    ioc1 = CaseIOC(
        case_id=case.id, ioc_type="ipv4", value="198.51.100.77", source="header_forensics"
    )
    ioc2 = CaseIOC(
        case_id=case.id, ioc_type="domain", value="evil-attacker.org", source="extracted_urls"
    )
    db_session.add_all([ioc1, ioc2])
    db_session.commit()

    # Generate PDF
    pdf_bytes, filename = service.generate_case_pdf(case_id=case.id, db=db_session)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")
    assert filename == f"ThreatTrace_Investigation_Report_{case.id[:8]}.pdf"


def test_report_data_missing_and_empty_telemetry_handling(
    db_session: Session, sample_analyst: User
):
    """Case with minimal/missing telemetry must handle 'N/A' and empty arrays safely without errors."""
    service = InvestigationReportService(generator=MockReportGenerator())

    case = Case(
        id="case-report-minimal",
        user_id=sample_analyst.id,
        file_name="minimal.eml",
        file_size_bytes=256,
        sha256_hash="1111111111111111111111111111111111111111111111111111111111111111",
        storage_key="case-report-minimal.eml",
        status=CaseStatus.UPLOADED,
        created_at=datetime.now(UTC),
    )
    db_session.add(case)
    db_session.commit()

    report_data = service.build_report_data(case_id=case.id, db=db_session)

    assert report_data.case_id == case.id
    assert report_data.subject == "N/A"
    assert report_data.sender == "N/A"
    assert report_data.probable_origin_ip == "N/A"
    assert report_data.threat_classification == "normal"
    assert report_data.threat_severity == "low"
    assert len(report_data.recommendations) > 0

    pdf_bytes, filename = service.generate_case_pdf(case_id=case.id, db=db_session)
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_report_generator_handles_extreme_subjects_and_long_text():
    """Verifies that PDF generator handles extremely long subjects, URLs, and Unicode without overflow."""
    generator = PDFReportGenerator()

    long_subject = (
        "CRITICAL ALERT: "
        + ("VERY_LONG_SUSPICIOUS_TOKEN_" * 20)
        + " 日本語 & Special <Characters> & Symbols"
    )
    extreme_report = InvestigationReportData(
        report_title="Incident Report",
        system_name="ThreatTrace AI",
        version="0.1.0",
        generated_at_iso="2026-08-23T14:00:00Z",
        case_id="case-extreme-text-001",
        file_name="extreme_sample.eml",
        file_size_bytes=1048576,
        sha256_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        case_status="PARSED",
        subject=long_subject,
        sender="attacker_with_extremely_long_address_string_that_spans_multiple_lines@subdomain.deep.threat-network.com",
        from_name="Long Name " * 10,
        from_address="attacker@threat-network.com",
        recipients=["victim1@corp.com", "victim2@corp.com", "victim3@corp.com"],
        incident_summary="Long executive summary paragraph. " * 15,
        threat_classification="BEC",
        threat_score=94.0,
        threat_severity="CRITICAL",
        explainability_reasons=["Extreme text reasoning rule " + str(i) for i in range(12)],
        iocs=[
            {
                "ioc_type": "url",
                "value": "https://malicious-gateway.evil.com/path/to/resource?param1="
                + ("token_" * 15),
                "source": "body_html",
            }
            for _ in range(8)
        ],
        timeline_events=[
            {
                "title": f"Milestone Step {i}",
                "timestamp_iso": "2026-08-23T14:00:00Z",
                "timestamp_quality": "EXACT",
                "delay_from_previous_seconds": 12.5,
            }
            for i in range(12)
        ],
        recommendations=["Critical action item " + str(i) for i in range(6)],
    )

    pdf_bytes = generator.generate_pdf(extreme_report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")


def test_report_service_nonexistent_case_raises_not_found(db_session: Session):
    service = InvestigationReportService()
    with pytest.raises(NotFoundError):
        service.build_report_data(case_id="nonexistent-case-id", db=db_session)
