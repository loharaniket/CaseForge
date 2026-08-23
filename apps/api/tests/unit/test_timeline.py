from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.models.user import User, UserRole
from src.services.timeline.service import ForensicTimelineService
from src.services.timeline.types import TimelineEventType, TimestampQuality


@pytest.fixture
def sample_analyst(db_session: Session) -> User:
    user = User(
        email="timeline_analyst@threattrace.io",
        full_name="Timeline Analyst",
        hashed_password="hashedpassword123",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_timeline_chronological_ordering_and_delays(db_session: Session, sample_analyst: User):
    service = ForensicTimelineService()

    base_time = datetime(2026, 8, 23, 10, 0, 0, tzinfo=UTC)
    t_email = base_time
    t_hop1 = base_time + timedelta(seconds=15)
    t_hop2 = base_time + timedelta(seconds=45)
    t_ingest = base_time + timedelta(minutes=5)
    t_parse = base_time + timedelta(minutes=5, seconds=2)
    t_threat = base_time + timedelta(minutes=5, seconds=5)

    case = Case(
        id="case-timeline-001",
        user_id=sample_analyst.id,
        file_name="suspicious_invoice.eml",
        file_size_bytes=4096,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_key="case-timeline-001.eml",
        status=CaseStatus.PARSED,
        created_at=t_ingest,
    )
    db_session.add(case)
    db_session.commit()

    parsed = ParsedEmail(
        case_id=case.id,
        sender="attacker@evil-domain.com",
        from_address="attacker@evil-domain.com",
        recipients=["victim@corp.com"],
        subject="Urgent Invoice Payment",
        date_raw="Sun, 23 Aug 2026 10:00:00 +0000",
        date_parsed=t_email,
        body_plain="Please pay the invoice immediately.",
        extracted_urls=["http://evil-domain.com/pay"],
        attachments_metadata=[],
        raw_headers={},
        created_at=t_parse,
    )
    db_session.add(parsed)

    forensics = HeaderForensics(
        case_id=case.id,
        relay_hops=[
            {
                "hop_number": 1,
                "from_host": "mail.evil-domain.com",
                "by_host": "relay.gateway.net",
                "with_protocol": "ESMTPS",
                "timestamp_raw": "Sun, 23 Aug 2026 10:00:15 +0000",
                "timestamp_iso": t_hop1.isoformat(),
                "delay_seconds": 15.0,
                "ip_addresses": ["198.51.100.10"],
                "is_private_relay": False,
            },
            {
                "hop_number": 2,
                "from_host": "relay.gateway.net",
                "by_host": "mx.corp.com",
                "with_protocol": "ESMTPS",
                "timestamp_raw": "Sun, 23 Aug 2026 10:00:45 +0000",
                "timestamp_iso": t_hop2.isoformat(),
                "delay_seconds": 30.0,
                "ip_addresses": ["198.51.100.20"],
                "is_private_relay": False,
            },
        ],
        origin_ip_candidates=["198.51.100.10"],
        probable_origin_ip="198.51.100.10",
        spf_status="fail",
        dkim_status="none",
        dmarc_status="fail",
        authentication_details={"spf": {"status": "fail"}},
        spoofing_indicators=[],
        anomalies=[],
        forensics_risk_score=75.0,
        created_at=t_parse,
    )
    db_session.add(forensics)

    threat = ThreatAssessment(
        case_id=case.id,
        classification="phishing",
        confidence=0.92,
        reasons=["Urgent language", "Suspicious link"],
        model_version="HeuristicThreatDetector-v0.1.0-dev",
        created_at=t_threat,
    )
    db_session.add(threat)

    risk = RiskAssessment(
        case_id=case.id,
        total_score=82.5,
        severity="critical",
        breakdown={"ai_score": 92.0, "header_score": 75.0, "total_score": 82.5},
        weights_applied={},
        missing_components=[],
        created_at=t_threat,
    )
    db_session.add(risk)
    db_session.commit()

    timeline = service.build_case_timeline(case_id=case.id, db=db_session)

    assert timeline.case_id == case.id
    assert timeline.total_events >= 5
    assert not timeline.has_missing_timestamps

    # Verify chronological ordering
    for i in range(len(timeline.events) - 1):
        curr_ts = timeline.events[i].timestamp_iso
        next_ts = timeline.events[i + 1].timestamp_iso
        if curr_ts and next_ts:
            assert curr_ts <= next_ts

    # Verify first event is Email Date Declared
    first_event = timeline.events[0]
    assert first_event.event_type == TimelineEventType.EMAIL_DATE
    assert first_event.timestamp_quality == TimestampQuality.HEADER_DECLARED

    # Verify relay hops
    hop_events = [e for e in timeline.events if e.event_type == TimelineEventType.MTA_RELAY]
    assert len(hop_events) == 2
    assert hop_events[0].title == "MTA Relay Hop #1: relay.gateway.net"
    assert hop_events[1].title == "MTA Relay Hop #2: mx.corp.com"

    # Verify delay between email and hop 1 is 15s
    assert hop_events[0].delay_from_previous_seconds == 15.0


def test_timeline_handles_missing_and_malformed_timestamps_without_fabrication(
    db_session: Session, sample_analyst: User
):
    service = ForensicTimelineService()

    case = Case(
        id="case-timeline-missing-ts",
        user_id=sample_analyst.id,
        file_name="malformed_date.eml",
        file_size_bytes=1024,
        sha256_hash="aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee",
        storage_key="case-timeline-missing-ts.eml",
        status=CaseStatus.PARSED,
        created_at=datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC),
    )
    db_session.add(case)
    db_session.commit()

    # Parsed email with invalid unparseable date
    parsed = ParsedEmail(
        case_id=case.id,
        sender="unknown@test.com",
        from_address="unknown@test.com",
        recipients=["test@corp.com"],
        subject="No Valid Date Header",
        date_raw="Invalid-Gibberish-Date-String",
        date_parsed=None,
        body_plain="Message without valid date",
        extracted_urls=[],
        attachments_metadata=[],
        raw_headers={},
        created_at=datetime(2026, 8, 23, 12, 0, 2, tzinfo=UTC),
    )
    db_session.add(parsed)

    # Forensics with hop lacking timestamp
    forensics = HeaderForensics(
        case_id=case.id,
        relay_hops=[
            {
                "hop_number": 1,
                "from_host": "unknown.hop",
                "by_host": "relay.hop",
                "timestamp_raw": None,
                "timestamp_iso": None,
                "delay_seconds": None,
                "ip_addresses": [],
                "is_private_relay": True,
            }
        ],
        origin_ip_candidates=[],
        probable_origin_ip=None,
        spf_status="none",
        dkim_status="none",
        dmarc_status="none",
        authentication_details={},
        spoofing_indicators=[],
        anomalies=[],
        forensics_risk_score=10.0,
        created_at=datetime(2026, 8, 23, 12, 0, 2, tzinfo=UTC),
    )
    db_session.add(forensics)
    db_session.commit()

    timeline = service.build_case_timeline(case_id=case.id, db=db_session)

    assert timeline.has_missing_timestamps is True

    # Ensure missing date event was not fabricated
    email_events = [e for e in timeline.events if e.event_type == TimelineEventType.EMAIL_DATE]
    assert len(email_events) == 1
    assert email_events[0].timestamp_quality == TimestampQuality.MISSING
    assert email_events[0].timestamp_iso is None
    assert email_events[0].timestamp_raw == "Invalid-Gibberish-Date-String"

    # Ensure missing relay hop timestamp was marked MISSING
    hop_events = [e for e in timeline.events if e.event_type == TimelineEventType.MTA_RELAY]
    assert len(hop_events) == 1
    assert hop_events[0].timestamp_quality == TimestampQuality.MISSING
    assert hop_events[0].timestamp_iso is None


def test_timeline_nonexistent_case_raises_not_found(db_session: Session):
    service = ForensicTimelineService()
    with pytest.raises(NotFoundError):
        service.build_case_timeline(case_id="nonexistent-case-id", db=db_session)
