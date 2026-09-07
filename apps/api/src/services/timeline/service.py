import datetime
import uuid
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.services.timeline.types import (
    ForensicTimelineResult,
    TimelineEvent,
    TimelineEventType,
    TimestampQuality,
)


def _safe_parse_iso(ts: Any) -> datetime.datetime | None:
    """Safely parses string or datetime into UTC datetime object."""
    if not ts:
        return None
    if isinstance(ts, datetime.datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=datetime.UTC)
        return ts.astimezone(datetime.UTC)
    if isinstance(ts, str):
        try:
            # Try ISO 8601 parsing
            dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=datetime.UTC)
            return dt.astimezone(datetime.UTC)
        except Exception:
            pass
        try:
            # Try RFC 2822 date parsing
            dt = parsedate_to_datetime(ts)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=datetime.UTC)
            return dt.astimezone(datetime.UTC)
        except Exception:
            pass
    return None


class ForensicTimelineService:
    """Extracts, normalizes, and chronologically orders forensic transmission and analysis events."""

    def build_case_timeline(self, case_id: str, db: Session) -> ForensicTimelineResult:
        """Constructs an accurate chronological investigation timeline for a given case."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' not found.")

        parsed_email = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        forensics = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()

        threat = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()

        risk = db.execute(
            select(RiskAssessment).where(RiskAssessment.case_id == case_id)
        ).scalar_one_or_none()

        raw_events: list[tuple[datetime.datetime | None, TimelineEvent]] = []

        # 1. Email Message Creation (RFC Date Header)
        if parsed_email:
            email_dt = _safe_parse_iso(parsed_email.date_parsed) or _safe_parse_iso(
                parsed_email.date_raw
            )
            raw_events.append(
                (
                    email_dt,
                    TimelineEvent(
                        event_id=f"email-date-{uuid.uuid4().hex[:8]}",
                        event_type=TimelineEventType.EMAIL_DATE,
                        title="Email Message Date Declared",
                        description=f"Message origin date header declared by sender: {parsed_email.from_address or parsed_email.sender or 'Unknown'}",
                        source="header.date",
                        timestamp_iso=email_dt.isoformat() if email_dt else None,
                        timestamp_raw=parsed_email.date_raw,
                        timestamp_quality=TimestampQuality.HEADER_DECLARED
                        if email_dt
                        else TimestampQuality.MISSING,
                        details={
                            "sender": parsed_email.from_address or parsed_email.sender,
                            "subject": parsed_email.subject,
                            "message_id": parsed_email.message_id,
                        },
                    ),
                )
            )

        # 2. MTA Relay Transmission Hops
        if forensics and forensics.relay_hops:
            for idx, hop in enumerate(forensics.relay_hops):
                hop_dt = (
                    _safe_parse_iso(hop.get("timestamp_parsed"))
                    or _safe_parse_iso(hop.get("timestamp_iso"))
                    or _safe_parse_iso(hop.get("timestamp_raw"))
                )
                hop_num = hop.get("hop_number", idx + 1)
                from_host = hop.get("from_host") or "Unknown"
                by_host = hop.get("by_host") or "Unknown"
                is_private = hop.get("is_private_relay", False)
                ips = hop.get("ip_addresses", [])

                raw_events.append(
                    (
                        hop_dt,
                        TimelineEvent(
                            event_id=f"relay-hop-{hop_num}-{uuid.uuid4().hex[:8]}",
                            event_type=TimelineEventType.MTA_RELAY,
                            title=f"MTA Relay Hop #{hop_num}: {by_host}",
                            description=f"Transmitted from {from_host} to {by_host} ({'Private Subnet' if is_private else 'Public Gateway'})",
                            source=f"header.received[{idx}]",
                            timestamp_iso=hop_dt.isoformat() if hop_dt else None,
                            timestamp_raw=hop.get("timestamp_raw"),
                            timestamp_quality=TimestampQuality.HEADER_DECLARED
                            if hop_dt
                            else TimestampQuality.MISSING,
                            details={
                                "hop_number": hop_num,
                                "from_host": from_host,
                                "by_host": by_host,
                                "protocol": hop.get("with_protocol"),
                                "ip_addresses": ips,
                                "is_private_relay": is_private,
                                "declared_delay_seconds": hop.get("delay_seconds"),
                            },
                        ),
                    )
                )

        # 3. Authentication Verification Milestone
        if forensics and (
            forensics.spf_status != "none"
            or forensics.dkim_status != "none"
            or forensics.dmarc_status != "none"
        ):
            # Authentication results are evaluated upon ingress by the receiving MTA
            receiving_dt = None
            if forensics.relay_hops:
                # Last hop is receiving MTA
                last_hop = forensics.relay_hops[-1]
                receiving_dt = (
                    _safe_parse_iso(last_hop.get("timestamp_parsed"))
                    or _safe_parse_iso(last_hop.get("timestamp_iso"))
                    or _safe_parse_iso(last_hop.get("timestamp_raw"))
                )

            raw_events.append(
                (
                    receiving_dt,
                    TimelineEvent(
                        event_id=f"auth-results-{uuid.uuid4().hex[:8]}",
                        event_type=TimelineEventType.AUTHENTICATION,
                        title="Email Authentication Protocol Evaluation",
                        description=f"SPF: {forensics.spf_status.upper()}, DKIM: {forensics.dkim_status.upper()}, DMARC: {forensics.dmarc_status.upper()}",
                        source="header.authentication-results",
                        timestamp_iso=receiving_dt.isoformat() if receiving_dt else None,
                        timestamp_raw=None,
                        timestamp_quality=TimestampQuality.DERIVED
                        if receiving_dt
                        else TimestampQuality.MISSING,
                        details={
                            "spf_status": forensics.spf_status,
                            "dkim_status": forensics.dkim_status,
                            "dmarc_status": forensics.dmarc_status,
                            "spoofing_indicators": forensics.spoofing_indicators,
                        },
                    ),
                )
            )

        # 4. Evidence Ingestion & Hashing Started
        case_dt = _safe_parse_iso(case.created_at)
        raw_events.append(
            (
                case_dt,
                TimelineEvent(
                    event_id=f"ingestion-{uuid.uuid4().hex[:8]}",
                    event_type=TimelineEventType.INGESTION_STARTED,
                    title="Evidence Ingested & SHA-256 Hashed",
                    description=f"Raw evidence file '{case.file_name}' ingested with SHA-256: {case.sha256_hash}",
                    source="system.ingestion",
                    timestamp_iso=case_dt.isoformat() if case_dt else None,
                    timestamp_raw=None,
                    timestamp_quality=TimestampQuality.SERVER_INGESTION
                    if case_dt
                    else TimestampQuality.MISSING,
                    details={
                        "file_name": case.file_name,
                        "file_size_bytes": case.file_size_bytes,
                        "sha256": case.sha256_hash,
                        "status": case.status,
                    },
                ),
            )
        )

        # 5. Deterministic Forensic Parsing Completed
        if parsed_email:
            parsed_dt = _safe_parse_iso(parsed_email.created_at)
            raw_events.append(
                (
                    parsed_dt,
                    TimelineEvent(
                        event_id=f"parsing-{uuid.uuid4().hex[:8]}",
                        event_type=TimelineEventType.PARSING_COMPLETED,
                        title="RFC Forensic Parsing Completed",
                        description=f"Extracted {len(parsed_email.extracted_urls)} URLs and {len(parsed_email.attachments_metadata)} attachments into PostgreSQL",
                        source="service.parser",
                        timestamp_iso=parsed_dt.isoformat() if parsed_dt else None,
                        timestamp_raw=None,
                        timestamp_quality=TimestampQuality.SERVER_INGESTION
                        if parsed_dt
                        else TimestampQuality.MISSING,
                        details={
                            "urls_count": len(parsed_email.extracted_urls),
                            "attachments_count": len(parsed_email.attachments_metadata),
                        },
                    ),
                )
            )

        # 6. AI Threat Assessment & Risk Scoring
        if threat and risk:
            threat_dt = _safe_parse_iso(threat.created_at) or _safe_parse_iso(risk.created_at)
            raw_events.append(
                (
                    threat_dt,
                    TimelineEvent(
                        event_id=f"assessment-{uuid.uuid4().hex[:8]}",
                        event_type=TimelineEventType.THREAT_ASSESSMENT,
                        title=f"Threat Classified: {threat.classification.upper()} ({risk.severity.upper()})",
                        description=f"Deterministic Risk Score: {round(risk.total_score, 1)} / 100 with {len(threat.reasons)} heuristic indicators",
                        source="service.risk",
                        timestamp_iso=threat_dt.isoformat() if threat_dt else None,
                        timestamp_raw=None,
                        timestamp_quality=TimestampQuality.SERVER_INGESTION
                        if threat_dt
                        else TimestampQuality.MISSING,
                        details={
                            "classification": threat.classification,
                            "confidence": threat.confidence,
                            "total_score": risk.total_score,
                            "severity": risk.severity,
                            "reasons": threat.reasons,
                        },
                    ),
                )
            )

        # 7. Sort events chronologically:
        # Valid datetime events first in ascending order, followed by timestamp-less events
        events_with_time = [e for e in raw_events if e[0] is not None]
        events_without_time = [e for e in raw_events if e[0] is None]

        events_with_time.sort(key=lambda item: item[0])  # type: ignore

        sorted_events: list[TimelineEvent] = []
        prev_dt: datetime.datetime | None = None

        # Calculate exact delta delays between consecutive timestamps
        for dt, event in events_with_time:
            if prev_dt is not None and dt is not None:
                delta_sec = max(0.0, (dt - prev_dt).total_seconds())
                event.delay_from_previous_seconds = delta_sec
            else:
                event.delay_from_previous_seconds = 0.0
            prev_dt = dt
            sorted_events.append(event)

        for _, event in events_without_time:
            event.delay_from_previous_seconds = None
            sorted_events.append(event)

        earliest_ts = (
            sorted_events[0].timestamp_iso
            if sorted_events and sorted_events[0].timestamp_iso
            else None
        )
        latest_ts = events_with_time[-1][1].timestamp_iso if events_with_time else None

        return ForensicTimelineResult(
            case_id=case_id,
            total_events=len(sorted_events),
            earliest_timestamp=earliest_ts,
            latest_timestamp=latest_ts,
            has_missing_timestamps=len(events_without_time) > 0,
            events=sorted_events,
        )


# Global default instance & dependency provider
default_timeline_service = ForensicTimelineService()


def get_timeline_service() -> ForensicTimelineService:
    """Dependency injector for ForensicTimelineService."""
    return default_timeline_service
