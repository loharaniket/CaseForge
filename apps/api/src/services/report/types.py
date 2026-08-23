from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class InvestigationReportData:
    """Comprehensive structured payload representing all 18 sections of the investigation report."""

    # 1. Header & System Metadata
    report_title: str
    system_name: str
    version: str
    generated_at_iso: str

    # 2. Case Identification & Custody
    case_id: str
    file_name: str
    file_size_bytes: int
    sha256_hash: str
    case_status: str
    analyst_name: str | None = None
    analyst_email: str | None = None

    # 3. Incident Summary & Executive Overview
    incident_summary: str = ""

    # 4 & 5. Threat Classification, Risk Score & Severity
    threat_classification: str = "UNKNOWN"
    threat_confidence: float = 0.0
    threat_model_version: str = "N/A"
    threat_score: float = 0.0
    threat_severity: str = "LOW"
    score_breakdown: dict[str, float] = field(default_factory=dict)
    explainability_reasons: list[str] = field(default_factory=list)

    # 6. Email Envelope & Headers Metadata
    subject: str = "N/A"
    sender: str = "N/A"
    from_name: str = "N/A"
    from_address: str = "N/A"
    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    date_declared: str = "N/A"
    message_id: str = "N/A"

    # 7. Authentication Status
    spf_status: str = "none"
    dkim_status: str = "none"
    dmarc_status: str = "none"
    authentication_details: dict[str, Any] = field(default_factory=dict)

    # 8. Header Forensics & Relay Hops
    probable_origin_ip: str = "N/A"
    origin_ip_candidates: list[str] = field(default_factory=list)
    relay_hops_count: int = 0
    relay_hops: list[dict[str, Any]] = field(default_factory=list)
    spoofing_indicators: list[str] = field(default_factory=list)
    header_anomalies: list[str] = field(default_factory=list)

    # 9. Extracted Indicators of Compromise (IOCs)
    total_iocs_count: int = 0
    iocs: list[dict[str, Any]] = field(default_factory=list)

    # 10 & 11. Threat Intelligence (IP & Domain)
    ip_intel_provider: str = "N/A"
    domain_intel_provider: str = "N/A"
    max_ip_risk_score: float | None = None
    max_domain_risk_score: float | None = None
    malicious_ips: list[str] = field(default_factory=list)
    malicious_domains: list[str] = field(default_factory=list)
    ip_intel_results: list[dict[str, Any]] = field(default_factory=list)
    domain_intel_results: list[dict[str, Any]] = field(default_factory=list)

    # 12. Geo Infrastructure Intelligence (Rule 14 Compliant)
    probable_infrastructure_origin: str = "N/A"
    origin_country: str = "N/A"
    origin_asn: int | None = None
    origin_isp: str = "N/A"
    geo_disclaimer: str = ""

    # 13. Chronological Forensic Timeline
    timeline_events_count: int = 0
    timeline_events: list[dict[str, Any]] = field(default_factory=list)

    # 14. Actionable SOC Remediation Recommendations
    recommendations: list[str] = field(default_factory=list)

    # 15. Evidence Custody & Hashing Placeholder
    evidence_sha256: str = "N/A"
    custody_verification: str = "VERIFIED_AUTHENTIC"

    def to_dict(self) -> dict[str, Any]:
        """Converts report data to serializable dictionary."""
        return asdict(self)
