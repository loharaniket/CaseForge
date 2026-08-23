from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class InvestigationReportDataResponse(BaseModel):
    """Pydantic response schema representing the structured 18-section investigation report."""

    model_config = ConfigDict(from_attributes=True)

    report_title: str = Field(..., description="Investigation report title")
    system_name: str = Field(..., description="ThreatTrace AI platform identifier")
    version: str = Field(..., description="Application version")
    generated_at_iso: str = Field(..., description="ISO 8601 UTC report generation timestamp")
    case_id: str = Field(..., description="Investigation case UUID")
    file_name: str = Field(..., description="Evidence file name")
    file_size_bytes: int = Field(..., description="Evidence file size in bytes")
    sha256_hash: str = Field(..., description="Evidence SHA-256 integrity hash")
    case_status: str = Field(..., description="Investigation status")
    analyst_name: str | None = Field(None, description="Assigned analyst full name")
    analyst_email: str | None = Field(None, description="Assigned analyst email")
    incident_summary: str = Field(..., description="Executive summary of the security incident")
    threat_classification: str = Field(..., description="Categorized threat classification")
    threat_confidence: float = Field(..., description="Detection confidence score")
    threat_model_version: str = Field(..., description="Threat detection model / heuristic version")
    threat_score: float = Field(..., description="Deterministic total risk score (0-100)")
    threat_severity: str = Field(..., description="Severity level (LOW, MEDIUM, HIGH, CRITICAL)")
    score_breakdown: dict[str, float] = Field(
        default_factory=dict, description="5-part risk score component breakdown"
    )
    explainability_reasons: list[str] = Field(
        default_factory=list, description="List of heuristic explainability indicators"
    )
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Raw sender header string")
    from_name: str = Field(..., description="Sender display name")
    from_address: str = Field(..., description="Sender email address")
    recipients: list[str] = Field(
        default_factory=list, description="Primary recipient email addresses"
    )
    cc: list[str] = Field(default_factory=list, description="Carbon copy recipient email addresses")
    reply_to: list[str] = Field(default_factory=list, description="Reply-to addresses")
    date_declared: str = Field(..., description="Declared email creation date string")
    message_id: str = Field(..., description="RFC Message-ID header")
    spf_status: str = Field(..., description="Normalized SPF authentication result")
    dkim_status: str = Field(..., description="Normalized DKIM authentication result")
    dmarc_status: str = Field(..., description="Normalized DMARC authentication result")
    authentication_details: dict[str, Any] = Field(
        default_factory=dict, description="Authentication evidence and details"
    )
    probable_origin_ip: str = Field(..., description="Probable source infrastructure origin IP")
    origin_ip_candidates: list[str] = Field(
        default_factory=list, description="Candidate source IP addresses"
    )
    relay_hops_count: int = Field(..., description="Total count of transmission relay hops")
    relay_hops: list[dict[str, Any]] = Field(
        default_factory=list, description="Detailed relay hop entities"
    )
    spoofing_indicators: list[str] = Field(
        default_factory=list, description="Detected email spoofing indicators"
    )
    header_anomalies: list[str] = Field(
        default_factory=list, description="Detected header anomalies"
    )
    total_iocs_count: int = Field(..., description="Total extracted indicators of compromise")
    iocs: list[dict[str, Any]] = Field(default_factory=list, description="Extracted IOC indicators")
    ip_intel_provider: str = Field(..., description="IP threat intelligence provider")
    domain_intel_provider: str = Field(..., description="Domain threat intelligence provider")
    max_ip_risk_score: float | None = Field(None, description="Maximum IP reputation risk score")
    max_domain_risk_score: float | None = Field(
        None, description="Maximum Domain reputation risk score"
    )
    malicious_ips: list[str] = Field(
        default_factory=list, description="List of flagged malicious IPs"
    )
    malicious_domains: list[str] = Field(
        default_factory=list, description="List of flagged malicious domains"
    )
    ip_intel_results: list[dict[str, Any]] = Field(
        default_factory=list, description="IP intelligence results"
    )
    domain_intel_results: list[dict[str, Any]] = Field(
        default_factory=list, description="Domain intelligence results"
    )
    probable_infrastructure_origin: str = Field(..., description="Probable infrastructure location")
    origin_country: str = Field(..., description="Infrastructure country name")
    origin_asn: int | None = Field(None, description="Autonomous System Number")
    origin_isp: str = Field(..., description="Internet Service Provider")
    geo_disclaimer: str = Field(..., description="Mandatory infrastructure disclaimer")
    timeline_events_count: int = Field(
        ..., description="Total count of chronological milestone events"
    )
    timeline_events: list[dict[str, Any]] = Field(
        default_factory=list, description="Chronological milestone events"
    )
    recommendations: list[str] = Field(
        default_factory=list, description="Actionable SOC remediation steps"
    )
    evidence_sha256: str = Field(..., description="Evidence file SHA-256 integrity hash")
    custody_verification: str = Field(
        ..., description="Chain of custody integrity verification status"
    )
