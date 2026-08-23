from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ReputationResultSchema(BaseModel):
    """Schema representing reputation assessment for an IP or Domain indicator."""

    indicator: str = Field(..., description="Target IP or Domain indicator string")
    indicator_type: str = Field(..., description="Indicator category ('ip' or 'domain')")
    provider_name: str = Field(..., description="Threat intelligence provider name")
    status: str = Field(
        ..., description="Lookup operational status (SUCCESS, UNAVAILABLE, RATE_LIMITED, etc.)"
    )
    reputation_score: float | None = Field(
        None, description="Normalized risk reputation score (0.0 to 100.0), None if unavailable"
    )
    is_malicious: bool | None = Field(
        None, description="Whether indicator exceeds malicious severity thresholds"
    )
    threat_tags: list[str] = Field(
        default_factory=list, description="Categorical threat classification tags"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Provider-specific diagnostic metadata"
    )
    attribution: str | None = Field(None, description="Intelligence source attribution")
    cached: bool = Field(False, description="Whether the result was served from cache")
    error_message: str | None = Field(None, description="Error diagnostics if lookup failed")

    model_config = ConfigDict(from_attributes=True)


class CaseThreatIntelResponse(BaseModel):
    """Response container for case-wide IP and Domain threat intelligence results."""

    case_id: str = Field(..., description="Associated case identifier")
    ip_provider: str = Field(..., description="Active IP reputation provider name")
    domain_provider: str = Field(..., description="Active Domain reputation provider name")
    ip_lookups_count: int = Field(..., description="Number of unique IPs queried")
    domain_lookups_count: int = Field(..., description="Number of unique domains queried")
    max_ip_score: float | None = Field(None, description="Maximum observed IP reputation score")
    max_domain_score: float | None = Field(
        None, description="Maximum observed Domain reputation score"
    )
    avg_ip_score: float | None = Field(None, description="Average observed IP reputation score")
    avg_domain_score: float | None = Field(
        None, description="Average observed Domain reputation score"
    )
    malicious_ips: list[str] = Field(
        default_factory=list, description="List of IPs classified as malicious"
    )
    malicious_domains: list[str] = Field(
        default_factory=list, description="List of domains classified as malicious"
    )
    ip_results: list[ReputationResultSchema] = Field(
        default_factory=list, description="IP reputation records"
    )
    domain_results: list[ReputationResultSchema] = Field(
        default_factory=list, description="Domain reputation records"
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "ip_provider": "AbuseIPDB",
                "domain_provider": "VirusTotal",
                "ip_lookups_count": 2,
                "domain_lookups_count": 2,
                "max_ip_score": 95.0,
                "max_domain_score": 92.0,
                "avg_ip_score": 47.5,
                "avg_domain_score": 46.0,
                "malicious_ips": ["198.51.100.200"],
                "malicious_domains": ["attacker-infra.com"],
                "ip_results": [
                    {
                        "indicator": "198.51.100.200",
                        "indicator_type": "ip",
                        "provider_name": "AbuseIPDB",
                        "status": "SUCCESS",
                        "reputation_score": 95.0,
                        "is_malicious": True,
                        "threat_tags": ["botnet", "c2"],
                        "details": {"total_reports": 142},
                        "attribution": "AbuseIPDB v2 Threat Intelligence",
                        "cached": False,
                        "error_message": None,
                    }
                ],
                "domain_results": [
                    {
                        "indicator": "attacker-infra.com",
                        "indicator_type": "domain",
                        "provider_name": "VirusTotal",
                        "status": "SUCCESS",
                        "reputation_score": 92.0,
                        "is_malicious": True,
                        "threat_tags": ["phishing"],
                        "details": {"malicious_count": 14, "total_engines": 70},
                        "attribution": "VirusTotal v3 Threat Intelligence",
                        "cached": False,
                        "error_message": None,
                    }
                ],
            }
        },
    )
