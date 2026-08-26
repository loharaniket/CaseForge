from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class AuthenticationStatus(StrEnum):
    """Normalized email sender authentication verification status."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


@dataclass
class RelayHop:
    """Individual mail transfer agent (MTA) hop in the transmission relay chain."""

    hop_number: int
    from_host: str | None = None
    by_host: str | None = None
    with_protocol: str | None = None
    ip_address: str | None = None
    is_private_ip: bool = False
    timestamp_raw: str | None = None
    timestamp_parsed: datetime | None = None
    delay_seconds: float | None = None
    timezone: str | None = None
    header_order: int | None = None
    parser_confidence: float = 1.0
    validation_issues: list[str] = field(default_factory=list)
    untrusted_node: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.timestamp_parsed:
            data["timestamp_parsed"] = self.timestamp_parsed.isoformat()
        return data


@dataclass
class AuthenticationResult:
    """Consolidated SPF, DKIM, and DMARC verification outcome."""

    spf_status: AuthenticationStatus = AuthenticationStatus.UNKNOWN
    spf_details: str | None = None
    dkim_status: AuthenticationStatus = AuthenticationStatus.UNKNOWN
    dkim_details: str | None = None
    dmarc_status: AuthenticationStatus = AuthenticationStatus.UNKNOWN
    dmarc_details: str | None = None
    raw_auth_results: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "spf_status": self.spf_status.value,
            "spf_details": self.spf_details,
            "dkim_status": self.dkim_status.value,
            "dkim_details": self.dkim_details,
            "dmarc_status": self.dmarc_status.value,
            "dmarc_details": self.dmarc_details,
            "raw_auth_results": self.raw_auth_results,
        }



@dataclass
class OriginCandidateScore:
    candidate_ip: str
    candidate_score: float
    reasons: list[str] = field(default_factory=list)
    confidence: float = 1.0
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class HeaderForensicsResult:
    """Comprehensive header forensics analysis outcome."""

    relay_hops: list[RelayHop] = field(default_factory=list)
    origin_ip_candidates: list[str] = field(default_factory=list)
    probable_origin_ip: str | None = None
    authentication: AuthenticationResult = field(default_factory=AuthenticationResult)
    spoofing_indicators: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    forensics_risk_score: float = 0.0
    origin_analysis: OriginCandidateScore | None = None
