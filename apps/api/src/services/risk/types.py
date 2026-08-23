from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RiskSeverity(StrEnum):
    """Standardized cybersecurity threat severity tiers."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskScoreBreakdown:
    """Normalized sub-scores (0.0 to 100.0) across all weighted risk dimensions."""

    ai: float = 0.0
    header_forensics: float = 0.0
    domain_reputation: float = 0.0
    ip_reputation: float = 0.0
    url_analysis: float = 0.0

    def to_dict(self) -> dict[str, float]:
        return {
            "ai": self.ai,
            "header_forensics": self.header_forensics,
            "domain_reputation": self.domain_reputation,
            "ip_reputation": self.ip_reputation,
            "url_analysis": self.url_analysis,
        }


@dataclass
class RiskCalculationResult:
    """Deterministic threat risk calculation outcome."""

    total_score: float
    severity: RiskSeverity
    breakdown: RiskScoreBreakdown
    weights_applied: dict[str, float]
    missing_components: list[str] = field(default_factory=list)
    signals_context: dict[str, Any] = field(default_factory=dict)
