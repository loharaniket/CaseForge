from dataclasses import dataclass, field
from enum import StrEnum


class ThreatCategory(StrEnum):
    """Standardized multi-class threat categories."""

    NORMAL = "normal"
    SPAM = "spam"
    PHISHING = "phishing"
    BEC = "BEC"


@dataclass
class ThreatDetectionResult:
    """Deterministic, explainable threat detection output payload."""

    classification: ThreatCategory
    confidence: float
    reasons: list[str] = field(default_factory=list)
    model_version: str = "rule-based-heuristic-v1.0.0-dev"
    signals_detected: dict[str, list[str]] = field(default_factory=dict)
