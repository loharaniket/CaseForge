"""Threat detection engine interfaces and rule-based detector."""

from src.services.detector.interface import ThreatDetector
from src.services.detector.rule_based import RuleBasedThreatDetector, default_rule_detector
from src.services.detector.types import ThreatCategory, ThreatDetectionResult

__all__ = [
    "RuleBasedThreatDetector",
    "ThreatCategory",
    "ThreatDetectionResult",
    "ThreatDetector",
    "default_rule_detector",
]
