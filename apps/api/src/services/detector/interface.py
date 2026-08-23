from abc import ABC, abstractmethod
from typing import Any

from src.services.detector.types import ThreatDetectionResult


class ThreatDetector(ABC):
    """Abstract interface for email threat detection models and heuristic engines."""

    @abstractmethod
    def detect(self, email_data: Any) -> ThreatDetectionResult:
        """Evaluates parsed email data and produces an explainable classification result.

        Args:
            email_data: Parsed email object containing headers, body, URLs, and metadata.

        Returns:
            ThreatDetectionResult containing classification, confidence, reasons, and model_version.
        """
        pass
