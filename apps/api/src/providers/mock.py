"""Development and testing mock providers.

Marked clearly as development-only adapters in compliance with Rule 5.
"""

from typing import Any

from src.providers.base import (
    GeoIPProvider,
    ReportGeneratorProvider,
    ThreatDetectorProvider,
    ThreatIntelProvider,
)


class MockThreatDetectorProvider(ThreatDetectorProvider):
    """Development-only threat detector mock."""

    @property
    def provider_name(self) -> str:
        return "mock_threat_detector (DEV ONLY)"

    @property
    def is_available(self) -> bool:
        return True

    async def analyze(self, content: str, headers: dict[str, Any]) -> dict[str, Any]:
        return {
            "classification": "unknown",
            "confidence": 0.0,
            "reasons": ["Mock threat detector analysis placeholder"],
            "modelVersion": "mock-v0.1.0-dev",
        }


class MockThreatIntelProvider(ThreatIntelProvider):
    """Development-only threat intelligence mock."""

    @property
    def provider_name(self) -> str:
        return "mock_threat_intel (DEV ONLY)"

    @property
    def is_available(self) -> bool:
        return True

    async def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        return {
            "ip": ip_address,
            "reputation_score": 0,
            "is_malicious": False,
            "provider": self.provider_name,
        }

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return {
            "domain": domain,
            "reputation_score": 0,
            "is_malicious": False,
            "provider": self.provider_name,
        }


class MockGeoIPProvider(GeoIPProvider):
    """Development-only GeoIP mock."""

    @property
    def provider_name(self) -> str:
        return "mock_geoip (DEV ONLY)"

    @property
    def is_available(self) -> bool:
        return True

    async def resolve_infrastructure(self, ip_address: str) -> dict[str, Any]:
        return {
            "ip": ip_address,
            "country": "Unknown",
            "asn": "AS0000",
            "org": "Mock Infrastructure Provider",
            "probable_infrastructure_origin": "Local/Unknown",
        }


class MockReportGeneratorProvider(ReportGeneratorProvider):
    """Development-only report generator mock."""

    @property
    def provider_name(self) -> str:
        return "mock_report_generator (DEV ONLY)"

    @property
    def is_available(self) -> bool:
        return True

    async def generate_report(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        return b"%PDF-1.4 Mock Report Placeholder\n%%EOF"
