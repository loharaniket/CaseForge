from abc import ABC, abstractmethod
from typing import Any


class BaseProvider(ABC):
    """Abstract base class for all external provider integrations."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider implementation."""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Indicates if the provider is configured and available."""
        pass


class ThreatDetectorProvider(BaseProvider):
    """Abstract interface for AI and heuristic threat detection engines."""

    @abstractmethod
    async def analyze(self, content: str, headers: dict[str, Any]) -> dict[str, Any]:
        """Perform threat classification and return explainable results."""
        pass


class ThreatIntelProvider(BaseProvider):
    """Abstract interface for reputation lookup (IPs, domains, hashes, URLs)."""

    @abstractmethod
    async def lookup_ip(self, ip_address: str) -> dict[str, Any]:
        """Query reputation data for an IP address."""
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Query reputation data for a domain."""
        pass


class GeoIPProvider(BaseProvider):
    """Abstract interface for IP infrastructure and geolocation resolution."""

    @abstractmethod
    async def resolve_infrastructure(self, ip_address: str) -> dict[str, Any]:
        """Resolve probable infrastructure origin for an IP."""
        pass


class ReportGeneratorProvider(BaseProvider):
    """Abstract interface for investigation report rendering."""

    @abstractmethod
    async def generate_report(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        """Render investigation summary report as binary content."""
        pass
