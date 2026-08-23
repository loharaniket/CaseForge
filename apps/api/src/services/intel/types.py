from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ProviderStatus(StrEnum):
    """Operational status of a threat intelligence provider lookup."""

    SUCCESS = "SUCCESS"
    UNAVAILABLE = "UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    DISABLED = "DISABLED"
    ERROR = "ERROR"


@dataclass
class ReputationResult:
    """Standardized threat intelligence indicator reputation assessment."""

    indicator: str
    indicator_type: str  # "ip" or "domain"
    provider_name: str
    status: ProviderStatus
    reputation_score: float | None = None  # Normalized 0.0 to 100.0 (None if unavailable)
    is_malicious: bool | None = None
    threat_tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    attribution: str | None = None
    cached: bool = False
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class IPReputationProvider(ABC):
    """Abstract interface for IP reputation intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name identifier of the provider."""
        ...

    @abstractmethod
    async def lookup_ip(self, ip: str) -> ReputationResult:
        """Queries IP threat reputation."""
        ...


class DomainReputationProvider(ABC):
    """Abstract interface for Domain reputation intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name identifier of the provider."""
        ...

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ReputationResult:
        """Queries Domain threat reputation."""
        ...
