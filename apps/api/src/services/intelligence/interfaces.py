from abc import ABC, abstractmethod
from typing import Any

from .types import IntelligenceResult


class BaseIntelligenceProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass

class IPIntelligenceProvider(BaseIntelligenceProvider):
    @abstractmethod
    async def lookup_ip(self, ip: str) -> IntelligenceResult[Any]:
        pass

class DomainIntelligenceProvider(BaseIntelligenceProvider):
    @abstractmethod
    async def lookup_domain(self, domain: str) -> IntelligenceResult[Any]:
        pass

class DNSProvider(BaseIntelligenceProvider):
    @abstractmethod
    async def lookup_dns(self, query: str, record_type: str = "A") -> IntelligenceResult[Any]:
        pass

class URLIntelligenceProvider(BaseIntelligenceProvider):
    @abstractmethod
    async def lookup_url(self, url: str) -> IntelligenceResult[Any]:
        pass

class ReputationProvider(BaseIntelligenceProvider):
    @abstractmethod
    async def lookup_reputation(self, indicator: str, indicator_type: str) -> IntelligenceResult[Any]:
        pass
