import asyncio
import time
from typing import Any

from sqlalchemy.orm import Session

from src.core.config import settings
from src.services.intel.providers.threatfox import ThreatFoxProvider
from src.services.intel.providers.urlhaus import URLhausProvider
from src.services.intel.providers.abuseipdb import AbuseIPDBProvider
from src.services.intel.providers.mock_provider import (
    MockDomainReputationProvider,
    MockIPReputationProvider,
)
from src.services.intel.providers.virustotal import VirusTotalDomainProvider
from src.services.intel.types import (
    DomainReputationProvider,
    IPReputationProvider,
    ReputationResult,
)
from src.services.ioc.service import IOCService, get_ioc_service
from src.services.ioc.types import IOCType


class ThreatIntelService:
    """Orchestrator for IP and Domain threat intelligence lookups with caching."""

    def __init__(
        self,
        ip_provider: IPReputationProvider | None = None,
        domain_provider: DomainReputationProvider | None = None,
        ioc_service: IOCService | None = None,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        # Select real external provider if API key present, otherwise fallback to mock
        if ip_provider:
            self.ip_provider = ip_provider
        elif settings.THREATFOX_API_KEY:
            self.ip_provider = ThreatFoxProvider()
        elif settings.ABUSEIPDB_API_KEY:
            self.ip_provider = AbuseIPDBProvider()
        else:
            self.ip_provider = MockIPReputationProvider()

        if domain_provider:
            self.domain_provider = domain_provider
        elif settings.THREATFOX_API_KEY:
            self.domain_provider = ThreatFoxProvider()
        elif settings.URLHAUS_API_KEY:
            self.domain_provider = URLhausProvider()
        elif settings.VIRUSTOTAL_API_KEY:
            self.domain_provider = VirusTotalDomainProvider()
        else:
            self.domain_provider = MockDomainReputationProvider()

        self.ioc_service = ioc_service or get_ioc_service()
        self.cache_ttl_seconds = cache_ttl_seconds
        # In-memory LRU/TTL cache: (indicator_type, indicator) -> (timestamp, ReputationResult)
        self._cache: dict[tuple[str, str], tuple[float, ReputationResult]] = {}

    def clear_cache(self) -> None:
        """Clears all cached indicator reputation records."""
        self._cache.clear()

    async def lookup_ip(self, ip: str) -> ReputationResult:
        """Queries IP threat reputation with cache resolution."""
        clean_ip = ip.strip()
        cache_key = ("ip", clean_ip)

        now = time.time()
        if cache_key in self._cache:
            ts, cached_result = self._cache[cache_key]
            if (now - ts) < self.cache_ttl_seconds:
                # Return copy with cached flag
                return ReputationResult(
                    indicator=cached_result.indicator,
                    indicator_type=cached_result.indicator_type,
                    provider_name=cached_result.provider_name,
                    status=cached_result.status,
                    reputation_score=cached_result.reputation_score,
                    is_malicious=cached_result.is_malicious,
                    threat_tags=list(cached_result.threat_tags),
                    details=dict(cached_result.details),
                    attribution=cached_result.attribution,
                    cached=True,
                    error_message=cached_result.error_message,
                )

        result = await self.ip_provider.lookup_ip(clean_ip)
        self._cache[cache_key] = (now, result)
        return result

    async def lookup_domain(self, domain: str) -> ReputationResult:
        """Queries Domain threat reputation with cache resolution."""
        clean_domain = domain.strip().lower()
        cache_key = ("domain", clean_domain)

        now = time.time()
        if cache_key in self._cache:
            ts, cached_result = self._cache[cache_key]
            if (now - ts) < self.cache_ttl_seconds:
                return ReputationResult(
                    indicator=cached_result.indicator,
                    indicator_type=cached_result.indicator_type,
                    provider_name=cached_result.provider_name,
                    status=cached_result.status,
                    reputation_score=cached_result.reputation_score,
                    is_malicious=cached_result.is_malicious,
                    threat_tags=list(cached_result.threat_tags),
                    details=dict(cached_result.details),
                    attribution=cached_result.attribution,
                    cached=True,
                    error_message=cached_result.error_message,
                )

        result = await self.domain_provider.lookup_domain(clean_domain)
        self._cache[cache_key] = (now, result)
        return result

    async def analyze_case_indicators(self, case_id: str, db: Session) -> dict[str, Any]:
        """Queries threat intelligence for all unique IPs and domains associated with a case."""
        case_iocs = self.ioc_service.get_case_iocs(case_id=case_id, db=db)

        unique_ips = sorted(
            {ioc.value for ioc in case_iocs if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6)}
        )
        unique_domains = sorted({ioc.value for ioc in case_iocs if ioc.ioc_type == IOCType.DOMAIN})

        # Run lookups concurrently
        ip_tasks = [self.lookup_ip(ip) for ip in unique_ips]
        domain_tasks = [self.lookup_domain(dom) for dom in unique_domains]

        ip_results: list[ReputationResult] = await asyncio.gather(*ip_tasks) if ip_tasks else []
        domain_results: list[ReputationResult] = (
            await asyncio.gather(*domain_tasks) if domain_tasks else []
        )

        valid_ip_scores = [r.reputation_score for r in ip_results if r.reputation_score is not None]
        valid_domain_scores = [
            r.reputation_score for r in domain_results if r.reputation_score is not None
        ]

        max_ip_score = max(valid_ip_scores) if valid_ip_scores else None
        max_domain_score = max(valid_domain_scores) if valid_domain_scores else None

        avg_ip_score = (
            round(sum(valid_ip_scores) / len(valid_ip_scores), 2) if valid_ip_scores else None
        )
        avg_domain_score = (
            round(sum(valid_domain_scores) / len(valid_domain_scores), 2)
            if valid_domain_scores
            else None
        )

        malicious_ips = [r.indicator for r in ip_results if r.is_malicious]
        malicious_domains = [r.indicator for r in domain_results if r.is_malicious]

        return {
            "case_id": case_id,
            "ip_provider": self.ip_provider.provider_name,
            "domain_provider": self.domain_provider.provider_name,
            "ip_lookups_count": len(ip_results),
            "domain_lookups_count": len(domain_results),
            "max_ip_score": max_ip_score,
            "max_domain_score": max_domain_score,
            "avg_ip_score": avg_ip_score,
            "avg_domain_score": avg_domain_score,
            "malicious_ips": malicious_ips,
            "malicious_domains": malicious_domains,
            "ip_results": [r.to_dict() for r in ip_results],
            "domain_results": [r.to_dict() for r in domain_results],
        }


# Default singleton instance
default_intel_service = ThreatIntelService()


def get_intel_service() -> ThreatIntelService:
    """Dependency injector for threat intelligence service."""
    return default_intel_service
