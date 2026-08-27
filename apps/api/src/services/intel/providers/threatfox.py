import httpx
from typing import Any

from src.core.config import settings
from src.services.intel.types import (
    IPReputationProvider,
    DomainReputationProvider,
    ProviderStatus,
    ReputationResult,
)


class ThreatFoxProvider(IPReputationProvider, DomainReputationProvider):
    """ThreatFox (abuse.ch) threat intelligence adapter."""

    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or settings.THREATFOX_API_KEY
        self.timeout_seconds = timeout_seconds
        self.client = client

    @property
    def provider_name(self) -> str:
        return "ThreatFox (abuse.ch)"

    async def _search(self, term: str) -> dict[str, Any]:
        payload = {
            "query": "search_ioc",
            "search_term": term.strip(),
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key
            headers["API-KEY"] = self.api_key

        if self.client:
            res = await self.client.post(
                self.API_URL, json=payload, headers=headers, timeout=self.timeout_seconds
            )
        else:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                res = await client.post(self.API_URL, json=payload, headers=headers)

        if res.status_code == 429:
            raise RuntimeError("RATE_LIMITED")
        if res.status_code != 200:
            raise RuntimeError(f"HTTP_{res.status_code}")
        return res.json()

    async def lookup_ip(self, ip: str) -> ReputationResult:
        clean_ip = ip.strip()
        if not self.api_key:
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.DISABLED,
                reputation_score=None,
                is_malicious=None,
                error_message="ThreatFox API key not configured.",
            )

        try:
            data = await self._search(clean_ip)
            if data.get("query_status") == "ok" and data.get("data"):
                top = data["data"][0]
                conf = float(top.get("confidence_level", 75))
                return ReputationResult(
                    indicator=clean_ip,
                    indicator_type="ip",
                    provider_name=self.provider_name,
                    status=ProviderStatus.SUCCESS,
                    reputation_score=conf,
                    is_malicious=True,
                    raw_data=top,
                )
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=0.0,
                is_malicious=False,
            )
        except Exception as e:
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.ERROR,
                reputation_score=None,
                is_malicious=None,
                error_message=str(e),
            )

    async def lookup_domain(self, domain: str) -> ReputationResult:
        clean_domain = domain.strip().lower()
        if not self.api_key:
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.DISABLED,
                reputation_score=None,
                is_malicious=None,
                error_message="ThreatFox API key not configured.",
            )

        try:
            data = await self._search(clean_domain)
            if data.get("query_status") == "ok" and data.get("data"):
                top = data["data"][0]
                conf = float(top.get("confidence_level", 80))
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.SUCCESS,
                    reputation_score=conf,
                    is_malicious=True,
                    raw_data=top,
                )
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=0.0,
                is_malicious=False,
            )
        except Exception as e:
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.ERROR,
                reputation_score=None,
                is_malicious=None,
                error_message=str(e),
            )
