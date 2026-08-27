import httpx
from typing import Any

from src.core.config import settings
from src.services.intel.types import (
    DomainReputationProvider,
    ProviderStatus,
    ReputationResult,
)


class URLhausProvider(DomainReputationProvider):
    """URLhaus (abuse.ch) domain & URL threat intelligence adapter."""

    URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or settings.URLHAUS_API_KEY
        self.timeout_seconds = timeout_seconds
        self.client = client

    @property
    def provider_name(self) -> str:
        return "URLhaus (abuse.ch)"

    async def lookup_domain(self, domain: str) -> ReputationResult:
        clean_domain = domain.strip().lower()
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            if self.client:
                res = await self.client.post(
                    self.HOST_API, data={"host": clean_domain}, headers=headers, timeout=self.timeout_seconds
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    res = await client.post(
                        self.HOST_API, data={"host": clean_domain}, headers=headers
                    )

            if res.status_code == 429:
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.ERROR,
                    reputation_score=None,
                    is_malicious=None,
                    error_message="Rate limit reached.",
                )
            if res.status_code != 200:
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.ERROR,
                    reputation_score=None,
                    is_malicious=None,
                    error_message=f"HTTP {res.status_code}",
                )

            data = res.json()
            if data.get("query_status") == "ok":
                url_count = int(data.get("url_count", 0))
                is_mal = url_count > 0
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.SUCCESS,
                    reputation_score=90.0 if is_mal else 0.0,
                    is_malicious=is_mal,
                    raw_data=data,
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
