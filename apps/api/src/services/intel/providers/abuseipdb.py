import httpx

from src.core.config import settings
from src.services.intel.types import (
    IPReputationProvider,
    ProviderStatus,
    ReputationResult,
)


class AbuseIPDBProvider(IPReputationProvider):
    """AbuseIPDB v2 IP threat intelligence adapter."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.timeout_seconds = timeout_seconds
        self.client = client

    @property
    def provider_name(self) -> str:
        return "AbuseIPDB"

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
                error_message="AbuseIPDB API key not configured in environment.",
            )

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params: dict[str, str | int | bool] = {
            "ipAddress": clean_ip,
            "maxAgeInDays": 90,
            "verbose": True,
        }

        try:
            if self.client:
                response = await self.client.get(
                    self.API_URL, headers=headers, params=params, timeout=self.timeout_seconds
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(self.API_URL, headers=headers, params=params)

            if response.status_code == 429:
                return ReputationResult(
                    indicator=clean_ip,
                    indicator_type="ip",
                    provider_name=self.provider_name,
                    status=ProviderStatus.RATE_LIMITED,
                    reputation_score=None,
                    is_malicious=None,
                    error_message="AbuseIPDB API rate limit reached (HTTP 429).",
                )

            if response.status_code != 200:
                return ReputationResult(
                    indicator=clean_ip,
                    indicator_type="ip",
                    provider_name=self.provider_name,
                    status=ProviderStatus.UNAVAILABLE,
                    reputation_score=None,
                    is_malicious=None,
                    error_message=f"AbuseIPDB server returned HTTP {response.status_code}.",
                )

            payload = response.json()
            data = payload.get("data", {})
            abuse_score = float(data.get("abuseConfidenceScore", 0.0))
            is_malicious = abuse_score >= 50.0

            tags: list[str] = []
            if data.get("isWhitelisted"):
                tags.append("whitelisted")
            if data.get("isTor"):
                tags.append("tor_node")
            if data.get("usageType"):
                tags.append(str(data.get("usageType")).lower())

            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=round(abuse_score, 2),
                is_malicious=is_malicious,
                threat_tags=tags,
                details={
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                },
                attribution="AbuseIPDB v2 Threat Intelligence",
            )

        except httpx.TimeoutException:
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.TIMEOUT,
                reputation_score=None,
                is_malicious=None,
                error_message=f"AbuseIPDB request timed out after {self.timeout_seconds}s.",
            )
        except Exception as exc:
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.UNAVAILABLE,
                reputation_score=None,
                is_malicious=None,
                error_message=f"AbuseIPDB provider unavailable: {exc}",
            )
