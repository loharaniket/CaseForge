import httpx
from datetime import datetime, timezone

from src.core.config import settings
from src.services.intelligence.interfaces import IPIntelligenceProvider
from src.services.intelligence.types import IntelligenceResult, ProviderStatus
from src.services.intelligence.dto import IPIntelligenceData

class AbuseIPDBFoundationProvider(IPIntelligenceProvider):
    """AbuseIPDB v2 IP threat intelligence adapter for the new foundation."""

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
    def name(self) -> str:
        return "AbuseIPDB"

    async def lookup_ip(self, ip: str) -> IntelligenceResult[IPIntelligenceData]:
        clean_ip = ip.strip()
        timestamp = datetime.now(timezone.utc)

        if not self.api_key:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=None,
                error_information="AbuseIPDB API key not configured.",
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
                return IntelligenceResult(
                    status=ProviderStatus.RATE_LIMITED,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    error_information="Rate limit reached.",
                )
            if response.status_code != 200:
                return IntelligenceResult(
                    status=ProviderStatus.UNAVAILABLE,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    error_information=f"HTTP {response.status_code}",
                )

            data = response.json().get("data", {})
            abuse_score = float(data.get("abuseConfidenceScore", 0.0))
            is_tor = bool(data.get("isTor", False))
            usage_type = str(data.get("usageType", ""))
            isp = str(data.get("isp", ""))
            domain = str(data.get("domain", ""))

            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=IPIntelligenceData(
                    country=str(data.get("countryCode", "")),
                    isp=isp,
                    organization=domain if domain else None,
                    hosting_provider="Data Center/Web Hosting" in usage_type or "Hosting" in usage_type,
                    tor_indicator=is_tor,
                    reputation="Malicious" if abuse_score >= 50.0 else "Clean",
                    abuse_threat_score=abuse_score
                ),
                confidence=float(abuse_score) / 100.0 if abuse_score > 0 else None
            )
        except httpx.TimeoutException:
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information="Request timed out."
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e)
            )
