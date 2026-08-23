import httpx

from src.core.config import settings
from src.services.intel.types import (
    DomainReputationProvider,
    ProviderStatus,
    ReputationResult,
)


class VirusTotalDomainProvider(DomainReputationProvider):
    """VirusTotal v3 Domain threat intelligence adapter."""

    API_BASE_URL = "https://www.virustotal.com/api/v3/domains"

    def __init__(
        self,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.timeout_seconds = timeout_seconds
        self.client = client

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

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
                error_message="VirusTotal API key not configured in environment.",
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }
        url = f"{self.API_BASE_URL}/{clean_domain}"

        try:
            if self.client:
                response = await self.client.get(url, headers=headers, timeout=self.timeout_seconds)
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(url, headers=headers)

            if response.status_code == 429:
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.RATE_LIMITED,
                    reputation_score=None,
                    is_malicious=None,
                    error_message="VirusTotal API rate limit reached (HTTP 429).",
                )

            if response.status_code == 404:
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.SUCCESS,
                    reputation_score=0.0,
                    is_malicious=False,
                    threat_tags=["not_found_clean"],
                    details={"status": "not_analyzed_by_virustotal"},
                    attribution="VirusTotal v3 Intelligence",
                )

            if response.status_code != 200:
                return ReputationResult(
                    indicator=clean_domain,
                    indicator_type="domain",
                    provider_name=self.provider_name,
                    status=ProviderStatus.UNAVAILABLE,
                    reputation_score=None,
                    is_malicious=None,
                    error_message=f"VirusTotal server returned HTTP {response.status_code}.",
                )

            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if total > 0:
                score = min(100.0, ((malicious * 1.0 + suspicious * 0.5) / max(1, total)) * 100.0)
            else:
                score = 0.0

            # Direct mapping: if multiple AV engines flag malicious
            is_malicious = malicious >= 3 or score >= 50.0

            tags: list[str] = attributes.get("tags", []) or []
            if malicious > 0:
                tags.append(f"malicious_votes:{malicious}")

            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=round(score, 2),
                is_malicious=is_malicious,
                threat_tags=tags,
                details={
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "total_engines": total,
                    "reputation_raw": attributes.get("reputation", 0),
                    "registrar": attributes.get("registrar"),
                },
                attribution="VirusTotal v3 Threat Intelligence",
            )

        except httpx.TimeoutException:
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.TIMEOUT,
                reputation_score=None,
                is_malicious=None,
                error_message=f"VirusTotal request timed out after {self.timeout_seconds}s.",
            )
        except Exception as exc:
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.UNAVAILABLE,
                reputation_score=None,
                is_malicious=None,
                error_message=f"VirusTotal provider unavailable: {exc}",
            )
