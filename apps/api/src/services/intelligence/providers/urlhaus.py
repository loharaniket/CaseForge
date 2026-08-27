import httpx
from datetime import datetime, timezone
from typing import Any

from src.core.config import settings
from src.services.intelligence.interfaces import URLIntelligenceProvider
from src.services.intelligence.types import IntelligenceResult, ProviderStatus
from src.services.intelligence.dto import URLIntelligenceData


class URLhausFoundationProvider(URLIntelligenceProvider):
    """URLhaus (abuse.ch) Malicious URL threat intelligence adapter."""

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
    def name(self) -> str:
        return "URLhaus (abuse.ch)"

    async def lookup_url(self, url: str) -> IntelligenceResult[dict[str, Any]]:
        clean_url = url.strip()
        timestamp = datetime.now(timezone.utc)

        headers = {
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        data = {"url": clean_url}

        try:
            if self.client:
                response = await self.client.post(
                    self.URL_API, data=data, headers=headers, timeout=self.timeout_seconds
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(
                        self.URL_API, data=data, headers=headers
                    )

            if response.status_code == 429:
                return IntelligenceResult(
                    status=ProviderStatus.RATE_LIMITED,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    error_information="URLhaus rate limit reached.",
                )
            if response.status_code != 200:
                return IntelligenceResult(
                    status=ProviderStatus.UNAVAILABLE,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    error_information=f"HTTP {response.status_code}",
                )

            res_json = response.json()
            query_status = res_json.get("query_status")

            if query_status == "ok":
                threat = res_json.get("threat") or "malware_download"
                url_status = res_json.get("url_status") or "online"
                tags = res_json.get("tags") or []
                risk_score = 90.0 if url_status == "online" else 70.0

                return IntelligenceResult(
                    status=ProviderStatus.AVAILABLE,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    normalized_result={
                        "reputation": "Malicious",
                        "risk_score": risk_score,
                        "threat": threat,
                        "url_status": url_status,
                        "tags": tags,
                    },
                    confidence=risk_score / 100.0,
                )

            # Not found in malicious database -> Clean
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result={
                    "reputation": "Clean",
                    "risk_score": 0.0,
                    "threat": None,
                },
            )

        except httpx.TimeoutException:
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information="URLhaus request timed out.",
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e),
            )
