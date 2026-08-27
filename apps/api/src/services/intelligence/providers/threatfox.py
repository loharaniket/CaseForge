import httpx
from datetime import datetime, timezone
from typing import Any

from src.core.config import settings
from src.services.intelligence.interfaces import (
    IPIntelligenceProvider,
    DomainIntelligenceProvider,
    ReputationProvider,
)
from src.services.intelligence.types import IntelligenceResult, ProviderStatus
from src.services.intelligence.dto import IPIntelligenceData, DomainIntelligenceData


class ThreatFoxFoundationProvider(
    IPIntelligenceProvider, DomainIntelligenceProvider, ReputationProvider
):
    """ThreatFox (abuse.ch) IOC threat intelligence adapter."""

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
    def name(self) -> str:
        return "ThreatFox (abuse.ch)"

    async def _query_threatfox(self, search_term: str) -> dict[str, Any]:
        payload = {
            "query": "search_ioc",
            "search_term": search_term.strip(),
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key
            headers["API-KEY"] = self.api_key

        if self.client:
            response = await self.client.post(
                self.API_URL, json=payload, headers=headers, timeout=self.timeout_seconds
            )
        else:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    self.API_URL, json=payload, headers=headers
                )

        if response.status_code == 429:
            raise RuntimeError("RATE_LIMITED")
        if response.status_code != 200:
            raise RuntimeError(f"HTTP_{response.status_code}")

        return response.json()

    async def lookup_ip(self, ip: str) -> IntelligenceResult[IPIntelligenceData]:
        clean_ip = ip.strip()
        timestamp = datetime.now(timezone.utc)

        if not self.api_key:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=None,
                error_information="ThreatFox API key not configured. Using local intelligence.",
            )

        try:
            res = await self._query_threatfox(clean_ip)
            query_status = res.get("query_status")

            if query_status == "ok":
                entries = res.get("data", [])
                matched = None
                for item in entries:
                    ioc_val = item.get("ioc", "").strip().lower()
                    ioc_host = ioc_val.split(":")[0]
                    if ioc_host == clean_ip or ioc_val == clean_ip:
                        matched = item
                        break

                if matched:
                    confidence = float(matched.get("confidence_level", 75))
                    threat_type = matched.get("threat_type_desc") or matched.get("threat_type") or "Malicious IOC"
                    malware = matched.get("malware_printable") or matched.get("malware") or "Unknown"

                    return IntelligenceResult(
                        status=ProviderStatus.AVAILABLE,
                        provider_name=self.name,
                        lookup_timestamp=timestamp,
                        normalized_result=IPIntelligenceData(
                            reputation="Malicious",
                            abuse_threat_score=confidence,
                            organization=f"ThreatFox: {malware} ({threat_type})",
                        ),
                        confidence=confidence / 100.0,
                    )

            # Not found in threat database -> Clean
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=IPIntelligenceData(
                    reputation="Clean",
                    abuse_threat_score=0.0,
                ),
            )
        except RuntimeError as rerr:
            if str(rerr) == "RATE_LIMITED":
                return IntelligenceResult(
                    status=ProviderStatus.RATE_LIMITED,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    error_information="ThreatFox rate limit reached.",
                )
            return IntelligenceResult(
                status=ProviderStatus.UNAVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(rerr),
            )
        except httpx.TimeoutException:
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information="ThreatFox request timed out.",
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e),
            )

    async def lookup_domain(self, domain: str) -> IntelligenceResult[DomainIntelligenceData]:
        clean_domain = domain.strip().lower()
        timestamp = datetime.now(timezone.utc)

        if not self.api_key:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=None,
                error_information="ThreatFox API key not configured. Using local intelligence.",
            )

        try:
            res = await self._query_threatfox(clean_domain)
            query_status = res.get("query_status")

            if query_status == "ok":
                entries = res.get("data", [])
                matched = None
                for item in entries:
                    ioc_val = item.get("ioc", "").strip().lower()
                    ioc_host = ioc_val.split(":")[0]
                    if ioc_host == clean_domain or ioc_val == clean_domain:
                        matched = item
                        break

                if matched:
                    confidence = float(matched.get("confidence_level", 80))
                    threat_type = matched.get("threat_type_desc") or matched.get("threat_type") or "Malicious IOC"
                    malware = matched.get("malware_printable") or matched.get("malware") or "Unknown"

                    return IntelligenceResult(
                        status=ProviderStatus.AVAILABLE,
                        provider_name=self.name,
                        lookup_timestamp=timestamp,
                        normalized_result=DomainIntelligenceData(
                            domain=clean_domain,
                            reputation="Malicious",
                            risk_score=confidence,
                        ),
                        confidence=confidence / 100.0,
                    )

            # Not found in threat database -> Clean
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=DomainIntelligenceData(
                    domain=clean_domain,
                    reputation="Clean",
                    risk_score=0.0,
                ),
            )
        except RuntimeError as rerr:
            if str(rerr) == "RATE_LIMITED":
                return IntelligenceResult(
                    status=ProviderStatus.RATE_LIMITED,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                )
            return IntelligenceResult(
                status=ProviderStatus.UNAVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(rerr),
            )
        except httpx.TimeoutException:
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=self.name,
                lookup_timestamp=timestamp,
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e),
            )

    async def lookup_reputation(
        self, indicator: str, indicator_type: str
    ) -> IntelligenceResult[dict[str, Any]]:
        timestamp = datetime.now(timezone.utc)
        if not self.api_key:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result={"reputation": "Clean", "risk_score": 0.0},
            )

        try:
            res = await self._query_threatfox(indicator)
            if res.get("query_status") == "ok" and res.get("data"):
                top = res["data"][0]
                confidence = float(top.get("confidence_level", 80))
                return IntelligenceResult(
                    status=ProviderStatus.AVAILABLE,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    normalized_result={
                        "reputation": "Malicious",
                        "risk_score": confidence,
                        "malware": top.get("malware_printable"),
                        "threat_type": top.get("threat_type_desc"),
                    },
                    confidence=confidence / 100.0,
                )
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result={"reputation": "Clean", "risk_score": 0.0},
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e),
            )
