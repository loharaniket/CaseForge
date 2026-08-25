import httpx
from datetime import datetime, timezone

from src.core.config import settings
from src.services.intelligence.interfaces import DomainIntelligenceProvider
from src.services.intelligence.types import IntelligenceResult, ProviderStatus
from src.services.intelligence.dto import DomainIntelligenceData

class VirusTotalDomainFoundationProvider(DomainIntelligenceProvider):
    """VirusTotal adapter for the new domain intelligence foundation."""
    
    API_URL = "https://www.virustotal.com/api/v3/domains"
    
    def __init__(self, api_key: str | None = None, timeout_seconds: float = 5.0, client: httpx.AsyncClient | None = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.timeout_seconds = timeout_seconds
        self.client = client
        
    @property
    def name(self) -> str:
        return "VirusTotal"
        
    async def lookup_domain(self, domain: str) -> IntelligenceResult[DomainIntelligenceData]:
        clean_domain = domain.strip().lower()
        timestamp = datetime.now(timezone.utc)
        
        if not self.api_key:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=None,
                error_information="VirusTotal API key not configured."
            )
            
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        url = f"{self.API_URL}/{clean_domain}"
        
        try:
            if self.client:
                response = await self.client.get(url, headers=headers, timeout=self.timeout_seconds)
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(url, headers=headers)
                    
            if response.status_code == 429:
                return IntelligenceResult(
                    status=ProviderStatus.RATE_LIMITED,
                    provider_name=self.name,
                    lookup_timestamp=timestamp
                )
            if response.status_code != 200:
                return IntelligenceResult(
                    status=ProviderStatus.UNAVAILABLE,
                    provider_name=self.name,
                    lookup_timestamp=timestamp,
                    error_information=f"HTTP {response.status_code}"
                )
                
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0)
            score = 0.0
            if total > 0:
                score = min(100.0, ((malicious * 1.0 + suspicious * 0.5) / max(1, total)) * 100.0)
                
            reputation = "Malicious" if (malicious >= 3 or score >= 50.0) else "Clean"
            
            data = DomainIntelligenceData(
                domain=clean_domain,
                registrar=attributes.get("registrar"),
                reputation=reputation,
                risk_score=round(score, 2)
            )
            
            # extract creation date
            creation = attributes.get("creation_date")
            if creation:
                data.creation_date = datetime.fromtimestamp(creation, timezone.utc)
                
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=data,
                confidence=score / 100.0 if score > 0 else None
            )
        except httpx.TimeoutException:
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=self.name,
                lookup_timestamp=timestamp
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e)
            )
