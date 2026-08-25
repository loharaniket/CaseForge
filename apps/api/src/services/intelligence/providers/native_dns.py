import asyncio
import dns.asyncresolver
from datetime import datetime, timezone

from src.services.intelligence.interfaces import DNSProvider
from src.services.intelligence.types import IntelligenceResult, ProviderStatus

class NativeDNSFoundationProvider(DNSProvider):
    """Native DNS provider using dnspython asyncresolver."""

    def __init__(self, timeout_seconds: float = 3.0):
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "NativeDNS"

    async def lookup_dns(self, query: str, record_type: str = "A") -> IntelligenceResult[list[str]]:
        clean_query = query.strip().lower()
        timestamp = datetime.now(timezone.utc)
        
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout_seconds
        resolver.lifetime = self.timeout_seconds
        
        try:
            answer = await resolver.resolve(clean_query, record_type)
            results = []
            for rdata in answer:
                if record_type == "MX":
                    results.append(f"{rdata.preference} {rdata.exchange.to_text(omit_final_dot=True)}")
                elif record_type == "TXT":
                    # txt records are typically bytes
                    txt = "".join([b.decode('utf-8', 'ignore') for b in rdata.strings])
                    results.append(txt)
                elif record_type == "NS":
                    results.append(rdata.target.to_text(omit_final_dot=True))
                else:
                    results.append(rdata.to_text())
            
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=results
            )
        except dns.resolver.NoAnswer:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=[]
            )
        except dns.resolver.NXDOMAIN:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=[]
            )
        except dns.resolver.Timeout:
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information="DNS lookup timed out"
            )
        except Exception as e:
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                error_information=str(e)
            )
