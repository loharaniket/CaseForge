import time
from typing import Any

from sqlalchemy.orm import Session

from src.core.config import settings
from src.services.forensics.service import HeaderForensicsService, get_forensics_service
from src.services.geo.providers.maxmind import MaxMindGeoIPProvider
from src.services.geo.providers.mock_provider import MockGeoIPProvider
from src.services.geo.types import (
    DISCLAIMER_TEXT,
    GeoIPProvider,
    GeoLocationResult,
)
from src.services.ioc.service import IOCService, get_ioc_service
from src.services.ioc.types import IOCType


class GeoIPService:
    """Orchestrator for GeoIP and network infrastructure intelligence."""

    def __init__(
        self,
        provider: GeoIPProvider | None = None,
        forensics_service: HeaderForensicsService | None = None,
        ioc_service: IOCService | None = None,
        cache_ttl_seconds: int = 86400,  # 24 hours
    ) -> None:
        if provider:
            self.provider = provider
        elif settings.GEOIP_CITY_DB_PATH:
            self.provider = MaxMindGeoIPProvider()
        else:
            self.provider = MockGeoIPProvider()

        self.forensics_service = forensics_service or get_forensics_service()
        self.ioc_service = ioc_service or get_ioc_service()
        self.cache_ttl_seconds = cache_ttl_seconds
        # In-memory TTL cache: ip_str -> (timestamp, GeoLocationResult)
        self._cache: dict[str, tuple[float, GeoLocationResult]] = {}

    def clear_cache(self) -> None:
        """Clears all cached GeoIP entries."""
        self._cache.clear()

    def lookup_ip(self, ip: str) -> GeoLocationResult:
        """Queries GeoIP infrastructure intelligence with caching."""
        clean_ip = ip.strip().strip("[]")

        now = time.time()
        if clean_ip in self._cache:
            ts, cached_result = self._cache[clean_ip]
            if (now - ts) < self.cache_ttl_seconds:
                return GeoLocationResult(
                    ip=cached_result.ip,
                    status=cached_result.status,
                    is_private=cached_result.is_private,
                    probable_infrastructure_origin=cached_result.probable_infrastructure_origin,
                    country_code=cached_result.country_code,
                    country_name=cached_result.country_name,
                    region_name=cached_result.region_name,
                    city_name=cached_result.city_name,
                    postal_code=cached_result.postal_code,
                    latitude=cached_result.latitude,
                    longitude=cached_result.longitude,
                    asn_number=cached_result.asn_number,
                    asn_org=cached_result.asn_org,
                    isp=cached_result.isp,
                    organization=cached_result.organization,
                    is_hosting_provider=cached_result.is_hosting_provider,
                    data_quality=cached_result.data_quality,
                    disclaimer=DISCLAIMER_TEXT,
                    provider_name=cached_result.provider_name,
                    cached=True,
                    error_message=cached_result.error_message,
                    details=dict(cached_result.details),
                )

        result = self.provider.lookup(clean_ip)
        self._cache[clean_ip] = (now, result)
        return result

    def analyze_case_infrastructure(self, case_id: str, db: Session) -> dict[str, Any]:
        """Enriches all candidate origin IPs, relay hops, and extracted IP IOCs for a case."""
        # 1. Retrieve header forensics for candidate origin
        forensics = None
        try:
            forensics = self.forensics_service.get_case_forensics(case_id=case_id, db=db)
        except Exception:
            pass

        # 2. Retrieve extracted IP IOCs
        case_iocs = self.ioc_service.get_case_iocs(case_id=case_id, db=db)
        unique_ips = sorted(
            {ioc.value for ioc in case_iocs if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6)}
        )

        # Include candidate origin IP if present
        candidate_origin_ip = (
            getattr(forensics, "probable_origin_ip", None)
            or getattr(forensics, "candidate_origin_ip", None)
            if forensics
            else None
        )
        if candidate_origin_ip and candidate_origin_ip not in unique_ips:
            unique_ips.append(candidate_origin_ip)

        # 3. Enrich all unique IPs
        enriched_results: list[GeoLocationResult] = [self.lookup_ip(ip) for ip in unique_ips]

        # 4. Primary origin infrastructure assessment
        origin_geo = None
        if candidate_origin_ip:
            origin_geo = self.lookup_ip(candidate_origin_ip)
        elif enriched_results:
            # First non-private IP
            non_private = [r for r in enriched_results if not r.is_private]
            if non_private:
                origin_geo = non_private[0]
            else:
                origin_geo = enriched_results[0]

        return {
            "case_id": case_id,
            "provider_name": self.provider.provider_name,
            "candidate_origin_ip": candidate_origin_ip,
            "probable_infrastructure_origin": origin_geo.probable_infrastructure_origin
            if origin_geo
            else None,
            "origin_country": origin_geo.country_name if origin_geo else None,
            "origin_country_code": origin_geo.country_code if origin_geo else None,
            "origin_asn": origin_geo.asn_number if origin_geo else None,
            "origin_isp": origin_geo.isp if origin_geo else None,
            "disclaimer": DISCLAIMER_TEXT,
            "total_ips_analyzed": len(enriched_results),
            "ip_infrastructure": [r.to_dict() for r in enriched_results],
        }


# Default singleton instance
default_geoip_service = GeoIPService()


def get_geoip_service() -> GeoIPService:
    """Dependency injector for GeoIP infrastructure service."""
    return default_geoip_service
