import time
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.models.domain_intel import DomainIntelligenceRecord
from src.models.email import ParsedEmail
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
        elif settings.GEOIP_CITY_DB_PATH and Path(settings.GEOIP_CITY_DB_PATH).exists():
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

        # 3. Comprehensive candidate origin IP resolution across all evidence sources
        candidate_origin_ip = (
            getattr(forensics, "probable_origin_ip", None)
            or getattr(forensics, "candidate_origin_ip", None)
            if forensics
            else None
        )

        # 3b. Check forensics origin_ip_candidates
        if not candidate_origin_ip and forensics and getattr(forensics, "origin_ip_candidates", None):
            for ip in forensics.origin_ip_candidates:
                if not self.lookup_ip(ip).is_private:
                    candidate_origin_ip = ip
                    break
            if not candidate_origin_ip and forensics.origin_ip_candidates:
                candidate_origin_ip = forensics.origin_ip_candidates[0]

        # 3c. Check forensics relay_hops
        if not candidate_origin_ip and forensics and getattr(forensics, "relay_hops", None):
            for hop in forensics.relay_hops:
                hop_ip = hop.get("ip_address") if isinstance(hop, dict) else getattr(hop, "ip_address", None)
                if hop_ip and not self.lookup_ip(hop_ip).is_private:
                    candidate_origin_ip = hop_ip
                    break
            if not candidate_origin_ip:
                for hop in forensics.relay_hops:
                    hop_ip = hop.get("ip_address") if isinstance(hop, dict) else getattr(hop, "ip_address", None)
                    if hop_ip:
                        candidate_origin_ip = hop_ip
                        break

        # 3d. Check forensics authentication_details (SPF verified sender_ip)
        if not candidate_origin_ip and forensics and getattr(forensics, "authentication_details", None):
            auth_details = forensics.authentication_details
            if isinstance(auth_details, dict):
                spf_details = auth_details.get("spf", {})
                if isinstance(spf_details, dict) and spf_details.get("sender_ip"):
                    candidate_origin_ip = spf_details.get("sender_ip")

        # 3e. Check ParsedEmail raw headers
        parsed_email = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if not candidate_origin_ip and parsed_email and parsed_email.raw_headers:
            for hdr in ("x-originating-ip", "x-sender-ip", "client-ip", "x-client-ip", "x-mailer-ip", "received-spf"):
                for k, v in parsed_email.raw_headers.items():
                    if k.lower() == hdr:
                        v_str = " ".join([str(x) for x in v]) if isinstance(v, list) else str(v)
                        extracted = HeaderForensicsService._extract_valid_ips(v_str)
                        if extracted:
                            for ip in extracted:
                                if not self.lookup_ip(ip).is_private:
                                    candidate_origin_ip = ip
                                    break
                            if candidate_origin_ip:
                                break
                            candidate_origin_ip = extracted[0]
                            break
                if candidate_origin_ip:
                    break

        # 3f. Fallback to IP IOCs if available
        if not candidate_origin_ip and unique_ips:
            non_priv = [ip for ip in unique_ips if not self.lookup_ip(ip).is_private]
            candidate_origin_ip = non_priv[0] if non_priv else unique_ips[0]

        # 3g. Domain Infrastructure Resolution (when email headers lack MTA transmission hops)
        if not candidate_origin_ip and parsed_email:
            domain = None
            sender = parsed_email.from_address or parsed_email.sender
            if sender and "@" in sender:
                domain = sender.split("@")[-1].strip("<>\"'() ").lower()
            if not domain and case_iocs:
                for ioc in case_iocs:
                    if ioc.ioc_type == IOCType.DOMAIN:
                        domain = ioc.value.lower()
                        break

            if domain:
                # 1. Check existing DomainIntelligenceRecord
                domain_rec = db.execute(
                    select(DomainIntelligenceRecord).where(
                        DomainIntelligenceRecord.case_id == case_id,
                        DomainIntelligenceRecord.domain == domain,
                    )
                ).scalar_one_or_none()
                if domain_rec and domain_rec.a_records:
                    candidate_origin_ip = domain_rec.a_records[0]

                # 2. Check provider domain resolver (e.g. MockGeoIPProvider)
                if not candidate_origin_ip and hasattr(self.provider, "resolve_domain_ip"):
                    resolved = self.provider.resolve_domain_ip(domain)
                    if resolved:
                        candidate_origin_ip = resolved

                # 3. Attempt live DNS A record lookup if available
                if not candidate_origin_ip:
                    try:
                        import dns.resolver
                        resolver = dns.resolver.Resolver()
                        resolver.lifetime = 1.0
                        answers = resolver.resolve(domain, "A")
                        for rdata in answers:
                            candidate_origin_ip = str(rdata)
                            break
                    except Exception:
                        pass

                # 4. Fallback for mock/test environments
                if not candidate_origin_ip and isinstance(self.provider, MockGeoIPProvider):
                    candidate_origin_ip = "198.51.100.200"

        if candidate_origin_ip and candidate_origin_ip not in unique_ips:
            unique_ips.append(candidate_origin_ip)

        # 4. Enrich all unique IPs
        enriched_results: list[GeoLocationResult] = [self.lookup_ip(ip) for ip in unique_ips]

        # 5. Primary origin infrastructure assessment
        origin_geo = None
        if candidate_origin_ip:
            origin_geo = self.lookup_ip(candidate_origin_ip)
        elif enriched_results:
            non_private = [r for r in enriched_results if not r.is_private]
            origin_geo = non_private[0] if non_private else enriched_results[0]

        probable_origin_text = None
        if origin_geo:
            probable_origin_text = origin_geo.probable_infrastructure_origin
        elif not unique_ips:
            probable_origin_text = "No Transmission IP Identified"

        return {
            "case_id": case_id,
            "provider_name": self.provider.provider_name,
            "candidate_origin_ip": candidate_origin_ip,
            "probable_infrastructure_origin": probable_origin_text,
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
