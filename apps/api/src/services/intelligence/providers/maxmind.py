import ipaddress
from pathlib import Path
from datetime import datetime, timezone

from src.core.config import settings
from src.services.intelligence.interfaces import IPIntelligenceProvider
from src.services.intelligence.types import IntelligenceResult, ProviderStatus
from src.services.intelligence.dto import IPIntelligenceData

class MaxMindFoundationProvider(IPIntelligenceProvider):
    """MaxMind GeoLite2 self-hosted MMDB and GeoIP2 Web API infrastructure adapter."""

    def __init__(
        self,
        city_db_path: str | None = None,
        asn_db_path: str | None = None,
        account_id: str | None = None,
        license_key: str | None = None,
    ) -> None:
        self.city_db_path = city_db_path or settings.GEOIP_CITY_DB_PATH
        self.asn_db_path = asn_db_path or settings.GEOIP_ASN_DB_PATH
        self.account_id = account_id or getattr(settings, "MAXMIND_ACCOUNT_ID", None)
        self.license_key = license_key or getattr(settings, "MAXMIND_LICENSE_KEY", None)
        self._city_reader = None
        self._asn_reader = None
        self._init_readers()

    def _init_readers(self) -> None:
        if not self.city_db_path and not self.asn_db_path:
            return

        try:
            import geoip2.database  # type: ignore
            if self.city_db_path and Path(self.city_db_path).exists():
                self._city_reader = geoip2.database.Reader(self.city_db_path)
            if self.asn_db_path and Path(self.asn_db_path).exists():
                self._asn_reader = geoip2.database.Reader(self.asn_db_path)
        except Exception:
            self._city_reader = None
            self._asn_reader = None

    @property
    def name(self) -> str:
        return "MaxMind GeoLite2"

    async def lookup_ip(self, ip: str) -> IntelligenceResult[IPIntelligenceData]:
        clean_ip = ip.strip()
        timestamp = datetime.now(timezone.utc)
        
        if not self._city_reader and not self._asn_reader:
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=timestamp,
                normalized_result=None,
                error_information="MaxMind GeoLite2 database not configured or missing."
            )

        data = IPIntelligenceData()
        
        if self._city_reader:
            try:
                city_resp = self._city_reader.city(clean_ip)
                if city_resp.country.iso_code:
                    data.country = city_resp.country.iso_code
                if city_resp.subdivisions.most_specific.name:
                    data.region = city_resp.subdivisions.most_specific.name
                if city_resp.city.name:
                    data.city = city_resp.city.name
                if city_resp.location.latitude:
                    data.latitude = city_resp.location.latitude
                if city_resp.location.longitude:
                    data.longitude = city_resp.location.longitude
                if city_resp.location.time_zone:
                    data.timezone = city_resp.location.time_zone
            except Exception:
                pass
                
        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(clean_ip)
                if asn_resp.autonomous_system_number:
                    data.asn = asn_resp.autonomous_system_number
                if asn_resp.autonomous_system_organization:
                    data.organization = asn_resp.autonomous_system_organization
            except Exception:
                pass

        return IntelligenceResult(
            status=ProviderStatus.AVAILABLE,
            provider_name=self.name,
            lookup_timestamp=timestamp,
            normalized_result=data
        )
