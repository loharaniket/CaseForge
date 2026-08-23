import ipaddress
from pathlib import Path

from src.core.config import settings
from src.services.geo.types import (
    DISCLAIMER_TEXT,
    DataQuality,
    GeoIPProvider,
    GeoLocationResult,
    GeoLookupStatus,
)

# Explicit RFC 1918, loopback, and link-local private networks
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def _is_private(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in RFC1918_NETWORKS:
        if ip_obj in net:
            return True
    return False


class MaxMindGeoIPProvider(GeoIPProvider):
    """MaxMind GeoLite2 MMDB infrastructure adapter."""

    def __init__(
        self,
        city_db_path: str | None = None,
        asn_db_path: str | None = None,
    ) -> None:
        self.city_db_path = city_db_path or settings.GEOIP_CITY_DB_PATH
        self.asn_db_path = asn_db_path or settings.GEOIP_ASN_DB_PATH
        self._city_reader = None
        self._asn_reader = None
        self._init_readers()

    def _init_readers(self) -> None:
        """Attempts to initialize MaxMind MMDB readers if files are present."""
        if not self.city_db_path and not self.asn_db_path:
            return

        try:
            import geoip2.database  # type: ignore[import-not-found]

            if self.city_db_path and Path(self.city_db_path).exists():
                self._city_reader = geoip2.database.Reader(self.city_db_path)
            if self.asn_db_path and Path(self.asn_db_path).exists():
                self._asn_reader = geoip2.database.Reader(self.asn_db_path)
        except Exception:
            # Missing dependency or unreadable file
            self._city_reader = None
            self._asn_reader = None

    @property
    def provider_name(self) -> str:
        return "MaxMindGeoIP"

    def lookup(self, ip: str) -> GeoLocationResult:
        clean_ip = ip.strip().strip("[]")

        # 1. Validate IP format
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return GeoLocationResult(
                ip=clean_ip,
                status=GeoLookupStatus.INVALID_IP,
                is_private=False,
                data_quality=DataQuality.UNAVAILABLE,
                disclaimer=DISCLAIMER_TEXT,
                provider_name=self.provider_name,
                error_message=f"Invalid IP address format: '{clean_ip}'",
            )

        # 2. Check RFC 1918 / Private / Loopback
        if _is_private(ip_obj):
            return GeoLocationResult(
                ip=clean_ip,
                status=GeoLookupStatus.PRIVATE_IP,
                is_private=True,
                probable_infrastructure_origin="Internal / Private Network (RFC 1918 / Loopback)",
                data_quality=DataQuality.PRIVATE_NETWORK,
                disclaimer=DISCLAIMER_TEXT,
                provider_name=self.provider_name,
                details={"scope": "private_unroutable"},
            )

        # 3. Check reader availability
        if not self._city_reader and not self._asn_reader:
            return GeoLocationResult(
                ip=clean_ip,
                status=GeoLookupStatus.UNAVAILABLE,
                is_private=False,
                data_quality=DataQuality.UNAVAILABLE,
                disclaimer=DISCLAIMER_TEXT,
                provider_name=self.provider_name,
                error_message="MaxMind GeoIP database files not configured or unreadable.",
            )

        country_code = None
        country_name = None
        region_name = None
        city_name = None
        postal_code = None
        latitude = None
        longitude = None
        data_quality = DataQuality.UNAVAILABLE

        # Query City database
        if self._city_reader:
            try:
                city_resp = self._city_reader.city(clean_ip)
                country_code = city_resp.country.iso_code
                country_name = city_resp.country.name
                if city_resp.subdivisions:
                    region_name = city_resp.subdivisions.most_specific.name
                city_name = city_resp.city.name
                postal_code = city_resp.postal.code
                if city_resp.location:
                    latitude = city_resp.location.latitude
                    longitude = city_resp.location.longitude

                if city_name:
                    data_quality = DataQuality.CITY_LEVEL
                elif country_name:
                    data_quality = DataQuality.COUNTRY_LEVEL
            except Exception:
                pass

        # Query ASN database
        asn_number = None
        asn_org = None
        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(clean_ip)
                asn_number = asn_resp.autonomous_system_number
                asn_org = asn_resp.autonomous_system_organization
                if data_quality == DataQuality.UNAVAILABLE and asn_org:
                    data_quality = DataQuality.ASN_ONLY
            except Exception:
                pass

        # Format probable infrastructure origin
        origin_parts = [p for p in (city_name, region_name, country_name) if p]
        origin_str = (
            ", ".join(origin_parts) if origin_parts else (asn_org or "Unknown Network Origin")
        )

        return GeoLocationResult(
            ip=clean_ip,
            status=GeoLookupStatus.SUCCESS,
            is_private=False,
            probable_infrastructure_origin=origin_str,
            country_code=country_code,
            country_name=country_name,
            region_name=region_name,
            city_name=city_name,
            postal_code=postal_code,
            latitude=latitude,
            longitude=longitude,
            asn_number=asn_number,
            asn_org=asn_org,
            isp=asn_org,
            organization=asn_org,
            data_quality=data_quality,
            disclaimer=DISCLAIMER_TEXT,
            provider_name=self.provider_name,
        )
