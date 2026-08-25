import ipaddress
from typing import Any

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


class MockGeoIPProvider(GeoIPProvider):
    """Deterministic development and test GeoIP provider."""

    KNOWN_INFRASTRUCTURE: dict[str, dict[str, Any]] = {
        "198.51.100.200": {
            "country_code": "DE",
            "country_name": "Germany",
            "region_name": "Hessen",
            "city_name": "Frankfurt am Main",
            "postal_code": "60311",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "asn_number": 24940,
            "asn_org": "Hetzner Online GmbH",
            "isp": "Hetzner Online",
            "organization": "Hetzner Infrastructure",
            "is_hosting_provider": True,
            "data_quality": DataQuality.CITY_LEVEL,
            "origin": "Frankfurt am Main, Hessen, Germany",
        },
        "203.0.113.88": {
            "country_code": "RU",
            "country_name": "Russia",
            "region_name": "Moscow",
            "city_name": "Moscow",
            "postal_code": "101000",
            "latitude": 55.7558,
            "longitude": 37.6173,
            "asn_number": 12389,
            "asn_org": "Rostelecom PJSC",
            "isp": "Rostelecom",
            "organization": "Broadband Backbone",
            "is_hosting_provider": False,
            "data_quality": DataQuality.CITY_LEVEL,
            "origin": "Moscow, Russia",
        },
        "198.51.100.45": {
            "country_code": "NL",
            "country_name": "Netherlands",
            "region_name": "North Holland",
            "city_name": "Amsterdam",
            "postal_code": "1012",
            "latitude": 52.3676,
            "longitude": 4.9041,
            "asn_number": 49981,
            "asn_org": "WorldStream B.V.",
            "isp": "WorldStream Hosting",
            "organization": "Dedicated Cloud Servers",
            "is_hosting_provider": True,
            "data_quality": DataQuality.CITY_LEVEL,
            "origin": "Amsterdam, North Holland, Netherlands",
        },
        "198.51.100.90": {
            "country_code": "US",
            "country_name": "United States",
            "region_name": "California",
            "city_name": "Mountain View",
            "postal_code": "94043",
            "latitude": 37.3861,
            "longitude": -122.0839,
            "asn_number": 15169,
            "asn_org": "Google LLC",
            "isp": "Google Cloud",
            "organization": "Google Mail MTA",
            "is_hosting_provider": True,
            "data_quality": DataQuality.CITY_LEVEL,
            "origin": "Mountain View, California, United States",
        },
    }

    @property
    def provider_name(self) -> str:
        return "MockGeoIPProvider"

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

        # 3. Lookup in known fixture map
        if clean_ip in self.KNOWN_INFRASTRUCTURE:
            entry = self.KNOWN_INFRASTRUCTURE[clean_ip]
            return GeoLocationResult(
                ip=clean_ip,
                status=GeoLookupStatus.SUCCESS,
                is_private=False,
                probable_infrastructure_origin=entry["origin"],
                country_code=entry["country_code"],
                country_name=entry["country_name"],
                region_name=entry["region_name"],
                city_name=entry["city_name"],
                postal_code=entry["postal_code"],
                latitude=entry["latitude"],
                longitude=entry["longitude"],
                asn_number=entry["asn_number"],
                asn_org=entry["asn_org"],
                isp=entry["isp"],
                organization=entry["organization"],
                is_hosting_provider=entry["is_hosting_provider"],
                data_quality=entry["data_quality"],
                disclaimer=DISCLAIMER_TEXT,
                provider_name=self.provider_name,
                details={"mock_matched": True},
            )

        # 4. Fallback for unmapped public IP
        return GeoLocationResult(
            ip=clean_ip,
            status=GeoLookupStatus.SUCCESS,
            is_private=False,
            probable_infrastructure_origin="United States",
            country_code="US",
            country_name="United States",
            region_name=None,
            city_name=None,
            latitude=37.751,
            longitude=-97.822,
            asn_number=13335,
            asn_org="Cloudflare, Inc.",
            isp="Cloudflare Public Infrastructure",
            organization="Cloudflare Edge",
            is_hosting_provider=True,
            data_quality=DataQuality.COUNTRY_LEVEL,
            disclaimer=DISCLAIMER_TEXT,
            provider_name=self.provider_name,
            details={"mock_matched": False, "fallback": True},
        )
