from src.services.geo.providers.maxmind import MaxMindGeoIPProvider
from src.services.geo.providers.mock_provider import MockGeoIPProvider
from src.services.geo.service import GeoIPService
from src.services.geo.types import (
    DISCLAIMER_TEXT,
    DataQuality,
    GeoLookupStatus,
)


def test_mock_geoip_known_public_ips():
    """Verify mock provider enriches known public IPs with location, ASN, and ISP."""
    provider = MockGeoIPProvider()

    res = provider.lookup("198.51.100.200")
    assert res.status == GeoLookupStatus.SUCCESS
    assert res.is_private is False
    assert res.country_code == "DE"
    assert res.country_name == "Germany"
    assert res.city_name == "Frankfurt am Main"
    assert res.asn_number == 24940
    assert res.asn_org == "Hetzner Online GmbH"
    assert res.is_hosting_provider is True
    assert res.data_quality == DataQuality.CITY_LEVEL
    assert "Frankfurt" in (res.probable_infrastructure_origin or "")
    assert res.disclaimer == DISCLAIMER_TEXT


def test_mock_geoip_rfc1918_private_ips():
    """Verify RFC 1918 private and loopback IPs are flagged as private without external lookups."""
    provider = MockGeoIPProvider()

    private_ips = ["10.0.0.1", "192.168.1.100", "172.16.0.5", "127.0.0.1", "::1"]

    for ip in private_ips:
        res = provider.lookup(ip)
        assert res.status == GeoLookupStatus.PRIVATE_IP
        assert res.is_private is True
        assert res.data_quality == DataQuality.PRIVATE_NETWORK
        assert "Internal / Private Network" in (res.probable_infrastructure_origin or "")
        assert res.disclaimer == DISCLAIMER_TEXT


def test_mock_geoip_invalid_ip_format():
    """Verify invalid IP strings produce INVALID_IP status."""
    provider = MockGeoIPProvider()

    res = provider.lookup("999.999.999.999")
    assert res.status == GeoLookupStatus.INVALID_IP
    assert res.is_private is False
    assert res.data_quality == DataQuality.UNAVAILABLE

    res2 = provider.lookup("not-an-ip")
    assert res2.status == GeoLookupStatus.INVALID_IP


def test_maxmind_missing_database_graceful_handling():
    """Verify MaxMind provider produces UNAVAILABLE when database files are absent."""
    provider = MaxMindGeoIPProvider(
        city_db_path="/nonexistent/GeoLite2-City.mmdb",
        asn_db_path="/nonexistent/GeoLite2-ASN.mmdb",
    )

    res = provider.lookup("198.51.100.200")
    assert res.status == GeoLookupStatus.UNAVAILABLE
    assert res.data_quality == DataQuality.UNAVAILABLE
    assert res.disclaimer == DISCLAIMER_TEXT
    assert "not configured or unreadable" in (res.error_message or "")


def test_mandatory_disclaimer_and_probable_origin_terminology():
    """Verify Rule 14 compliance: 'Probable Infrastructure Origin' used, disclaimer present, no 'Attacker Location'."""
    provider = MockGeoIPProvider()
    res = provider.lookup("203.0.113.88")

    # Disclaimer check
    assert res.disclaimer == (
        "Geolocation describes network infrastructure and does not establish the "
        "physical location or identity of an attacker."
    )

    # Probable infrastructure origin field populated
    assert res.probable_infrastructure_origin is not None
    assert "Attacker Location" not in res.probable_infrastructure_origin


def test_geoip_service_caching_and_deduplication():
    """Verify GeoIPService caches results and serves repeat queries with cached=True."""
    provider = MockGeoIPProvider()
    service = GeoIPService(provider=provider)

    # First lookup
    r1 = service.lookup_ip("198.51.100.45")
    assert r1.cached is False
    assert r1.city_name == "Amsterdam"

    # Second lookup
    r2 = service.lookup_ip("198.51.100.45")
    assert r2.cached is True
    assert r2.city_name == "Amsterdam"
    assert r2.asn_number == r1.asn_number
