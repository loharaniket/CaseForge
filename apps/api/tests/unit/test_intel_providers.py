import httpx
import pytest

from src.services.intel.providers.abuseipdb import AbuseIPDBProvider
from src.services.intel.providers.mock_provider import (
    MockDomainReputationProvider,
    MockIPReputationProvider,
)
from src.services.intel.providers.virustotal import VirusTotalDomainProvider
from src.services.intel.service import ThreatIntelService
from src.services.intel.types import ProviderStatus


@pytest.mark.asyncio
async def test_mock_ip_and_domain_providers_determinism():
    """Verify mock providers return deterministic responses for known test indicators."""
    ip_provider = MockIPReputationProvider()
    mal_ip = await ip_provider.lookup_ip("198.51.100.200")
    assert mal_ip.status == ProviderStatus.SUCCESS
    assert mal_ip.reputation_score == 95.0
    assert mal_ip.is_malicious is True

    clean_ip = await ip_provider.lookup_ip("192.0.2.15")
    assert clean_ip.status == ProviderStatus.SUCCESS
    assert clean_ip.reputation_score == 0.0
    assert clean_ip.is_malicious is False

    domain_provider = MockDomainReputationProvider()
    mal_dom = await domain_provider.lookup_domain("attacker-infra.com")
    assert mal_dom.status == ProviderStatus.SUCCESS
    assert mal_dom.reputation_score == 92.0
    assert mal_dom.is_malicious is True

    clean_dom = await domain_provider.lookup_domain("security-ops.com")
    assert clean_dom.status == ProviderStatus.SUCCESS
    assert clean_dom.reputation_score == 0.0
    assert clean_dom.is_malicious is False


@pytest.mark.asyncio
async def test_abuseipdb_success_response():
    """Verify AbuseIPDB adapter parses valid API JSON payload."""
    mock_payload = {
        "data": {
            "ipAddress": "198.51.100.200",
            "isPublic": True,
            "abuseConfidenceScore": 88,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Malicious Cloud LLC",
            "domain": "badcloud.net",
            "totalReports": 45,
            "isWhitelisted": False,
            "isTor": False,
        }
    }

    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=mock_payload))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = AbuseIPDBProvider(api_key="test-api-key", client=client)
        result = await provider.lookup_ip("198.51.100.200")

        assert result.status == ProviderStatus.SUCCESS
        assert result.reputation_score == 88.0
        assert result.is_malicious is True
        assert "data center/web hosting/transit" in result.threat_tags
        assert result.details["total_reports"] == 45


@pytest.mark.asyncio
async def test_abuseipdb_rate_limit_429():
    """Verify AbuseIPDB HTTP 429 produces RATE_LIMITED status with None score."""
    transport = httpx.MockTransport(lambda request: httpx.Response(429, text="Rate limit exceeded"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = AbuseIPDBProvider(api_key="test-api-key", client=client)
        result = await provider.lookup_ip("198.51.100.200")

        assert result.status == ProviderStatus.RATE_LIMITED
        assert result.reputation_score is None
        assert result.is_malicious is None


@pytest.mark.asyncio
async def test_abuseipdb_unavailable_503():
    """Verify server 503 error produces UNAVAILABLE status with None score."""
    transport = httpx.MockTransport(lambda request: httpx.Response(503, text="Service Unavailable"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = AbuseIPDBProvider(api_key="test-api-key", client=client)
        result = await provider.lookup_ip("198.51.100.200")

        assert result.status == ProviderStatus.UNAVAILABLE
        assert result.reputation_score is None
        assert result.is_malicious is None


@pytest.mark.asyncio
async def test_abuseipdb_timeout_handling():
    """Verify request timeout produces TIMEOUT status."""

    def _timeout_handler(request):
        raise httpx.ReadTimeout("Connection timed out")

    transport = httpx.MockTransport(_timeout_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = AbuseIPDBProvider(api_key="test-api-key", client=client)
        result = await provider.lookup_ip("198.51.100.200")

        assert result.status == ProviderStatus.TIMEOUT
        assert result.reputation_score is None
        assert result.is_malicious is None


@pytest.mark.asyncio
async def test_abuseipdb_missing_api_key():
    """Verify missing API key produces DISABLED status without throwing."""
    provider = AbuseIPDBProvider(api_key=None)
    result = await provider.lookup_ip("198.51.100.200")

    assert result.status == ProviderStatus.DISABLED
    assert result.reputation_score is None


@pytest.mark.asyncio
async def test_virustotal_success_response():
    """Verify VirusTotal adapter parses valid domain payload."""
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 3,
                    "harmless": 50,
                    "undetected": 5,
                },
                "reputation": -40,
                "registrar": "NameCheap",
                "tags": ["phishing", "malicious_host"],
            }
        }
    }

    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=mock_payload))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalDomainProvider(api_key="test-vt-key", client=client)
        result = await provider.lookup_domain("evil-phishing.org")

        assert result.status == ProviderStatus.SUCCESS
        assert result.reputation_score is not None
        assert result.reputation_score > 15.0
        assert result.is_malicious is True
        assert "phishing" in result.threat_tags


@pytest.mark.asyncio
async def test_virustotal_rate_limit_429():
    """Verify VirusTotal 429 produces RATE_LIMITED."""
    transport = httpx.MockTransport(lambda request: httpx.Response(429, text="Quota exceeded"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalDomainProvider(api_key="test-vt-key", client=client)
        result = await provider.lookup_domain("evil-phishing.org")

        assert result.status == ProviderStatus.RATE_LIMITED
        assert result.reputation_score is None


@pytest.mark.asyncio
async def test_virustotal_unavailable_503():
    """Verify VirusTotal 503 produces UNAVAILABLE."""
    transport = httpx.MockTransport(lambda request: httpx.Response(503, text="Service Down"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalDomainProvider(api_key="test-vt-key", client=client)
        result = await provider.lookup_domain("evil-phishing.org")

        assert result.status == ProviderStatus.UNAVAILABLE
        assert result.reputation_score is None


@pytest.mark.asyncio
async def test_virustotal_missing_api_key():
    """Verify VirusTotal missing key produces DISABLED."""
    provider = VirusTotalDomainProvider(api_key=None)
    result = await provider.lookup_domain("evil-phishing.org")

    assert result.status == ProviderStatus.DISABLED
    assert result.reputation_score is None


@pytest.mark.asyncio
async def test_threat_intel_service_caching_and_deduplication():
    """Verify repeat lookups for the same indicator are served from cache."""
    call_count = {"ip": 0}

    def _ip_handler(request):
        call_count["ip"] += 1
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 50, "totalReports": 1}})

    transport = httpx.MockTransport(_ip_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        ip_provider = AbuseIPDBProvider(api_key="test-key", client=client)
        service = ThreatIntelService(ip_provider=ip_provider)

        # First lookup
        r1 = await service.lookup_ip("198.51.100.25")
        assert r1.cached is False
        assert call_count["ip"] == 1

        # Second lookup (must hit cache)
        r2 = await service.lookup_ip("198.51.100.25")
        assert r2.cached is True
        assert call_count["ip"] == 1
        assert r2.reputation_score == r1.reputation_score
