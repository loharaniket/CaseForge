import pytest
from src.services.intelligence.providers.native_dns import NativeDNSFoundationProvider
import dns.resolver

@pytest.mark.asyncio
async def test_native_dns_provider():
    provider = NativeDNSFoundationProvider(timeout_seconds=2.0)
    # Testing a known domain like example.com
    result = await provider.lookup_dns("example.com", "A")
    assert result.status.value == "AVAILABLE"
    assert result.normalized_result is not None
    assert len(result.normalized_result) > 0
    
    # Test nonexistent domain
    result = await provider.lookup_dns("invalid.nonexistent.threattrace.io", "A")
    assert result.status.value == "AVAILABLE"
    assert result.normalized_result == []
