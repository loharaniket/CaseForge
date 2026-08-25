import asyncio
from datetime import datetime, timezone
import pytest
from typing import Any

from src.services.intelligence import (
    BaseIntelligenceProvider,
    IPIntelligenceProvider,
    DomainIntelligenceProvider,
    ProviderStatus,
    IntelligenceResult,
    IntelligenceService,
)

class MockIPProvider(IPIntelligenceProvider):
    @property
    def name(self) -> str:
        return "MockIPProvider"

    async def lookup_ip(self, ip: str) -> IntelligenceResult[Any]:
        if ip == "invalid_ip":
            return IntelligenceResult(
                status=ProviderStatus.INVALID_INPUT,
                provider_name=self.name,
                lookup_timestamp=datetime.now(timezone.utc),
                error_information="Invalid IP format"
            )
        if ip == "unavailable":
            return IntelligenceResult(
                status=ProviderStatus.UNAVAILABLE,
                provider_name=self.name,
                lookup_timestamp=datetime.now(timezone.utc),
                error_information="Provider unavailable"
            )
        if ip == "malformed":
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=self.name,
                lookup_timestamp=datetime.now(timezone.utc),
                error_information="Malformed response from upstream"
            )
        if ip == "timeout":
            await asyncio.sleep(2.0)
            return IntelligenceResult(
                status=ProviderStatus.AVAILABLE,
                provider_name=self.name,
                lookup_timestamp=datetime.now(timezone.utc),
            )
        if ip == "error":
            raise ValueError("Unexpected crash")
            
        return IntelligenceResult(
            status=ProviderStatus.AVAILABLE,
            provider_name=self.name,
            lookup_timestamp=datetime.now(timezone.utc),
            normalized_result={"ip": ip, "reputation": "good"},
            confidence=0.99
        )

class MockDomainProvider(DomainIntelligenceProvider):
    @property
    def name(self) -> str:
        return "MockDomainProvider"

    async def lookup_domain(self, domain: str) -> IntelligenceResult[Any]:
        if domain == "missing.com":
            return IntelligenceResult(
                status=ProviderStatus.NOT_FOUND,
                provider_name=self.name,
                lookup_timestamp=datetime.now(timezone.utc),
            )
        return IntelligenceResult(
            status=ProviderStatus.AVAILABLE,
            provider_name=self.name,
            lookup_timestamp=datetime.now(timezone.utc),
            normalized_result={"domain": domain}
        )

@pytest.mark.asyncio
async def test_successful_provider_result():
    service = IntelligenceService(timeout_seconds=1.0)
    provider = MockIPProvider()
    result = await service.execute_provider(provider, provider.lookup_ip, "1.1.1.1")
    
    assert result.status == ProviderStatus.AVAILABLE
    assert result.provider_name == "MockIPProvider"
    assert result.normalized_result["ip"] == "1.1.1.1"
    assert result.confidence == 0.99
    assert result.lookup_timestamp is not None

@pytest.mark.asyncio
async def test_provider_timeout():
    # Service timeout is 0.5s, provider sleeps for 2.0s
    service = IntelligenceService(timeout_seconds=0.5)
    provider = MockIPProvider()
    result = await service.execute_provider(provider, provider.lookup_ip, "timeout")
    
    assert result.status == ProviderStatus.TIMEOUT
    assert "timed out" in result.error_information

@pytest.mark.asyncio
async def test_provider_error():
    service = IntelligenceService(timeout_seconds=1.0)
    provider = MockIPProvider()
    result = await service.execute_provider(provider, provider.lookup_ip, "error")
    
    # The service layer must catch the ValueError and wrap it safely
    assert result.status == ProviderStatus.PROVIDER_ERROR
    assert "Unexpected crash" in result.error_information

@pytest.mark.asyncio
async def test_invalid_ip():
    service = IntelligenceService(timeout_seconds=1.0)
    provider = MockIPProvider()
    result = await service.execute_provider(provider, provider.lookup_ip, "invalid_ip")
    
    assert result.status == ProviderStatus.INVALID_INPUT

@pytest.mark.asyncio
async def test_missing_domain():
    service = IntelligenceService(timeout_seconds=1.0)
    provider = MockDomainProvider()
    result = await service.execute_provider(provider, provider.lookup_domain, "missing.com")
    
    assert result.status == ProviderStatus.NOT_FOUND

@pytest.mark.asyncio
async def test_provider_unavailable():
    service = IntelligenceService(timeout_seconds=1.0)
    provider = MockIPProvider()
    result = await service.execute_provider(provider, provider.lookup_ip, "unavailable")
    
    assert result.status == ProviderStatus.UNAVAILABLE

@pytest.mark.asyncio
async def test_malformed_provider_result():
    service = IntelligenceService(timeout_seconds=1.0)
    provider = MockIPProvider()
    result = await service.execute_provider(provider, provider.lookup_ip, "malformed")
    
    assert result.status == ProviderStatus.PROVIDER_ERROR
