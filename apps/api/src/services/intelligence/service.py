import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, TypeVar

from src.core.config import settings
from src.core.logging import logger

from .interfaces import BaseIntelligenceProvider
from .types import IntelligenceResult, ProviderStatus

T = TypeVar("T")

class IntelligenceService:
    """Service layer for safely querying intelligence providers."""

    def __init__(self, timeout_seconds: float | None = None):
        self.timeout_seconds = timeout_seconds or settings.PROVIDER_TIMEOUT_SECONDS

    async def execute_provider(
        self,
        provider: BaseIntelligenceProvider,
        func: Callable[..., Awaitable[IntelligenceResult[T]]],
        *args: Any,
        **kwargs: Any,
    ) -> IntelligenceResult[T]:
        """
        Executes a provider method safely with timeouts, structured logging,
        and fallback error handling.
        """
        start_time = datetime.now(UTC)
        logger.info(f"Executing {provider.name} provider for intelligence lookup.")

        try:
            result = await asyncio.wait_for(
                func(*args, **kwargs),
                timeout=self.timeout_seconds
            )
            return result
        except TimeoutError:
            logger.error(f"Provider {provider.name} timed out after {self.timeout_seconds}s")
            return IntelligenceResult(
                status=ProviderStatus.TIMEOUT,
                provider_name=provider.name,
                lookup_timestamp=start_time,
                error_information=f"Provider timed out after {self.timeout_seconds} seconds"
            )
        except Exception as e:
            logger.exception(f"Provider {provider.name} failed with unhandled error: {str(e)}")
            return IntelligenceResult(
                status=ProviderStatus.PROVIDER_ERROR,
                provider_name=provider.name,
                lookup_timestamp=start_time,
                error_information=str(e)
            )
