from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Generic, TypeVar

T = TypeVar("T")

class ProviderStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_INPUT = "INVALID_INPUT"

@dataclass
class IntelligenceResult(Generic[T]):
    status: ProviderStatus
    provider_name: str
    lookup_timestamp: datetime
    normalized_result: T | None = None
    confidence: float | None = None
    error_information: str | None = None
