from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class IOCType(StrEnum):
    """Normalized Indicator of Compromise (IOC) classification type."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    SHA256 = "sha256"


@dataclass
class IOCRecord:
    """Standardized Indicator of Compromise record."""

    value: str
    type: IOCType
    source: str
    confidence: float = 1.0
    context: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["type"] = self.type.value
        return data


@dataclass
class IOCExtractionResult:
    """Aggregated outcome of email IOC extraction and deduplication."""

    iocs: list[IOCRecord] = field(default_factory=list)
    total_count: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    unique_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_count": self.total_count,
            "by_type": self.by_type,
            "unique_types": self.unique_types,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
        }
