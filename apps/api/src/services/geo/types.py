from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

DISCLAIMER_TEXT = (
    "Geolocation describes network infrastructure and does not establish the "
    "physical location or identity of an attacker."
)


class GeoLookupStatus(StrEnum):
    """Operational status of a GeoIP infrastructure lookup."""

    SUCCESS = "SUCCESS"
    PRIVATE_IP = "PRIVATE_IP"
    NOT_FOUND = "NOT_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_IP = "INVALID_IP"
    ERROR = "ERROR"


class DataQuality(StrEnum):
    """Qualitative assessment of geolocation data resolution without fabricating confidence."""

    CITY_LEVEL = "city_level"
    COUNTRY_LEVEL = "country_level"
    ASN_ONLY = "asn_only"
    PRIVATE_NETWORK = "private_network"
    UNAVAILABLE = "unavailable"


@dataclass
class GeoLocationResult:
    """Enriched network infrastructure and probable origin details for an IP."""

    ip: str
    status: GeoLookupStatus
    is_private: bool = False
    probable_infrastructure_origin: str | None = None  # e.g., "Frankfurt, Hessen, Germany"
    country_code: str | None = None
    country_name: str | None = None
    region_name: str | None = None
    city_name: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn_number: int | None = None
    asn_org: str | None = None
    isp: str | None = None
    organization: str | None = None
    is_hosting_provider: bool | None = None
    data_quality: DataQuality = DataQuality.UNAVAILABLE
    disclaimer: str = DISCLAIMER_TEXT
    provider_name: str = "Unknown"
    cached: bool = False
    error_message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["data_quality"] = self.data_quality.value
        return data


class GeoIPProvider(ABC):
    """Abstract interface for GeoIP and network infrastructure intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name identifier of the provider."""
        ...

    @abstractmethod
    def lookup(self, ip: str) -> GeoLocationResult:
        """Enriches an IP with network infrastructure information."""
        ...
