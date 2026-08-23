from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.services.geo.types import DISCLAIMER_TEXT


class GeoLocationResultSchema(BaseModel):
    """Schema for individual IP geolocation and infrastructure enrichment."""

    ip: str = Field(..., description="Target IP address")
    status: str = Field(
        ..., description="Lookup operational status (SUCCESS, PRIVATE_IP, UNAVAILABLE, etc.)"
    )
    is_private: bool = Field(
        False, description="Whether the IP is an unroutable RFC 1918 / loopback address"
    )
    probable_infrastructure_origin: str | None = Field(
        None, description="Probable network infrastructure geographic origin"
    )
    country_code: str | None = Field(None, description="ISO two-letter country code")
    country_name: str | None = Field(None, description="Full country name")
    region_name: str | None = Field(None, description="Subdivision or state/province name")
    city_name: str | None = Field(None, description="City name if resolved")
    postal_code: str | None = Field(None, description="Postal/ZIP code if resolved")
    latitude: float | None = Field(None, description="Latitude coordinate for map visualization")
    longitude: float | None = Field(None, description="Longitude coordinate for map visualization")
    asn_number: int | None = Field(None, description="Autonomous System Number (ASN)")
    asn_org: str | None = Field(None, description="Autonomous System Organization")
    isp: str | None = Field(None, description="Internet Service Provider")
    organization: str | None = Field(None, description="Operating organization name")
    is_hosting_provider: bool | None = Field(
        None, description="Whether IP belongs to a datacenter/cloud host"
    )
    data_quality: str = Field(
        ..., description="Qualitative resolution level without fabricated confidence"
    )
    disclaimer: str = Field(
        default=DISCLAIMER_TEXT, description="Mandatory legal and forensic attribution disclaimer"
    )
    provider_name: str = Field(..., description="Name of GeoIP database or provider")
    cached: bool = Field(False, description="Whether the result was served from cache")
    error_message: str | None = Field(None, description="Diagnostic error details if lookup failed")
    details: dict[str, Any] = Field(default_factory=dict, description="Provider metadata")

    model_config = ConfigDict(from_attributes=True)


class CaseGeoInfrastructureResponse(BaseModel):
    """Response container for case-wide IP infrastructure and geographic intelligence."""

    case_id: str = Field(..., description="Associated case identifier")
    provider_name: str = Field(..., description="Active GeoIP provider name")
    candidate_origin_ip: str | None = Field(
        None, description="Candidate external origin IP from relay analysis"
    )
    probable_infrastructure_origin: str | None = Field(
        None, description="Probable infrastructure origin for the email sender"
    )
    origin_country: str | None = Field(None, description="Probable origin infrastructure country")
    origin_country_code: str | None = Field(None, description="Probable origin country ISO code")
    origin_asn: int | None = Field(None, description="Origin Autonomous System Number")
    origin_isp: str | None = Field(None, description="Origin Internet Service Provider")
    disclaimer: str = Field(default=DISCLAIMER_TEXT, description="Mandatory forensic disclaimer")
    total_ips_analyzed: int = Field(..., description="Total count of unique IPs enriched")
    ip_infrastructure: list[GeoLocationResultSchema] = Field(
        default_factory=list, description="Detailed enrichment for all case IPs"
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "provider_name": "MockGeoIPProvider",
                "candidate_origin_ip": "198.51.100.200",
                "probable_infrastructure_origin": "Frankfurt am Main, Hessen, Germany",
                "origin_country": "Germany",
                "origin_country_code": "DE",
                "origin_asn": 24940,
                "origin_isp": "Hetzner Online",
                "disclaimer": DISCLAIMER_TEXT,
                "total_ips_analyzed": 2,
                "ip_infrastructure": [
                    {
                        "ip": "198.51.100.200",
                        "status": "SUCCESS",
                        "is_private": False,
                        "probable_infrastructure_origin": "Frankfurt am Main, Hessen, Germany",
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
                        "data_quality": "city_level",
                        "disclaimer": DISCLAIMER_TEXT,
                        "provider_name": "MockGeoIPProvider",
                        "cached": False,
                        "error_message": None,
                        "details": {"mock_matched": True},
                    }
                ],
            }
        },
    )
