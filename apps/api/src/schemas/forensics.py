from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RelayHopSchema(BaseModel):
    """Schema representing an MTA hop in the email relay path."""

    hop_number: int = Field(
        ..., description="Transmission hop sequence number (1 = earliest origin)"
    )
    from_host: str | None = Field(None, description="Sender hostname parsed from Received header")
    by_host: str | None = Field(None, description="Receiving MTA hostname")
    with_protocol: str | None = Field(
        None, description="Transmission protocol (e.g. ESMTP, ESMTPS)"
    )
    ip_address: str | None = Field(None, description="Extracted transmitting IP address")
    is_private_ip: bool = Field(False, description="Whether IP is RFC1918 internal/private")
    timestamp_raw: str | None = Field(None, description="Raw date string from header")
    timestamp_parsed: str | None = Field(None, description="ISO8601 parsed date")
    delay_seconds: float | None = Field(
        None, description="Transmission delay in seconds from preceding hop"
    )

    model_config = ConfigDict(from_attributes=True)


class AuthenticationResultSchema(BaseModel):
    """Schema for SPF, DKIM, and DMARC verification results."""

    spf_status: str = Field(
        ..., description="SPF verification result (pass, fail, softfail, neutral, none)"
    )
    spf_details: str | None = Field(None, description="SPF diagnostic details")
    dkim_status: str = Field(..., description="DKIM signature verification result")
    dkim_details: str | None = Field(None, description="DKIM diagnostic details")
    dmarc_status: str = Field(..., description="DMARC policy alignment result")
    dmarc_details: str | None = Field(None, description="DMARC diagnostic details")
    raw_auth_results: str | None = Field(
        None, description="Raw Authentication-Results header content"
    )

    model_config = ConfigDict(from_attributes=True)


class HeaderForensicsResponse(BaseModel):
    """Forensic email header analysis and spoofing assessment response."""

    id: str = Field(..., description="Unique header forensics assessment identifier")
    case_id: str = Field(..., description="Associated investigation Case ID")
    relay_hops: list[RelayHopSchema] = Field(
        default_factory=list, description="Chronological MTA hops"
    )
    origin_ip_candidates: list[str] = Field(
        default_factory=list,
        description="Candidate source IP addresses extracted from transmission chain",
    )
    probable_origin_ip: str | None = Field(
        None, description="First external/public MTA IP in transmission chain"
    )
    spf_status: str = Field(..., description="SPF verification status")
    dkim_status: str = Field(..., description="DKIM verification status")
    dmarc_status: str = Field(..., description="DMARC verification status")
    authentication_details: dict[str, Any] = Field(
        default_factory=dict, description="Consolidated authentication verification details"
    )
    spoofing_indicators: list[str] = Field(
        default_factory=list, description="Identified sender/domain spoofing anomalies"
    )
    anomalies: list[str] = Field(
        default_factory=list, description="Header formatting or hop anomalies"
    )
    forensics_risk_score: float = Field(
        ..., description="Normalized forensics risk score contribution (0.0 to 100.0)"
    )
    created_at: datetime = Field(..., description="Analysis timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "f1234567-89ab-cdef-0123-456789abcdef",
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "relay_hops": [
                    {
                        "hop_number": 1,
                        "from_host": "mail.attacker-relay.com",
                        "by_host": "mx.victim-corp.com",
                        "with_protocol": "ESMTPS",
                        "ip_address": "198.51.100.25",
                        "is_private_ip": False,
                        "timestamp_raw": "Sun, 23 Aug 2026 18:00:00 +0000",
                        "timestamp_parsed": "2026-08-23T18:00:00+00:00",
                        "delay_seconds": 0.0,
                    }
                ],
                "origin_ip_candidates": ["198.51.100.25"],
                "probable_origin_ip": "198.51.100.25",
                "spf_status": "fail",
                "dkim_status": "none",
                "dmarc_status": "fail",
                "authentication_details": {
                    "spf_status": "fail",
                    "dkim_status": "none",
                    "dmarc_status": "fail",
                },
                "spoofing_indicators": [
                    "Return-Path domain mismatch: Return-Path ('attacker.org') does not match From ('victim-corp.com').",
                    "SPF sender policy check FAILED (fail).",
                    "DMARC alignment policy check FAILED (fail).",
                ],
                "anomalies": [],
                "forensics_risk_score": 90.0,
                "created_at": "2026-08-23T06:00:00Z",
            }
        },
    )
