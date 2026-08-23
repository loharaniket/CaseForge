from pydantic import BaseModel, ConfigDict, Field


class IOCRecordSchema(BaseModel):
    """Schema representing an individual normalized Indicator of Compromise."""

    id: str = Field(..., description="Unique IOC record identifier")
    case_id: str = Field(..., description="Associated case identifier")
    ioc_type: str = Field(..., description="IOC category (ipv4, ipv6, domain, url, email, sha256)")
    value: str = Field(..., description="Normalized indicator string value")
    source: str = Field(
        ..., description="Evidence origin (e.g. header.from, body.url, attachment.file)"
    )
    confidence: float = Field(1.0, description="Extraction confidence score (0.0 to 1.0)")
    context: str | None = Field(None, description="Diagnostic contextual metadata")

    model_config = ConfigDict(from_attributes=True)


class CaseIOCListResponse(BaseModel):
    """Response container for all extracted Indicators of Compromise for a case."""

    case_id: str = Field(..., description="Associated case identifier")
    total_count: int = Field(..., description="Total unique extracted IOC count")
    by_type: dict[str, int] = Field(default_factory=dict, description="IOC count breakdown by type")
    iocs: list[IOCRecordSchema] = Field(
        default_factory=list, description="List of normalized IOC records"
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "total_count": 4,
                "by_type": {
                    "ipv4": 1,
                    "domain": 1,
                    "url": 1,
                    "email": 1,
                },
                "iocs": [
                    {
                        "id": "ioc-1111-2222",
                        "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                        "ioc_type": "ipv4",
                        "value": "198.51.100.25",
                        "source": "header.received",
                        "confidence": 0.98,
                        "context": None,
                    },
                    {
                        "id": "ioc-3333-4444",
                        "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                        "ioc_type": "domain",
                        "value": "attacker-c2.net",
                        "source": "body.url_domain",
                        "confidence": 0.95,
                        "context": None,
                    },
                ],
            }
        },
    )
