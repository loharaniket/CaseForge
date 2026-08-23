from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EmailUploadResponse(BaseModel):
    """Secure email ingestion response payload."""

    case_id: str = Field(..., description="Unique investigation case identifier (UUID)")
    status: str = Field(default="received", description="Current status of the investigation case")
    file_name: str = Field(..., description="Original evidence file name (sanitized)")
    file_size_bytes: int = Field(..., description="Size of evidence in bytes")
    sha256: str = Field(..., description="Cryptographic SHA-256 evidence hash")
    created_at: datetime = Field(..., description="Evidence ingestion timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "status": "received",
                "file_name": "suspicious_invoice.eml",
                "file_size_bytes": 14250,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "created_at": "2026-08-23T02:00:00Z",
            }
        },
    )
