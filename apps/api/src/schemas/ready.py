from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from src.schemas.health import DatabaseStatus


class ReadyStatus(StrEnum):
    READY = "ready"
    NOT_READY = "not_ready"


class ReadyResponse(BaseModel):
    """Readiness probe response schema verifying critical dependencies."""

    status: ReadyStatus = Field(..., description="Readiness operational state")
    database: DatabaseStatus = Field(..., description="PostgreSQL database status")
    version: str = Field(..., description="Service version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of readiness probe",
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Diagnostic details on dependency readiness",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "ready",
                "database": "connected",
                "version": "0.1.0",
                "timestamp": "2026-08-23T00:00:00Z",
                "details": None,
            }
        }
    }
