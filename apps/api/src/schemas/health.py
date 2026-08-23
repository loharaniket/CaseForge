from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class DatabaseStatus(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    NOT_CONFIGURED = "not_configured"


class HealthResponse(BaseModel):
    """API health status response schema."""

    status: HealthStatus = Field(..., description="Overall service status")
    version: str = Field(..., description="Service semantic version")
    environment: str = Field(..., description="Application execution environment")
    database: DatabaseStatus = Field(..., description="Database connectivity status")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="UTC timestamp of the health check"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "healthy",
                "version": "0.1.0",
                "environment": "development",
                "database": "connected",
                "timestamp": "2026-08-23T00:00:00Z",
            }
        }
    }
