from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TimelineEventSchema(BaseModel):
    """Pydantic schema for a discrete forensic timeline milestone."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str = Field(..., description="Unique event identifier")
    event_type: str = Field(
        ..., description="Timeline milestone type (EMAIL_DATE, MTA_RELAY, AUTHENTICATION, etc.)"
    )
    title: str = Field(..., description="Human-readable event summary")
    description: str = Field(..., description="Detailed forensic context and metrics")
    source: str = Field(
        ..., description="Underlying telemetry source (e.g. header.received, system.ingestion)"
    )
    timestamp_iso: str | None = Field(None, description="ISO 8601 UTC timestamp if available")
    timestamp_raw: str | None = Field(
        None, description="Original unparsed timestamp string if present"
    )
    timestamp_quality: str = Field(
        ..., description="Quality/reliability grade (EXACT, HEADER_DECLARED, MISSING, etc.)"
    )
    delay_from_previous_seconds: float | None = Field(
        None, description="Elapsed seconds since preceding chronological event"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Metadata dictionary for event details"
    )


class ForensicTimelineResponse(BaseModel):
    """Pydantic response schema for case forensic timeline."""

    model_config = ConfigDict(from_attributes=True)

    case_id: str = Field(..., description="Target investigation case UUID")
    total_events: int = Field(..., description="Total count of chronological milestone events")
    earliest_timestamp: str | None = Field(
        None, description="Earliest recorded ISO timestamp in evidence"
    )
    latest_timestamp: str | None = Field(
        None, description="Latest recorded ISO timestamp in investigation"
    )
    has_missing_timestamps: bool = Field(
        False, description="Whether any events lacked parseable timestamps"
    )
    events: list[TimelineEventSchema] = Field(
        default_factory=list, description="Chronologically ordered milestone events"
    )
