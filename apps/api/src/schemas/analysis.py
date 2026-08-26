from pydantic import BaseModel, Field


class AnalysisHistoryRecordSchema(BaseModel):
    """Schema representing an analysis event history record."""

    id: str = Field(description="Unique record UUID")
    case_id: str = Field(description="Associated investigation case UUID")
    analysis_timestamp: str = Field(description="ISO 8601 timestamp of analysis")
    parser_version: str | None = Field(default=None, description="Version of the parser used")
    detector_version: str | None = Field(default=None, description="Version of the detector used")
    intel_provider: str | None = Field(default=None, description="Name of intelligence provider")
    provider_lookup_timestamp: str | None = Field(default=None, description="ISO 8601 timestamp of provider lookup")
    result_status: str = Field(description="Result status of the analysis")


class CaseAnalysisHistoryResponse(BaseModel):
    """API response model for case analysis event history."""

    case_id: str
    total_records: int
    records: list[AnalysisHistoryRecordSchema]

class AnalysisStatusResponse(BaseModel):
    """API response model for near-real-time analysis status."""

    case_id: str
    analysis_status: str
    analysis_step: str
    error_message: str | None = None
