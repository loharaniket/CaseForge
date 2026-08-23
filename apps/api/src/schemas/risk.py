from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskBreakdownSchema(BaseModel):
    """Normalized sub-scores across weighted threat intelligence dimensions."""

    ai: float = Field(..., description="AI threat detection risk component (0-100)")
    header_forensics: float = Field(
        ..., description="Email header / SPF / DKIM / DMARC risk component (0-100)"
    )
    domain_reputation: float = Field(..., description="Domain reputation risk component (0-100)")
    ip_reputation: float = Field(..., description="IP reputation risk component (0-100)")
    url_analysis: float = Field(..., description="URL / Link analysis risk component (0-100)")

    model_config = ConfigDict(from_attributes=True)


class RiskAssessmentResponse(BaseModel):
    """Deterministic cybersecurity risk calculation and severity scoring payload."""

    id: str = Field(..., description="Unique risk assessment identifier")
    case_id: str = Field(..., description="Associated investigation Case ID")
    total_score: float = Field(
        ..., description="Final deterministic weighted risk score (0.0 to 100.0)"
    )
    severity: str = Field(..., description="Severity classification (LOW, MEDIUM, HIGH, CRITICAL)")
    breakdown: RiskBreakdownSchema = Field(..., description="Itemized score breakdown")
    weights_applied: dict[str, float] = Field(
        ..., description="Immutable MVP formula weights distribution"
    )
    missing_components: list[str] = Field(
        default_factory=list, description="Components pending evaluation"
    )
    created_at: datetime = Field(..., description="Assessment calculation timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "e891234a-9b12-4c5d-8e7f-1234567890ab",
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "total_score": 82.5,
                "severity": "CRITICAL",
                "breakdown": {
                    "ai": 95.0,
                    "header_forensics": 80.0,
                    "domain_reputation": 70.0,
                    "ip_reputation": 65.0,
                    "url_analysis": 85.0,
                },
                "weights_applied": {
                    "ai_analysis": 0.40,
                    "header_forensics": 0.25,
                    "domain_reputation": 0.15,
                    "ip_reputation": 0.10,
                    "url_analysis": 0.10,
                },
                "missing_components": [],
                "created_at": "2026-08-23T05:00:00Z",
            }
        },
    )
