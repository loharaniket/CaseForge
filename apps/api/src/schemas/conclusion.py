from pydantic import BaseModel

class InvestigationConclusionResponse(BaseModel):
    """API response model for an investigation conclusion."""

    id: str
    case_id: str
    classification: str
    risk_score: float
    confidence: float
    primary_findings: list[str]
    supporting_evidence: list[str]
    probable_infrastructure: str
    attribution_assessment: str
    limitations: list[str]
