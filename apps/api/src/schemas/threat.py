from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatAssessmentResponse(BaseModel):
    """Explainable AI / heuristic threat classification response."""

    id: str = Field(..., description="Unique assessment identifier")
    case_id: str = Field(..., description="Associated investigation Case ID")
    classification: str = Field(
        ..., description="Multi-class threat category (normal, spam, phishing, BEC)"
    )
    confidence: float = Field(..., description="Deterministic confidence metric (0.0 to 1.0)")
    reasons: list[str] = Field(
        default_factory=list, description="Auditable list of forensic rationale and indicators"
    )
    model_version: str = Field(..., description="Threat detector model/rule-set version identifier")
    signals_detected: dict[str, Any] = Field(
        default_factory=dict,
        description="Categorized breakdown of matched forensic trigger signals",
    )
    created_at: datetime = Field(..., description="Assessment execution timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "7b8e1a2c-3d4e-5f6a-7b8c-9d0e1f2a3b4c",
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "classification": "phishing",
                "confidence": 0.94,
                "reasons": [
                    "Credential harvesting language detected: verify password, reset credentials",
                    "Account lockout/suspension threat detected: account will be suspended",
                    "Suspicious URL indicators present: Direct IP target in URL: http://198.51.100.99/auth",
                ],
                "model_version": "rule-based-heuristic-v1.0.0-dev",
                "signals_detected": {
                    "credentials": ["verify password"],
                    "suspension": ["account will be suspended"],
                },
                "created_at": "2026-08-23T04:30:00Z",
            }
        },
    )
