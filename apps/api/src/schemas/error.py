from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Standardized inner error object."""

    code: str = Field(..., description="Machine-readable error classification code")
    message: str = Field(..., description="Human-readable error description")
    details: Any = Field(None, description="Additional structured error metadata or field errors")


class ErrorResponse(BaseModel):
    """Standard top-level API error envelope."""

    error: ErrorDetail

    model_config = {
        "json_schema_extra": {
            "example": {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request validation failed.",
                    "details": [
                        {
                            "location": "body -> field_name",
                            "message": "Field required",
                            "type": "missing",
                        }
                    ],
                }
            }
        }
    }
