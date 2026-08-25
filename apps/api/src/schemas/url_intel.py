from datetime import datetime
from pydantic import BaseModel, ConfigDict

class URLIntelligenceRecordSchema(BaseModel):
    id: str
    case_id: str
    raw_url: str
    scheme: str | None = None
    hostname: str | None = None
    registrable_domain: str | None = None
    path: str | None = None
    query: str | None = None
    fragment: str | None = None
    port: int | None = None
    
    is_raw_ip: bool
    is_shortener: bool
    has_excessive_subdomains: bool
    has_suspicious_path: bool
    has_credential_path: bool
    is_punycode: bool
    has_homoglyphs: bool
    is_lookalike: bool
    has_suspicious_query: bool
    has_mismatch_text: bool

    lookalike_target: str | None = None
    explanation: str | None = None
    
    reputation: str | None = None
    risk_score: float | None = None
    provider_status: str | None = None
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)

class CaseURLIntelligenceResponse(BaseModel):
    case_id: str
    url_intelligence: list[URLIntelligenceRecordSchema]
