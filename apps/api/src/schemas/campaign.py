from datetime import datetime
from pydantic import BaseModel, Field

class CampaignInvestigationLinkResponse(BaseModel):
    case_id: str
    correlation_score: float
    matched_on: list[str]
    
    class Config:
        from_attributes = True

class CampaignResponse(BaseModel):
    campaign_id: str
    related_investigations: list[str]
    shared_indicators: dict[str, list[str]]
    shared_infrastructure: dict[str, list[str]]
    first_seen: datetime
    last_seen: datetime
    confidence: float
    
    class Config:
        from_attributes = True
