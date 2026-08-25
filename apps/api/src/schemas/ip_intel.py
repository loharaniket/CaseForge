from datetime import datetime
from pydantic import BaseModel, ConfigDict

class IPIntelligenceRecordSchema(BaseModel):
    ip_address: str
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    asn: int | None = None
    isp: str | None = None
    organization: str | None = None
    hosting_provider: bool | None = None
    proxy_vpn_indicator: bool | None = None
    tor_indicator: bool | None = None
    reputation: str | None = None
    abuse_threat_score: float | None = None
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)

class CaseIPIntelligenceResponse(BaseModel):
    case_id: str
    ip_intelligence: list[IPIntelligenceRecordSchema]
