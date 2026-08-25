from datetime import datetime
from pydantic import BaseModel, ConfigDict

class DomainIntelligenceRecordSchema(BaseModel):
    domain: str
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    nameservers: list[str] = []
    a_records: list[str] = []
    aaaa_records: list[str] = []
    mx_records: list[str] = []
    txt_records: list[str] = []
    spf_record: str | None = None
    dmarc_record: str | None = None
    reputation: str | None = None
    risk_score: float | None = None
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)

class CaseDomainIntelligenceResponse(BaseModel):
    case_id: str
    domain_intelligence: list[DomainIntelligenceRecordSchema]
