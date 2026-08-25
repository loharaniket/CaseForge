from pydantic import BaseModel

class IPIntelligenceData(BaseModel):
    ip_address: str | None = None
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

from datetime import datetime

class DomainIntelligenceData(BaseModel):
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
