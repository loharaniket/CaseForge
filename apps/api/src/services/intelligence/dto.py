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

class URLIntelligenceData(BaseModel):
    raw_url: str
    scheme: str | None = None
    hostname: str | None = None
    registrable_domain: str | None = None
    path: str | None = None
    query: str | None = None
    fragment: str | None = None
    port: int | None = None

    is_raw_ip: bool = False
    is_shortener: bool = False
    has_excessive_subdomains: bool = False
    has_suspicious_path: bool = False
    has_credential_path: bool = False
    is_punycode: bool = False
    has_homoglyphs: bool = False
    is_lookalike: bool = False
    has_suspicious_query: bool = False
    has_mismatch_text: bool = False

    lookalike_target: str | None = None
    explanation: str | None = None
    reputation: str | None = None
    risk_score: float | None = None
    provider_status: str | None = None
