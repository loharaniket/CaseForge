import sys
f = 'apps/api/src/services/intelligence/dto.py'
with open(f, 'a') as file:
    file.write('''
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
''')
