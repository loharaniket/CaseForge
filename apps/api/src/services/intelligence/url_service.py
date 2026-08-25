import ipaddress
import re
from typing import Any
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from src.services.intelligence.service import IntelligenceService
from src.services.intelligence.providers.virustotal_domain import VirusTotalDomainFoundationProvider
from src.services.intelligence.redirect_analyzer import SafeRedirectAnalyzer
from src.services.intelligence.dto import URLIntelligenceData
from src.services.intelligence.types import ProviderStatus
from src.models.url_intel import URLIntelligenceRecord
from src.services.intelligence.lookalike_detector import detect_lookalike
from src.services.ioc.types import IOCType

SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "adf.ly"
}

SUSPICIOUS_PATHS = [
    "login", "signin", "verify", "secure", "account", "update", "banking", "billing", "auth"
]

class AggregatedURLIntelligenceService:
    def __init__(self, intel_service: IntelligenceService | None = None):
        self.intel_service = intel_service or IntelligenceService()
        self.vt_provider = VirusTotalDomainFoundationProvider()
        
    async def get_url_intelligence(self, raw_url: str) -> URLIntelligenceData:
        data = URLIntelligenceData(raw_url=raw_url)
        
        try:
            parsed = urlparse(raw_url)
            data.scheme = parsed.scheme
            data.hostname = parsed.hostname
            data.path = parsed.path
            data.query = parsed.query
            data.fragment = parsed.fragment
            data.port = parsed.port
            
            if data.hostname:
                parts = data.hostname.split('.')
                if len(parts) > 2:
                    data.registrable_domain = f"{parts[-2]}.{parts[-1]}"
                    data.has_excessive_subdomains = len(parts) > 4
                else:
                    data.registrable_domain = data.hostname
                    
                # IP detection
                try:
                    ipaddress.ip_address(data.hostname)
                    data.is_raw_ip = True
                except ValueError:
                    pass
                
                # Shortener detection
                if data.registrable_domain and data.registrable_domain.lower() in SHORTENER_DOMAINS:
                    data.is_shortener = True
                elif data.hostname.lower() in SHORTENER_DOMAINS:
                    data.is_shortener = True
                    
                # Lookalike
                is_lookalike, target, explanation = detect_lookalike(data.hostname)
                data.is_lookalike = is_lookalike
                data.lookalike_target = target
                data.explanation = explanation
                
            # Path analysis
            if data.path:
                lower_path = data.path.lower()
                for sus in SUSPICIOUS_PATHS:
                    if sus in lower_path:
                        data.has_suspicious_path = True
                        data.has_credential_path = True
                        break
                        
            # Query analysis (e.g. email passed in URL)
            if data.query:
                lower_query = data.query.lower()
                if "%40" in lower_query or "@" in lower_query or "email=" in lower_query:
                    data.has_suspicious_query = True

            # Use VT provider for domain reputation of URL
            if data.hostname and not data.is_raw_ip:
                vt_res = await self.intel_service.execute_provider(self.vt_provider, self.vt_provider.lookup_domain, data.registrable_domain or data.hostname)
                if vt_res.status == ProviderStatus.AVAILABLE and vt_res.normalized_result:
                    data.reputation = vt_res.normalized_result.reputation
                    data.risk_score = vt_res.normalized_result.risk_score
                data.provider_status = vt_res.status.value
            else:
                data.provider_status = "SKIPPED"
                
        except Exception as e:
            data.explanation = f"URL parsing error: {str(e)}"
            
        return data

    async def analyze_case_url_intelligence(self, case_id: str, db: Session) -> list[URLIntelligenceRecord]:
        from src.services.ioc.service import IOCService
        
        ioc_service = IOCService()
        case_iocs = ioc_service.get_case_iocs(case_id=case_id, db=db)
        
        unique_urls = set()
        for ioc in case_iocs:
            if ioc.ioc_type == IOCType.URL:
                unique_urls.add(ioc.value)
                
        results = []
        for url in unique_urls:
            existing = db.query(URLIntelligenceRecord).filter(
                URLIntelligenceRecord.case_id == case_id,
                URLIntelligenceRecord.raw_url == url
            ).first()
            
            if existing:
                results.append(existing)
                continue
                
            data = await self.get_url_intelligence(url)
            try:
                redirects = await SafeRedirectAnalyzer.analyze(url)
                data.redirect_chain = redirects
            except Exception as e:
                data.redirect_chain = [{"original_url": url, "status": "ERROR", "error": str(e)}]
            
            record = URLIntelligenceRecord(
                case_id=case_id,
                raw_url=data.raw_url,
                scheme=data.scheme,
                hostname=data.hostname,
                registrable_domain=data.registrable_domain,
                path=data.path,
                query=data.query,
                fragment=data.fragment,
                port=data.port,
                is_raw_ip=data.is_raw_ip,
                is_shortener=data.is_shortener,
                has_excessive_subdomains=data.has_excessive_subdomains,
                has_suspicious_path=data.has_suspicious_path,
                has_credential_path=data.has_credential_path,
                is_punycode=data.is_punycode,
                has_homoglyphs=data.has_homoglyphs,
                is_lookalike=data.is_lookalike,
                has_suspicious_query=data.has_suspicious_query,
                has_mismatch_text=data.has_mismatch_text,
                lookalike_target=data.lookalike_target,
                explanation=data.explanation,
                reputation=data.reputation,
                risk_score=data.risk_score,
                provider_status=data.provider_status,
                redirect_chain=data.redirect_chain
            )
            db.add(record)
            results.append(record)
            
        db.commit()
        return results

    def get_case_url_intelligence(self, case_id: str, db: Session) -> list[URLIntelligenceRecord]:
        return db.query(URLIntelligenceRecord).filter(URLIntelligenceRecord.case_id == case_id).all()

def get_url_intel_service() -> AggregatedURLIntelligenceService:
    return AggregatedURLIntelligenceService()
