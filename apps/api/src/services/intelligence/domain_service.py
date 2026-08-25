import asyncio
from typing import Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from src.services.intelligence.service import IntelligenceService
from src.services.intelligence.providers.native_dns import NativeDNSFoundationProvider
from src.services.intelligence.providers.virustotal_domain import VirusTotalDomainFoundationProvider
from src.services.intelligence.dto import DomainIntelligenceData
from src.services.intelligence.types import ProviderStatus
from src.models.domain_intel import DomainIntelligenceRecord

class AggregatedDomainIntelligenceService:
    def __init__(self, intel_service: IntelligenceService | None = None):
        self.intel_service = intel_service or IntelligenceService()
        self.dns_provider = NativeDNSFoundationProvider()
        self.vt_provider = VirusTotalDomainFoundationProvider()
        
    async def get_domain_intelligence(self, domain: str) -> DomainIntelligenceData:
        # Launch DNS queries
        task_a = self.intel_service.execute_provider(self.dns_provider, self.dns_provider.lookup_dns, domain, "A")
        task_aaaa = self.intel_service.execute_provider(self.dns_provider, self.dns_provider.lookup_dns, domain, "AAAA")
        task_mx = self.intel_service.execute_provider(self.dns_provider, self.dns_provider.lookup_dns, domain, "MX")
        task_txt = self.intel_service.execute_provider(self.dns_provider, self.dns_provider.lookup_dns, domain, "TXT")
        task_ns = self.intel_service.execute_provider(self.dns_provider, self.dns_provider.lookup_dns, domain, "NS")
        
        # Launch Reputation/Metadata query
        task_vt = self.intel_service.execute_provider(self.vt_provider, self.vt_provider.lookup_domain, domain)
        
        res_a, res_aaaa, res_mx, res_txt, res_ns, res_vt = await asyncio.gather(
            task_a, task_aaaa, task_mx, task_txt, task_ns, task_vt
        )
        
        data = DomainIntelligenceData(domain=domain)
        
        if res_vt.status == ProviderStatus.AVAILABLE and res_vt.normalized_result:
            vt_data: DomainIntelligenceData = res_vt.normalized_result
            data.registrar = vt_data.registrar
            data.creation_date = vt_data.creation_date
            data.reputation = vt_data.reputation
            data.risk_score = vt_data.risk_score
            
        if res_a.status == ProviderStatus.AVAILABLE and res_a.normalized_result:
            data.a_records = res_a.normalized_result
        if res_aaaa.status == ProviderStatus.AVAILABLE and res_aaaa.normalized_result:
            data.aaaa_records = res_aaaa.normalized_result
        if res_mx.status == ProviderStatus.AVAILABLE and res_mx.normalized_result:
            data.mx_records = res_mx.normalized_result
        if res_ns.status == ProviderStatus.AVAILABLE and res_ns.normalized_result:
            data.nameservers = res_ns.normalized_result
        if res_txt.status == ProviderStatus.AVAILABLE and res_txt.normalized_result:
            data.txt_records = res_txt.normalized_result
            # Check for SPF/DMARC in TXT records
            for txt in data.txt_records:
                if txt.startswith("v=spf1"):
                    data.spf_record = txt
                elif txt.startswith("v=DMARC1"):
                    data.dmarc_record = txt
                    
        return data

    async def analyze_case_domain_intelligence(self, case_id: str, db: Session) -> list[DomainIntelligenceRecord]:
        from src.services.ioc.service import IOCService
        from src.services.ioc.types import IOCType
        
        ioc_service = IOCService()
        case_iocs = ioc_service.get_case_iocs(case_id=case_id, db=db)
        
        # Extract domains. (In future we could extract from URLs, but we stick to domain type IOCs or extract from URL iocs too)
        unique_domains = set()
        for ioc in case_iocs:
            if ioc.ioc_type == IOCType.DOMAIN:
                unique_domains.add(ioc.value.lower())
            elif ioc.ioc_type == IOCType.URL:
                try:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(ioc.value)
                    if parsed.netloc:
                        # naive host extraction, ignoring port
                        host = parsed.netloc.split(':')[0].lower()
                        # simple filter to ensure it's likely a domain and not an IP
                        import ipaddress
                        try:
                            ipaddress.ip_address(host)
                        except ValueError:
                            unique_domains.add(host)
                except Exception:
                    pass
                    
        # Also grab sender domain from case email
        from src.models.case import Case
        case = db.query(Case).filter(Case.id == case_id).first()
        if case and case.sender_domain:
            unique_domains.add(case.sender_domain.lower())
            
        valid_domains = [d for d in unique_domains if d and '.' in d]
        
        results = []
        for domain in valid_domains:
            existing = db.query(DomainIntelligenceRecord).filter(
                DomainIntelligenceRecord.case_id == case_id,
                DomainIntelligenceRecord.domain == domain
            ).first()
            
            if existing:
                results.append(existing)
                continue
                
            data = await self.get_domain_intelligence(domain)
            if data:
                record = DomainIntelligenceRecord(
                    case_id=case_id,
                    domain=domain,
                    registrar=data.registrar,
                    creation_date=data.creation_date,
                    expiration_date=data.expiration_date,
                    nameservers=data.nameservers,
                    a_records=data.a_records,
                    aaaa_records=data.aaaa_records,
                    mx_records=data.mx_records,
                    txt_records=data.txt_records,
                    spf_record=data.spf_record,
                    dmarc_record=data.dmarc_record,
                    reputation=data.reputation,
                    risk_score=data.risk_score
                )
                db.add(record)
                results.append(record)
                
        db.commit()
        return results

    def get_case_domain_intelligence(self, case_id: str, db: Session) -> list[DomainIntelligenceRecord]:
        return db.query(DomainIntelligenceRecord).filter(DomainIntelligenceRecord.case_id == case_id).all()

def get_domain_intel_service() -> AggregatedDomainIntelligenceService:
    return AggregatedDomainIntelligenceService()
