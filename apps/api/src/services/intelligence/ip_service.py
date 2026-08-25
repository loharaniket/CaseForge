from src.models.ip_intel import IPIntelligenceRecord
import asyncio
import ipaddress
from typing import Any
from sqlalchemy.orm import Session

from src.services.intelligence.service import IntelligenceService
from src.services.intelligence.providers.abuseipdb import AbuseIPDBFoundationProvider
from src.services.intelligence.providers.maxmind import MaxMindFoundationProvider
from src.services.intelligence.dto import IPIntelligenceData
from src.services.intelligence.types import ProviderStatus


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]

def is_valid_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_unspecified:
            return False
        for net in RFC1918_NETWORKS:
            if ip_obj in net:
                return False
        return True
    except ValueError:
        return False

class AggregatedIPIntelligenceService:
    def __init__(self, intel_service: IntelligenceService | None = None):
        self.intel_service = intel_service or IntelligenceService()
        self.abuseipdb_provider = AbuseIPDBFoundationProvider()
        self.maxmind_provider = MaxMindFoundationProvider()
        
    async def get_ip_intelligence(self, ip: str) -> IPIntelligenceData | None:
        if not is_valid_public_ip(ip):
            return None
            
        abuse_task = self.intel_service.execute_provider(self.abuseipdb_provider, self.abuseipdb_provider.lookup_ip, ip)
        maxmind_task = self.intel_service.execute_provider(self.maxmind_provider, self.maxmind_provider.lookup_ip, ip)
        
        abuse_result, maxmind_result = await asyncio.gather(abuse_task, maxmind_task)
        
        data = IPIntelligenceData(ip_address=ip)
        
        # Merge MaxMind Data
        if maxmind_result.status == ProviderStatus.AVAILABLE and maxmind_result.normalized_result:
            mm: IPIntelligenceData = maxmind_result.normalized_result
            data.country = mm.country
            data.region = mm.region
            data.city = mm.city
            data.latitude = mm.latitude
            data.longitude = mm.longitude
            data.timezone = mm.timezone
            data.asn = mm.asn
            data.organization = mm.organization
            
        # Merge AbuseIPDB Data (takes precedence for shared fields like ISP/country)
        if abuse_result.status == ProviderStatus.AVAILABLE and abuse_result.normalized_result:
            ab: IPIntelligenceData = abuse_result.normalized_result
            if ab.country:
                data.country = ab.country
            data.isp = ab.isp
            if ab.organization:
                data.organization = ab.organization
            data.hosting_provider = ab.hosting_provider
            data.tor_indicator = ab.tor_indicator
            data.reputation = ab.reputation
            data.abuse_threat_score = ab.abuse_threat_score
            
        return data



    async def analyze_case_ip_intelligence(self, case_id: str, db: Session) -> list[IPIntelligenceRecord]:
        from src.services.ioc.service import IOCService
        from src.services.forensics.service import HeaderForensicsService
        from src.services.ioc.types import IOCType
        
        ioc_service = IOCService()
        forensics_service = HeaderForensicsService()
        
        # Get unique IPs
        case_iocs = ioc_service.get_case_iocs(case_id=case_id, db=db)
        unique_ips = set(ioc.value for ioc in case_iocs if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6))
        
        try:
            forensics = forensics_service.get_case_forensics(case_id=case_id, db=db)
            if forensics:
                if getattr(forensics, "probable_origin_ip", None):
                    unique_ips.add(str(forensics.probable_origin_ip))
                if getattr(forensics, "origin_ip_candidates", None):
                    for cand in forensics.origin_ip_candidates:
                        unique_ips.add(str(cand))
        except Exception:
            pass
            
        valid_ips = [ip for ip in unique_ips if ip and is_valid_public_ip(ip)]
        
        
        
        results = []
        for ip in valid_ips:
            existing = db.query(IPIntelligenceRecord).filter(
                IPIntelligenceRecord.case_id == case_id,
                IPIntelligenceRecord.ip_address == ip
            ).first()
            
            if existing:
                results.append(existing)
                continue
                
            data = await self.get_ip_intelligence(ip)
            if data:
                record = IPIntelligenceRecord(
                    case_id=case_id,
                    ip_address=ip,
                    country=data.country,
                    region=data.region,
                    city=data.city,
                    latitude=data.latitude,
                    longitude=data.longitude,
                    timezone=data.timezone,
                    asn=data.asn,
                    isp=data.isp,
                    organization=data.organization,
                    hosting_provider=data.hosting_provider,
                    proxy_vpn_indicator=data.proxy_vpn_indicator,
                    tor_indicator=data.tor_indicator,
                    reputation=data.reputation,
                    abuse_threat_score=data.abuse_threat_score
                )
                db.add(record)
                results.append(record)
                
        db.commit()
        return results
        
    def get_case_ip_intelligence(self, case_id: str, db: Session) -> list[IPIntelligenceRecord]:
        
        return db.query(IPIntelligenceRecord).filter(IPIntelligenceRecord.case_id == case_id).all()



def get_ip_intel_service() -> AggregatedIPIntelligenceService:
    return AggregatedIPIntelligenceService()
