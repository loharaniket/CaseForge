import logging
from datetime import datetime
from typing import Any
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.case import Case, CaseStatus
from src.models.campaign import Campaign, CampaignInvestigationLink
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.ioc import CaseIOC
from src.services.ioc.types import IOCType
from src.models.domain_intel import DomainIntelligenceRecord
from src.models.ip_intel import IPIntelligenceRecord
from src.models.url_intel import URLIntelligenceRecord

logger = logging.getLogger("threattrace")

COMMON_DOMAINS = {
    "gmail.com", "google.com", "yahoo.com", "hotmail.com", "outlook.com", 
    "microsoft.com", "aol.com", "protonmail.com", "icloud.com", "mail.com", "amazon.com"
}

COMMON_ORGS = {
    "google llc", "microsoft corporation", "cloudflare, inc.", "amazon.com",
    "amazon data services", "fastly", "akamai"
}

CORRELATION_THRESHOLD = 60.0

class CampaignCorrelationService:
    def __init__(self):
        pass

    def extract_case_indicators(self, case_id: str, db: Session) -> dict[str, set[str]]:
        indicators = defaultdict(set)
        
        parsed = db.execute(select(ParsedEmail).where(ParsedEmail.case_id == case_id)).scalar_one_or_none()
        if parsed:
            if parsed.from_address:
                email = parsed.from_address.strip().lower()
                if email:
                    indicators["email"].add(email)
                    domain = email.split("@")[-1] if "@" in email else ""
                    if domain and domain not in COMMON_DOMAINS:
                        indicators["domain"].add(domain)
                        
            if parsed.reply_to:
                for rt in parsed.reply_to:
                    email = rt.strip().lower()
                    if email:
                        indicators["email"].add(email)
                        domain = email.split("@")[-1] if "@" in email else ""
                        if domain and domain not in COMMON_DOMAINS:
                            indicators["domain"].add(domain)

        urls = db.execute(select(URLIntelligenceRecord).where(URLIntelligenceRecord.case_id == case_id)).scalars().all()
        for u in urls:
            indicators["url"].add(u.raw_url)
            if u.hostname and u.hostname.lower() not in COMMON_DOMAINS:
                indicators["domain"].add(u.hostname.lower())

        domains = db.execute(select(DomainIntelligenceRecord).where(DomainIntelligenceRecord.case_id == case_id)).scalars().all()
        for d in domains:
            if d.domain.lower() not in COMMON_DOMAINS:
                indicators["domain"].add(d.domain.lower())

        ips = db.execute(select(IPIntelligenceRecord).where(IPIntelligenceRecord.case_id == case_id)).scalars().all()
        for ip in ips:
            indicators["ip"].add(ip.ip_address)
            if ip.asn:
                indicators["asn"].add(str(ip.asn))
            if ip.organization:
                org = ip.organization.lower()
                if not any(co in org for co in COMMON_ORGS):
                    indicators["org"].add(org)

        iocs = db.execute(select(CaseIOC).where(CaseIOC.case_id == case_id)).scalars().all()
        for ioc in iocs:
            val = ioc.value.lower()
            if ioc.ioc_type in (IOCType.IPV4.value, IOCType.IPV6.value):
                indicators["ip"].add(val)
            elif ioc.ioc_type == IOCType.DOMAIN.value and val not in COMMON_DOMAINS:
                indicators["domain"].add(val)
            elif ioc.ioc_type == IOCType.URL.value:
                indicators["url"].add(val)
            else:
                indicators["ioc"].add(val)

        return dict(indicators)

    def correlate_case(self, case_id: str, db: Session):
        """Correlate a case and link it to campaigns if threshold met."""
        indicators = self.extract_case_indicators(case_id, db)
        if not indicators:
            return

        matched_cases = defaultdict(lambda: {"score": 0.0, "matches": set()})

        def add_match(c_id: str, score: float, match_str: str):
            if c_id != case_id:
                matched_cases[c_id]["score"] += score
                matched_cases[c_id]["matches"].add(match_str)

        if indicators.get("url"):
            rows = db.execute(select(URLIntelligenceRecord.case_id, URLIntelligenceRecord.raw_url).where(URLIntelligenceRecord.raw_url.in_(indicators["url"]))).all()
            for r in rows:
                add_match(r.case_id, 100, f"url:{r.raw_url}")

        if indicators.get("domain"):
            doms = db.execute(select(DomainIntelligenceRecord.case_id, DomainIntelligenceRecord.domain).where(DomainIntelligenceRecord.domain.in_(indicators["domain"]))).all()
            for r in doms:
                add_match(r.case_id, 80, f"domain:{r.domain.lower()}")
                
            # ParsedEmail domains requires filtering in Python for simplicity, but we can just use ends_with
            # Or we can just skip sender domains in query since they are also often extracted as IOCs or DomainIntel
            pass

        if indicators.get("ip"):
            ips = db.execute(select(IPIntelligenceRecord.case_id, IPIntelligenceRecord.ip_address).where(IPIntelligenceRecord.ip_address.in_(indicators["ip"]))).all()
            for r in ips:
                add_match(r.case_id, 80, f"ip:{r.ip_address}")

        if indicators.get("email"):
            emails = db.execute(select(ParsedEmail.case_id, ParsedEmail.from_address).where(ParsedEmail.from_address.in_(indicators["email"]))).all()
            for r in emails:
                if r.from_address:
                    add_match(r.case_id, 100, f"email:{r.from_address.lower()}")
                    
        if indicators.get("ioc"):
            iocs = db.execute(select(CaseIOC.case_id, CaseIOC.value).where(CaseIOC.value.in_(indicators["ioc"]))).all()
            for r in iocs:
                add_match(r.case_id, 100, f"ioc:{r.value.lower()}")

        if indicators.get("asn"):
            asn_ints = [int(a) for a in indicators["asn"] if a.isdigit()]
            if asn_ints:
                ips = db.execute(select(IPIntelligenceRecord.case_id, IPIntelligenceRecord.asn).where(IPIntelligenceRecord.asn.in_(asn_ints))).all()
                for r in ips:
                    add_match(r.case_id, 20, f"asn:{r.asn}")
                
        if indicators.get("org"):
            # Like query or just fetch all since DB might not be too big in MVP
            ips = db.execute(select(IPIntelligenceRecord.case_id, IPIntelligenceRecord.organization)).all()
            for r in ips:
                if r.organization and r.organization.lower() in indicators["org"]:
                    add_match(r.case_id, 20, f"org:{r.organization.lower()}")

        for match_case_id, data in matched_cases.items():
            if data["score"] >= CORRELATION_THRESHOLD:
                self._link_to_campaign(case_id, match_case_id, data["score"], list(data["matches"]), db)

    def _link_to_campaign(self, case_id: str, match_case_id: str, score: float, matches: list[str], db: Session):
        existing_link = db.execute(select(CampaignInvestigationLink).where(CampaignInvestigationLink.case_id == match_case_id)).scalars().first()
        
        if existing_link:
            campaign = existing_link.campaign
        else:
            campaign = Campaign()
            db.add(campaign)
            db.flush()
            
            link1 = CampaignInvestigationLink(
                campaign_id=campaign.id,
                case_id=match_case_id,
                correlation_score=score,
                matched_on=matches
            )
            db.add(link1)
            
        current_link = db.execute(select(CampaignInvestigationLink).where(CampaignInvestigationLink.case_id == case_id, CampaignInvestigationLink.campaign_id == campaign.id)).scalars().first()
        
        if not current_link:
            link2 = CampaignInvestigationLink(
                campaign_id=campaign.id,
                case_id=case_id,
                correlation_score=score,
                matched_on=matches
            )
            db.add(link2)
            
            campaign.last_seen = datetime.utcnow()
            
            # Since SQLAlchemy tracks JSON as a whole, we must copy it
            new_indicators = dict(campaign.shared_indicators) if campaign.shared_indicators else {}
            new_infra = dict(campaign.shared_infrastructure) if campaign.shared_infrastructure else {}
            
            for m in matches:
                parts = m.split(":", 1)
                if len(parts) == 2:
                    k, v = parts
                    if k in ["url", "domain", "email", "ip", "ioc"]:
                        if k not in new_indicators:
                            new_indicators[k] = []
                        if v not in new_indicators[k]:
                            new_indicators[k].append(v)
                    elif k in ["asn", "org"]:
                        if k not in new_infra:
                            new_infra[k] = []
                        if v not in new_infra[k]:
                            new_infra[k].append(v)
                            
            campaign.shared_indicators = new_indicators
            campaign.shared_infrastructure = new_infra
                            
            if score > campaign.confidence:
                # Cap at 100
                campaign.confidence = min(score, 100.0)
                
        db.commit()

default_campaign_service = CampaignCorrelationService()

def get_campaign_service() -> CampaignCorrelationService:
    return default_campaign_service
