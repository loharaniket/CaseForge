from sqlalchemy import text
import pytest
from sqlalchemy.orm import Session
from datetime import datetime

from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.campaign import Campaign, CampaignInvestigationLink
from src.models.url_intel import URLIntelligenceRecord
from src.models.ip_intel import IPIntelligenceRecord
from src.models.domain_intel import DomainIntelligenceRecord
from src.models.ioc import CaseIOC
from src.services.ioc.types import IOCType
from src.services.campaign.service import CampaignCorrelationService

def setup_case(db: Session, user_id: int, case_id: str, email: str = "test@example.com", ip: str = None, url: str = None, domain: str = None):
    c = Case(id=case_id, user_id=user_id, file_name="f.eml", file_size_bytes=10, sha256_hash=case_id, storage_key="a", status=CaseStatus.PARSED)
    db.add(c)
    
    p = ParsedEmail(case_id=case_id, sender=email, from_address=email, from_name="A", subject="B", recipients=["victim@test.com"], raw_headers={}, attachments_metadata=[])
    db.add(p)
    
    if ip:
        db.add(IPIntelligenceRecord(case_id=case_id, ip_address=ip))
    if url:
        db.add(URLIntelligenceRecord(case_id=case_id, raw_url=url, hostname=url.split("/")[2] if "//" in url else ""))
    if domain:
        db.add(DomainIntelligenceRecord(case_id=case_id, domain=domain))
        
    db.commit()

@pytest.fixture
def test_user(db_session: Session):
    from src.models.user import User, UserRole
    from src.core.security import hash_password
    user = User(email="t@t.com", hashed_password=hash_password("A"), full_name="A", role=UserRole.ANALYST, is_active=True)
    db_session.add(user)
    db_session.commit()
    return user

def test_same_malicious_domain(db_session: Session, test_user):
    setup_case(db_session, test_user.id, "c1", email="bad@evil.com", domain="evil.com")
    setup_case(db_session, test_user.id, "c2", email="worse@evil.com", domain="evil.com")
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c1", db_session)
    srv.correlate_case("c2", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c2'")).fetchall()
    assert len(links) == 1
    assert links[0].correlation_score >= 80

def test_same_malicious_ip(db_session: Session, test_user):
    setup_case(db_session, test_user.id, "c3", ip="1.2.3.4")
    setup_case(db_session, test_user.id, "c4", ip="1.2.3.4")
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c3", db_session)
    srv.correlate_case("c4", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c4'")).fetchall()
    assert len(links) == 1

def test_same_url(db_session: Session, test_user):
    setup_case(db_session, test_user.id, "c5", url="http://bad.com/login")
    setup_case(db_session, test_user.id, "c6", url="http://bad.com/login")
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c5", db_session)
    srv.correlate_case("c6", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c6'")).fetchall()
    assert len(links) == 1
    
def test_unrelated_emails(db_session: Session, test_user):
    setup_case(db_session, test_user.id, "c7", email="a@a.com", ip="1.1.1.1")
    setup_case(db_session, test_user.id, "c8", email="b@b.com", ip="2.2.2.2")
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c7", db_session)
    srv.correlate_case("c8", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c8'")).fetchall()
    assert len(links) == 0

def test_common_provider_domains(db_session: Session, test_user):
    setup_case(db_session, test_user.id, "c9", email="a@gmail.com", domain="gmail.com")
    setup_case(db_session, test_user.id, "c10", email="b@gmail.com", domain="gmail.com")
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c9", db_session)
    srv.correlate_case("c10", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c10'")).fetchall()
    assert len(links) == 0

def test_weak_correlation(db_session: Session, test_user):
    # Only shared ASN = +20, Org = +20, total 40 < 60 threshold
    setup_case(db_session, test_user.id, "c11", email="a@diff.com")
    setup_case(db_session, test_user.id, "c12", email="b@diff2.com")
    
    # Manually add ASN and Org
    db_session.add(IPIntelligenceRecord(case_id="c11", ip_address="3.3.3.3", asn=123, organization="small co"))
    db_session.add(IPIntelligenceRecord(case_id="c12", ip_address="4.4.4.4", asn=123, organization="small co"))
    db_session.commit()
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c11", db_session)
    srv.correlate_case("c12", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c12'")).fetchall()
    assert len(links) == 0

def test_strong_correlation(db_session: Session, test_user):
    # Shared ASN, Org, Domain, URL, IP
    setup_case(db_session, test_user.id, "c13", ip="5.5.5.5", url="http://bad.com/a", domain="bad.com")
    setup_case(db_session, test_user.id, "c14", ip="5.5.5.5", url="http://bad.com/a", domain="bad.com")
    
    srv = CampaignCorrelationService()
    srv.correlate_case("c13", db_session)
    srv.correlate_case("c14", db_session)
    
    links = db_session.execute(text("SELECT * FROM campaign_investigations WHERE case_id='c14'")).fetchall()
    assert len(links) == 1
    assert links[0].correlation_score >= 100
