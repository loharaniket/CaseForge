from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.ioc import CaseIOC
from src.models.user import User, UserRole
from src.services.graph.repository import (
    InMemoryThreatGraphRepository,
    Neo4jThreatGraphRepository,
)
from src.services.graph.service import ThreatGraphService
from src.services.graph.types import (
    GraphNodeType,
    GraphRelationshipType,
)
from src.services.ioc.types import IOCType
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def test_user(db_session: Session) -> User:
    user = User(
        email="graph.analyst@threattrace.io",
        hashed_password=hash_password("Pass123!"),
        full_name="Graph Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def populated_case(db_session: Session, test_user: User, tmp_path: Path) -> Case:
    storage = LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))
    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "phishing_graph.eml")

    case = Case(
        user_id=test_user.id,
        file_name="phishing_graph.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.PARSED,
    )
    db_session.add(case)
    db_session.commit()

    # Parsed Email
    parsed = ParsedEmail(
        case_id=case.id,
        sender="attacker@evil-corp-update.com",
        from_address="attacker@evil-corp-update.com",
        from_name="Security Alert",
        subject="Urgent: Account Verification Required",
        recipients=["victim@target-corp.com"],
        raw_headers={},
        attachments_metadata=[
            {
                "filename": "payload.exe",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size_bytes": 4096,
                "content_type": "application/octet-stream",
            }
        ],
    )
    db_session.add(parsed)

    # IOCs
    ioc1 = CaseIOC(
        case_id=case.id, ioc_type=IOCType.DOMAIN, value="evil-corp-update.com", source="body"
    )
    ioc2 = CaseIOC(
        case_id=case.id, ioc_type=IOCType.DOMAIN, value="malicious-login-portal.net", source="link"
    )
    ioc3 = CaseIOC(case_id=case.id, ioc_type=IOCType.IPV4, value="185.220.101.5", source="relay")
    ioc4 = CaseIOC(
        case_id=case.id,
        ioc_type=IOCType.SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source="attachment",
    )
    db_session.add_all([ioc1, ioc2, ioc3, ioc4])

    # Forensics
    forensics = HeaderForensics(
        case_id=case.id,
        probable_origin_ip="185.220.101.5",
        origin_ip_candidates=["185.220.101.5"],
        spf_status="fail",
        dkim_status="fail",
        dmarc_status="fail",
        forensics_risk_score=80.0,
    )
    db_session.add(forensics)
    db_session.commit()

    return case


def test_graph_creation_full_schema(db_session: Session, populated_case: Case):
    """Test: Graph correctly creates all 6 node types and 5 relationship types."""
    repo = InMemoryThreatGraphRepository()
    geoip_mock = MagicMock()
    geoip_mock.analyze_case_infrastructure.return_value = {
        "candidate_origin_ip": "185.220.101.5",
        "ip_infrastructure": [
            {
                "ip": "185.220.101.5",
                "country_name": "Germany",
                "country_code": "DE",
            }
        ],
    }

    service = ThreatGraphService(repository=repo, geoip_service=geoip_mock)
    result = service.build_case_graph(populated_case.id, db_session)

    assert result.status == "available"
    assert result.total_nodes > 0
    assert result.total_relationships > 0

    node_types = {n.type for n in result.nodes}
    assert GraphNodeType.EMAIL in node_types
    assert GraphNodeType.EMAIL_ADDRESS in node_types
    assert GraphNodeType.DOMAIN in node_types
    assert GraphNodeType.IP in node_types
    assert GraphNodeType.COUNTRY in node_types
    assert GraphNodeType.ATTACHMENT_HASH in node_types

    rel_types = {r.type for r in result.relationships}
    assert GraphRelationshipType.SENT_FROM in rel_types
    assert GraphRelationshipType.USES_DOMAIN in rel_types
    assert GraphRelationshipType.RESOLVES_TO in rel_types
    assert GraphRelationshipType.LOCATED_IN in rel_types
    assert GraphRelationshipType.CONTAINS_HASH in rel_types


def test_graph_idempotency_repeated_processing(db_session: Session, populated_case: Case):
    """Test: Repeated graph builds on same case produce identical counts without duplication."""
    repo = InMemoryThreatGraphRepository()
    service = ThreatGraphService(repository=repo)

    result_1 = service.build_case_graph(populated_case.id, db_session)
    count_nodes_1 = result_1.total_nodes
    count_rels_1 = result_1.total_relationships

    # Build second time
    result_2 = service.build_case_graph(populated_case.id, db_session)
    assert result_2.total_nodes == count_nodes_1
    assert result_2.total_relationships == count_rels_1


def test_graph_duplicate_indicators_handling(db_session: Session, populated_case: Case):
    """Test: Duplicate IOCs across sources are deduplicated in graph nodes."""
    # Add duplicate IOCs
    dup1 = CaseIOC(
        case_id=populated_case.id,
        ioc_type=IOCType.DOMAIN,
        value="evil-corp-update.com",
        source="header",
    )
    dup2 = CaseIOC(
        case_id=populated_case.id, ioc_type=IOCType.IPV4, value="185.220.101.5", source="hop2"
    )
    db_session.add_all([dup1, dup2])
    db_session.commit()

    repo = InMemoryThreatGraphRepository()
    service = ThreatGraphService(repository=repo)
    result = service.build_case_graph(populated_case.id, db_session)

    # Check there is only one node for domain and one for IP
    domain_nodes = [n for n in result.nodes if n.id == "domain:evil-corp-update.com"]
    ip_nodes = [n for n in result.nodes if n.id == "ip:185.220.101.5"]

    assert len(domain_nodes) == 1
    assert len(ip_nodes) == 1


def test_graph_missing_country_fallback(db_session: Session, populated_case: Case):
    """Test: Missing GeoIP country still generates valid graph without crashing."""
    repo = InMemoryThreatGraphRepository()
    geoip_mock = MagicMock()
    geoip_mock.analyze_case_infrastructure.return_value = {"ip_infrastructure": []}

    service = ThreatGraphService(repository=repo, geoip_service=geoip_mock)
    result = service.build_case_graph(populated_case.id, db_session)

    assert result.status == "available"
    assert GraphNodeType.COUNTRY not in {n.type for n in result.nodes}


def test_graph_neo4j_unavailable_resilient_fallback(db_session: Session, populated_case: Case):
    """Test: When Neo4j is offline or health check fails, in-memory fallback serves graph cleanly."""
    failing_neo4j = Neo4jThreatGraphRepository(uri="bolt://invalid-host:9999")
    service = ThreatGraphService(repository=failing_neo4j)

    result = service.build_case_graph(populated_case.id, db_session)
    assert result.status == "available"
    assert result.total_nodes > 0


def test_graph_nonexistent_case_raises_404(db_session: Session):
    """Test: Querying non-existent case raises NotFoundError."""
    service = ThreatGraphService()
    with pytest.raises(NotFoundError):
        service.get_case_graph("00000000-0000-0000-0000-000000000000", db_session)


def test_graph_failed_case_raises_app_exception(db_session: Session, test_user: User):
    """Test: Querying failed case raises AppException."""
    failed_case = Case(
        user_id=test_user.id,
        file_name="failed.eml",
        file_size_bytes=100,
        sha256_hash="deadbeef",
        storage_key="failed.eml",
        status=CaseStatus.FAILED,
        error_message="Corrupted RFC 822 file header",
    )
    db_session.add(failed_case)
    db_session.commit()

    service = ThreatGraphService()
    with pytest.raises(AppException) as exc:
        service.build_case_graph(failed_case.id, db_session)
    assert exc.value.status_code == 400
