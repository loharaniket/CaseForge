import logging
from typing import Any
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError, AppException
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.ioc import CaseIOC
from src.services.ioc.types import IOCType
from src.models.domain_intel import DomainIntelligenceRecord
from src.models.ip_intel import IPIntelligenceRecord
from src.models.url_intel import URLIntelligenceRecord
from src.services.graph.repository import (
    InMemoryThreatGraphRepository,
    Neo4jThreatGraphRepository,
    ThreatGraphRepository,
)
from src.services.graph.types import (
    GraphNode,
    GraphNodeType,
    GraphRelationship,
    GraphRelationshipType,
    ThreatGraphResult,
)

logger = logging.getLogger("threattrace")

class ThreatGraphService:
    """Service for constructing and persisting threat correlation graphs."""

    def __init__(
        self,
        repository: ThreatGraphRepository | None = None,
        geoip_service: Any | None = None,
    ) -> None:
        self._fallback_repo = InMemoryThreatGraphRepository()
        self._neo4j_repo = repository if repository else Neo4jThreatGraphRepository()
        self.geoip_service = geoip_service

    def _get_active_repository(self) -> ThreatGraphRepository:
        if self._neo4j_repo.is_healthy():
            return self._neo4j_repo
        logger.debug("Neo4j graph repository unavailable; using in-memory fallback.")
        return self._fallback_repo

    def build_case_graph(self, case_id: str, db: Session) -> ThreatGraphResult:
        """Extracts indicators from persistence and constructs the threat graph."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")
            
        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot generate threat graph for failed case '{case_id}': {case.error_message}",
                code="GRAPH_GENERATION_FAILED",
                status_code=400,
            )

        parsed = db.execute(select(ParsedEmail).where(ParsedEmail.case_id == case_id)).scalar_one_or_none()
        forensics = db.execute(select(HeaderForensics).where(HeaderForensics.case_id == case_id)).scalar_one_or_none()
        iocs = db.execute(select(CaseIOC).where(CaseIOC.case_id == case_id)).scalars().all()
        
        domain_records = db.execute(select(DomainIntelligenceRecord).where(DomainIntelligenceRecord.case_id == case_id)).scalars().all()
        ip_records = db.execute(select(IPIntelligenceRecord).where(IPIntelligenceRecord.case_id == case_id)).scalars().all()
        url_records = db.execute(select(URLIntelligenceRecord).where(URLIntelligenceRecord.case_id == case_id)).scalars().all()

        nodes_dict: dict[str, GraphNode] = {}
        relationships_dict: dict[str, GraphRelationship] = {}
        
        def add_node(n_id: str, label: str, n_type: GraphNodeType, properties: dict = None):
            if n_id not in nodes_dict:
                nodes_dict[n_id] = GraphNode(id=n_id, label=label, type=n_type, properties=properties or {})

        def add_rel(source: str, target: str, r_type: GraphRelationshipType, r_id: str = None):
            r_id = r_id or f"{source}-{r_type.value}->{target}"
            if r_id not in relationships_dict:
                relationships_dict[r_id] = GraphRelationship(id=r_id, source=source, target=target, type=r_type)

        # 1. CASE Node
        case_node_id = f"case:{case_id}"
        add_node(case_node_id, f"Case {case_id[:8]}", GraphNodeType.CASE, {"case_id": case_id})
        
        # 2. EMAIL Node
        email_node_id = f"email:{case_id}"
        email_subject = parsed.subject if parsed and parsed.subject else f"Investigation Case {case_id[:8]}"
        add_node(email_node_id, email_subject, GraphNodeType.EMAIL, {"case_id": case_id, "subject": email_subject})
        
        # CASE -> CONTAINS -> EMAIL
        add_rel(case_node_id, email_node_id, GraphRelationshipType.CONTAINS)

        if parsed:
            # EMAIL -> SENT_FROM -> DOMAIN and EMAIL_ADDRESS
            sender_email = parsed.from_address or parsed.sender
            if sender_email:
                clean_sender = sender_email.strip().lower()
                sender_id = f"email_addr:{clean_sender}"
                add_node(sender_id, clean_sender, GraphNodeType.EMAIL_ADDRESS)
                # We'll link EMAIL -> SENT_FROM -> DOMAIN as required
                
                if "@" in clean_sender:
                    sender_domain = clean_sender.split("@", 1)[1].strip()
                    if sender_domain:
                        dom_id = f"domain:{sender_domain}"
                        add_node(dom_id, sender_domain, GraphNodeType.DOMAIN)
                        add_rel(email_node_id, dom_id, GraphRelationshipType.SENT_FROM)

            # EMAIL -> REPLY_TO -> EMAIL_ADDRESS
            if parsed.reply_to:
                for rt in parsed.reply_to:
                    clean_rt = rt.strip().lower()
                    rt_id = f"email_addr:{clean_rt}"
                    add_node(rt_id, clean_rt, GraphNodeType.EMAIL_ADDRESS)
                    add_rel(email_node_id, rt_id, GraphRelationshipType.REPLY_TO)
                    
        # 3. EMAIL -> CONTAINS -> URL
        for url_intel in url_records:
            url_id = f"url:{url_intel.id}"
            add_node(url_id, url_intel.raw_url[:100], GraphNodeType.URL, {"url": url_intel.raw_url})
            add_rel(email_node_id, url_id, GraphRelationshipType.CONTAINS)
            
            # URL -> HOSTED_ON -> DOMAIN
            if url_intel.hostname:
                dom_id = f"domain:{url_intel.hostname.lower()}"
                add_node(dom_id, url_intel.hostname.lower(), GraphNodeType.DOMAIN)
                add_rel(url_id, dom_id, GraphRelationshipType.HOSTED_ON)

        # 4. EMAIL -> CONTAINS -> IOC (and map specific IOCs to their types)
        for ioc in iocs:
            if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                ip_id = f"ip:{ioc.value}"
                add_node(ip_id, ioc.value, GraphNodeType.IP)
                add_rel(email_node_id, ip_id, GraphRelationshipType.CONTAINS)
            elif ioc.ioc_type == IOCType.DOMAIN:
                dom_id = f"domain:{ioc.value.lower()}"
                add_node(dom_id, ioc.value.lower(), GraphNodeType.DOMAIN)
                add_rel(email_node_id, dom_id, GraphRelationshipType.CONTAINS)
            elif ioc.ioc_type == IOCType.URL:
                url_id = f"url:{ioc.id}"
                add_node(url_id, ioc.value[:100], GraphNodeType.URL, {"url": ioc.value})
                add_rel(email_node_id, url_id, GraphRelationshipType.CONTAINS)
            else:
                ioc_id = f"ioc:{ioc.id}"
                add_node(ioc_id, ioc.value, GraphNodeType.IOC, {"ioc_type": str(ioc.ioc_type)})
                add_rel(email_node_id, ioc_id, GraphRelationshipType.CONTAINS)
        
        # Also, check forensics.probable_origin_ip if we missed it
        if forensics and forensics.probable_origin_ip:
            ip_id = f"ip:{forensics.probable_origin_ip}"
            add_node(ip_id, forensics.probable_origin_ip, GraphNodeType.IP)
            add_rel(email_node_id, ip_id, GraphRelationshipType.TRAVELED_THROUGH)

            
        # Add domains from domain intelligence
        for dom_intel in domain_records:
            dom_id = f"domain:{dom_intel.domain.lower()}"
            add_node(dom_id, dom_intel.domain.lower(), GraphNodeType.DOMAIN)
            
            # DOMAIN -> RESOLVES_TO -> IP
            a_records = dom_intel.a_records or []
            aaaa_records = dom_intel.aaaa_records or []
            for ip in a_records + aaaa_records:
                ip_id = f"ip:{ip}"
                add_node(ip_id, ip, GraphNodeType.IP)
                add_rel(dom_id, ip_id, GraphRelationshipType.RESOLVES_TO)
                
            # DOMAIN -> USES_MX -> DOMAIN
            mx_records = dom_intel.mx_records or []
            for mx in mx_records:
                clean_mx = mx.rstrip('.').lower()
                mx_id = f"domain:{clean_mx}"
                add_node(mx_id, clean_mx, GraphNodeType.DOMAIN)
                add_rel(dom_id, mx_id, GraphRelationshipType.USES_MX)
                
        # 5. IP Intelligence
        for ip_intel in ip_records:
            ip_id = f"ip:{ip_intel.ip_address}"
            add_node(ip_id, ip_intel.ip_address, GraphNodeType.IP)
            
            # IP -> BELONGS_TO -> ASN
            if ip_intel.asn:
                asn_id = f"asn:{ip_intel.asn}"
                add_node(asn_id, f"AS{ip_intel.asn}", GraphNodeType.ASN)
                add_rel(ip_id, asn_id, GraphRelationshipType.BELONGS_TO)
                
            # IP -> OPERATED_BY -> ORGANIZATION
            org = ip_intel.organization or ip_intel.isp
            if org:
                org_id = f"org:{hashlib.md5(org.encode()).hexdigest()}"
                add_node(org_id, org, GraphNodeType.ORGANIZATION)
                add_rel(ip_id, org_id, GraphRelationshipType.OPERATED_BY)

            # IP -> LOCATED_IN -> COUNTRY
            if ip_intel.country:
                country_id = f"country:{ip_intel.country}"
                add_node(country_id, ip_intel.country, GraphNodeType.COUNTRY)
                add_rel(ip_id, country_id, GraphRelationshipType.LOCATED_IN)
                
        # 6. EMAIL -> TRAVELED_THROUGH -> IP
        if forensics and forensics.relay_hops:
            for hop in forensics.relay_hops:
                if hop.get('ip_address'):
                    ip = hop['ip_address']
                    ip_id = f"ip:{ip}"
                    add_node(ip_id, ip, GraphNodeType.IP)
                    add_rel(email_node_id, ip_id, GraphRelationshipType.TRAVELED_THROUGH)

        # Save graph to active repository
        nodes_list = list(nodes_dict.values())
        relationships_list = list(relationships_dict.values())

        repo = self._get_active_repository()
        try:
            repo.save_graph(case_id=case_id, nodes=nodes_list, relationships=relationships_list)
            return repo.get_case_graph(case_id=case_id)
        except Exception as e:
            logger.warning(f"Error persisting graph to repository: {e}")
            self._fallback_repo.save_graph(
                case_id=case_id, nodes=nodes_list, relationships=relationships_list
            )
            return self._fallback_repo.get_case_graph(case_id=case_id)

    def get_case_graph(self, case_id: str, db: Session) -> ThreatGraphResult:
        """Retrieves or generates on demand the investigation threat graph."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")
            
        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot retrieve graph for failed case '{case_id}': {case.error_message}",
                code="GRAPH_RETRIEVAL_FAILED",
                status_code=400,
            )

        repo = self._get_active_repository()
        graph = repo.get_case_graph(case_id=case_id)
        if graph.total_nodes > 0:
            return graph

        return self.build_case_graph(case_id=case_id, db=db)

default_graph_service = ThreatGraphService()

def get_graph_service() -> ThreatGraphService:
    """Dependency injector for ThreatGraphService."""
    return default_graph_service
