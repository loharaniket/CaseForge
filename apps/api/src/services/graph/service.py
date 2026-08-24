import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.services.geo.service import GeoIPService, get_geoip_service
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
from src.services.ioc.service import IOCService, get_ioc_service
from src.services.ioc.types import IOCType
from src.services.parser_service import ParserService, get_parser_service

logger = logging.getLogger("threattrace")


class ThreatGraphService:
    """Investigation threat relationship graph builder and query orchestrator.

    Minimal Graph Model:
    - Nodes: Email, EmailAddress, Domain, IP, Country, AttachmentHash
    - Relationships:
        Email -SENT_FROM-> EmailAddress
        Email -USES_DOMAIN-> Domain
        Domain -RESOLVES_TO-> IP
        IP -LOCATED_IN-> Country
        Email -CONTAINS_HASH-> AttachmentHash
    """

    def __init__(
        self,
        repository: ThreatGraphRepository | None = None,
        parser_service: ParserService | None = None,
        ioc_service: IOCService | None = None,
        geoip_service: GeoIPService | None = None,
    ) -> None:
        self._primary_repo = repository or Neo4jThreatGraphRepository()
        self._fallback_repo = InMemoryThreatGraphRepository()
        self.parser_service = parser_service or get_parser_service()
        self.ioc_service = ioc_service or get_ioc_service()
        self.geoip_service = geoip_service or get_geoip_service()

    def _get_active_repository(self) -> ThreatGraphRepository:
        """Returns the healthy repository (Neo4j if online, otherwise in-memory fallback)."""
        try:
            if self._primary_repo.is_healthy():
                return self._primary_repo
        except Exception as e:
            logger.debug(f"Primary graph repository unavailable: {e}")
        return self._fallback_repo

    def build_case_graph(self, case_id: str, db: Session) -> ThreatGraphResult:
        """Constructs and persists the case threat relationship graph."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot construct graph on failed case '{case_id}': {case.error_message}",
                code="CASE_PARSING_FAILED",
                status_code=400,
            )

        # 1. Retrieve parsed email data
        parsed = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()
        if not parsed:
            try:
                parsed = self.parser_service.parse_case(case_id=case_id, db=db)
            except Exception:
                parsed = None

        # 2. Retrieve extracted IOCs
        try:
            iocs = self.ioc_service.get_case_iocs(case_id=case_id, db=db)
        except Exception:
            iocs = []

        # 3. Retrieve header forensics
        forensics = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()

        # 4. Retrieve GeoIP infrastructure intelligence
        geo_data: dict[str, Any] = {}
        try:
            geo_data = self.geoip_service.analyze_case_infrastructure(case_id=case_id, db=db)
        except Exception as e:
            logger.debug(f"GeoIP enrichment unavailable for graph: {e}")

        # Construct Graph Elements
        nodes_dict: dict[str, GraphNode] = {}
        relationships_dict: dict[str, GraphRelationship] = {}

        # 1. Root Email Node
        email_node_id = f"email:{case_id}"
        email_subject = (
            parsed.subject if parsed and parsed.subject else f"Investigation Case {case_id[:8]}"
        )
        nodes_dict[email_node_id] = GraphNode(
            id=email_node_id,
            label=email_subject,
            type=GraphNodeType.EMAIL,
            properties={"case_id": case_id, "subject": email_subject},
        )

        # 2. Email Address & Domain Nodes
        sender_email = parsed.from_address or parsed.sender if parsed else None
        if sender_email:
            clean_sender = sender_email.strip().lower()
            sender_id = f"email_addr:{clean_sender}"
            nodes_dict[sender_id] = GraphNode(
                id=sender_id,
                label=clean_sender,
                type=GraphNodeType.EMAIL_ADDRESS,
            )
            # Email -SENT_FROM-> EmailAddress
            rel_id = f"{email_node_id}-SENT_FROM->{sender_id}"
            relationships_dict[rel_id] = GraphRelationship(
                id=rel_id,
                source=email_node_id,
                target=sender_id,
                type=GraphRelationshipType.SENT_FROM,
            )

            if "@" in clean_sender:
                sender_domain = clean_sender.split("@", 1)[1].strip()
                if sender_domain:
                    dom_id = f"domain:{sender_domain}"
                    nodes_dict[dom_id] = GraphNode(
                        id=dom_id,
                        label=sender_domain,
                        type=GraphNodeType.DOMAIN,
                    )
                    # Email -USES_DOMAIN-> Domain
                    dom_rel_id = f"{email_node_id}-USES_DOMAIN->{dom_id}"
                    relationships_dict[dom_rel_id] = GraphRelationship(
                        id=dom_rel_id,
                        source=email_node_id,
                        target=dom_id,
                        type=GraphRelationshipType.USES_DOMAIN,
                    )

        # 3. Extracted Domain IOCs
        domain_iocs = [
            ioc.value.lower() for iococ in [iocs] for ioc in iococ if ioc.ioc_type == IOCType.DOMAIN
        ]
        for dom in domain_iocs:
            dom_id = f"domain:{dom}"
            if dom_id not in nodes_dict:
                nodes_dict[dom_id] = GraphNode(
                    id=dom_id,
                    label=dom,
                    type=GraphNodeType.DOMAIN,
                )
            dom_rel_id = f"{email_node_id}-USES_DOMAIN->{dom_id}"
            relationships_dict[dom_rel_id] = GraphRelationship(
                id=dom_rel_id,
                source=email_node_id,
                target=dom_id,
                type=GraphRelationshipType.USES_DOMAIN,
            )

        # 4. IP Nodes & Domain -RESOLVES_TO-> IP
        origin_ip = forensics.probable_origin_ip if forensics else None
        if not origin_ip and geo_data:
            origin_ip = geo_data.get("candidate_origin_ip")

        ip_list: list[str] = []
        if origin_ip:
            ip_list.append(origin_ip)

        for ioc in iocs:
            if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                if ioc.value not in ip_list:
                    ip_list.append(ioc.value)

        # Map domain to resolved IP
        for ip_val in ip_list:
            ip_id = f"ip:{ip_val}"
            nodes_dict[ip_id] = GraphNode(
                id=ip_id,
                label=ip_val,
                type=GraphNodeType.IP,
            )

            # Connect domains to IP (RESOLVES_TO)
            for d_node_id, d_node in list(nodes_dict.items()):
                if d_node.type == GraphNodeType.DOMAIN:
                    res_rel_id = f"{d_node_id}-RESOLVES_TO->{ip_id}"
                    if res_rel_id not in relationships_dict:
                        relationships_dict[res_rel_id] = GraphRelationship(
                            id=res_rel_id,
                            source=d_node_id,
                            target=ip_id,
                            type=GraphRelationshipType.RESOLVES_TO,
                        )

        # 5. Country Nodes & IP -LOCATED_IN-> Country
        ip_infrastructure = geo_data.get("ip_infrastructure", [])
        for item in ip_infrastructure:
            ip_addr = item.get("ip")
            country_name = item.get("country_name") or item.get("country_code")
            if ip_addr and country_name:
                ip_id = f"ip:{ip_addr}"
                country_id = f"country:{country_name}"
                nodes_dict[country_id] = GraphNode(
                    id=country_id,
                    label=country_name,
                    type=GraphNodeType.COUNTRY,
                )
                loc_rel_id = f"{ip_id}-LOCATED_IN->{country_id}"
                relationships_dict[loc_rel_id] = GraphRelationship(
                    id=loc_rel_id,
                    source=ip_id,
                    target=country_id,
                    type=GraphRelationshipType.LOCATED_IN,
                )

        # 6. Attachment Hashes: Email -CONTAINS_HASH-> AttachmentHash
        hash_iocs = [ioc.value.lower() for ioc in iocs if ioc.ioc_type == IOCType.SHA256]
        # Also check parsed attachments if any
        if parsed and parsed.attachments_metadata:
            for att in parsed.attachments_metadata:
                h_val = att.get("sha256")
                if h_val and h_val.lower() not in hash_iocs:
                    hash_iocs.append(h_val.lower())

        for h_val in hash_iocs:
            hash_id = f"hash:{h_val}"
            nodes_dict[hash_id] = GraphNode(
                id=hash_id,
                label=f"{h_val[:12]}...",
                type=GraphNodeType.ATTACHMENT_HASH,
                properties={"sha256": h_val},
            )
            hash_rel_id = f"{email_node_id}-CONTAINS_HASH->{hash_id}"
            relationships_dict[hash_rel_id] = GraphRelationship(
                id=hash_rel_id,
                source=email_node_id,
                target=hash_id,
                type=GraphRelationshipType.CONTAINS_HASH,
            )

        # Save graph to active repository
        nodes_list = list(nodes_dict.values())
        relationships_list = list(relationships_dict.values())

        repo = self._get_active_repository()
        try:
            repo.save_graph(case_id=case_id, nodes=nodes_list, relationships=relationships_list)
            return repo.get_case_graph(case_id=case_id)
        except Exception as e:
            logger.warning(f"Error persisting graph to repository: {e}")
            # Use in-memory fallback
            self._fallback_repo.save_graph(
                case_id=case_id, nodes=nodes_list, relationships=relationships_list
            )
            return self._fallback_repo.get_case_graph(case_id=case_id)

    def get_case_graph(self, case_id: str, db: Session) -> ThreatGraphResult:
        """Retrieves or generates on demand the investigation threat graph."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        repo = self._get_active_repository()
        graph = repo.get_case_graph(case_id=case_id)
        if graph.total_nodes > 0:
            return graph

        return self.build_case_graph(case_id=case_id, db=db)


default_graph_service = ThreatGraphService()


def get_graph_service() -> ThreatGraphService:
    """Dependency injector for ThreatGraphService."""
    return default_graph_service
