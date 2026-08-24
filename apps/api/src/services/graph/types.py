from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class GraphNodeType(StrEnum):
    """Investigation threat graph node categories."""

    EMAIL = "Email"
    EMAIL_ADDRESS = "EmailAddress"
    DOMAIN = "Domain"
    IP = "IP"
    COUNTRY = "Country"
    ATTACHMENT_HASH = "AttachmentHash"


class GraphRelationshipType(StrEnum):
    """Investigation threat graph relationship classifications."""

    SENT_FROM = "SENT_FROM"
    USES_DOMAIN = "USES_DOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    LOCATED_IN = "LOCATED_IN"
    CONTAINS_HASH = "CONTAINS_HASH"


@dataclass(frozen=True)
class GraphNode:
    """Represents a node in the investigation threat graph."""

    id: str
    label: str
    type: GraphNodeType
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.type.value,
            "properties": self.properties,
        }


@dataclass(frozen=True)
class GraphRelationship:
    """Represents a directed edge between two threat graph nodes."""

    id: str
    source: str
    target: str
    type: GraphRelationshipType
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "properties": self.properties,
        }


@dataclass
class ThreatGraphResult:
    """Aggregated graph payload for an investigation case."""

    case_id: str
    status: str  # "available" | "unavailable"
    nodes: list[GraphNode] = field(default_factory=list)
    relationships: list[GraphRelationship] = field(default_factory=list)
    error_message: str | None = None

    @property
    def total_nodes(self) -> int:
        return len(self.nodes)

    @property
    def total_relationships(self) -> int:
        return len(self.relationships)

    @property
    def node_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for n in self.nodes:
            counts[n.type.value] = counts.get(n.type.value, 0) + 1
        return counts

    @property
    def relationship_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.relationships:
            counts[r.type.value] = counts.get(r.type.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "status": self.status,
            "total_nodes": self.total_nodes,
            "total_relationships": self.total_relationships,
            "node_counts": self.node_counts,
            "relationship_counts": self.relationship_counts,
            "nodes": [n.to_dict() for n in self.nodes],
            "relationships": [r.to_dict() for r in self.relationships],
            "error_message": self.error_message,
        }
