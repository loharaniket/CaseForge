from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GraphNodeSchema(BaseModel):
    """Schema representing an individual graph node."""

    id: str = Field(..., description="Unique node identifier")
    label: str = Field(..., description="Human-readable node label")
    type: str = Field(..., description="Node classification type")
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Node telemetry attributes"
    )

    model_config = ConfigDict(from_attributes=True)


class GraphRelationshipSchema(BaseModel):
    """Schema representing a directed relationship between graph nodes."""

    id: str = Field(..., description="Unique relationship identifier")
    source: str = Field(..., description="Source node identifier")
    target: str = Field(..., description="Target node identifier")
    type: str = Field(..., description="Relationship classification type")
    properties: dict[str, Any] = Field(default_factory=dict, description="Relationship metadata")

    model_config = ConfigDict(from_attributes=True)


class CaseThreatGraphResponse(BaseModel):
    """Investigation case threat relationship graph response."""

    case_id: str = Field(..., description="Investigation case unique identifier")
    status: str = Field(..., description="Graph availability status ('available' or 'unavailable')")
    total_nodes: int = Field(default=0, description="Total node count in graph")
    total_relationships: int = Field(default=0, description="Total relationship count in graph")
    node_counts: dict[str, int] = Field(
        default_factory=dict, description="Distribution count by node type"
    )
    relationship_counts: dict[str, int] = Field(
        default_factory=dict, description="Distribution count by relationship type"
    )
    nodes: list[GraphNodeSchema] = Field(default_factory=list, description="List of graph nodes")
    relationships: list[GraphRelationshipSchema] = Field(
        default_factory=list, description="List of directed relationship edges"
    )
    error_message: str | None = Field(
        default=None, description="Error reason if graph is unavailable"
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "case_id": "8677e9ef-16aa-4dd5-a437-24ab59a1bb76",
                "status": "available",
                "total_nodes": 5,
                "total_relationships": 4,
                "node_counts": {
                    "Email": 1,
                    "EmailAddress": 1,
                    "Domain": 1,
                    "IP": 1,
                    "Country": 1,
                },
                "relationship_counts": {
                    "SENT_FROM": 1,
                    "USES_DOMAIN": 1,
                    "RESOLVES_TO": 1,
                    "LOCATED_IN": 1,
                },
                "nodes": [
                    {
                        "id": "email:123",
                        "label": "Phishing Alert",
                        "type": "Email",
                        "properties": {},
                    },
                    {
                        "id": "email_addr:attacker@corp.net",
                        "label": "attacker@corp.net",
                        "type": "EmailAddress",
                        "properties": {},
                    },
                    {
                        "id": "domain:corp.net",
                        "label": "corp.net",
                        "type": "Domain",
                        "properties": {},
                    },
                    {
                        "id": "ip:198.51.100.88",
                        "label": "198.51.100.88",
                        "type": "IP",
                        "properties": {},
                    },
                    {
                        "id": "country:Germany",
                        "label": "Germany",
                        "type": "Country",
                        "properties": {},
                    },
                ],
                "relationships": [
                    {
                        "id": "rel1",
                        "source": "email:123",
                        "target": "email_addr:attacker@corp.net",
                        "type": "SENT_FROM",
                        "properties": {},
                    },
                    {
                        "id": "rel2",
                        "source": "email:123",
                        "target": "domain:corp.net",
                        "type": "USES_DOMAIN",
                        "properties": {},
                    },
                    {
                        "id": "rel3",
                        "source": "domain:corp.net",
                        "target": "ip:198.51.100.88",
                        "type": "RESOLVES_TO",
                        "properties": {},
                    },
                    {
                        "id": "rel4",
                        "source": "ip:198.51.100.88",
                        "target": "country:Germany",
                        "type": "LOCATED_IN",
                        "properties": {},
                    },
                ],
                "error_message": None,
            }
        },
    )
