import logging
from abc import ABC, abstractmethod
from typing import Any

from src.core.config import settings
from src.services.graph.types import (
    GraphNode,
    GraphNodeType,
    GraphRelationship,
    GraphRelationshipType,
    ThreatGraphResult,
)

logger = logging.getLogger("threattrace")


class ThreatGraphRepository(ABC):
    """Abstract interface for storing and querying investigation threat graphs."""

    @abstractmethod
    def save_graph(
        self,
        case_id: str,
        nodes: list[GraphNode],
        relationships: list[GraphRelationship],
    ) -> None:
        """Persists or merges graph nodes and relationships idempotently for a case."""
        pass

    @abstractmethod
    def get_case_graph(self, case_id: str) -> ThreatGraphResult:
        """Retrieves the case-scoped subgraph."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Checks if the underlying graph backend is connected and healthy."""
        pass


class InMemoryThreatGraphRepository(ThreatGraphRepository):
    """In-memory thread-safe threat graph repository for local dev and offline fallback."""

    def __init__(self) -> None:
        self._nodes_by_case: dict[str, dict[str, GraphNode]] = {}
        self._relationships_by_case: dict[str, dict[str, GraphRelationship]] = {}

    def is_healthy(self) -> bool:
        return True

    def save_graph(
        self,
        case_id: str,
        nodes: list[GraphNode],
        relationships: list[GraphRelationship],
    ) -> None:
        if case_id not in self._nodes_by_case:
            self._nodes_by_case[case_id] = {}
            self._relationships_by_case[case_id] = {}

        # Merge nodes idempotently
        for node in nodes:
            self._nodes_by_case[case_id][node.id] = node

        # Merge relationships idempotently
        for rel in relationships:
            self._relationships_by_case[case_id][rel.id] = rel

    def get_case_graph(self, case_id: str) -> ThreatGraphResult:
        nodes = list(self._nodes_by_case.get(case_id, {}).values())
        relationships = list(self._relationships_by_case.get(case_id, {}).values())

        return ThreatGraphResult(
            case_id=case_id,
            status="available",
            nodes=nodes,
            relationships=relationships,
        )


class Neo4jThreatGraphRepository(ThreatGraphRepository):
    """Production Neo4j graph database repository with Cypher MERGE idempotency."""

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> None:
        self.uri = uri or settings.NEO4J_URI
        self.user = user or settings.NEO4J_USER
        self.password = password or settings.NEO4J_PASSWORD
        self.database = database or settings.NEO4J_DATABASE
        self._driver: Any = None

    def _get_driver(self) -> Any:
        if self._driver is None:
            from neo4j import GraphDatabase

            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
            )
        return self._driver

    def is_healthy(self) -> bool:
        """Verifies active connectivity to Neo4j."""
        try:
            driver = self._get_driver()
            with driver.session(database=self.database) as session:
                result = session.run("RETURN 1 AS ping")
                record = result.single()
                return record is not None and record["ping"] == 1
        except Exception as exc:
            logger.debug(f"Neo4j health check failed: {exc}")
            return False

    def save_graph(
        self,
        case_id: str,
        nodes: list[GraphNode],
        relationships: list[GraphRelationship],
    ) -> None:
        driver = self._get_driver()
        with driver.session(database=self.database) as session:
            # 1. Upsert nodes with MERGE
            for node in nodes:
                cypher_node = f"""
                MERGE (n:{node.type.value} {{id: $node_id}})
                SET n.label = $label,
                    n.case_id = $case_id
                """
                session.run(
                    cypher_node,
                    node_id=node.id,
                    label=node.label,
                    case_id=case_id,
                )

            # 2. Upsert relationships with MERGE
            for rel in relationships:
                cypher_rel = f"""
                MATCH (a {{id: $source_id}})
                MATCH (b {{id: $target_id}})
                MERGE (a)-[r:{rel.type.value} {{case_id: $case_id}}]->(b)
                SET r.id = $rel_id
                """
                session.run(
                    cypher_rel,
                    source_id=rel.source,
                    target_id=rel.target,
                    rel_id=rel.id,
                    case_id=case_id,
                )

    def get_case_graph(self, case_id: str) -> ThreatGraphResult:
        driver = self._get_driver()
        nodes_dict: dict[str, GraphNode] = {}
        relationships_list: list[GraphRelationship] = []

        with driver.session(database=self.database) as session:
            # Fetch nodes scoped to case_id
            node_query = """
            MATCH (n)
            WHERE n.case_id = $case_id
            RETURN n.id AS id, labels(n)[0] AS type, n.label AS label
            """
            node_records = session.run(node_query, case_id=case_id)
            for rec in node_records:
                n_id = rec["id"]
                n_type_str = rec["type"]
                try:
                    n_type = GraphNodeType(n_type_str)
                except ValueError:
                    n_type = GraphNodeType.EMAIL
                nodes_dict[n_id] = GraphNode(
                    id=n_id,
                    label=rec["label"] or n_id,
                    type=n_type,
                )

            # Fetch relationships scoped to case_id
            rel_query = """
            MATCH (a)-[r]->(b)
            WHERE r.case_id = $case_id
            RETURN r.id AS id, a.id AS source, b.id AS target, type(r) AS type
            """
            rel_records = session.run(rel_query, case_id=case_id)
            for rec in rel_records:
                rel_id = rec["id"] or f"{rec['source']}->{rec['target']}"
                rel_type_str = rec["type"]
                try:
                    rel_type = GraphRelationshipType(rel_type_str)
                except ValueError:
                    continue

                relationships_list.append(
                    GraphRelationship(
                        id=rel_id,
                        source=rec["source"],
                        target=rec["target"],
                        type=rel_type,
                    )
                )

        return ThreatGraphResult(
            case_id=case_id,
            status="available",
            nodes=list(nodes_dict.values()),
            relationships=relationships_list,
        )

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None
