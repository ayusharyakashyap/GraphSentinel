"""Typed, bounded read access to the GraphSentinel FalkorDB graph."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping
from uuid import uuid4

from falkordb import FalkorDB

from graphsentinel.config import settings
from graphsentinel.schema import NODE_REQUIRED_PROPERTIES

MAX_TRAVERSAL_DEPTH = 6
MAX_RECORDS = 200
DEFAULT_LIMIT = 100


class GraphRepositoryError(RuntimeError):
    """Raised when FalkorDB cannot execute a repository operation."""


class ResponseActionNotFoundError(LookupError):
    """Raised when a persisted simulated response action does not exist."""


class InvalidActionTransition(RuntimeError):
    """Raised when an action attempts a transition that is not permitted."""


class ActionStateConflict(RuntimeError):
    """Raised when the simulation target changed after an action was proposed."""


@dataclass(frozen=True)
class GraphNode:
    id: str
    label: str
    properties: Mapping[str, Any]


@dataclass(frozen=True)
class GraphRelationship:
    type: str
    source_id: str
    target_id: str
    properties: Mapping[str, Any]


@dataclass(frozen=True)
class GraphPath:
    nodes: tuple[GraphNode, ...]
    relationships: tuple[GraphRelationship, ...]


@dataclass(frozen=True)
class AlertContext:
    alert: GraphNode | None
    nodes: tuple[GraphNode, ...]
    relationships: tuple[GraphRelationship, ...]


@dataclass(frozen=True)
class DependencyImpact:
    service: GraphNode | None
    dependencies: tuple[GraphNode, ...]
    dependents: tuple[GraphNode, ...]
    dependency_paths: tuple[GraphPath, ...]
    impact_paths: tuple[GraphPath, ...]


@dataclass(frozen=True)
class EvidenceRecord:
    evidence: GraphNode
    linked_nodes: tuple[GraphNode, ...]
    relationships: tuple[GraphRelationship, ...]


@dataclass(frozen=True)
class HistoricalIncident:
    incident: GraphNode
    shared_entity_ids: tuple[str, ...]
    relevance_reasons: tuple[str, ...]
    supporting_evidence: tuple[GraphNode, ...]


@dataclass(frozen=True)
class HistoricalEpisode:
    episode: GraphNode
    shared_entity_ids: tuple[str, ...]
    matching_event_types: tuple[str, ...]
    relevance_reasons: tuple[str, ...]


@dataclass(frozen=True)
class StoredResponseAction:
    action: GraphNode
    audit_events: tuple[GraphNode, ...]


def _node(value: Any) -> GraphNode:
    properties = dict(value.properties)
    identifier = properties.get("id")
    labels = list(value.labels)
    if not identifier or len(labels) != 1:
        raise GraphRepositoryError("FalkorDB returned a node without a stable ID or unique label.")
    return GraphNode(id=str(identifier), label=labels[0], properties=properties)


def _relationship(value: Any, source_id: str, target_id: str) -> GraphRelationship:
    return GraphRelationship(
        type=value.relation,
        source_id=source_id,
        target_id=target_id,
        properties=dict(value.properties),
    )


def _validate_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RECORDS:
        raise ValueError(f"limit must be an integer from 1 to {MAX_RECORDS}")
    return limit


def _validate_depth(max_depth: int) -> int:
    if (
        isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or not 1 <= max_depth <= MAX_TRAVERSAL_DEPTH
    ):
        raise ValueError(f"max_depth must be an integer from 1 to {MAX_TRAVERSAL_DEPTH}")
    return max_depth


class GraphRepository:
    """Centralizes FalkorDB access and converts driver values to stable records."""

    def __init__(
        self,
        graph: Any | None = None,
        timeout_provider: Callable[[], int] | None = None,
        read_only: bool = False,
    ) -> None:
        self._timeout_provider = timeout_provider
        self._read_only = read_only
        if graph is not None:
            self._graph = graph
            return
        try:
            client = FalkorDB(
                host=settings.host,
                port=settings.port,
                password=settings.password,
            )
            self._graph = client.select_graph(settings.graph_name)
        except Exception as error:
            raise GraphRepositoryError(f"Could not connect to FalkorDB: {error}") from error

    def with_timeout_provider(self, provider: Callable[[], int]) -> "GraphRepository":
        return GraphRepository(
            graph=self._graph,
            timeout_provider=provider,
            read_only=self._read_only,
        )

    def as_read_only(self) -> "GraphRepository":
        return GraphRepository(
            graph=self._graph,
            timeout_provider=self._timeout_provider,
            read_only=True,
        )

    def _query(self, query: str, parameters: Mapping[str, Any] | None = None) -> list[list[Any]]:
        try:
            timeout = self._timeout_provider() if self._timeout_provider is not None else None
            if timeout is not None and timeout <= 0:
                raise GraphRepositoryError("Investigation deadline reached before database query")
            query_method = self._graph.ro_query if self._read_only else self._graph.query
            if timeout is None:
                result = query_method(query, dict(parameters or {}))
            else:
                result = query_method(query, dict(parameters or {}), timeout=timeout)
        except Exception as error:
            if isinstance(error, GraphRepositoryError):
                raise
            raise GraphRepositoryError(f"FalkorDB query failed: {error}") from error
        return result.result_set

    def ping(self) -> None:
        self._query("RETURN 1 AS ok")

    def list_alerts(self, limit: int = DEFAULT_LIMIT) -> tuple[GraphNode, ...]:
        _validate_limit(limit)
        rows = self._query(
            "MATCH (alert:Alert) RETURN alert ORDER BY alert.timestamp DESC LIMIT $limit",
            {"limit": limit},
        )
        return tuple(_node(row[0]) for row in rows)

    def get_node(self, label: str, identifier: str) -> GraphNode | None:
        if label not in NODE_REQUIRED_PROPERTIES:
            raise ValueError(f"Unsupported node label: {label}")
        rows = self._query(
            f"MATCH (node:{label} {{id: $id}}) RETURN node LIMIT 1",
            {"id": identifier},
        )
        return _node(rows[0][0]) if rows else None

    def get_alert_context(self, alert_id: str, limit: int = DEFAULT_LIMIT) -> AlertContext:
        _validate_limit(limit)
        rows = self._query(
            "MATCH (alert:Alert {id: $id}) "
            "OPTIONAL MATCH (alert)-[relationship]->(related) "
            "RETURN alert, relationship, related LIMIT $limit",
            {"id": alert_id, "limit": limit},
        )
        if not rows:
            return AlertContext(alert=None, nodes=(), relationships=())

        alert = _node(rows[0][0])
        nodes: dict[str, GraphNode] = {}
        relationships: dict[tuple[str, str, str], GraphRelationship] = {}
        for _, relationship, related in rows:
            if relationship is None or related is None:
                continue
            related_node = _node(related)
            nodes[related_node.id] = related_node
            mapped_relationship = _relationship(relationship, alert.id, related_node.id)
            key = (mapped_relationship.type, mapped_relationship.source_id, mapped_relationship.target_id)
            relationships[key] = mapped_relationship
        return AlertContext(
            alert=alert,
            nodes=tuple(nodes[key] for key in sorted(nodes)),
            relationships=tuple(relationships[key] for key in sorted(relationships)),
        )

    def trace_attack_paths(
        self,
        alert_id: str,
        max_depth: int = 5,
        limit: int = DEFAULT_LIMIT,
    ) -> tuple[GraphPath, ...]:
        depth = _validate_depth(max_depth)
        _validate_limit(limit)
        rows = self._query(
            f"MATCH path=(alert:Alert {{id: $id}})-[*1..{depth}]->(target) "
            "RETURN path LIMIT $limit",
            {"id": alert_id, "limit": limit},
        )
        paths: dict[tuple[Any, ...], GraphPath] = {}
        for row in rows:
            path_value = row[0]
            path_nodes = tuple(_node(node) for node in path_value.nodes())
            stable_ids_by_driver_id = {
                driver_node.id: mapped_node.id
                for driver_node, mapped_node in zip(path_value.nodes(), path_nodes)
            }
            path_relationships: list[GraphRelationship] = []
            for relationship in path_value.edges():
                source_id = stable_ids_by_driver_id.get(relationship.src_node)
                target_id = stable_ids_by_driver_id.get(relationship.dest_node)
                if source_id is None or target_id is None:
                    raise GraphRepositoryError("FalkorDB returned a path edge outside its ordered nodes.")
                path_relationships.append(_relationship(relationship, source_id, target_id))
            signature = tuple(
                (edge.type, edge.source_id, edge.target_id) for edge in path_relationships
            )
            if signature:
                paths.setdefault(signature, GraphPath(path_nodes, tuple(path_relationships)))
        return tuple(paths.values())

    def get_service_impact(
        self,
        service_id: str,
        max_depth: int = 4,
        limit: int = DEFAULT_LIMIT,
    ) -> DependencyImpact:
        depth = _validate_depth(max_depth)
        _validate_limit(limit)
        service = self.get_node("Service", service_id)
        if service is None:
            return DependencyImpact(None, (), (), (), ())

        dependency_paths = self._get_service_paths(
            f"MATCH path=(root:Service {{id: $id}})-[:DEPENDS_ON*1..{depth}]->(related:Service) "
            "RETURN path LIMIT $limit",
            service_id,
            limit,
        )
        impact_paths = self._get_service_paths(
            f"MATCH path=(related:Service)-[:DEPENDS_ON*1..{depth}]->(root:Service {{id: $id}}) "
            "RETURN path LIMIT $limit",
            service_id,
            limit,
        )
        dependencies = {
            node.id: node
            for path in dependency_paths
            for node in path.nodes
            if node.id != service_id and node.label == "Service"
        }
        dependents = {
            node.id: node
            for path in impact_paths
            for node in path.nodes
            if node.id != service_id and node.label == "Service"
        }
        return DependencyImpact(
            service=service,
            dependencies=tuple(dependencies[key] for key in sorted(dependencies)),
            dependents=tuple(dependents[key] for key in sorted(dependents)),
            dependency_paths=dependency_paths,
            impact_paths=impact_paths,
        )

    def _get_service_paths(self, query: str, service_id: str, limit: int) -> tuple[GraphPath, ...]:
        rows = self._query(query, {"id": service_id, "limit": limit})
        paths: dict[tuple[Any, ...], GraphPath] = {}
        for row in rows:
            path_value = row[0]
            driver_nodes = path_value.nodes()
            mapped_nodes = tuple(_node(node) for node in driver_nodes)
            stable_ids = {node.id: mapped.id for node, mapped in zip(driver_nodes, mapped_nodes)}
            relationships = tuple(
                _relationship(
                    relationship,
                    stable_ids[relationship.src_node],
                    stable_ids[relationship.dest_node],
                )
                for relationship in path_value.edges()
            )
            signature = tuple((edge.type, edge.source_id, edge.target_id) for edge in relationships)
            if signature:
                paths.setdefault(signature, GraphPath(mapped_nodes, relationships))
        return tuple(paths.values())

    def find_related_incidents(
        self,
        alert_id: str,
        limit: int = DEFAULT_LIMIT,
    ) -> tuple[HistoricalIncident, ...]:
        _validate_limit(limit)
        rows = self._query(
            "MATCH (alert:Alert {id: $id})-[:OBSERVED_ON]->(entity) "
            "<-[:INVOLVES]-(incident:Incident) "
            "RETURN DISTINCT incident, collect(DISTINCT entity) AS shared LIMIT $limit",
            {"id": alert_id, "limit": limit},
        )
        if not rows:
            return ()

        matches: dict[str, tuple[GraphNode, dict[str, GraphNode]]] = {}
        for incident_value, shared_values in rows:
            incident = _node(incident_value)
            shared = {_node(value).id: _node(value) for value in shared_values}
            if incident.id not in matches:
                matches[incident.id] = (incident, shared)
            else:
                matches[incident.id][1].update(shared)

        incident_ids = list(matches)
        support_rows = self._query(
            "MATCH (incident:Incident)-[:SUPPORTED_BY]->(evidence:Evidence) "
            "WHERE incident.id IN $incident_ids "
            "RETURN incident.id, evidence LIMIT $limit",
            {"incident_ids": incident_ids, "limit": limit},
        )
        evidence_by_incident: dict[str, dict[str, GraphNode]] = {}
        for incident_id, evidence_value in support_rows:
            evidence = _node(evidence_value)
            evidence_by_incident.setdefault(incident_id, {})[evidence.id] = evidence

        incidents: list[HistoricalIncident] = []
        for incident_id, (incident, shared) in matches.items():
            shared_nodes = tuple(shared[key] for key in sorted(shared))
            reasons = tuple(
                f"Shares {node.label.lower()} {node.id}; this is contextual, not proof of the same attack."
                for node in shared_nodes
            )
            incidents.append(
                HistoricalIncident(
                    incident=incident,
                    shared_entity_ids=tuple(node.id for node in shared_nodes),
                    relevance_reasons=reasons,
                    supporting_evidence=tuple(
                        evidence_by_incident.get(incident_id, {}).get(key)
                        for key in sorted(evidence_by_incident.get(incident_id, {}))
                    ),
                )
            )
        return tuple(
            sorted(incidents, key=lambda item: item.incident.properties.get("created_at", ""), reverse=True)
        )

    def get_evidence(
        self,
        evidence_ids: Iterable[str],
        limit: int = DEFAULT_LIMIT,
    ) -> tuple[EvidenceRecord, ...]:
        _validate_limit(limit)
        ids = sorted(set(evidence_ids))
        if not ids:
            return ()
        if len(ids) > MAX_RECORDS:
            raise ValueError(f"At most {MAX_RECORDS} evidence IDs may be requested")

        evidence_nodes: dict[str, GraphNode] = {}
        linked_nodes: dict[str, dict[str, GraphNode]] = {}
        relationships: dict[str, dict[tuple[str, str, str], GraphRelationship]] = {}
        about_rows = self._query(
            "MATCH (evidence:Evidence) WHERE evidence.id IN $ids "
            "OPTIONAL MATCH (evidence)-[relationship:ABOUT]->(entity) "
            "RETURN evidence, relationship, entity LIMIT $limit",
            {"ids": ids, "limit": limit},
        )
        for evidence_value, relationship_value, entity_value in about_rows:
            evidence = _node(evidence_value)
            evidence_nodes[evidence.id] = evidence
            if relationship_value is None or entity_value is None:
                continue
            entity = _node(entity_value)
            linked_nodes.setdefault(evidence.id, {})[entity.id] = entity
            relationship = _relationship(relationship_value, evidence.id, entity.id)
            key = (relationship.type, relationship.source_id, relationship.target_id)
            relationships.setdefault(evidence.id, {})[key] = relationship

        owner_rows = self._query(
            "MATCH (owner)-[relationship:HAS_EVIDENCE|SUPPORTED_BY]->(evidence:Evidence) "
            "WHERE evidence.id IN $ids RETURN owner, relationship, evidence LIMIT $limit",
            {"ids": ids, "limit": limit},
        )
        for owner_value, relationship_value, evidence_value in owner_rows:
            owner = _node(owner_value)
            evidence = _node(evidence_value)
            evidence_nodes[evidence.id] = evidence
            linked_nodes.setdefault(evidence.id, {})[owner.id] = owner
            relationship = _relationship(relationship_value, owner.id, evidence.id)
            key = (relationship.type, relationship.source_id, relationship.target_id)
            relationships.setdefault(evidence.id, {})[key] = relationship

        return tuple(
            EvidenceRecord(
                evidence=evidence_nodes[key],
                linked_nodes=tuple(
                    linked_nodes.get(key, {})[node_id]
                    for node_id in sorted(linked_nodes.get(key, {}))
                ),
                relationships=tuple(
                    relationships.get(key, {})[relationship_key]
                    for relationship_key in sorted(relationships.get(key, {}))
                ),
            )
            for key in sorted(evidence_nodes)
        )

    def save_investigation_episode(self, result: Mapping[str, Any]) -> GraphNode:
        """Persist one complete structured response and its graph provenance links."""
        alert_id = result.get("alert_id")
        episode_id = result.get("investigation_id")
        if not isinstance(alert_id, str) or not isinstance(episode_id, str):
            raise ValueError("Investigation result must include stable alert and investigation IDs")
        context = self.get_alert_context(alert_id)
        if context.alert is None:
            raise ValueError(f"Cannot persist an episode for missing alert {alert_id}")

        episode_nodes = {node.id: node for node in context.nodes}
        for path in result.get("attack_paths", []):
            for node in path.get("nodes", []):
                if isinstance(node, Mapping) and node.get("id") and node.get("label"):
                    episode_nodes[str(node["id"])] = GraphNode(
                        id=str(node["id"]),
                        label=str(node["label"]),
                        properties=dict(node.get("properties", {})),
                    )
        entities = sorted(
            node_id
            for node_id, node in episode_nodes.items()
            if node.label in {"Identity", "Device", "Service", "Vulnerability"}
        )
        involved_entities = sorted(
            node_id
            for node_id, node in episode_nodes.items()
            if node.label in {"Identity", "Device", "Service"}
        )
        vulnerabilities = sorted(
            node_id for node_id, node in episode_nodes.items() if node.label == "Vulnerability"
        )
        evidence_ids = sorted(node.id for node in context.nodes if node.label == "Evidence")
        event_nodes = [node for node in context.nodes if node.label == "Event"]
        event_ids = sorted(node.id for node in event_nodes)
        service_ids = sorted(
            node_id for node_id, node in episode_nodes.items() if node.label == "Service"
        )
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        properties = {
            "id": episode_id,
            "alert_id": alert_id,
            "alert_type": str(context.alert.properties.get("type", "")),
            "summary": str(result["summary"]),
            "risk_score": int(result["risk_score"]),
            "risk_level": str(result["risk_level"]),
            "confidence": float(result["confidence"]),
            "evidence_completeness": float(result["evidence_completeness"]),
            "created_at": created_at,
            "outcome": "INVESTIGATED",
            "event_types_json": json.dumps(sorted({str(event.properties.get("type", "")) for event in event_nodes})),
            "entity_ids_json": json.dumps(entities),
            "evidence_ids_json": json.dumps(evidence_ids),
            "attack_paths_json": json.dumps(result.get("attack_paths", []), separators=(",", ":")),
            "risk_factors_json": json.dumps(result.get("risk_factors", []), separators=(",", ":")),
            "recommendation_json": json.dumps(result.get("recommended_action", {}), separators=(",", ":")),
            "result_json": json.dumps(dict(result), separators=(",", ":")),
        }
        rows = self._query(
            "MATCH (alert:Alert {id: $alert_id}) "
            "MERGE (episode:InvestigationEpisode {id: $id}) "
            "ON CREATE SET episode += $properties "
            "MERGE (episode)-[:INVESTIGATES]->(alert) "
            "RETURN episode",
            {"alert_id": alert_id, "id": episode_id, "properties": properties},
        )
        if not rows:
            raise GraphRepositoryError(f"Alert {alert_id} disappeared before episode persistence")
        self._link_episode_nodes(episode_id, "INVOLVES", involved_entities)
        self._link_episode_nodes(episode_id, "DISCOVERED", vulnerabilities)
        self._link_episode_nodes(episode_id, "HAS_EVIDENCE", evidence_ids)
        self._link_episode_nodes(episode_id, "HAS_EVENT", event_ids)
        self._link_episode_nodes(episode_id, "FOLLOWED_PATH", service_ids)
        return _node(rows[0][0])

    def _link_episode_nodes(self, episode_id: str, relation: str, node_ids: list[str]) -> None:
        if not node_ids:
            return
        allowed_relations = {
            "INVOLVES", "DISCOVERED", "HAS_EVIDENCE", "HAS_EVENT", "FOLLOWED_PATH",
        }
        if relation not in allowed_relations:
            raise ValueError(f"Unsupported episode relationship: {relation}")
        self._query(
            "UNWIND $node_ids AS node_id "
            "MATCH (episode:InvestigationEpisode {id: $episode_id}) "
            "MATCH (related {id: node_id}) "
            f"MERGE (episode)-[:{relation}]->(related)",
            {"episode_id": episode_id, "node_ids": node_ids},
        )

    def get_investigation_episode(self, episode_id: str) -> GraphNode | None:
        rows = self._query(
            "MATCH (episode:InvestigationEpisode {id: $id}) RETURN episode LIMIT 1",
            {"id": episode_id},
        )
        return _node(rows[0][0]) if rows else None

    def find_related_episodes(
        self,
        alert_id: str,
        limit: int = DEFAULT_LIMIT,
    ) -> tuple[HistoricalEpisode, ...]:
        _validate_limit(limit)
        matches: dict[str, dict[str, Any]] = {}
        entity_rows = self._query(
            "MATCH (alert:Alert {id: $id})-[:OBSERVED_ON]->(entity) "
            "<-[:INVOLVES]-(episode:InvestigationEpisode) "
            "RETURN episode, collect(DISTINCT entity) AS shared "
            "ORDER BY episode.created_at DESC LIMIT $limit",
            {"id": alert_id, "limit": limit},
        )
        for episode_value, shared_values in entity_rows:
            episode = _node(episode_value)
            entry = matches.setdefault(
                episode.id,
                {"episode": episode, "entities": set(), "events": set()},
            )
            entry["entities"].update(_node(value).id for value in shared_values)

        event_rows = self._query(
            "MATCH (alert:Alert {id: $id})-[:HAS_EVENT]->(event:Event) "
            "MATCH (episode:InvestigationEpisode)-[:HAS_EVENT]->(past_event:Event) "
            "WHERE event.type = past_event.type "
            "RETURN episode, collect(DISTINCT past_event.type) AS shared_types "
            "ORDER BY episode.created_at DESC LIMIT $limit",
            {"id": alert_id, "limit": limit},
        )
        for episode_value, event_types in event_rows:
            episode = _node(episode_value)
            entry = matches.setdefault(
                episode.id,
                {"episode": episode, "entities": set(), "events": set()},
            )
            entry["events"].update(str(event_type) for event_type in event_types)

        related: list[HistoricalEpisode] = []
        for entry in matches.values():
            episode = entry["episode"]
            entity_ids = tuple(sorted(entry["entities"]))
            event_types = tuple(sorted(entry["events"]))
            reasons = [
                f"Shares graph entity {entity_id}; prior investigation is context, not proof of the same incident."
                for entity_id in entity_ids
            ]
            reasons.extend(
                f"Shares event type {event_type}; event-type similarity is contextual, not proof of the same incident."
                for event_type in event_types
            )
            related.append(HistoricalEpisode(episode, entity_ids, event_types, tuple(reasons)))
        related.sort(
            key=lambda item: str(item.episode.properties.get("created_at", "")),
            reverse=True,
        )
        return tuple(related[:limit])

    def get_response_action(self, action_id: str) -> StoredResponseAction | None:
        rows = self._query(
            "MATCH (action:ResponseAction {id: $id}) "
            "OPTIONAL MATCH (action)-[:HAS_AUDIT_EVENT]->(audit:ActionAudit) "
            "RETURN action, audit LIMIT $limit",
            {"id": action_id, "limit": MAX_RECORDS},
        )
        if not rows:
            return None
        action = _node(rows[0][0])
        audits = {
            _node(row[1]).id: _node(row[1])
            for row in rows
            if row[1] is not None
        }
        return StoredResponseAction(
            action=action,
            audit_events=tuple(
                sorted(audits.values(), key=lambda audit: str(audit.properties.get("timestamp", "")))
            ),
        )

    def create_response_action(
        self,
        properties: Mapping[str, Any],
        target_label: str,
    ) -> StoredResponseAction:
        if target_label not in {"Identity", "Device", "Service", "Vulnerability"}:
            raise ValueError("Unsupported simulated action target label")
        action_id = str(properties["id"])
        audit_id = str(uuid4())
        created_at = str(properties["created_at"])
        audit = {
            "id": audit_id,
            "action_id": action_id,
            "event_type": "PROPOSED",
            "from_state": "NONE",
            "to_state": "PROPOSED",
            "actor": "investigator",
            "timestamp": created_at,
            "details_json": json.dumps({"target_entity_id": properties["target_entity_id"]}),
        }
        rows = self._query(
            "MATCH (episode:InvestigationEpisode {id: $episode_id}) "
            f"MATCH (target:{target_label} {{id: $target_id}}) "
            "WHERE coalesce(target.simulation_version, 0) = $expected_version "
            "AND coalesce(target.simulation_state, \"NORMAL\") = $previous_state "
            "CREATE (action:ResponseAction) SET action += $properties "
            "CREATE (audit:ActionAudit) SET audit += $audit "
            "MERGE (episode)-[:PROPOSES]->(action) "
            "MERGE (action)-[:HAS_AUDIT_EVENT]->(audit) "
            "SET episode.outcome = \"ACTION_PROPOSED\", episode.response_action_id = action.id "
            "RETURN action",
            {
                "episode_id": properties["investigation_id"],
                "target_id": properties["target_entity_id"],
                "expected_version": properties["expected_version"],
                "previous_state": properties["previous_state"],
                "properties": dict(properties),
                "audit": audit,
            },
        )
        if not rows:
            raise ActionStateConflict("Target simulation state changed before proposal was recorded")
        stored = self.get_response_action(action_id)
        if stored is None:
            raise GraphRepositoryError("Proposed response action could not be reloaded")
        return stored

    def approve_response_action(self, action_id: str, approved_by: str) -> StoredResponseAction:
        return self._transition_pending_action(
            action_id=action_id,
            actor=approved_by,
            new_status="APPROVED",
            approval_status="APPROVED",
            event_type="APPROVED",
            outcome="ACTION_APPROVED",
            reason="",
        )

    def reject_response_action(
        self,
        action_id: str,
        rejected_by: str,
        reason: str,
    ) -> StoredResponseAction:
        return self._transition_pending_action(
            action_id=action_id,
            actor=rejected_by,
            new_status="REJECTED",
            approval_status="REJECTED",
            event_type="REJECTED",
            outcome="ACTION_REJECTED",
            reason=reason,
        )

    def _transition_pending_action(
        self,
        action_id: str,
        actor: str,
        new_status: str,
        approval_status: str,
        event_type: str,
        outcome: str,
        reason: str,
    ) -> StoredResponseAction:
        current = self.get_response_action(action_id)
        if current is None:
            raise ResponseActionNotFoundError(action_id)
        if current.action.properties.get("status") != "PROPOSED":
            raise InvalidActionTransition(
                f"Cannot transition action from {current.action.properties.get('status')}"
            )
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        audit_id = str(uuid4())
        details = {"reason": reason} if reason else {}
        audit = {
            "id": audit_id,
            "action_id": action_id,
            "event_type": event_type,
            "from_state": "PROPOSED",
            "to_state": new_status,
            "actor": actor,
            "timestamp": timestamp,
            "details_json": json.dumps(details),
        }
        updates: dict[str, Any] = {
            "status": new_status,
            "approval_status": approval_status,
        }
        if new_status == "APPROVED":
            updates["approved_by"] = actor
            updates["approved_at"] = timestamp
        else:
            updates["rejected_by"] = actor
            updates["rejection_reason"] = reason
        rows = self._query(
            "MATCH (action:ResponseAction {id: $id}) "
            "MATCH (episode:InvestigationEpisode) WHERE episode.id = action.investigation_id "
            "AND action.status = \"PROPOSED\" AND action.approval_status = \"PENDING\" "
            "SET action += $updates "
            "CREATE (audit:ActionAudit) SET audit += $audit "
            "MERGE (action)-[:HAS_AUDIT_EVENT]->(audit) "
            "SET episode.outcome = $outcome "
            "RETURN action",
            {"id": action_id, "updates": updates, "audit": audit, "outcome": outcome},
        )
        if not rows:
            raise InvalidActionTransition("Action is no longer in PROPOSED state")
        stored = self.get_response_action(action_id)
        if stored is None:
            raise GraphRepositoryError("Transitioned response action could not be reloaded")
        return stored

    def execute_simulated_action(self, action_id: str, executed_by: str = "simulator") -> StoredResponseAction:
        current = self.get_response_action(action_id)
        if current is None:
            raise ResponseActionNotFoundError(action_id)
        properties = current.action.properties
        if properties.get("status") != "APPROVED" or properties.get("approval_status") != "APPROVED":
            raise InvalidActionTransition("Only an explicitly approved action can execute")
        target_label = str(properties.get("target_label", ""))
        if target_label not in {"Identity", "Device", "Service", "Vulnerability"}:
            raise InvalidActionTransition("Response action target label is invalid")
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        audit_id = str(uuid4())
        audit = {
            "id": audit_id,
            "action_id": action_id,
            "event_type": "EXECUTED_SIMULATED",
            "from_state": "APPROVED",
            "to_state": "EXECUTED_SIMULATED",
            "actor": executed_by,
            "timestamp": timestamp,
            "details_json": json.dumps({"simulated": True}),
        }
        rows = self._query(
            "MATCH (action:ResponseAction {id: $id}) "
            f"MATCH (target:{target_label} {{id: $target_id}}) "
            "MATCH (episode:InvestigationEpisode {id: $episode_id}) "
            "WHERE action.status = \"APPROVED\" AND action.approval_status = \"APPROVED\" "
            "AND coalesce(target.simulation_version, 0) = action.expected_version "
            "AND coalesce(target.simulation_state, \"NORMAL\") = action.previous_state "
            "SET target.simulation_state = action.proposed_state, "
            "target.simulation_version = coalesce(target.simulation_version, 0) + 1, "
            "action.status = \"EXECUTED_SIMULATED\", action.executed_at = $timestamp, "
            "action.result = \"Simulated state change applied in FalkorDB only.\" "
            "CREATE (audit:ActionAudit) SET audit += $audit "
            "MERGE (action)-[:HAS_AUDIT_EVENT]->(audit) "
            "SET episode.outcome = \"EXECUTED_SIMULATED\" "
            "RETURN action",
            {
                "id": action_id,
                "target_id": properties["target_entity_id"],
                "episode_id": properties["investigation_id"],
                "timestamp": timestamp,
                "audit": audit,
            },
        )
        if not rows:
            raise ActionStateConflict("Approved action was not applied because target state or version changed")
        stored = self.get_response_action(action_id)
        if stored is None:
            raise GraphRepositoryError("Executed response action could not be reloaded")
        return stored

    def verify_simulated_action(
        self,
        action_id: str,
        verified_by: str = "verifier",
    ) -> StoredResponseAction:
        current = self.get_response_action(action_id)
        if current is None:
            raise ResponseActionNotFoundError(action_id)
        properties = current.action.properties
        if properties.get("status") != "EXECUTED_SIMULATED":
            raise InvalidActionTransition("Only an EXECUTED_SIMULATED action can be verified")
        target_label = str(properties.get("target_label", ""))
        if target_label not in {"Identity", "Device", "Service", "Vulnerability"}:
            raise InvalidActionTransition("Response action target label is invalid")
        target_id = str(properties["target_entity_id"])
        target = self.get_node(target_label, target_id)
        if target is None:
            raise GraphRepositoryError("Simulated target disappeared before verification")

        expected_state = str(properties["proposed_state"])
        expected_version = int(properties["expected_version"]) + 1
        observed_state = str(target.properties.get("simulation_state", "NORMAL"))
        observed_version = int(target.properties.get("simulation_version", 0))
        passed = observed_state == expected_state and observed_version == expected_version
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        next_status = "VERIFIED" if passed else "EXECUTED_SIMULATED"
        verification_status = "PASSED" if passed else "FAILED"
        outcome = "ACTION_VERIFIED" if passed else "VERIFICATION_FAILED"
        verification_result = (
            f"Verified simulation state {observed_state} at version {observed_version}."
            if passed
            else f"Expected {expected_state} at version {expected_version}; observed {observed_state} at version {observed_version}."
        )
        audit_id = str(uuid4())
        audit = {
            "id": audit_id,
            "action_id": action_id,
            "event_type": "VERIFICATION_PASSED" if passed else "VERIFICATION_FAILED",
            "from_state": "EXECUTED_SIMULATED",
            "to_state": next_status,
            "actor": verified_by,
            "timestamp": timestamp,
            "details_json": json.dumps({
                "expected_state": expected_state,
                "observed_state": observed_state,
                "expected_version": expected_version,
                "observed_version": observed_version,
            }),
        }
        rows = self._query(
            "MATCH (action:ResponseAction {id: $id}) "
            f"MATCH (target:{target_label} {{id: $target_id}}) "
            "MATCH (episode:InvestigationEpisode {id: $episode_id}) "
            "WHERE action.status = \"EXECUTED_SIMULATED\" "
            "AND target.simulation_state = $observed_state "
            "AND coalesce(target.simulation_version, 0) = $observed_version "
            "SET action.status = $next_status, action.verification_status = $verification_status, "
            "action.verification_result = $verification_result, action.verified_at = $timestamp "
            "CREATE (audit:ActionAudit) SET audit += $audit "
            "MERGE (action)-[:HAS_AUDIT_EVENT]->(audit) "
            "SET episode.outcome = $outcome "
            "RETURN action",
            {
                "id": action_id,
                "target_id": target_id,
                "episode_id": properties["investigation_id"],
                "observed_state": observed_state,
                "observed_version": observed_version,
                "next_status": next_status,
                "verification_status": verification_status,
                "verification_result": verification_result,
                "timestamp": timestamp,
                "audit": audit,
                "outcome": outcome,
            },
        )
        if not rows:
            raise ActionStateConflict("Target changed while verification was being recorded")
        stored = self.get_response_action(action_id)
        if stored is None:
            raise GraphRepositoryError("Verified response action could not be reloaded")
        if passed:
            self._query(
                "MATCH (episode:InvestigationEpisode {id: $episode_id}) "
                "MATCH (action:ResponseAction {id: $action_id, status: \"VERIFIED\"}) "
                "MERGE (episode)-[:RESOLVED_BY]->(action)",
                {"episode_id": properties["investigation_id"], "action_id": action_id},
            )
            stored = self.get_response_action(action_id)
            if stored is None:
                raise GraphRepositoryError("Verified response action could not be reloaded")
        return stored