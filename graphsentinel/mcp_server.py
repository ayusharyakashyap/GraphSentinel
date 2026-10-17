"""GraphSentinel MCP server exposing bounded, read-only graph investigation tools."""

import json
import logging
from typing import Annotated, Any

from mcp.server import MCPServer
from pydantic import Field

from graphsentinel.config import settings
from graphsentinel.mcp_models import (
    AlertContextInput,
    AlertContextResponse,
    AttackPathInput,
    AttackPathsResult,
    EntityId,
    EvidenceInput,
    EvidenceRecordResponse,
    EvidenceResult,
    IncidentMemoryInput,
    IncidentMemoryResult,
    ServiceImpactInput,
    ServiceImpactResponse,
)
from graphsentinel.models import (
    AttackPathResponse,
    GraphNodeResponse,
    GraphRelationshipResponse,
    HistoricalEpisodeResponse,
    HistoricalIncidentResponse,
)
from graphsentinel.repository import GraphPath, GraphRepository

def _node_response(node: Any) -> GraphNodeResponse:
    return GraphNodeResponse(
        id=node.id,
        label=node.label,
        properties=dict(node.properties),
    )


def _relationship_response(relationship: Any) -> GraphRelationshipResponse:
    return GraphRelationshipResponse(
        type=relationship.type,
        source_id=relationship.source_id,
        target_id=relationship.target_id,
        properties=dict(relationship.properties),
    )


def _path_response(path: GraphPath) -> AttackPathResponse:
    return AttackPathResponse(
        nodes=[_node_response(node) for node in path.nodes],
        relationships=[_relationship_response(item) for item in path.relationships],
    )


def _episode_response(match: Any) -> HistoricalEpisodeResponse:
    properties = match.episode.properties
    return HistoricalEpisodeResponse(
        episode_id=match.episode.id,
        alert_id=str(properties["alert_id"]),
        summary=str(properties["summary"]),
        risk_score=int(properties["risk_score"]),
        risk_level=str(properties["risk_level"]),
        created_at=str(properties["created_at"]),
        outcome=str(properties["outcome"]),
        shared_entity_ids=list(match.shared_entity_ids),
        matching_event_types=list(match.matching_event_types),
        relevance_reasons=list(match.relevance_reasons),
        evidence_ids=json.loads(properties.get("evidence_ids_json", "[]")),
    )


def create_mcp_server(repository: GraphRepository | None = None) -> MCPServer:
    """Create a server instance suitable for stdio serving or in-process tests."""
    graph_repository = (repository or GraphRepository()).as_read_only()
    server = MCPServer(
        name="GraphSentinel Read-Only Investigation",
        version="0.5.0",
        instructions=(
            "These tools perform read-only security investigation against the synthetic "
            "GraphSentinel graph. A graph path is a possible route, not proof of compromise. "
            "Historical similarity is context, not proof of a common attack. Response actions "
            "are not exposed through MCP; use the separately approval-gated FastAPI backend."
        ),
    )

    @server.tool(
        description="Read one alert and its immediate outgoing graph context. This operation is read-only.",
        structured_output=True,
    )
    def get_alert_context(
        alert_id: EntityId,
        limit: Annotated[int, Field(ge=1, le=200)] = 100,
    ) -> AlertContextResponse:
        request = AlertContextInput(alert_id=alert_id, limit=limit)
        context = graph_repository.get_alert_context(request.alert_id, request.limit)
        if context.alert is None:
            raise ValueError(f"Alert '{request.alert_id}' was not found")
        return AlertContextResponse(
            alert=_node_response(context.alert),
            nodes=[_node_response(node) for node in context.nodes],
            relationships=[_relationship_response(edge) for edge in context.relationships],
        )

    @server.tool(
        description=(
            "Trace bounded outgoing paths from an alert. Paths preserve edge direction and "
            "represent possible routes, not proof of compromise."
        ),
        structured_output=True,
    )
    def trace_attack_paths(
        alert_id: EntityId,
        max_depth: Annotated[int, Field(ge=1, le=6)] = 5,
        limit: Annotated[int, Field(ge=1, le=200)] = 100,
    ) -> AttackPathsResult:
        request = AttackPathInput(alert_id=alert_id, max_depth=max_depth, limit=limit)
        if request.max_depth > settings.max_traversal_depth:
            raise ValueError("max_depth exceeds the configured investigation limit")
        if request.limit > settings.max_returned_records:
            raise ValueError("limit exceeds the configured result limit")
        paths = graph_repository.trace_attack_paths(
            request.alert_id,
            max_depth=request.max_depth,
            limit=request.limit,
        )
        return AttackPathsResult(
            alert_id=request.alert_id,
            max_depth=request.max_depth,
            paths=[_path_response(path) for path in paths],
        )

    @server.tool(
        description=(
            "Read downstream dependencies and upstream dependent-service impact for a service. "
            "This operation does not modify service state."
        ),
        structured_output=True,
    )
    def get_service_impact(
        service_id: EntityId,
        max_depth: Annotated[int, Field(ge=1, le=6)] = 4,
        limit: Annotated[int, Field(ge=1, le=200)] = 100,
    ) -> ServiceImpactResponse:
        request = ServiceImpactInput(service_id=service_id, max_depth=max_depth, limit=limit)
        if request.max_depth > settings.max_traversal_depth:
            raise ValueError("max_depth exceeds the configured investigation limit")
        if request.limit > settings.max_returned_records:
            raise ValueError("limit exceeds the configured result limit")
        impact = graph_repository.get_service_impact(
            request.service_id,
            max_depth=request.max_depth,
            limit=request.limit,
        )
        if impact.service is None:
            raise ValueError(f"Service '{request.service_id}' was not found")
        return ServiceImpactResponse(
            service=_node_response(impact.service),
            dependencies=[_node_response(node) for node in impact.dependencies],
            dependents=[_node_response(node) for node in impact.dependents],
            dependency_paths=[_path_response(path) for path in impact.dependency_paths],
            impact_paths=[_path_response(path) for path in impact.impact_paths],
        )

    @server.tool(
        description=(
            "Retrieve evidence records by stable evidence ID, including source, timestamp, "
            "polarity, linked graph nodes, and relationship provenance. This operation is read-only."
        ),
        structured_output=True,
    )
    def get_evidence(
        evidence_ids: Annotated[list[EntityId], Field(min_length=1, max_length=50)],
        limit: Annotated[int, Field(ge=1, le=200)] = 100,
    ) -> EvidenceResult:
        request = EvidenceInput(evidence_ids=evidence_ids, limit=limit)
        if request.limit > settings.max_returned_records:
            raise ValueError("limit exceeds the configured result limit")
        records = graph_repository.get_evidence(
            request.evidence_ids,
            limit=request.limit,
        )
        return EvidenceResult(
            records=[
                EvidenceRecordResponse(
                    evidence=_node_response(record.evidence),
                    linked_nodes=[_node_response(node) for node in record.linked_nodes],
                    relationships=[
                        _relationship_response(relationship)
                        for relationship in record.relationships
                    ],
                )
                for record in records
            ]
        )

    @server.tool(
        description=(
            "Retrieve historical incidents and saved investigation episodes matching this alert "
            "by shared observed entities or event types. Each match is contextual, not proof "
            "of the same attack."
        ),
        structured_output=True,
    )
    def get_incident_memory(
        alert_id: EntityId,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
    ) -> IncidentMemoryResult:
        request = IncidentMemoryInput(alert_id=alert_id, limit=limit)
        if request.limit > settings.max_returned_records:
            raise ValueError("limit exceeds the configured result limit")
        if graph_repository.get_node("Alert", request.alert_id) is None:
            raise ValueError(f"Alert '{request.alert_id}' was not found")
        incidents = graph_repository.find_related_incidents(
            request.alert_id,
            limit=request.limit,
        )
        episodes = graph_repository.find_related_episodes(
            request.alert_id,
            limit=request.limit,
        )
        return IncidentMemoryResult(
            alert_id=request.alert_id,
            incidents=[
                HistoricalIncidentResponse(
                    incident=_node_response(item.incident),
                    shared_entity_ids=list(item.shared_entity_ids),
                    relevance_reasons=list(item.relevance_reasons),
                    supporting_evidence_ids=[node.id for node in item.supporting_evidence],
                )
                for item in incidents
            ],
            episodes=[_episode_response(item) for item in episodes],
        )

    return server


mcp = create_mcp_server()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")