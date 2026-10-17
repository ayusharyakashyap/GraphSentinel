"""Strict request and structured-output models for the read-only MCP tools."""

from pydantic import Field

from graphsentinel.models import (
    AlertContextResponse,
    AttackPathResponse,
    EntityId,
    GraphNodeResponse,
    GraphRelationshipResponse,
    HistoricalEpisodeResponse,
    HistoricalIncidentResponse,
    ServiceImpactResponse,
    StrictModel,
)


class AlertContextInput(StrictModel):
    alert_id: EntityId
    limit: int = Field(default=100, ge=1, le=200)


class AttackPathInput(StrictModel):
    alert_id: EntityId
    max_depth: int = Field(default=5, ge=1, le=6)
    limit: int = Field(default=100, ge=1, le=200)


class ServiceImpactInput(StrictModel):
    service_id: EntityId
    max_depth: int = Field(default=4, ge=1, le=6)
    limit: int = Field(default=100, ge=1, le=200)


class EvidenceInput(StrictModel):
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=50)
    limit: int = Field(default=100, ge=1, le=200)


class IncidentMemoryInput(StrictModel):
    alert_id: EntityId
    limit: int = Field(default=50, ge=1, le=200)


class AttackPathsResult(StrictModel):
    alert_id: EntityId
    paths: list[AttackPathResponse] = Field(max_length=200)
    max_depth: int = Field(ge=1, le=6)


class EvidenceRecordResponse(StrictModel):
    evidence: GraphNodeResponse
    linked_nodes: list[GraphNodeResponse] = Field(max_length=200)
    relationships: list[GraphRelationshipResponse] = Field(max_length=200)


class EvidenceResult(StrictModel):
    records: list[EvidenceRecordResponse] = Field(max_length=200)


class IncidentMemoryResult(StrictModel):
    alert_id: EntityId
    incidents: list[HistoricalIncidentResponse] = Field(max_length=200)
    episodes: list[HistoricalEpisodeResponse] = Field(max_length=200)
    matching_basis: str = (
        "Shared observed entities and matching event types are contextual links, not proof of the same attack."
    )


__all__ = [
    "AlertContextInput",
    "AlertContextResponse",
    "AttackPathInput",
    "AttackPathsResult",
    "EvidenceInput",
    "EvidenceResult",
    "EvidenceRecordResponse",
    "IncidentMemoryInput",
    "IncidentMemoryResult",
    "ServiceImpactInput",
    "ServiceImpactResponse",
]