"""Strict API and structured investigator schemas."""

from typing import Any, Literal
from typing_extensions import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

EntityId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    ),
]

NodeLabel = Literal[
    "Identity", "Device", "Service", "Alert", "Event", "Vulnerability",
    "Incident", "Evidence", "ResponseAction", "InvestigationEpisode", "ActionAudit",
]
ToolName = Literal[
    "get_alert_context", "trace_attack_paths", "get_service_impact",
    "find_related_incidents", "find_related_episodes", "get_evidence",
]
RecommendationType = Literal[
    "temporary_identity_restriction", "device_isolation", "configuration_rollback",
    "vulnerability_remediation", "monitor_only",
]
SimulatedActionType = Literal[
    "temporary_identity_restriction", "device_isolation",
    "configuration_rollback", "vulnerability_remediation",
]
RiskLevel = Literal["low", "moderate", "high", "critical"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class InvestigationRequest(StrictModel):
    alert_id: EntityId


class GraphNodeResponse(StrictModel):
    id: EntityId
    label: NodeLabel
    properties: dict[str, Any]


class GraphRelationshipResponse(StrictModel):
    type: str = Field(min_length=1, max_length=64)
    source_id: EntityId
    target_id: EntityId
    properties: dict[str, Any]


class AttackPathResponse(StrictModel):
    nodes: list[GraphNodeResponse] = Field(min_length=2, max_length=7)
    relationships: list[GraphRelationshipResponse] = Field(min_length=1, max_length=6)

    @model_validator(mode="after")
    def validate_directed_path(self) -> "AttackPathResponse":
        if len(self.relationships) != len(self.nodes) - 1:
            raise ValueError("A path must have exactly one relationship between adjacent nodes")
        for index, relationship in enumerate(self.relationships):
            if (
                relationship.source_id != self.nodes[index].id
                or relationship.target_id != self.nodes[index + 1].id
            ):
                raise ValueError("Path relationship direction must match its ordered nodes")
        return self


class EvidenceFinding(StrictModel):
    finding: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=20)
    related_node_ids: list[EntityId] = Field(default_factory=list, max_length=20)
    source: str | None = Field(default=None, max_length=200)
    timestamp: str | None = Field(default=None, max_length=64)


class RiskFactorResponse(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    score: int = Field(ge=-100, le=100)
    explanation: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=20)
    path_node_ids: list[EntityId] = Field(default_factory=list, max_length=20)


class HistoricalIncidentResponse(StrictModel):
    incident: GraphNodeResponse
    shared_entity_ids: list[EntityId] = Field(max_length=100)
    relevance_reasons: list[str] = Field(max_length=100)
    supporting_evidence_ids: list[EntityId] = Field(max_length=100)


class HistoricalEpisodeResponse(StrictModel):
    episode_id: EntityId
    alert_id: EntityId
    summary: str = Field(min_length=1, max_length=2000)
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    created_at: str = Field(min_length=1, max_length=64)
    outcome: str = Field(min_length=1, max_length=64)
    shared_entity_ids: list[EntityId] = Field(max_length=100)
    matching_event_types: list[str] = Field(max_length=100)
    relevance_reasons: list[str] = Field(max_length=100)
    evidence_ids: list[EntityId] = Field(max_length=100)


class RecommendationResponse(StrictModel):
    action_type: RecommendationType
    target_entity_id: EntityId | None
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[EntityId] = Field(max_length=20)
    execution_mode: Literal["recommendation_only"] = "recommendation_only"


class ToolCallResponse(StrictModel):
    tool_name: ToolName
    arguments: dict[str, Any]
    result_summary: str = Field(min_length=1, max_length=500)
    status: Literal["succeeded", "rejected", "failed"]


class AlertListResponse(StrictModel):
    alerts: list[GraphNodeResponse] = Field(max_length=200)


class AlertContextResponse(StrictModel):
    alert: GraphNodeResponse
    nodes: list[GraphNodeResponse] = Field(max_length=200)
    relationships: list[GraphRelationshipResponse] = Field(max_length=200)


class ServiceImpactResponse(StrictModel):
    service: GraphNodeResponse
    dependencies: list[GraphNodeResponse] = Field(max_length=200)
    dependents: list[GraphNodeResponse] = Field(max_length=200)
    dependency_paths: list[AttackPathResponse] = Field(max_length=200)
    impact_paths: list[AttackPathResponse] = Field(max_length=200)


class HealthResponse(StrictModel):
    status: Literal["ok"]
    database: Literal["connected"]


class ErrorInfo(StrictModel):
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=500)


class ErrorEnvelope(StrictModel):
    error: ErrorInfo


class InvestigationResponse(StrictModel):
    investigation_id: EntityId
    alert_id: EntityId
    summary: str = Field(min_length=1, max_length=2000)
    mode: Literal["llm", "fallback"]
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(ge=0, le=1)
    evidence_completeness: float = Field(ge=0, le=1)
    observed_facts: list[EvidenceFinding] = Field(max_length=200)
    inferences: list[EvidenceFinding] = Field(max_length=100)
    contradictory_evidence: list[EvidenceFinding] = Field(max_length=100)
    missing_evidence: list[str] = Field(max_length=20)
    risk_factors: list[RiskFactorResponse] = Field(max_length=20)
    attack_paths: list[AttackPathResponse] = Field(max_length=200)
    affected_services: list[GraphNodeResponse] = Field(max_length=200)
    historical_incidents: list[HistoricalIncidentResponse] = Field(max_length=100)
    historical_episodes: list[HistoricalEpisodeResponse] = Field(default_factory=list, max_length=100)
    recommended_action: RecommendationResponse
    tool_calls: list[ToolCallResponse] = Field(max_length=20)
    limitations: list[str] = Field(max_length=20)


class ActionProposalRequest(StrictModel):
    action_type: SimulatedActionType
    target_entity_id: EntityId
    justification: str = Field(min_length=6, max_length=1000)
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=20)


class ApprovalRequest(StrictModel):
    approved_by: str = Field(min_length=2, max_length=120)


class RejectionRequest(StrictModel):
    rejected_by: str = Field(min_length=2, max_length=120)
    reason: str = Field(min_length=3, max_length=1000)


class AuditEventResponse(StrictModel):
    id: EntityId
    event_type: str = Field(min_length=1, max_length=64)
    from_state: str = Field(min_length=1, max_length=64)
    to_state: str = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=120)
    timestamp: str = Field(min_length=1, max_length=64)
    details: dict[str, Any]


class ResponseActionResponse(StrictModel):
    id: EntityId
    investigation_id: EntityId
    action_type: SimulatedActionType
    target_entity_id: EntityId
    justification: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=20)
    status: Literal[
        "PROPOSED", "APPROVED", "REJECTED", "EXECUTED_SIMULATED", "VERIFIED",
    ]
    approval_status: Literal["PENDING", "APPROVED", "REJECTED"]
    verification_status: Literal["PENDING", "PASSED", "FAILED"]
    previous_state: str = Field(min_length=1, max_length=100)
    proposed_state: str = Field(min_length=1, max_length=100)
    result: str = Field(max_length=1000)
    verification_result: str = Field(max_length=1000)
    approved_by: str = Field(max_length=120)
    created_at: str = Field(min_length=1, max_length=64)
    executed_at: str | None = Field(default=None, max_length=64)
    verified_at: str | None = Field(default=None, max_length=64)
    simulated: Literal[True] = True
    audit_events: list[AuditEventResponse] = Field(max_length=100)


class FindingDraft(StrictModel):
    finding: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=10)


class NarrativeDraft(StrictModel):
    summary: str = Field(min_length=1, max_length=1200)
    inferences: list[FindingDraft] = Field(max_length=20)
    action_type: RecommendationType
    target_entity_id: EntityId | None
    rationale: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[EntityId] = Field(min_length=1, max_length=10)


class ToolResult(StrictModel):
    """Validated envelope returned by a read-only investigation tool."""

    result: dict[str, Any]