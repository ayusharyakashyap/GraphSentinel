"""FastAPI application for read-only investigation and structured results."""

import logging
import json
from typing import Annotated

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from graphsentinel.config import Settings, settings
from graphsentinel.investigator import AlertNotFoundError, Investigator
from graphsentinel.models import (
    AlertContextResponse,
    AlertListResponse,
    ActionProposalRequest,
    ApprovalRequest,
    AttackPathResponse,
    ErrorEnvelope,
    ErrorInfo,
    GraphNodeResponse,
    GraphRelationshipResponse,
    HealthResponse,
    InvestigationRequest,
    InvestigationResponse,
    HistoricalIncidentResponse,
    HistoricalEpisodeResponse,
    RejectionRequest,
    ResponseActionResponse,
    NodeLabel,
    ServiceImpactResponse,
    EntityId,
)
from graphsentinel.repository import (
    ActionStateConflict,
    GraphNode,
    GraphRepository,
    GraphRepositoryError,
    InvalidActionTransition,
    ResponseActionNotFoundError,
)
from graphsentinel.responses import ActionPolicyError, SimulatedResponseEngine

logger = logging.getLogger(__name__)


class ResourceNotFoundError(LookupError):
    def __init__(self, resource: str, identifier: str) -> None:
        self.resource = resource
        self.identifier = identifier
        super().__init__(identifier)


def _node_response(node: GraphNode) -> GraphNodeResponse:
    return GraphNodeResponse(id=node.id, label=node.label, properties=dict(node.properties))


def create_app(
    repository: GraphRepository | None = None,
    investigator: Investigator | None = None,
    configuration: Settings = settings,
) -> FastAPI:
    graph_repository = repository or (investigator.repository if investigator is not None else GraphRepository())
    investigation_service = investigator or Investigator(graph_repository, configuration)
    response_engine = SimulatedResponseEngine(graph_repository)
    app = FastAPI(
        title="GraphSentinel API",
        version="0.3.0",
        description="Evidence-grounded synthetic security investigations.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[configuration.frontend_origin],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )
    app.state.repository = graph_repository
    app.state.investigator = investigation_service
    app.state.response_engine = response_engine
    app.state.investigations: dict[str, InvestigationResponse] = {}

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        del request, error
        return JSONResponse(
            status_code=422,
            content=ErrorEnvelope(
                error=ErrorInfo(code="invalid_request", message="Request validation failed.")
            ).model_dump(),
        )

    @app.exception_handler(AlertNotFoundError)
    async def missing_alert_handler(request: Request, error: AlertNotFoundError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=404,
            content=ErrorEnvelope(
                error=ErrorInfo(code="alert_not_found", message=f"Alert '{error.args[0]}' was not found.")
            ).model_dump(),
        )

    @app.exception_handler(ResourceNotFoundError)
    async def missing_resource_handler(request: Request, error: ResourceNotFoundError) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=404,
            content=ErrorEnvelope(
                error=ErrorInfo(
                    code=f"{error.resource}_not_found",
                    message=f"{error.resource.replace('_', ' ').capitalize()} '{error.identifier}' was not found.",
                )
            ).model_dump(),
        )

    @app.exception_handler(ResponseActionNotFoundError)
    async def missing_response_action_handler(
        request: Request,
        error: ResponseActionNotFoundError,
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=404,
            content=ErrorEnvelope(
                error=ErrorInfo(
                    code="response_action_not_found",
                    message=f"Response action '{error.args[0]}' was not found.",
                )
            ).model_dump(),
        )

    @app.exception_handler(InvalidActionTransition)
    async def invalid_action_transition_handler(
        request: Request,
        error: InvalidActionTransition,
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=409,
            content=ErrorEnvelope(
                error=ErrorInfo(code="invalid_action_transition", message=str(error))
            ).model_dump(),
        )

    @app.exception_handler(ActionStateConflict)
    async def action_state_conflict_handler(
        request: Request,
        error: ActionStateConflict,
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=409,
            content=ErrorEnvelope(
                error=ErrorInfo(code="action_state_conflict", message=str(error))
            ).model_dump(),
        )

    @app.exception_handler(ActionPolicyError)
    async def action_policy_error_handler(
        request: Request,
        error: ActionPolicyError,
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=422,
            content=ErrorEnvelope(
                error=ErrorInfo(code="action_policy_violation", message=str(error))
            ).model_dump(),
        )

    @app.exception_handler(GraphRepositoryError)
    async def database_error_handler(request: Request, error: GraphRepositoryError) -> JSONResponse:
        logger.error(
            "GraphSentinel database request failed",
            extra={"path": request.url.path, "error_type": type(error).__name__},
        )
        return JSONResponse(
            status_code=503,
            content=ErrorEnvelope(
                error=ErrorInfo(code="database_unavailable", message="The graph database is unavailable.")
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, error: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled GraphSentinel API error",
            extra={"path": request.url.path, "error_type": type(error).__name__},
        )
        return JSONResponse(
            status_code=500,
            content=ErrorEnvelope(
                error=ErrorInfo(code="internal_error", message="The request could not be completed.")
            ).model_dump(),
        )

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        graph_repository.ping()
        return HealthResponse(status="ok", database="connected")

    @app.get("/alerts", response_model=AlertListResponse)
    def list_alerts(
        limit: Annotated[int, Query(ge=1, le=configuration.max_returned_records)] = min(
            100, configuration.max_returned_records
        ),
    ) -> AlertListResponse:
        return AlertListResponse(
            alerts=[_node_response(node) for node in graph_repository.list_alerts(limit)]
        )

    @app.get("/alerts/{alert_id}", response_model=AlertContextResponse)
    def get_alert(alert_id: EntityId) -> AlertContextResponse:
        context = graph_repository.get_alert_context(
            alert_id,
            configuration.max_returned_records,
        )
        if context.alert is None:
            raise AlertNotFoundError(alert_id)
        return AlertContextResponse(
            alert=_node_response(context.alert),
            nodes=[_node_response(node) for node in context.nodes],
            relationships=[
                GraphRelationshipResponse(
                    type=edge.type,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    properties=dict(edge.properties),
                )
                for edge in context.relationships
            ],
        )

    @app.get("/alerts/{alert_id}/incidents", response_model=list[HistoricalIncidentResponse])
    def related_incidents(alert_id: EntityId) -> list[HistoricalIncidentResponse]:
        if graph_repository.get_node("Alert", alert_id) is None:
            raise AlertNotFoundError(alert_id)
        matches = graph_repository.find_related_incidents(
            alert_id,
            configuration.max_returned_records,
        )
        return [
            HistoricalIncidentResponse(
                incident=_node_response(match.incident),
                shared_entity_ids=list(match.shared_entity_ids),
                relevance_reasons=list(match.relevance_reasons),
                supporting_evidence_ids=[node.id for node in match.supporting_evidence],
            )
            for match in matches
        ]

    @app.get("/alerts/{alert_id}/episodes", response_model=list[HistoricalEpisodeResponse])
    def related_episodes(alert_id: EntityId) -> list[HistoricalEpisodeResponse]:
        if graph_repository.get_node("Alert", alert_id) is None:
            raise AlertNotFoundError(alert_id)
        return [
            HistoricalEpisodeResponse(
                episode_id=match.episode.id,
                alert_id=str(match.episode.properties["alert_id"]),
                summary=str(match.episode.properties["summary"]),
                risk_score=int(match.episode.properties["risk_score"]),
                risk_level=str(match.episode.properties["risk_level"]),
                created_at=str(match.episode.properties["created_at"]),
                outcome=str(match.episode.properties["outcome"]),
                shared_entity_ids=list(match.shared_entity_ids),
                matching_event_types=list(match.matching_event_types),
                relevance_reasons=list(match.relevance_reasons),
                evidence_ids=json.loads(match.episode.properties.get("evidence_ids_json", "[]")),
            )
            for match in graph_repository.find_related_episodes(
                alert_id,
                configuration.max_returned_records,
            )
        ]

    @app.get("/graph/nodes/{label}/{node_id}", response_model=GraphNodeResponse)
    def get_graph_node(label: NodeLabel, node_id: EntityId) -> GraphNodeResponse:
        node = graph_repository.get_node(label, node_id)
        if node is None:
            raise ResourceNotFoundError("graph_node", node_id)
        return _node_response(node)

    @app.get("/services/{service_id}/impact", response_model=ServiceImpactResponse)
    def get_service_impact(
        service_id: EntityId,
        max_depth: Annotated[
            int,
            Query(ge=1, le=configuration.max_traversal_depth),
        ] = min(4, configuration.max_traversal_depth),
        limit: Annotated[
            int,
            Query(ge=1, le=configuration.max_returned_records),
        ] = min(100, configuration.max_returned_records),
    ) -> ServiceImpactResponse:
        impact = graph_repository.get_service_impact(service_id, max_depth, limit)
        if impact.service is None:
            raise ResourceNotFoundError("service", service_id)
        return ServiceImpactResponse(
            service=_node_response(impact.service),
            dependencies=[_node_response(node) for node in impact.dependencies],
            dependents=[_node_response(node) for node in impact.dependents],
            dependency_paths=[AttackPathResponse(
                nodes=[_node_response(node) for node in path.nodes],
                relationships=[
                    GraphRelationshipResponse(
                        type=edge.type,
                        source_id=edge.source_id,
                        target_id=edge.target_id,
                        properties=dict(edge.properties),
                    )
                    for edge in path.relationships
                ],
            ) for path in impact.dependency_paths],
            impact_paths=[AttackPathResponse(
                nodes=[_node_response(node) for node in path.nodes],
                relationships=[
                    GraphRelationshipResponse(
                        type=edge.type,
                        source_id=edge.source_id,
                        target_id=edge.target_id,
                        properties=dict(edge.properties),
                    )
                    for edge in path.relationships
                ],
            ) for path in impact.impact_paths],
        )

    @app.post("/investigations", response_model=InvestigationResponse)
    def start_investigation(request: InvestigationRequest) -> InvestigationResponse:
        result = investigation_service.investigate(request.alert_id)
        app.state.investigations[result.investigation_id] = result
        return result

    @app.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
    def get_investigation(investigation_id: EntityId) -> InvestigationResponse:
        episode = graph_repository.get_investigation_episode(investigation_id)
        if episode is None:
            raise ResourceNotFoundError("investigation", investigation_id)
        try:
            return InvestigationResponse.model_validate_json(episode.properties["result_json"])
        except (KeyError, ValueError) as error:
            raise GraphRepositoryError("Stored investigation result is invalid") from error

    @app.post(
        "/investigations/{investigation_id}/response-actions",
        response_model=ResponseActionResponse,
    )
    def propose_response_action(
        investigation_id: EntityId,
        request: ActionProposalRequest,
    ) -> ResponseActionResponse:
        return response_engine.propose(investigation_id, request)

    @app.get("/response-actions/{action_id}", response_model=ResponseActionResponse)
    def get_response_action(action_id: EntityId) -> ResponseActionResponse:
        return response_engine.get(action_id)

    @app.post("/response-actions/{action_id}/approve", response_model=ResponseActionResponse)
    def approve_response_action(
        action_id: EntityId,
        request: ApprovalRequest,
    ) -> ResponseActionResponse:
        return response_engine.approve(action_id, request.approved_by)

    @app.post("/response-actions/{action_id}/reject", response_model=ResponseActionResponse)
    def reject_response_action(
        action_id: EntityId,
        request: RejectionRequest,
    ) -> ResponseActionResponse:
        return response_engine.reject(action_id, request.rejected_by, request.reason)

    @app.post("/response-actions/{action_id}/execute", response_model=ResponseActionResponse)
    def execute_response_action(action_id: EntityId) -> ResponseActionResponse:
        return response_engine.execute(action_id)

    @app.post("/response-actions/{action_id}/verify", response_model=ResponseActionResponse)
    def verify_response_action(action_id: EntityId) -> ResponseActionResponse:
        return response_engine.verify(action_id)

    return app


app = create_app()