"""Tool-calling investigator tests with deterministic fake model responses."""

from dataclasses import replace
from types import SimpleNamespace

from graphsentinel.config import settings
from graphsentinel.investigator import Investigator
from graphsentinel.repository import (
    AlertContext,
    EvidenceRecord,
    GraphNode,
    GraphRepository,
    HistoricalIncident,
)
from graphsentinel.risk import RiskAssessment, RiskFactor
from graphsentinel.seed import connect_graph, load_fixture, seed_graph


def _tool_call(name: str, arguments: str, call_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _message(content: str | None = None, tool_calls: list[SimpleNamespace] | None = None) -> SimpleNamespace:
    return SimpleNamespace(content=content, tool_calls=tool_calls)


class FakeCompletions:
    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self.responses = responses
        self.requests: list[dict] = []

    def create(self, **request: object) -> SimpleNamespace:
        self.requests.append(request)
        return self.responses[len(self.requests) - 1]


class FakeClient:
    def __init__(self, responses: list[SimpleNamespace]) -> None:
        self.completions = FakeCompletions(responses)
        self.chat = SimpleNamespace(completions=self.completions)


def _response(message: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _final_message() -> SimpleNamespace:
    return _message(
        '{"summary":"An unusual privileged login is linked to a possible service path; exploitation is not established.",'
        '"inferences":[{"finding":"The graph shows a potential route, not proof of exploitation.","evidence_ids":["ev-geo-ava"]}],'
        '"action_type":"temporary_identity_restriction","target_entity_id":"id-ava-chen",'
        '"rationale":"Temporarily restrict the privileged identity while an analyst validates the login and change.",'
        '"evidence_ids":["ev-geo-ava"]}'
    )


def _setup(client: FakeClient, max_tool_calls: int = 3) -> Investigator:
    seed_graph(connect_graph(), load_fixture())
    configuration = replace(
        settings,
        llm_api_key="test-key",
        llm_base_url="https://example.invalid/v1",
        max_tool_calls=max_tool_calls,
    )
    return Investigator(GraphRepository(connect_graph()), configuration, client)


def test_model_inspects_real_tool_outputs_and_obeys_call_limit() -> None:
    client = FakeClient(
        [
            _response(_message(tool_calls=[_tool_call("get_alert_context", "{}", "call-1")])),
            _response(_message(tool_calls=[_tool_call(
                "trace_attack_paths",
                '{"max_depth":5,"limit":100}',
                "call-2",
            )])),
            _response(_message(tool_calls=[_tool_call(
                "get_evidence",
                '{"evidence_ids":["ev-geo-ava"],"limit":100}',
                "call-3",
            )])),
            _response(_final_message()),
        ]
    )
    investigator = _setup(client, max_tool_calls=3)

    result = investigator.investigate("alert-2026-1015-001")

    assert result.mode == "llm"
    assert result.risk_score == 85
    assert [call.tool_name for call in result.tool_calls] == [
        "get_alert_context", "trace_attack_paths", "get_evidence",
    ]
    assert len(result.tool_calls) == 3
    assert client.completions.requests[-1]["tool_choice"] == "none"
    allowed = {
        tool["function"]["name"]
        for tool in client.completions.requests[0]["tools"]
    }
    assert allowed == {
        "get_alert_context", "trace_attack_paths", "get_service_impact",
        "find_related_incidents", "find_related_episodes", "get_evidence",
    }
    assert any(
        message.get("role") == "tool" and "alert-2026-1015-001" in message.get("content", "")
        for message in client.completions.requests[-1]["messages"]
    )


def test_unregistered_command_is_never_executed() -> None:
    client = FakeClient(
        [_response(_message(tool_calls=[_tool_call("run_cypher", '{"query":"MATCH (n) DELETE n"}', "bad-1")]))]
    )
    investigator = _setup(client)

    result = investigator.investigate("alert-2026-1015-001")

    assert result.mode == "fallback"
    assert "not an LLM-driven result" in result.limitations[0]
    names = {tool["function"]["name"] for tool in client.completions.requests[0]["tools"]}
    assert "run_cypher" not in names
    assert len(client.completions.requests) == 1


def test_model_api_failure_uses_honestly_labeled_fallback() -> None:
    class FailingCompletions:
        def create(self, **request: object) -> SimpleNamespace:
            del request
            raise TimeoutError("test timeout")

    client = SimpleNamespace(chat=SimpleNamespace(completions=FailingCompletions()))
    investigator = _setup(client)

    result = investigator.investigate("alert-2026-1015-002")

    assert result.mode == "fallback"
    assert "not an LLM-driven result" in result.limitations[0]
    assert result.risk_score == 0


def test_historical_evidence_is_not_misattributed_to_current_alert() -> None:
    alert = GraphNode(
        id="alert-current",
        label="Alert",
        properties={"id": "alert-current", "timestamp": "2026-10-15T10:00:00Z"},
    )
    incident = GraphNode(
        id="incident-history",
        label="Incident",
        properties={"id": "incident-history", "created_at": "2026-09-01T00:00:00Z"},
    )
    old_evidence = GraphNode(
        id="evidence-history-only",
        label="Evidence",
        properties={
            "id": "evidence-history-only",
            "evidence_type": "authentication",
            "supports_finding": True,
            "confidence": 1.0,
            "timestamp": "2026-09-01T00:00:00Z",
            "source": "historical-test",
            "description": "Evidence from a prior, separate incident.",
        },
    )
    historical = HistoricalIncident(
        incident=incident,
        shared_entity_ids=("shared-device",),
        relevance_reasons=("Shares device shared-device; contextual only.",),
        supporting_evidence=(old_evidence,),
    )

    class HistoricalOnlyRepository:
        def with_timeout_provider(self, provider):
            del provider
            return self

        def get_alert_context(self, alert_id, limit):
            del alert_id, limit
            return AlertContext(alert, (), ())

        def trace_attack_paths(self, alert_id, max_depth, limit):
            del alert_id, max_depth, limit
            return ()

        def find_related_incidents(self, alert_id, limit):
            del alert_id, limit
            return (historical,)

        def find_related_episodes(self, alert_id, limit):
            del alert_id, limit
            return ()

        def get_evidence(self, evidence_ids, limit):
            del limit
            assert not evidence_ids
            return ()

        def save_investigation_episode(self, result):
            return GraphNode(
                id=result["investigation_id"],
                label="InvestigationEpisode",
                properties={"id": result["investigation_id"]},
            )

    configuration = replace(settings, llm_api_key=None, llm_base_url=None)
    result = Investigator(HistoricalOnlyRepository(), configuration).investigate("alert-current")

    assert result.risk_score == 0
    assert result.confidence == 0
    assert result.observed_facts == []
    assert result.historical_incidents[0].supporting_evidence_ids == ["evidence-history-only"]


def test_fallback_inference_trims_related_nodes_before_schema_validation() -> None:
    path_nodes = tuple(f"node-{index}" for index in range(25))
    candidate_nodes = tuple(
        GraphNode(
            id=node_id,
            label="Identity" if index % 2 == 0 else "Service",
            properties={"id": node_id, "name": node_id},
        )
        for index, node_id in enumerate(path_nodes)
    )
    risk = RiskAssessment(
        risk_score=85,
        risk_level="critical",
        confidence=0.9,
        evidence_completeness=1.0,
        factors=(
            RiskFactor(
                name="potential_vulnerable_service_path",
                score=15,
                explanation="Possible vulnerable service route.",
                evidence_ids=("ev-vuln-scan",),
                path_node_ids=path_nodes,
            ),
        ),
        contradictory_evidence_ids=(),
        missing_evidence=(),
    )
    evidence = EvidenceRecord(
        evidence=GraphNode(
            id="ev-vuln-scan",
            label="Evidence",
            properties={
                "id": "ev-vuln-scan",
                "evidence_type": "vulnerability_inventory",
                "supports_finding": True,
                "description": "Vulnerability evidence.",
                "source": "synthetic",
                "timestamp": "2026-10-15T12:00:00Z",
                "confidence": 0.9,
            },
        ),
        linked_nodes=candidate_nodes,
        relationships=(),
    )

    result = Investigator._fallback_inferences(risk, {"ev-vuln-scan": evidence})

    assert len(result) == 1
    assert len(result[0].related_node_ids) <= 20
    assert result[0].related_node_ids[0] == "node-0"
    assert "node-24" in result[0].related_node_ids


def test_second_investigation_uses_episode_after_repository_reconnection() -> None:
    seed_graph(connect_graph(), load_fixture())
    first_repository = GraphRepository(connect_graph())
    configuration = replace(settings, llm_api_key=None, llm_base_url=None)
    first = Investigator(first_repository, configuration).investigate("alert-2026-1015-001")

    second_repository = GraphRepository(connect_graph())
    second = Investigator(second_repository, configuration).investigate("alert-2026-1015-001")
    remembered = {episode.episode_id: episode for episode in second.historical_episodes}

    assert first.investigation_id in remembered
    prior = remembered[first.investigation_id]
    assert {"id-ava-chen", "dev-ava-laptop"}.issubset(prior.shared_entity_ids)
    assert "successful_login" in prior.matching_event_types
    assert any("not proof" in reason for reason in prior.relevance_reasons)
    assert "saved investigation episodes" in second.summary