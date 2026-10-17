"""FastAPI integration tests using the live synthetic FalkorDB graph."""

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from graphsentinel.api import create_app
from graphsentinel.config import settings
from graphsentinel.investigator import Investigator
from graphsentinel.repository import GraphRepository
from graphsentinel.seed import connect_graph, load_fixture, seed_graph


@pytest.fixture
def api_client() -> tuple[TestClient, GraphRepository]:
    seed_graph(connect_graph(), load_fixture())
    repository = GraphRepository(connect_graph())
    configuration = replace(settings, llm_api_key=None, llm_base_url=None)
    investigator = Investigator(repository, configuration)
    return TestClient(create_app(repository, investigator, configuration)), repository


def test_api_health_alerts_and_context_are_live_graph_data(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, _ = api_client

    assert client.get("/health").json() == {"status": "ok", "database": "connected"}
    alerts = client.get("/alerts").json()["alerts"]
    assert len(alerts) >= 5
    context = client.get("/alerts/alert-2026-1015-001").json()
    assert context["alert"]["id"] == "alert-2026-1015-001"
    assert any(node["id"] == "id-ava-chen" for node in context["nodes"])
    graph_node = client.get("/graph/nodes/Identity/id-ava-chen")
    assert graph_node.status_code == 200
    assert graph_node.json()["properties"]["privilege_level"] == "admin"
    impact = client.get("/services/svc-deploy/impact")
    assert impact.status_code == 200
    assert {node["id"] for node in impact.json()["dependencies"]} == {
        "svc-artifact", "svc-payments", "svc-identity",
    }
    local_preflight = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    foreign_preflight = client.options(
        "/health",
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert local_preflight.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in foreign_preflight.headers


def test_high_risk_api_investigation_is_cited_and_recommendation_only(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, repository = api_client
    device_before = repository.get_node("Device", "dev-ava-laptop")
    response = client.post(
        "/investigations",
        json={"alert_id": "alert-2026-1015-001"},
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["mode"] == "fallback"
    assert "not LLM-driven" in result["limitations"][0]
    assert result["risk_score"] == 85
    assert result["risk_level"] == "critical"
    assert result["observed_facts"]
    assert all(finding["evidence_ids"] for finding in result["observed_facts"])
    assert all(factor["evidence_ids"] for factor in result["risk_factors"] if factor["score"] > 0)
    assert result["recommended_action"]["action_type"] == "temporary_identity_restriction"
    assert result["recommended_action"]["execution_mode"] == "recommendation_only"
    assert client.get(f"/investigations/{result['investigation_id']}").json() == result
    remembered = client.get("/alerts/alert-2026-1015-001/episodes")
    assert remembered.status_code == 200
    assert result["investigation_id"] in {item["episode_id"] for item in remembered.json()}
    restarted_client = TestClient(
        create_app(
            GraphRepository(connect_graph()),
            Investigator(
                GraphRepository(connect_graph()),
                replace(settings, llm_api_key=None, llm_base_url=None),
            ),
            replace(settings, llm_api_key=None, llm_base_url=None),
        )
    )
    assert restarted_client.get(f"/investigations/{result['investigation_id']}").json() == result
    assert repository.get_node("Device", "dev-ava-laptop") == device_before


def test_low_risk_api_investigation_reports_counterevidence(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, _ = api_client
    response = client.post(
        "/investigations",
        json={"alert_id": "alert-2026-1015-002"},
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["mode"] == "fallback"
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert {item["evidence_ids"][0] for item in result["contradictory_evidence"]} >= {
        "ev-noah-healthy-device", "ev-noah-denied",
    }
    assert result["recommended_action"]["action_type"] == "monitor_only"


def test_api_validation_and_missing_resources_use_error_envelopes(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, _ = api_client

    invalid = client.post(
        "/investigations",
        json={"alert_id": "alert-2026-1015-001", "extra": "rejected"},
    )
    missing_alert = client.post("/investigations", json={"alert_id": "missing-alert"})
    missing_result = client.get("/investigations/missing-investigation")
    invalid_path_id = client.get("/alerts/not%20a%20stable%20id")
    unbounded_impact = client.get("/services/svc-deploy/impact?max_depth=99")

    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_request"
    assert missing_alert.status_code == 404
    assert missing_alert.json()["error"]["code"] == "alert_not_found"
    assert missing_result.status_code == 404
    assert missing_result.json()["error"]["code"] == "investigation_not_found"
    assert invalid_path_id.status_code == 422
    assert unbounded_impact.status_code == 422


def test_related_incidents_endpoint_explains_shared_entities(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, _ = api_client
    response = client.get("/alerts/alert-2026-1015-001/incidents")

    assert response.status_code == 200
    matches = {item["incident"]["id"]: item for item in response.json()}
    assert "inc-2026-044" in matches
    assert "dev-ava-laptop" in matches["inc-2026-044"]["shared_entity_ids"]
    assert all("not proof" in reason for reason in matches["inc-2026-044"]["relevance_reasons"])


def test_api_requires_approval_before_simulated_execution(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, repository = api_client
    identity_before = repository.get_node("Identity", "id-ava-chen")
    assert identity_before is not None
    investigation = client.post(
        "/investigations",
        json={"alert_id": "alert-2026-1015-001"},
    ).json()
    proposal = client.post(
        f"/investigations/{investigation['investigation_id']}/response-actions",
        json={
            "action_type": "temporary_identity_restriction",
            "target_entity_id": "id-ava-chen",
            "justification": "Restrict the privileged identity while its unusual login is reviewed.",
            "evidence_ids": ["ev-geo-ava", "ev-privilege-ava"],
        },
    )
    assert proposal.status_code == 200, proposal.text
    action_id = proposal.json()["id"]

    blocked = client.post(f"/response-actions/{action_id}/execute")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "invalid_action_transition"
    assert client.get(f"/response-actions/{action_id}").json()["status"] == "PROPOSED"

    approved = client.post(
        f"/response-actions/{action_id}/approve",
        json={"approved_by": "demo-analyst"},
    )
    executed = client.post(f"/response-actions/{action_id}/execute")
    verified = client.post(f"/response-actions/{action_id}/verify")

    assert approved.json()["status"] == "APPROVED"
    assert executed.json()["status"] == "EXECUTED_SIMULATED"
    assert verified.json()["status"] == "VERIFIED"
    assert verified.json()["simulated"] is True
    assert [event["to_state"] for event in verified.json()["audit_events"]] == [
        "PROPOSED", "APPROVED", "EXECUTED_SIMULATED", "VERIFIED",
    ]
    target = GraphRepository(connect_graph()).get_node("Identity", "id-ava-chen")
    assert target is not None
    assert target.properties["simulation_state"] == "RESTRICTED"
    original_properties = {
        key: value for key, value in identity_before.properties.items()
        if not key.startswith("simulation_")
    }
    final_properties = {
        key: value for key, value in target.properties.items()
        if not key.startswith("simulation_")
    }
    assert final_properties == original_properties


def test_api_rejection_is_terminal_and_action_remains_audited(
    api_client: tuple[TestClient, GraphRepository],
) -> None:
    client, repository = api_client
    target_before = repository.get_node("Identity", "id-ava-chen")
    assert target_before is not None
    investigation = client.post(
        "/investigations",
        json={"alert_id": "alert-2026-1015-001"},
    ).json()
    proposed = client.post(
        f"/investigations/{investigation['investigation_id']}/response-actions",
        json={
            "action_type": "temporary_identity_restriction",
            "target_entity_id": "id-ava-chen",
            "justification": "Restrict the privileged identity while its unusual login is reviewed.",
            "evidence_ids": ["ev-privilege-ava"],
        },
    ).json()

    rejected = client.post(
        f"/response-actions/{proposed['id']}/reject",
        json={"rejected_by": "demo-analyst", "reason": "Analyst rejected containment after review."},
    )
    execute = client.post(f"/response-actions/{proposed['id']}/execute")

    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert [event["to_state"] for event in rejected.json()["audit_events"]] == [
        "PROPOSED", "REJECTED",
    ]
    assert execute.status_code == 409
    target = repository.get_node("Identity", "id-ava-chen")
    assert target is not None
    assert target.properties.get("simulation_state") == target_before.properties.get("simulation_state")
    assert target.properties.get("simulation_version", 0) == target_before.properties.get("simulation_version", 0)