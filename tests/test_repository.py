"""Live FalkorDB tests for bounded repository queries and provenance."""

from uuid import uuid4

from graphsentinel.investigator import Investigator
from graphsentinel.repository import GraphRepository
from graphsentinel.seed import connect_graph, load_fixture, seed_graph


def repository() -> GraphRepository:
    seed_graph(connect_graph(), load_fixture())
    return GraphRepository(connect_graph())


def test_trace_reconstructs_both_expected_fixture_paths() -> None:
    graph_repository = repository()
    fixture = load_fixture()

    for expected in fixture["expected_paths"]:
        paths = graph_repository.trace_attack_paths(expected["alert_id"], max_depth=6)
        signature = (tuple(expected["node_ids"]), tuple(expected["relationship_types"]))
        actual = {
            (
                tuple(node.id for node in path.nodes),
                tuple(relationship.type for relationship in path.relationships),
            )
            for path in paths
        }
        assert signature in actual


def test_context_and_queries_handle_missing_records() -> None:
    graph_repository = repository()

    assert graph_repository.get_alert_context("missing-alert").alert is None
    assert graph_repository.trace_attack_paths("missing-alert") == ()
    assert graph_repository.get_service_impact("missing-service").service is None
    assert graph_repository.find_related_incidents("alert-2026-1015-002") == ()
    assert graph_repository.get_evidence([]) == ()
    assert graph_repository.get_evidence(["missing-evidence"]) == ()


def test_service_dependency_and_impact_direction() -> None:
    impact = repository().get_service_impact("svc-deploy", max_depth=4)

    assert {node.id for node in impact.dependencies} == {
        "svc-artifact", "svc-payments", "svc-identity",
    }
    assert {node.id for node in impact.dependents} == set()
    assert any(
        [edge.source_id, edge.target_id] == ["svc-deploy", "svc-artifact"]
        for path in impact.dependency_paths
        for edge in path.relationships
    )

    reverse_impact = repository().get_service_impact("svc-payments", max_depth=4)
    assert {node.id for node in reverse_impact.dependents} == {"svc-deploy", "svc-artifact"}


def test_historical_incidents_include_shared_entity_reasons_and_evidence() -> None:
    incidents = repository().find_related_incidents("alert-2026-1015-001")
    by_id = {match.incident.id: match for match in incidents}

    assert "inc-2026-044" in by_id
    match = by_id["inc-2026-044"]
    assert {"id-ava-chen", "dev-ava-laptop"}.issubset(match.shared_entity_ids)
    assert all("not proof" in reason for reason in match.relevance_reasons)
    assert "ev-no-prod-write" in {item.id for item in match.supporting_evidence}


def test_evidence_provenance_preserves_sources_times_and_graph_links() -> None:
    evidence = repository().get_evidence(["ev-config-change"])

    assert len(evidence) == 1
    record = evidence[0]
    assert record.evidence.properties["source"] == "synthetic-change-log"
    assert record.evidence.properties["timestamp"] == "2026-10-15T08:55:00Z"
    assert {node.id for node in record.linked_nodes} >= {
        "svc-deploy", "alert-2026-1015-001", "inc-2026-031",
    }
    assert {relationship.type for relationship in record.relationships} >= {
        "ABOUT", "HAS_EVIDENCE", "SUPPORTED_BY",
    }


def test_traversals_reject_unbounded_arguments() -> None:
    graph_repository = repository()

    try:
        graph_repository.trace_attack_paths("alert-2026-1015-001", max_depth=100)
    except ValueError as error:
        assert "max_depth" in str(error)
    else:
        raise AssertionError("max_depth beyond the hard limit must be rejected")

    try:
        graph_repository.get_alert_context("alert-2026-1015-001", limit=201)
    except ValueError as error:
        assert "limit" in str(error)
    else:
        raise AssertionError("limit beyond the hard limit must be rejected")


def test_investigation_episode_survives_repository_reconnection() -> None:
    graph_repository = repository()
    result = Investigator(graph_repository).investigate("alert-2026-1015-001")
    result.investigation_id = f"episode-test-{uuid4()}"

    saved = graph_repository.save_investigation_episode(result.model_dump(mode="json"))
    reconnected_repository = GraphRepository(connect_graph())
    loaded = reconnected_repository.get_investigation_episode(saved.id)
    related = reconnected_repository.find_related_episodes("alert-2026-1015-001")
    match = next(item for item in related if item.episode.id == saved.id)

    assert loaded is not None
    assert loaded.properties["result_json"]
    assert {"id-ava-chen", "dev-ava-laptop"}.issubset(match.shared_entity_ids)
    assert "successful_login" in match.matching_event_types
    assert any("not proof" in reason for reason in match.relevance_reasons)
    evidence_link = reconnected_repository._query(
        "MATCH (episode:InvestigationEpisode {id: $episode_id}) "
        "-[:HAS_EVIDENCE]->(evidence:Evidence {id: $evidence_id}) "
        "RETURN count(evidence)",
        {"episode_id": saved.id, "evidence_id": "ev-geo-ava"},
    )
    assert evidence_link[0][0] == 1