"""Phase 1 fixture validation and live FalkorDB seed smoke tests."""

from collections import Counter

import pytest

from graphsentinel.seed import connect_graph, load_fixture, seed_graph


def test_fixture_has_required_demo_coverage() -> None:
    fixture = load_fixture()
    labels = Counter(node["label"] for node in fixture["nodes"])
    evidence_and_events = labels["Evidence"] + labels["Event"]

    assert sum(labels[label] for label in ("Identity", "Device", "Service")) >= 15
    assert labels["Alert"] >= 5
    assert evidence_and_events >= 20
    assert len(fixture["expected_paths"]) >= 2


def test_seed_is_idempotent_in_falkordb() -> None:
    fixture = load_fixture()
    graph = connect_graph()
    first = seed_graph(graph, fixture)
    second = seed_graph(graph, fixture)

    assert first == second
    assert first["nodes"] >= len(fixture["nodes"])
    assert first["relationships"] >= len(fixture["relationships"])


@pytest.fixture(scope="session", autouse=True)
def require_falkordb() -> None:
    try:
        connect_graph().query("RETURN 1")
    except Exception as error:
        pytest.fail(f"FalkorDB is not reachable; start it with docker compose up -d: {error}")