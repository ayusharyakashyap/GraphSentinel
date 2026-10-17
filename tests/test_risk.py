"""Unit and live-fixture coverage for deterministic risk scoring."""

from graphsentinel.repository import (
    AlertContext,
    EvidenceRecord,
    GraphNode,
    GraphRepository,
)
from graphsentinel.risk import calculate_risk
from graphsentinel.seed import connect_graph, load_fixture, seed_graph


def _record(
    identifier: str,
    evidence_type: str,
    supports: bool,
    confidence: float,
    linked_nodes: tuple[GraphNode, ...] = (),
) -> EvidenceRecord:
    evidence = GraphNode(
        id=identifier,
        label="Evidence",
        properties={
            "id": identifier,
            "evidence_type": evidence_type,
            "supports_finding": supports,
            "confidence": confidence,
            "timestamp": "2026-10-15T09:00:00Z",
            "source": "unit-test",
        },
    )
    return EvidenceRecord(evidence, linked_nodes, ())


def _context(
    nodes: tuple[GraphNode, ...] = (),
    timestamp: str = "2026-10-15T10:00:00Z",
) -> AlertContext:
    alert = GraphNode(
        id="test-alert",
        label="Alert",
        properties={"id": "test-alert", "timestamp": timestamp},
    )
    return AlertContext(alert, nodes, ())


def test_duplicate_evidence_does_not_change_score_or_confidence() -> None:
    context = _context()
    records = [_record("ev-auth", "authentication", True, 0.96)]

    original = calculate_risk(context, (), records)
    duplicated = calculate_risk(context, (), [*records, *records])

    assert duplicated == original


def test_missing_evidence_does_not_increase_risk() -> None:
    assessment = calculate_risk(_context(), (), ())

    assert assessment.risk_score == 0
    assert assessment.confidence == 0
    assert assessment.evidence_completeness == 0
    assert "authentication" in assessment.missing_evidence
    assert assessment.factors == ()


def test_contradictory_evidence_reduces_risk_and_is_linked() -> None:
    context = _context()
    supporting = _record("ev-auth", "authentication", True, 0.96)
    contradictory = _record("ev-denied", "access_control", False, 0.92)

    baseline = calculate_risk(context, (), [supporting])
    with_contradiction = calculate_risk(context, (), [supporting, contradictory])

    assert baseline.risk_score == 20
    assert with_contradiction.risk_score == 10
    factor = next(item for item in with_contradiction.factors if item.score < 0)
    assert factor.evidence_ids == ("ev-denied",)
    assert with_contradiction.contradictory_evidence_ids == ("ev-denied",)


def test_conflicting_duplicate_evidence_id_is_rejected() -> None:
    first = _record("ev-duplicate", "authentication", True, 0.96)
    second = _record("ev-duplicate", "authentication", True, 0.2)

    try:
        calculate_risk(_context(), (), [first, second])
    except ValueError as error:
        assert "Conflicting records" in str(error)
    else:
        raise AssertionError("Conflicting evidence under a stable ID must be rejected")


def test_live_high_and_low_risk_scenarios_are_materially_different() -> None:
    seed_graph(connect_graph(), load_fixture())
    repository = GraphRepository(connect_graph())

    def assess(alert_id: str):
        context = repository.get_alert_context(alert_id)
        assert context.alert is not None
        evidence_ids = [
            node.id for node in context.nodes
            if node.label == "Evidence"
        ]
        evidence = repository.get_evidence(evidence_ids)
        paths = repository.trace_attack_paths(alert_id, max_depth=6)
        return calculate_risk(context, paths, evidence)

    high = assess("alert-2026-1015-001")
    low = assess("alert-2026-1015-002")

    assert high.risk_score == 85
    assert high.risk_level == "critical"
    assert low.risk_score == 0
    assert low.risk_level == "low"
    assert high.risk_score - low.risk_score >= 50
    assert "ev-noah-denied" in low.contradictory_evidence_ids
    assert high.evidence_completeness > low.evidence_completeness
    assert all(
        factor.evidence_ids
        for factor in high.factors
        if factor.score > 0
    )