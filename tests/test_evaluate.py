"""Tests for explicit evaluation baseline and unsupported-claim checks."""

from types import SimpleNamespace

from graphsentinel.evaluate import _p95, _unsupported_claims, alert_only_baseline


def test_alert_only_baseline_uses_documented_severity_mapping() -> None:
    high = alert_only_baseline({"severity": "high"})
    medium = alert_only_baseline({"severity": "medium"})

    assert high["risk_score"] == 60
    assert high["risk_level"] == "high"
    assert medium["risk_score"] == 35
    assert medium["risk_level"] == "moderate"
    assert high["graph_queries"] == medium["graph_queries"] == 0
    assert "not a calibrated" not in high["basis"]


def test_unsupported_claim_detector_ignores_explicit_negation() -> None:
    response = SimpleNamespace(
        summary="The route is only a possibility.",
        observed_facts=[],
        inferences=[SimpleNamespace(finding="The evidence does not show that it was exploited.")],
        contradictory_evidence=[],
    )

    assert _unsupported_claims(response) == []


def test_unsupported_claim_detector_reports_affirmative_compromise_claim() -> None:
    response = SimpleNamespace(
        summary="The identity was compromised.",
        observed_facts=[],
        inferences=[],
        contradictory_evidence=[],
    )

    assert _unsupported_claims(response) == ["was compromised"]


def test_p95_returns_none_for_no_queries_and_measured_rank_for_samples() -> None:
    assert _p95([]) is None
    assert _p95([1.0, 2.0, 3.0, 4.0, 100.0]) == 100.0