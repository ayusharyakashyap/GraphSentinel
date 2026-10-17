"""Measure the checked-in synthetic investigation scenarios against live FalkorDB."""

import argparse
import json
import re
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from dataclasses import replace

from graphsentinel.config import settings
from graphsentinel.investigator import Investigator
from graphsentinel.repository import GraphRepository
from graphsentinel.responses import SimulatedResponseEngine
from graphsentinel.models import ActionProposalRequest
from graphsentinel.risk import calculate_risk
from graphsentinel.seed import connect_graph, load_fixture, seed_graph


class QueryTimer:
    """Transparent FalkorDB graph proxy used only to measure real query timings."""

    def __init__(self, graph: Any) -> None:
        self.graph = graph
        self.durations_ms: list[float] = []

    def query(self, query: str, params: dict[str, Any] | None = None, timeout: int | None = None) -> Any:
        started = time.perf_counter()
        try:
            if timeout is None:
                return self.graph.query(query, params)
            return self.graph.query(query, params, timeout=timeout)
        finally:
            self.durations_ms.append((time.perf_counter() - started) * 1000)

    def ro_query(self, query: str, params: dict[str, Any] | None = None, timeout: int | None = None) -> Any:
        started = time.perf_counter()
        try:
            if timeout is None:
                return self.graph.ro_query(query, params)
            return self.graph.ro_query(query, params, timeout=timeout)
        finally:
            self.durations_ms.append((time.perf_counter() - started) * 1000)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.graph, name)


def alert_only_baseline(alert: dict[str, Any]) -> dict[str, Any]:
    """A severity-only comparator. These illustrative points are not probabilities."""
    started = time.perf_counter()
    points = {"critical": 85, "high": 60, "medium": 35, "low": 15}
    score = points.get(str(alert.get("severity", "")).lower(), 0)
    level = "critical" if score >= 75 else "high" if score >= 50 else "moderate" if score >= 25 else "low"
    baseline = {
        "risk_score": score,
        "risk_level": level,
        "basis": "Illustrative severity-only rule; no graph traversal or evidence corroboration.",
        "graph_queries": 0,
        "tool_calls": 0,
    }
    # The baseline only reads the fixture alert's severity; it performs no graph query.
    baseline["latency_ms"] = round((time.perf_counter() - started) * 1000, 4)
    return baseline


def _expected_signature(scenario: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return tuple(scenario["node_ids"]), tuple(scenario["relationship_types"])


def _path_signature(path: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(node.id for node in path.nodes),
        tuple(relationship.type for relationship in path.relationships),
    )


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))) )
    return round(ordered[index], 4)


def _unsupported_claims(result: Any) -> list[str]:
    text = " ".join(
        [result.summary]
        + [finding.finding for finding in result.observed_facts]
        + [finding.finding for finding in result.inferences]
        + [finding.finding for finding in result.contradictory_evidence]
    )
    claim_pattern = re.compile(
        r"\b(?:is|was|has been|confirmed as)\s+(?:compromised|exploited|malicious)\b",
        re.IGNORECASE,
    )
    negation_pattern = re.compile(
        r"\b(?:not|no evidence|does not|doesn't|did not|never|without)\b",
        re.IGNORECASE,
    )
    unsupported: list[str] = []
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        for match in claim_pattern.finditer(sentence):
            if not negation_pattern.search(sentence[:match.start()]):
                unsupported.append(match.group(0))
    return unsupported


def evaluate_scenarios() -> dict[str, Any]:
    fixture = load_fixture()
    seed_graph(connect_graph(), fixture)
    nodes = {node["id"]: node for node in fixture["nodes"]}
    scenario_results: list[dict[str, Any]] = []
    all_passed = True
    response_verification: dict[str, Any] = {
        "attempted": False,
        "verified": False,
        "simulated_only": True,
        "status": "not_run",
        "latency_ms": None,
    }

    for scenario in fixture["expected_paths"]:
        alert_id = scenario["alert_id"]
        alert = nodes[alert_id]["properties"]
        timed_graph = QueryTimer(connect_graph())
        repository = GraphRepository(graph=timed_graph)
        no_llm_settings = replace(settings, llm_api_key=None, llm_base_url=None)
        investigator = Investigator(repository, no_llm_settings)
        query_start = len(timed_graph.durations_ms)
        started = time.perf_counter()
        result = investigator.investigate(alert_id)
        investigation_latency_ms = (time.perf_counter() - started) * 1000
        investigation_queries = timed_graph.durations_ms[query_start:]

        actual_paths = {_path_signature(path) for path in result.attack_paths}
        expected_path = _expected_signature(scenario)
        actual_evidence = {
            evidence_id
            for finding in (
                *result.observed_facts,
                *result.contradictory_evidence,
                *result.inferences,
            )
            for evidence_id in finding.evidence_ids
        }
        expected_evidence = set(scenario["expected_evidence_ids"])
        expected_risk = int(scenario["expected_risk_score"])

        check_repository = GraphRepository(connect_graph())
        query_start = len(timed_graph.durations_ms)
        context = check_repository.get_alert_context(alert_id)
        paths_for_score = check_repository.trace_attack_paths(alert_id, max_depth=6)
        evidence_ids = [node.id for node in context.nodes if node.label == "Evidence"]
        evidence_for_score = check_repository.get_evidence(evidence_ids)
        repeated_risk = calculate_risk(context, paths_for_score, evidence_for_score)
        risk_consistent = repeated_risk.risk_score == result.risk_score == expected_risk

        reconnect = GraphRepository(connect_graph())
        memory_started = time.perf_counter()
        remembered = reconnect.find_related_episodes(alert_id)
        memory_latency_ms = (time.perf_counter() - memory_started) * 1000
        memory_success = any(item.episode.id == result.investigation_id for item in remembered)

        expected_path_found = expected_path in actual_paths
        evidence_found = expected_evidence.issubset(actual_evidence)
        unsupported = _unsupported_claims(result)
        scenario_passed = (
            expected_path_found
            and evidence_found
            and memory_success
            and risk_consistent
            and not unsupported
        )
        all_passed = all_passed and scenario_passed

        baseline = alert_only_baseline(alert)
        scenario_results.append({
            "scenario": scenario["scenario"],
            "alert_id": alert_id,
            "graph_powered": {
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "expected_risk_score": expected_risk,
                "risk_consistent": risk_consistent,
                "expected_path_found": expected_path_found,
                "expected_path_node_ids": list(expected_path[0]),
                "expected_path_relationship_types": list(expected_path[1]),
                "relevant_evidence_expected": sorted(expected_evidence),
                "relevant_evidence_retrieved": sorted(expected_evidence.intersection(actual_evidence)),
                "evidence_complete_for_expected_set": evidence_found,
                "memory_retrieval_success": memory_success,
                "matching_episode_count": len(remembered),
                "matching_episode_count_is_capped": len(remembered) >= settings.max_returned_records,
                "unsupported_assertions_detected": unsupported,
                "mode": result.mode,
                "llm_tool_call_count": len(result.tool_calls) if result.mode == "llm" else 0,
                "repository_query_count": len(investigation_queries),
                "repository_query_latency_ms_total": round(sum(investigation_queries), 4),
                "repository_query_latency_ms_mean": round(statistics.fmean(investigation_queries), 4) if investigation_queries else None,
                "repository_query_latency_ms_p95": _p95(investigation_queries),
                "investigation_end_to_end_latency_ms": round(investigation_latency_ms, 4),
                "memory_retrieval_latency_ms": round(memory_latency_ms, 4),
            },
            "alert_only_baseline": baseline,
            "risk_delta_graph_minus_baseline": result.risk_score - baseline["risk_score"],
            "passed": scenario_passed,
        })

        if scenario["scenario"] == "higher-risk-privileged-login":
            action_started = time.perf_counter()
            try:
                simulator = SimulatedResponseEngine(check_repository)
                proposal = simulator.propose(
                    result.investigation_id,
                    ActionProposalRequest(
                        action_type="temporary_identity_restriction",
                        target_entity_id="id-ava-chen",
                        justification="Evaluation-only simulation of an evidence-backed approval workflow.",
                        evidence_ids=["ev-privilege-ava"],
                    ),
                )
                blocked_before_approval = False
                from graphsentinel.repository import InvalidActionTransition
                try:
                    simulator.execute(proposal.id)
                except InvalidActionTransition:
                    blocked_before_approval = True
                approved = simulator.approve(proposal.id, "evaluation-analyst")
                executed = simulator.execute(proposal.id)
                verified = simulator.verify(proposal.id, "evaluation-verifier")
                response_verification.update({
                    "attempted": True,
                    "verified": verified.status == "VERIFIED" and verified.verification_status == "PASSED",
                    "status": verified.status,
                    "approval_required": blocked_before_approval,
                    "simulated_only": verified.simulated,
                    "status_sequence": [proposal.status, approved.status, executed.status, verified.status],
                    "latency_ms": round((time.perf_counter() - action_started) * 1000, 4),
                    "action_id": proposal.id,
                })
            except Exception as error:
                response_verification.update({
                    "attempted": True,
                    "verified": False,
                    "status": "failed",
                    "error": f"{type(error).__name__}: {error}",
                    "latency_ms": round((time.perf_counter() - action_started) * 1000, 4),
                })
            all_passed = all_passed and response_verification["verified"] and response_verification.get("approval_required", False)

    return {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "database": settings.graph_name,
        "fixture": str(Path("data/demo_graph.json")),
        "baseline": {
            "name": "alert-only severity rule",
            "severity_points": {"critical": 85, "high": 60, "medium": 35, "low": 15},
            "calibrated_probability": False,
            "graph_queries": 0,
            "llm_tool_calls": 0,
            "method": "Map the alert's severity to illustrative points; use no graph, event, or evidence context.",
        },
        "response_verification": response_verification,
        "scenarios": scenario_results,
        "all_checks_passed": all_passed,
        "limitations": [
            "Only the two hand-authored synthetic scenarios are evaluated; results are not production security accuracy.",
            "The alert-only baseline is a transparent illustrative comparator, not a calibrated detector.",
            "LLM calls are disabled for reproducibility; the fallback investigation reports zero LLM tool calls.",
            "Latency reflects this local process, persistent Docker database, and synthetic graph only.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    args = parser.parse_args()
    report = evaluate_scenarios()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if not report["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()