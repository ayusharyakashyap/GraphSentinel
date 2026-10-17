"""Database-backed tests for approval-gated simulated response actions."""

import json

import pytest

from graphsentinel.config import settings
from graphsentinel.investigator import Investigator
from graphsentinel.models import ActionProposalRequest
from graphsentinel.repository import (
    ActionStateConflict,
    GraphRepository,
    InvalidActionTransition,
)
from graphsentinel.responses import SimulatedResponseEngine
from graphsentinel.seed import connect_graph, load_fixture, seed_graph


@pytest.fixture
def investigated_episode() -> tuple[GraphRepository, SimulatedResponseEngine, str]:
    seed_graph(connect_graph(), load_fixture())
    repository = GraphRepository(connect_graph())
    result = Investigator(repository, settings).investigate("alert-2026-1015-001")
    return repository, SimulatedResponseEngine(repository), result.investigation_id


def _proposal(
    action_type: str,
    target_id: str,
    evidence_ids: list[str],
) -> ActionProposalRequest:
    return ActionProposalRequest(
        action_type=action_type,
        target_entity_id=target_id,
        justification="Contain or remediate the evidence-backed demo finding.",
        evidence_ids=evidence_ids,
    )


def test_unapproved_action_never_executes(
    investigated_episode: tuple[GraphRepository, SimulatedResponseEngine, str],
) -> None:
    repository, simulator, episode_id = investigated_episode
    target_before = repository.get_node("Identity", "id-ava-chen")
    action = simulator.propose(
        episode_id,
        _proposal("temporary_identity_restriction", "id-ava-chen", ["ev-privilege-ava"]),
    )

    with pytest.raises(InvalidActionTransition):
        simulator.execute(action.id)

    target_after = repository.get_node("Identity", "id-ava-chen")
    stored = simulator.get(action.id)
    assert target_after == target_before
    assert stored.status == "PROPOSED"
    assert [event.event_type for event in stored.audit_events] == ["PROPOSED"]


def test_rejected_action_is_terminal_and_never_executes(
    investigated_episode: tuple[GraphRepository, SimulatedResponseEngine, str],
) -> None:
    repository, simulator, episode_id = investigated_episode
    target_before = repository.get_node("Device", "dev-ava-laptop")
    action = simulator.propose(
        episode_id,
        _proposal("device_isolation", "dev-ava-laptop", ["ev-deploy-reach"]),
    )
    rejected = simulator.reject(action.id, "analyst@example.test", "Device posture is healthy.")

    with pytest.raises(InvalidActionTransition):
        simulator.execute(action.id)

    target_after = repository.get_node("Device", "dev-ava-laptop")
    stored = simulator.get(action.id)
    assert rejected.status == "REJECTED"
    assert stored.status == "REJECTED"
    assert stored.approval_status == "REJECTED"
    assert target_after == target_before
    assert [event.to_state for event in stored.audit_events] == ["PROPOSED", "REJECTED"]


def test_approved_simulation_is_independently_verified(
    investigated_episode: tuple[GraphRepository, SimulatedResponseEngine, str],
) -> None:
    repository, simulator, episode_id = investigated_episode
    original = repository.get_node("Service", "svc-deploy")
    action = simulator.propose(
        episode_id,
        _proposal("configuration_rollback", "svc-deploy", ["ev-config-change"]),
    )
    approved = simulator.approve(action.id, "demo-analyst")
    executed = simulator.execute(action.id)
    target_after_execution = GraphRepository(connect_graph()).get_node("Service", "svc-deploy")
    verified = simulator.verify(action.id, "verification-worker")

    assert approved.status == "APPROVED"
    assert executed.status == "EXECUTED_SIMULATED"
    assert target_after_execution is not None
    assert target_after_execution.properties["simulation_state"] == "ROLLED_BACK"
    assert target_after_execution.properties["state"] == original.properties["state"]
    assert verified.status == "VERIFIED"
    assert verified.verification_status == "PASSED"
    assert [event.to_state for event in verified.audit_events] == [
        "PROPOSED", "APPROVED", "EXECUTED_SIMULATED", "VERIFIED",
    ]
    assert repository._query(
        "MATCH (episode:InvestigationEpisode {id: $episode_id})-[:RESOLVED_BY]->(action:ResponseAction {id: $action_id}) RETURN count(action)",
        {"episode_id": episode_id, "action_id": action.id},
    )[0][0] == 1


def test_failed_verification_is_recorded_without_marking_verified(
    investigated_episode: tuple[GraphRepository, SimulatedResponseEngine, str],
) -> None:
    repository, simulator, episode_id = investigated_episode
    action = simulator.propose(
        episode_id,
        _proposal(
            "vulnerability_remediation",
            "vuln-demo-2026-041",
            ["ev-vuln-deploy"],
        ),
    )
    simulator.approve(action.id, "demo-analyst")
    simulator.execute(action.id)
    connect_graph().query(
        "MATCH (target:Vulnerability {id: $id}) "
        "SET target.simulation_state = $state RETURN target",
        {"id": "vuln-demo-2026-041", "state": "MISMATCHED"},
    )

    failed = simulator.verify(action.id)

    assert failed.status == "EXECUTED_SIMULATED"
    assert failed.verification_status == "FAILED"
    assert "Expected REMEDIATION_SIMULATED" in failed.verification_result
    assert failed.audit_events[-1].event_type == "VERIFICATION_FAILED"
    assert repository.get_response_action(action.id).action.properties["status"] == "EXECUTED_SIMULATED"


def test_action_policy_rejects_unsupported_or_weakly_supported_proposals(
    investigated_episode: tuple[GraphRepository, SimulatedResponseEngine, str],
) -> None:
    _, simulator, episode_id = investigated_episode

    with pytest.raises(ValueError, match="not discovered"):
        simulator.propose(
            episode_id,
            _proposal("device_isolation", "unknown-device", ["ev-deploy-reach"]),
        )

    with pytest.raises(ValueError, match="linked to this investigation"):
        simulator.propose(
            episode_id,
            _proposal("temporary_identity_restriction", "id-ava-chen", ["ev-noah-denied"]),
        )

    with pytest.raises(ValueError, match="does not support"):
        simulator.propose(
            episode_id,
            _proposal("temporary_identity_restriction", "id-ava-chen", ["ev-config-change"]),
        )


def test_optimistic_version_check_prevents_conflicting_simulations(
    investigated_episode: tuple[GraphRepository, SimulatedResponseEngine, str],
) -> None:
    _, simulator, episode_id = investigated_episode
    first = simulator.propose(
        episode_id,
        _proposal("temporary_identity_restriction", "id-ava-chen", ["ev-privilege-ava"]),
    )
    second = simulator.propose(
        episode_id,
        _proposal("temporary_identity_restriction", "id-ava-chen", ["ev-privilege-ava"]),
    )
    simulator.approve(first.id, "first-analyst")
    simulator.approve(second.id, "second-analyst")
    simulator.execute(first.id)

    with pytest.raises(ActionStateConflict):
        simulator.execute(second.id)