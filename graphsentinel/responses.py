"""Approval-gated simulated response policies and API projections."""

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from graphsentinel.models import (
    ActionProposalRequest,
    AuditEventResponse,
    ResponseActionResponse,
)
from graphsentinel.repository import (
    GraphRepository,
    InvalidActionTransition,
    ResponseActionNotFoundError,
    StoredResponseAction,
)

TARGETS = {
    "temporary_identity_restriction": ("Identity", "RESTRICTED"),
    "device_isolation": ("Device", "ISOLATED"),
    "configuration_rollback": ("Service", "ROLLED_BACK"),
    "vulnerability_remediation": ("Vulnerability", "REMEDIATION_SIMULATED"),
}


class ActionPolicyError(ValueError):
    """Raised when a proposed action is unsupported or disproportionate."""


class SimulatedResponseEngine:
    """Creates and advances simulated actions without contacting live systems."""

    def __init__(self, repository: GraphRepository) -> None:
        self.repository = repository

    def propose(
        self,
        investigation_id: str,
        request: ActionProposalRequest,
    ) -> ResponseActionResponse:
        episode = self.repository.get_investigation_episode(investigation_id)
        if episode is None:
            raise ResponseActionNotFoundError(investigation_id)
        action_type = request.action_type
        target_label, proposed_state = TARGETS[action_type]
        if len(set(request.evidence_ids)) != len(request.evidence_ids):
            raise ActionPolicyError("Evidence IDs must be unique")

        target_ids = set(json.loads(episode.properties.get("entity_ids_json", "[]")))
        if request.target_entity_id not in target_ids:
            raise ActionPolicyError("Action target was not discovered in this investigation")
        evidence_ids = set(json.loads(episode.properties.get("evidence_ids_json", "[]")))
        if not set(request.evidence_ids).issubset(evidence_ids):
            raise ActionPolicyError("Action evidence must be linked to this investigation")
        evidence_records = self.repository.get_evidence(request.evidence_ids)
        if {record.evidence.id for record in evidence_records} != set(request.evidence_ids):
            raise ActionPolicyError("One or more action evidence records are unavailable")

        risk_score = int(episode.properties["risk_score"])
        factors = json.loads(episode.properties.get("risk_factors_json", "[]"))
        factor_names = {factor.get("name") for factor in factors if isinstance(factor, dict)}
        if action_type in {"temporary_identity_restriction", "device_isolation"} and risk_score < 50:
            raise ActionPolicyError("Containment proposals require a high-risk investigation")
        if action_type == "configuration_rollback" and "recent_configuration_change" not in factor_names:
            raise ActionPolicyError("Configuration rollback requires a supported recent change finding")
        if action_type == "vulnerability_remediation" and request.target_entity_id not in target_ids:
            raise ActionPolicyError("Vulnerability target was not discovered in this investigation")

        required_evidence_types = {
            "temporary_identity_restriction": {"identity_context"},
            "device_isolation": {"network", "device_posture"},
            "configuration_rollback": {"configuration"},
        }
        if action_type in required_evidence_types and not any(
            record.evidence.properties.get("evidence_type") in required_evidence_types[action_type]
            and record.evidence.properties.get("supports_finding") is True
            and any(
                node.id == request.target_entity_id and node.label == target_label
                for node in record.linked_nodes
            )
            for record in evidence_records
        ):
            raise ActionPolicyError("Selected evidence does not support the requested action target")
        if action_type == "vulnerability_remediation":
            vulnerable_paths = [
                factor for factor in factors
                if factor.get("name") == "potential_vulnerable_service_path"
                and request.target_entity_id in factor.get("path_node_ids", [])
                and set(factor.get("evidence_ids", [])).intersection(request.evidence_ids)
            ]
            if not vulnerable_paths:
                raise ActionPolicyError("Vulnerability remediation requires a cited path and inventory finding")

        target = self.repository.get_node(target_label, request.target_entity_id)
        if target is None:
            raise ActionPolicyError("Action target no longer exists")
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        properties = {
            "id": str(uuid4()),
            "investigation_id": investigation_id,
            "action_type": action_type,
            "target_entity_id": target.id,
            "target_label": target_label,
            "justification": request.justification,
            "evidence_ids_json": json.dumps(request.evidence_ids),
            "status": "PROPOSED",
            "approval_status": "PENDING",
            "verification_status": "PENDING",
            "previous_state": str(target.properties.get("simulation_state", "NORMAL")),
            "proposed_state": proposed_state,
            "expected_version": int(target.properties.get("simulation_version", 0)),
            "created_at": created_at,
            "approved_by": "",
            "approved_at": "",
            "rejected_by": "",
            "rejection_reason": "",
            "executed_at": "",
            "verified_at": "",
            "result": "Awaiting explicit human approval.",
            "verification_result": "",
            "simulated": True,
        }
        return self._response(self.repository.create_response_action(properties, target_label))

    def get(self, action_id: str) -> ResponseActionResponse:
        stored = self.repository.get_response_action(action_id)
        if stored is None:
            raise ResponseActionNotFoundError(action_id)
        return self._response(stored)

    def approve(self, action_id: str, approved_by: str) -> ResponseActionResponse:
        actor = self._actor(approved_by)
        return self._response(self.repository.approve_response_action(action_id, actor))

    def reject(self, action_id: str, rejected_by: str, reason: str) -> ResponseActionResponse:
        actor = self._actor(rejected_by)
        return self._response(self.repository.reject_response_action(action_id, actor, reason))

    def execute(self, action_id: str) -> ResponseActionResponse:
        return self._response(self.repository.execute_simulated_action(action_id))

    def verify(self, action_id: str, verified_by: str = "verifier") -> ResponseActionResponse:
        return self._response(self.repository.verify_simulated_action(action_id, self._actor(verified_by)))

    @staticmethod
    def _actor(actor: str) -> str:
        normalized = actor.strip()
        if len(normalized) < 2:
            raise ActionPolicyError("An explicit actor name is required")
        return normalized

    @staticmethod
    def _response(stored: StoredResponseAction) -> ResponseActionResponse:
        properties = stored.action.properties
        audit_events = []
        for event in stored.audit_events:
            event_properties = event.properties
            try:
                details: dict[str, Any] = json.loads(event_properties.get("details_json", "{}"))
            except (TypeError, json.JSONDecodeError):
                details = {"unavailable": "Audit detail could not be decoded"}
            audit_events.append(
                AuditEventResponse(
                    id=event.id,
                    event_type=str(event_properties["event_type"]),
                    from_state=str(event_properties["from_state"]),
                    to_state=str(event_properties["to_state"]),
                    actor=str(event_properties["actor"]),
                    timestamp=str(event_properties["timestamp"]),
                    details=details,
                )
            )
        return ResponseActionResponse(
            id=stored.action.id,
            investigation_id=str(properties["investigation_id"]),
            action_type=properties["action_type"],
            target_entity_id=str(properties["target_entity_id"]),
            justification=str(properties["justification"]),
            evidence_ids=json.loads(properties["evidence_ids_json"]),
            status=properties["status"],
            approval_status=properties["approval_status"],
            verification_status=properties["verification_status"],
            previous_state=str(properties["previous_state"]),
            proposed_state=str(properties["proposed_state"]),
            result=str(properties.get("result", "")),
            verification_result=str(properties.get("verification_result", "")),
            approved_by=str(properties.get("approved_by", "")),
            created_at=str(properties["created_at"]),
            executed_at=properties.get("executed_at") or None,
            verified_at=properties.get("verified_at") or None,
            audit_events=audit_events,
        )