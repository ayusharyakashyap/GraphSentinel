"""Deterministic, evidence-linked risk scoring for investigation snapshots."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from graphsentinel.repository import AlertContext, EvidenceRecord, GraphPath

EVIDENCE_CATEGORIES = (
    "authentication",
    "identity_context",
    "device_posture",
    "configuration",
    "network",
    "vulnerability_inventory",
    "access_control",
    "compromise_confirmation",
)


@dataclass(frozen=True)
class RiskWeights:
    suspicious_authentication: int = 20
    privileged_identity: int = 20
    recent_configuration_change: int = 15
    vulnerable_service_path: int = 15
    independent_corroboration: int = 15
    confirmed_compromise: int = 15
    contradictory_evidence: int = 10

    def __post_init__(self) -> None:
        if any(value < 0 for value in self.positive_weights):
            raise ValueError("Risk weights must be non-negative")
        if self.contradictory_evidence < 0:
            raise ValueError("Contradictory evidence weight must be non-negative")
        if sum(self.positive_weights) > 100:
            raise ValueError("Positive risk weights must sum to at most 100")

    @property
    def positive_weights(self) -> tuple[int, ...]:
        return (
            self.suspicious_authentication,
            self.privileged_identity,
            self.recent_configuration_change,
            self.vulnerable_service_path,
            self.independent_corroboration,
            self.confirmed_compromise,
        )


@dataclass(frozen=True)
class RiskFactor:
    name: str
    score: int
    explanation: str
    evidence_ids: tuple[str, ...]
    path_node_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskAssessment:
    risk_score: int
    risk_level: str
    confidence: float
    evidence_completeness: float
    factors: tuple[RiskFactor, ...]
    contradictory_evidence_ids: tuple[str, ...]
    missing_evidence: tuple[str, ...]


def _deduplicate_evidence(evidence: Iterable[EvidenceRecord]) -> tuple[EvidenceRecord, ...]:
    unique: dict[str, EvidenceRecord] = {}
    for record in evidence:
        evidence_id = record.evidence.id
        previous = unique.get(evidence_id)
        if previous is not None and dict(previous.evidence.properties) != dict(record.evidence.properties):
            raise ValueError(f"Conflicting records share evidence ID {evidence_id}")
        unique[evidence_id] = record
    return tuple(unique[key] for key in sorted(unique))


def _confidence(record: EvidenceRecord) -> float:
    try:
        value = float(record.evidence.properties.get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0
    return value if 0.0 <= value <= 1.0 else 0.0


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def calculate_risk(
    context: AlertContext,
    paths: Iterable[GraphPath],
    evidence: Iterable[EvidenceRecord],
    weights: RiskWeights = RiskWeights(),
) -> RiskAssessment:
    """Score a graph-backed alert snapshot without treating paths as proof of compromise."""
    if context.alert is None:
        raise ValueError("An existing alert is required to calculate risk")

    unique_evidence = _deduplicate_evidence(evidence)
    evidence_by_id = {record.evidence.id: record for record in unique_evidence}
    supporting = [
        record
        for record in unique_evidence
        if record.evidence.properties.get("supports_finding") is True
    ]
    contradictory = [
        record
        for record in unique_evidence
        if record.evidence.properties.get("supports_finding") is False
    ]
    factors: list[RiskFactor] = []

    authentication = sorted(
        (
            record
            for record in supporting
            if record.evidence.properties.get("evidence_type") == "authentication"
            and _confidence(record) >= 0.75
        ),
        key=lambda record: (-_confidence(record), record.evidence.id),
    )
    if authentication:
        strongest_auth = authentication[0]
        auth_score = (
            weights.suspicious_authentication
            if _confidence(strongest_auth) >= 0.9
            else weights.suspicious_authentication // 2
        )
        factors.append(
            RiskFactor(
                name="suspicious_authentication",
                score=auth_score,
                explanation="Supporting authentication evidence indicates an unusual successful login.",
                evidence_ids=(strongest_auth.evidence.id,),
            )
        )

    identity_nodes = {
        node.id: node for node in context.nodes if node.label == "Identity"
    }
    privileged_evidence = sorted(
        (
            record
            for record in supporting
            if record.evidence.properties.get("evidence_type") == "identity_context"
            and any(
                node.id in identity_nodes
                and str(identity_nodes[node.id].properties.get("privilege_level", "")).lower()
                in {"admin", "administrator", "privileged", "high"}
                for node in record.linked_nodes
            )
        ),
        key=lambda record: record.evidence.id,
    )
    if privileged_evidence:
        factors.append(
            RiskFactor(
                name="privileged_identity",
                score=weights.privileged_identity,
                explanation="Directory evidence confirms the alert subject has elevated privileges.",
                evidence_ids=(privileged_evidence[0].evidence.id,),
            )
        )

    alert_time = _timestamp(context.alert.properties.get("timestamp"))
    recent_configuration = []
    if alert_time is not None:
        for record in supporting:
            evidence_time = _timestamp(record.evidence.properties.get("timestamp"))
            if (
                record.evidence.properties.get("evidence_type") == "configuration"
                and evidence_time is not None
                and timedelta(0) <= alert_time - evidence_time <= timedelta(hours=24)
            ):
                recent_configuration.append(record)
    if recent_configuration:
        chosen = min(recent_configuration, key=lambda record: record.evidence.id)
        factors.append(
            RiskFactor(
                name="recent_configuration_change",
                score=weights.recent_configuration_change,
                explanation="Supporting change evidence is timestamped within 24 hours before the alert.",
                evidence_ids=(chosen.evidence.id,),
            )
        )

    investigation_paths = tuple(paths)
    evidence_by_service = {
        node.id: record.evidence.id
        for record in supporting
        if record.evidence.properties.get("evidence_type") == "vulnerability_inventory"
        for node in record.linked_nodes
        if node.label == "Service"
    }
    network_evidence_by_entity = {
        node.id: record.evidence.id
        for record in supporting
        if record.evidence.properties.get("evidence_type") == "network"
        and _confidence(record) >= 0.75
        for node in record.linked_nodes
    }
    vulnerable_paths: list[tuple[GraphPath, tuple[str, ...]]] = []
    for path in investigation_paths:
        services = [
            node for node in path.nodes
            if node.label == "Service"
            and node.properties.get("environment") == "production"
            and node.properties.get("criticality") in {"high", "critical"}
        ]
        vulnerabilities = [
            node for node in path.nodes
            if node.label == "Vulnerability" and node.properties.get("exploitable") is True
        ]
        for service in services:
            if service.id not in evidence_by_service:
                continue
            network_ids = sorted(
                network_evidence_by_entity[node.id]
                for node in path.nodes
                if node.id in network_evidence_by_entity
            )
            if vulnerabilities and network_ids:
                vulnerable_paths.append(
                    (path, (evidence_by_service[service.id], network_ids[0]))
                )
    if vulnerable_paths:
        selected_path, evidence_ids = min(
            vulnerable_paths,
            key=lambda candidate: tuple(node.id for node in candidate[0].nodes),
        )
        factors.append(
            RiskFactor(
                name="potential_vulnerable_service_path",
                score=weights.vulnerable_service_path,
                explanation=(
                    "Graph relationships and inventory evidence show a possible route to a "
                    "vulnerable production service; this does not establish exploitation."
                ),
                evidence_ids=evidence_ids,
                path_node_ids=tuple(node.id for node in selected_path.nodes),
            )
        )

    corroborating_types = {
        "authentication", "configuration", "network", "vulnerability_inventory",
    }
    independent_records: dict[str, EvidenceRecord] = {}
    for record in supporting:
        evidence_type = record.evidence.properties.get("evidence_type")
        if evidence_type not in corroborating_types or _confidence(record) < 0.75:
            continue
        previous = independent_records.get(evidence_type)
        if previous is None or (
            -_confidence(record), record.evidence.id
        ) < (-_confidence(previous), previous.evidence.id):
            independent_records[evidence_type] = record
    if len(independent_records) >= 3:
        factors.append(
            RiskFactor(
                name="independent_corroboration",
                score=weights.independent_corroboration,
                explanation="Three or more independent evidence categories corroborate the concern.",
                evidence_ids=tuple(
                    independent_records[key].evidence.id for key in sorted(independent_records)
                ),
            )
        )

    confirmed_compromise = sorted(
        (
            record for record in supporting
            if record.evidence.properties.get("evidence_type") == "compromise_confirmation"
            and _confidence(record) >= 0.95
        ),
        key=lambda record: record.evidence.id,
    )
    if confirmed_compromise:
        factors.append(
            RiskFactor(
                name="confirmed_compromise",
                score=weights.confirmed_compromise,
                explanation="High-confidence evidence explicitly records a successful compromise.",
                evidence_ids=(confirmed_compromise[0].evidence.id,),
            )
        )

    mitigating = sorted(
        (
            record for record in contradictory
            if record.evidence.properties.get("evidence_type") in {"device_posture", "access_control"}
            and _confidence(record) >= 0.8
        ),
        key=lambda record: record.evidence.id,
    )
    if mitigating:
        factors.append(
            RiskFactor(
                name="contradictory_device_or_access_evidence",
                score=-weights.contradictory_evidence,
                explanation="Healthy device posture or denied access counters the concern.",
                evidence_ids=tuple(record.evidence.id for record in mitigating),
            )
        )

    score = max(0, min(100, sum(factor.score for factor in factors)))
    valid_confidences = [_confidence(record) for record in unique_evidence]
    confidence = sum(valid_confidences) / len(valid_confidences) if valid_confidences else 0.0
    observed_categories = {
        record.evidence.properties.get("evidence_type")
        for record in unique_evidence
        if record.evidence.properties.get("evidence_type") in EVIDENCE_CATEGORIES
    }
    missing = tuple(category for category in EVIDENCE_CATEGORIES if category not in observed_categories)
    completeness = (len(EVIDENCE_CATEGORIES) - len(missing)) / len(EVIDENCE_CATEGORIES)
    return RiskAssessment(
        risk_score=score,
        risk_level=_risk_level(score),
        confidence=confidence,
        evidence_completeness=completeness,
        factors=tuple(factors),
        contradictory_evidence_ids=tuple(record.evidence.id for record in contradictory),
        missing_evidence=missing,
    )