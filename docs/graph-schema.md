# Graph Schema

The demo uses the named FalkorDB graph `graphsentinel`. Node `id` values are stable, globally unique fixture identifiers. The loader uses `MERGE` on those IDs, so rerunning it updates fixture properties without duplicating nodes or relationships.

## Nodes

| Label | Required properties |
| --- | --- |
| `Identity` | `id`, `name`, `department`, `privilege_level` |
| `Device` | `id`, `hostname`, `device_type`, `criticality`, `state` |
| `Service` | `id`, `name`, `criticality`, `environment`, `state` |
| `Alert` | `id`, `type`, `severity`, `timestamp`, `status`, `description` |
| `Event` | `id`, `type`, `timestamp`, `source`, `confidence`, `description` |
| `Vulnerability` | `id`, `cve`, `severity`, `exploitable`, `description` |
| `Incident` | `id`, `type`, `risk_score`, `status`, `created_at`, `summary` |
| `Evidence` | `id`, `description`, `source`, `timestamp`, `confidence`, `evidence_type`, `supports_finding` |
| `ResponseAction` | `id`, `action_type`, `status`, `created_at`, `approved_by`, `result` |
| `InvestigationEpisode` | `id`, `alert_id`, `summary`, `risk_score`, `risk_level`, `confidence`, `evidence_completeness`, `created_at`, `outcome`, plus JSON-encoded event types, entity/evidence IDs, paths, factors, recommendation, and complete structured result |
| `ActionAudit` | `id`, `action_id`, `event_type`, `from_state`, `to_state`, `actor`, `timestamp`, `details_json` |

## Relationships

Arrows point from the first entity to the second. A graph path is a possible relationship chain, not proof that an attack occurred.

| Relationship | Direction and meaning |
| --- | --- |
| `USES` | `Identity -> Device`: device assigned to or used by an identity. |
| `ACCESSES` | `Identity -> Service`: known service access relationship. |
| `CONNECTS_TO` | `Device -> Service`: observed or configured network reachability. |
| `DEPENDS_ON` | `Service -> Service`: upstream service depends on downstream service. |
| `HAS_VULNERABILITY` | `Service -> Vulnerability`: vulnerability record associated with a service. |
| `OBSERVED_ON` | `Alert -> Identity/Device/Service`: alert subject. |
| `INVOLVES` | `Event/Incident/InvestigationEpisode -> Identity/Device/Service`: entity associated with an event, incident, or saved investigation. |
| `HAS_EVENT` | `Alert -> Event`: event attached to an alert. |
| `HAS_EVIDENCE` | `Alert/InvestigationEpisode -> Evidence`: neutral association; evidence polarity remains on the Evidence node. |
| `ABOUT` | `Evidence -> Identity/Device/Service`: entity a record describes. |
| `SUPPORTED_BY` | `Incident -> Evidence`: evidence linked to a historical incident. |
| `RELATED_TO` | `Incident -> Incident`: explicitly curated incident relationship. |
| `FOLLOWED_PATH` | `Incident/InvestigationEpisode -> Service`: service recorded in the incident or investigation path. |
| `PROPOSES` | `Incident/InvestigationEpisode -> ResponseAction`: response action proposed for that record. |
| `RESOLVED_BY` | `Incident/InvestigationEpisode -> ResponseAction`: action recorded as resolving an incident or verified episode response. |
| `INVESTIGATES` | `InvestigationEpisode -> Alert`: alert investigated by a saved episode. |
| `DISCOVERED` | `InvestigationEpisode -> Vulnerability`: vulnerability node present in a saved investigation path. |
| `HAS_AUDIT_EVENT` | `ResponseAction -> ActionAudit`: immutable lifecycle audit record. |

## Episode memory matching

Each completed investigation is stored as an `InvestigationEpisode` with its complete structured response, alert type, discovered entities, evidence IDs, paths, factors, and recommendation. Typed links preserve graph traversal and evidence provenance. A later alert can retrieve episodes by a shared `OBSERVED_ON` entity and by matching `Event.type` values. Each match states which criterion matched and explicitly says that similarity is contextual, not proof of a common attack. Past evidence remains attached to its episode and is not re-scored as current-alert evidence.

## Simulated response state

`ResponseAction` records approval, captured target simulation state/version, proposed state, execution result, and verification. `ActionAudit` nodes are linked in timestamp order. The target's base `state` is not changed; simulations write only `simulation_state` and increment `simulation_version` on the graph node. `RESOLVED_BY` is added only after verification passes.

Allowed action target mappings are: identity restriction -> `Identity`, device isolation -> `Device`, configuration rollback -> `Service`, and vulnerability remediation -> `Vulnerability`. Actions only run through the FastAPI simulator. There is no integration to live enterprise systems.

Evidence polarity, confidence, source, and timestamp live on `Evidence` nodes. Event source, confidence, and timestamp live on `Event` nodes. Synthetic CVE-like identifiers are demo labels and do not assert a real vulnerability.