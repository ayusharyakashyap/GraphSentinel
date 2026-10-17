export type NodeLabel =
  | "Identity"
  | "Device"
  | "Service"
  | "Alert"
  | "Event"
  | "Vulnerability"
  | "Incident"
  | "Evidence"
  | "ResponseAction"
  | "InvestigationEpisode"
  | "ActionAudit";

export type RiskLevel = "low" | "moderate" | "high" | "critical";
export type RecommendationType =
  | "temporary_identity_restriction"
  | "device_isolation"
  | "configuration_rollback"
  | "vulnerability_remediation"
  | "monitor_only";
export type SimulatedActionType = Exclude<RecommendationType, "monitor_only">;
export type ActionStatus =
  | "PROPOSED"
  | "APPROVED"
  | "REJECTED"
  | "EXECUTED_SIMULATED"
  | "VERIFIED";

export interface GraphNode {
  id: string;
  label: NodeLabel;
  properties: Record<string, unknown>;
}

export interface GraphRelationship {
  type: string;
  source_id: string;
  target_id: string;
  properties: Record<string, unknown>;
}

export interface AlertContext {
  alert: GraphNode;
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export interface AlertList {
  alerts: GraphNode[];
}

export interface AttackPath {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export interface EvidenceFinding {
  finding: string;
  evidence_ids: string[];
  related_node_ids: string[];
  source: string | null;
  timestamp: string | null;
}

export interface RiskFactor {
  name: string;
  score: number;
  explanation: string;
  evidence_ids: string[];
  path_node_ids: string[];
}

export interface HistoricalIncident {
  incident: GraphNode;
  shared_entity_ids: string[];
  relevance_reasons: string[];
  supporting_evidence_ids: string[];
}

export interface HistoricalEpisode {
  episode_id: string;
  alert_id: string;
  summary: string;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
  outcome: string;
  shared_entity_ids: string[];
  matching_event_types: string[];
  relevance_reasons: string[];
  evidence_ids: string[];
}

export interface Recommendation {
  action_type: RecommendationType;
  target_entity_id: string | null;
  rationale: string;
  evidence_ids: string[];
  execution_mode: "recommendation_only";
}

export interface ToolCall {
  tool_name: string;
  arguments: Record<string, unknown>;
  result_summary: string;
  status: "succeeded" | "rejected" | "failed";
}

export interface Investigation {
  investigation_id: string;
  alert_id: string;
  summary: string;
  mode: "llm" | "fallback";
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  evidence_completeness: number;
  observed_facts: EvidenceFinding[];
  inferences: EvidenceFinding[];
  contradictory_evidence: EvidenceFinding[];
  missing_evidence: string[];
  risk_factors: RiskFactor[];
  attack_paths: AttackPath[];
  affected_services: GraphNode[];
  historical_incidents: HistoricalIncident[];
  historical_episodes: HistoricalEpisode[];
  recommended_action: Recommendation;
  tool_calls: ToolCall[];
  limitations: string[];
}

export interface AuditEvent {
  id: string;
  event_type: string;
  from_state: string;
  to_state: string;
  actor: string;
  timestamp: string;
  details: Record<string, unknown>;
}

export interface ResponseAction {
  id: string;
  investigation_id: string;
  action_type: SimulatedActionType;
  target_entity_id: string;
  justification: string;
  evidence_ids: string[];
  status: ActionStatus;
  approval_status: "PENDING" | "APPROVED" | "REJECTED";
  verification_status: "PENDING" | "PASSED" | "FAILED";
  previous_state: string;
  proposed_state: string;
  result: string;
  verification_result: string;
  approved_by: string;
  created_at: string;
  executed_at: string | null;
  verified_at: string | null;
  simulated: true;
  audit_events: AuditEvent[];
}

export interface ApiError {
  error: { code: string; message: string };
}