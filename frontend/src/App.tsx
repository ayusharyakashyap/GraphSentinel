import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Ban,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  Clock3,
  Cpu,
  Database,
  Fingerprint,
  GitBranch,
  History,
  LoaderCircle,
  LockKeyhole,
  Network,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sparkles,
  Unplug,
  UserRound,
  Waypoints,
  X,
} from "lucide-react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  Handle,
  Position,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { api } from "./api";
import type {
  ActionStatus,
  AlertContext,
  AttackPath,
  EvidenceFinding,
  GraphNode,
  GraphRelationship,
  HistoricalEpisode,
  Investigation,
  NodeLabel,
  ResponseAction,
  RiskFactor,
  SimulatedActionType,
} from "./types";

type ApiState = "checking" | "connected" | "offline";
type FlowNodeData = {
  label: NodeLabel;
  title: string;
  subtitle: string;
  selected: boolean;
  vertical: boolean;
};
type FlowEntityNode = Node<FlowNodeData, "entity">;

const NODE_ICONS: Record<NodeLabel, typeof UserRound> = {
  Alert: AlertTriangle,
  Identity: UserRound,
  Device: Cpu,
  Service: Server,
  Vulnerability: ShieldAlert,
  Evidence: Search,
  Event: Activity,
  Incident: History,
  ResponseAction: ShieldCheck,
  InvestigationEpisode: GitBranch,
  ActionAudit: Clock3,
};

const LABEL_COLORS: Record<NodeLabel, string> = {
  Alert: "#f49c63",
  Identity: "#74d3bd",
  Device: "#86b9e8",
  Service: "#d4c36e",
  Vulnerability: "#ef7f73",
  Evidence: "#9ba9a0",
  Event: "#a4bd8a",
  Incident: "#c99a72",
  ResponseAction: "#77c6a8",
  InvestigationEpisode: "#9fb3ab",
  ActionAudit: "#9ba9a0",
};

const ACTION_LABEL: Record<SimulatedActionType, string> = {
  temporary_identity_restriction: "Restrict identity",
  device_isolation: "Isolate device",
  configuration_rollback: "Rollback configuration",
  vulnerability_remediation: "Simulate remediation",
};

const ACTION_TARGET: Record<SimulatedActionType, NodeLabel> = {
  temporary_identity_restriction: "Identity",
  device_isolation: "Device",
  configuration_rollback: "Service",
  vulnerability_remediation: "Vulnerability",
};

const ACTION_FACTOR: Record<SimulatedActionType, string> = {
  temporary_identity_restriction: "privileged_identity",
  device_isolation: "potential_vulnerable_service_path",
  configuration_rollback: "recent_configuration_change",
  vulnerability_remediation: "potential_vulnerable_service_path",
};

function formatTime(value: string | null | undefined): string {
  if (!value) return "Time unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      }).format(parsed);
}

function shortId(value: string): string {
  return value.length > 22 ? `${value.slice(0, 11)}...${value.slice(-6)}` : value;
}

function titleCase(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function nodeTitle(node: GraphNode): string {
  const properties = node.properties;
  const main = properties.name ?? properties.hostname ?? properties.type ?? node.id;
  return String(main);
}

function nodeSubtitle(node: GraphNode): string {
  const properties = node.properties;
  const detail =
    properties.privilege_level ??
    properties.environment ??
    properties.severity ??
    properties.device_type ??
    properties.cve ??
    properties.evidence_type ??
    properties.status ??
    node.id;
  return String(detail);
}

function EntityNode({ data }: NodeProps<FlowEntityNode>) {
  const Icon = NODE_ICONS[data.label];
  return (
    <div className={`graph-node graph-node-${data.label.toLowerCase()}${data.selected ? " is-selected" : ""}`}>
      <Handle type="target" position={data.vertical ? Position.Top : Position.Left} />
      <span className="graph-node-icon"><Icon size={14} strokeWidth={1.8} /></span>
      <span className="graph-node-copy">
        <span className="graph-node-label">{data.label}</span>
        <strong>{data.title}</strong>
        <small>{data.subtitle}</small>
      </span>
      <Handle type="source" position={data.vertical ? Position.Bottom : Position.Right} />
    </div>
  );
}

function severity(alert: GraphNode): string {
  return String(alert.properties.severity ?? "unknown").toLowerCase();
}

function riskColor(level: string): string {
  if (level === "critical" || level === "high") return "coral";
  if (level === "moderate") return "amber";
  return "mint";
}

function graphRecords(context: AlertContext | null, investigation: Investigation | null) {
  const nodes = new Map<string, GraphNode>();
  const relationships = new Map<string, GraphRelationship>();
  for (const node of context?.nodes ?? []) nodes.set(node.id, node);
  if (context?.alert) nodes.set(context.alert.id, context.alert);
  for (const relationship of context?.relationships ?? []) {
    relationships.set(`${relationship.type}:${relationship.source_id}:${relationship.target_id}`, relationship);
  }
  for (const path of investigation?.attack_paths ?? []) {
    for (const node of path.nodes) nodes.set(node.id, node);
    for (const relationship of path.relationships) {
      relationships.set(`${relationship.type}:${relationship.source_id}:${relationship.target_id}`, relationship);
    }
  }
  return { nodes: [...nodes.values()], relationships: [...relationships.values()] };
}

function layoutGraph(
  records: ReturnType<typeof graphRecords>,
  selectedNodeId: string | null,
  highlightedPath: AttackPath | null,
  vertical: boolean,
): { nodes: FlowEntityNode[]; edges: Edge[] } {
  const columns: Record<string, number> = {
    Alert: 0,
    Identity: 1,
    Device: 2,
    Service: 3,
    Vulnerability: 4,
    Event: 4,
    Evidence: 5,
    Incident: 5,
    InvestigationEpisode: 5,
    ResponseAction: 5,
    ActionAudit: 6,
  };
  const rows = new Map<string, number>();
  const positioned = records.nodes.map((node, index) => {
    const key = node.label;
    const row = rows.get(key) ?? 0;
    rows.set(key, row + 1);
    return {
      id: node.id,
      type: "entity" as const,
      position: {
        x: vertical ? 55 : (columns[key] ?? 3) * 235,
        y: vertical ? index * 94 + 22 : row * 126 + (columns[key] === 0 ? 185 : 40),
      },
      sourcePosition: vertical ? Position.Bottom : Position.Right,
      targetPosition: vertical ? Position.Top : Position.Left,
      data: {
        label: node.label,
        title: nodeTitle(node),
        subtitle: nodeSubtitle(node),
        selected: selectedNodeId === node.id,
        vertical,
      },
    };
  });

  const highlighted = new Set(
    (highlightedPath?.relationships ?? []).map(
      (edge) => `${edge.type}:${edge.source_id}:${edge.target_id}`,
    ),
  );
  const edges = records.relationships.map((relationship) => {
    const key = `${relationship.type}:${relationship.source_id}:${relationship.target_id}`;
    const isHighlighted = highlighted.has(key);
    return {
      id: key,
      source: relationship.source_id,
      target: relationship.target_id,
      label: relationship.type,
      type: "smoothstep",
      animated: isHighlighted,
      className: isHighlighted ? "graph-edge-highlight" : "graph-edge",
      style: {
        stroke: isHighlighted ? "#d9d17a" : "#53635e",
        strokeWidth: isHighlighted ? 2.5 : 1.25,
      },
      labelStyle: { fill: isHighlighted ? "#e9e3a6" : "#7f8d86", fontSize: 9 },
      labelBgStyle: { fill: "#151d1a", fillOpacity: 0.94 },
      labelBgPadding: [4, 3] as [number, number],
    };
  });
  return { nodes: positioned, edges };
}

function FindingRow({
  finding,
  kind,
  selected,
  onClick,
}: {
  finding: EvidenceFinding;
  kind: "fact" | "inference" | "contradiction";
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button className={`finding-row finding-${kind}${selected ? " finding-selected" : ""}`} onClick={onClick}>
      <span className="finding-mark">{kind === "contradiction" ? <X size={13} /> : kind === "inference" ? <Sparkles size={13} /> : <Check size={13} />}</span>
      <span className="finding-copy">
        <span>{finding.finding}</span>
        <small>
          {finding.evidence_ids.map(shortId).join(", ")}
          {finding.source ? ` / ${finding.source}` : ""}
          {finding.timestamp ? ` / ${formatTime(finding.timestamp)}` : ""}
        </small>
      </span>
      <ArrowUpRight size={13} className="finding-jump" />
    </button>
  );
}

function App() {
  const stableNodeTypes = useMemo(() => ({ entity: EntityNode }), []);
  const [isNarrow, setIsNarrow] = useState(() => window.matchMedia("(max-width: 560px)").matches);
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [alerts, setAlerts] = useState<GraphNode[]>([]);
  const [episodeCounts, setEpisodeCounts] = useState<Record<string, number>>({});
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [alertContext, setAlertContext] = useState<AlertContext | null>(null);
  const [recentEpisodes, setRecentEpisodes] = useState<HistoricalEpisode[]>([]);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [responseAction, setResponseAction] = useState<ResponseAction | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);
  const [searchText, setSearchText] = useState("");
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [loadingContext, setLoadingContext] = useState(false);
  const [investigating, setInvestigating] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionType, setActionType] = useState<SimulatedActionType | "">("");
  const [targetId, setTargetId] = useState("");
  const [evidenceIds, setEvidenceIds] = useState<string[]>([]);
  const [justification, setJustification] = useState("");
  const [approvedBy, setApprovedBy] = useState("security-analyst");
  const [rejectedBy, setRejectedBy] = useState("security-analyst");
  const [rejectionReason, setRejectionReason] = useState("");

  const loadInbox = useCallback(async (chooseFirst = false) => {
    setLoadingAlerts(true);
    try {
      const response = await api.alerts();
      setAlerts(response.alerts);
      setApiState("connected");
      setError(null);
      if (chooseFirst && response.alerts.length > 0) {
        setSelectedAlertId((current) => current ?? response.alerts[0].id);
      }
      const counts = await Promise.all(
        response.alerts.map(async (alert) => {
          try {
            const episodes = await api.episodes(alert.id);
            return [alert.id, episodes.length] as const;
          } catch {
            return [alert.id, 0] as const;
          }
        }),
      );
      setEpisodeCounts(Object.fromEntries(counts));
    } catch (cause) {
      setApiState("offline");
      setError(cause instanceof Error ? cause.message : "Could not load alerts.");
    } finally {
      setLoadingAlerts(false);
    }
  }, []);

  useEffect(() => {
    void api.health().then(() => setApiState("connected")).catch(() => setApiState("offline"));
    void loadInbox(true);
  }, [loadInbox]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 560px)");
    const update = () => setIsNarrow(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  const loadAlertContext = useCallback(async (alertId: string) => {
    setLoadingContext(true);
    try {
      const [context, episodes] = await Promise.all([api.alertContext(alertId), api.episodes(alertId)]);
      setAlertContext(context);
      setRecentEpisodes(episodes);
      setError(null);
      return context;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load alert context.");
      return null;
    } finally {
      setLoadingContext(false);
    }
  }, []);

  useEffect(() => {
    if (selectedAlertId) void loadAlertContext(selectedAlertId);
  }, [selectedAlertId, loadAlertContext]);

  const selectAlert = (alertId: string) => {
    setSelectedAlertId(alertId);
    setAlertContext(null);
    setRecentEpisodes([]);
    setAlertContext(null);
    setRecentEpisodes([]);
    setInvestigation(null);
    setResponseAction(null);
    setSelectedFindingId(null);
    setSelectedNodeId(null);
    setSelectedPathIndex(0);
    setActionType("");
    setTargetId("");
    setEvidenceIds([]);
    setError(null);
    setNotice(null);
  };

  const runInvestigation = async () => {
    if (!selectedAlertId) return;
    setInvestigating(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api.investigate(selectedAlertId);
      setInvestigation(result);
      setResponseAction(null);
      setSelectedPathIndex(0);
      setSelectedFindingId(null);
      setActionType(result.recommended_action.action_type === "monitor_only" ? "" : result.recommended_action.action_type);
      setTargetId(result.recommended_action.target_entity_id ?? "");
      setEvidenceIds([]);
      setJustification(result.recommended_action.rationale);
      setNotice(result.mode === "fallback" ? "Deterministic investigation saved to graph memory." : "Investigation saved to graph memory.");
      const [context, episodes] = await Promise.all([
        api.alertContext(selectedAlertId),
        api.episodes(selectedAlertId),
      ]);
      setAlertContext(context);
      setRecentEpisodes(episodes);
      setEpisodeCounts((current) => ({ ...current, [selectedAlertId]: episodes.length }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Investigation failed.");
    } finally {
      setInvestigating(false);
    }
  };

  const activePath = investigation?.attack_paths[selectedPathIndex] ?? null;
  const graph = useMemo(() => {
    const complete = graphRecords(alertContext, investigation);
    if (!isNarrow || !investigation || !activePath) return complete;
    return {
      nodes: activePath.nodes,
      relationships: activePath.relationships,
    };
  }, [alertContext, investigation, isNarrow, activePath]);
  const flow = useMemo(
    () => layoutGraph(graph, selectedNodeId, activePath, isNarrow),
    [graph, selectedNodeId, activePath, isNarrow],
  );
  const graphNodeById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const selectedNode = selectedNodeId ? graphNodeById.get(selectedNodeId) ?? null : null;

  const allFindings = useMemo(() => {
    if (!investigation) return [];
    return [
      ...investigation.observed_facts.map((finding, index) => ({ finding, kind: "fact" as const, key: `fact-${index}` })),
      ...investigation.inferences.map((finding, index) => ({ finding, kind: "inference" as const, key: `inference-${index}` })),
      ...investigation.contradictory_evidence.map((finding, index) => ({ finding, kind: "contradiction" as const, key: `contradiction-${index}` })),
    ];
  }, [investigation]);

  const evidenceOptions = useMemo(() => {
    if (!investigation || !actionType || !targetId) return [];
    const evidenceById = new Map<string, EvidenceFinding>();
    for (const finding of [...investigation.observed_facts, ...investigation.inferences]) {
      for (const id of finding.evidence_ids) evidenceById.set(id, finding);
    }
    const factor = investigation.risk_factors.find((item) => item.name === ACTION_FACTOR[actionType]);
    const eligible = new Set<string>();
    for (const [id, finding] of evidenceById) {
      if (finding.related_node_ids.includes(targetId)) eligible.add(id);
    }
    for (const id of factor?.evidence_ids ?? []) eligible.add(id);
    return [...eligible].map((id) => ({ id, finding: evidenceById.get(id) }));
  }, [actionType, investigation, targetId]);

  useEffect(() => {
    if (!actionType || !targetId || evidenceOptions.length === 0) {
      setEvidenceIds([]);
      return;
    }
    setEvidenceIds((current) => {
      if (current.length > 0 && current.every((id) => evidenceOptions.some((option) => option.id === id))) {
        return current;
      }
      const defaultCount = actionType === "vulnerability_remediation" ? 2 : 1;
      return evidenceOptions.slice(0, defaultCount).map((option) => option.id);
    });
  }, [actionType, targetId, evidenceOptions]);

  const filteredAlerts = alerts.filter((alert) => {
    const searchable = `${nodeTitle(alert)} ${alert.properties.description ?? ""} ${alert.id}`.toLowerCase();
    return searchable.includes(searchText.toLowerCase());
  });

  const chooseFinding = (key: string, finding: EvidenceFinding) => {
    setSelectedFindingId(key);
    setSelectedPathIndex((current) => {
      const match = investigation?.attack_paths.findIndex((path) =>
        finding.related_node_ids.some((id) => path.nodes.some((node) => node.id === id)),
      ) ?? -1;
      return match >= 0 ? match : current;
    });
    const matchingNode = finding.related_node_ids.find((id) => graphNodeById.has(id));
    if (matchingNode) setSelectedNodeId(matchingNode);
  };

  const proposeAction = async () => {
    if (!investigation || !actionType || !targetId || evidenceIds.length === 0) return;
    setActionBusy(true);
    setError(null);
    try {
      const proposed = await api.propose(
        investigation.investigation_id,
        actionType,
        targetId,
        evidenceIds,
        justification,
      );
      setResponseAction(proposed);
      setNotice("Simulated response proposed. No state changes until approval and execution.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Response proposal was rejected.");
    } finally {
      setActionBusy(false);
    }
  };

  const updateAction = async (operation: "approve" | "reject" | "execute" | "verify") => {
    if (!responseAction) return;
    setActionBusy(true);
    setError(null);
    try {
      const updated = operation === "approve"
        ? await api.approve(responseAction.id, approvedBy)
        : operation === "reject"
          ? await api.reject(responseAction.id, rejectedBy, rejectionReason)
          : operation === "execute"
            ? await api.execute(responseAction.id)
            : await api.verify(responseAction.id);
      setResponseAction(updated);
      setNotice(operation === "verify"
        ? updated.verification_status === "PASSED" ? "Simulation independently verified." : "Verification failed; the action was not marked verified."
        : `Simulated action state: ${updated.status}.`);
      if (updated.status === "VERIFIED" || updated.status === "REJECTED") {
        await loadInbox(false);
        if (selectedAlertId) setRecentEpisodes(await api.episodes(selectedAlertId));
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : `Could not ${operation} simulated action.`);
    } finally {
      setActionBusy(false);
    }
  };

  const toggleEvidence = (id: string) => {
    setEvidenceIds((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  };

  const reopenEpisode = async (episodeId: string) => {
    setInvestigating(true);
    setError(null);
    try {
      const saved = await api.getInvestigation(episodeId);
      setInvestigation(saved);
      setResponseAction(null);
      setSelectedPathIndex(0);
      setActionType(saved.recommended_action.action_type === "monitor_only" ? "" : saved.recommended_action.action_type);
      setTargetId(saved.recommended_action.target_entity_id ?? "");
      setJustification(saved.recommended_action.rationale);
      setNotice("Loaded the saved investigation episode from FalkorDB.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load saved investigation.");
    } finally {
      setInvestigating(false);
    }
  };

  const currentAlert = alerts.find((alert) => alert.id === selectedAlertId) ?? alertContext?.alert ?? null;
  const isSelectedAlertInvestigated = selectedAlertId ? (episodeCounts[selectedAlertId] ?? 0) > 0 : false;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><Waypoints size={19} strokeWidth={1.8} /></div>
          <div className="brand-title"><strong>GraphSentinel</strong><span>SECURITY INVESTIGATION</span></div>
        </div>
        <div className="topbar-center"><span className="topbar-kicker">INCIDENT RESPONSE</span><span className="topbar-divider" /><span>{currentAlert ? shortId(currentAlert.id) : "NO ALERT SELECTED"}</span></div>
        <div className="topbar-actions">
          <span className={`api-indicator api-${apiState}`}><span />{apiState === "connected" ? "GRAPH ONLINE" : apiState === "checking" ? "CONNECTING" : "API OFFLINE"}</span>
          <button className="icon-button refresh-button" title="Refresh alerts" aria-label="Refresh alerts" onClick={() => void loadInbox(false)} disabled={loadingAlerts}><RefreshCw size={15} className={loadingAlerts ? "spin" : ""} /></button>
          <span className="operator-chip"><span className="operator-dot">SA</span><span>Security analyst</span></span>
        </div>
      </header>

      {(error || notice) && (
        <div className={`notice-banner ${error ? "notice-error" : "notice-success"}`} role={error ? "alert" : "status"}>
          {error ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />}
          <span>{error ?? notice}</span>
          <button aria-label="Dismiss notification" onClick={() => { setError(null); setNotice(null); }}><X size={15} /></button>
        </div>
      )}

      <main className="workspace">
        <aside className="inbox-rail" aria-label="Alert inbox">
          <div className="rail-heading">
            <div><span className="eyebrow">QUEUE / 01</span><h1>Alert inbox</h1></div>
            <span className="count-pill">{alerts.length.toString().padStart(2, "0")}</span>
          </div>
          <label className="search-box">
            <Search size={15} />
            <input value={searchText} onChange={(event) => setSearchText(event.target.value)} placeholder="Filter alerts" aria-label="Filter alerts" />
            {searchText && <button aria-label="Clear search" onClick={() => setSearchText("")}><X size={13} /></button>}
          </label>
          <div className="inbox-filters"><span className="filter-active"><span className="filter-dot" /> All alerts</span><span>{alerts.length} total</span></div>
          <div className="alert-list">
            {loadingAlerts && alerts.length === 0 && <div className="rail-state"><LoaderCircle className="spin" size={17} /> Loading alert stream</div>}
            {!loadingAlerts && filteredAlerts.length === 0 && <div className="rail-empty"><Search size={18} /><span>{alerts.length === 0 ? "No alerts returned by the API." : "No alerts match this filter."}</span></div>}
            {filteredAlerts.map((alert) => {
              const selected = selectedAlertId === alert.id;
              const level = severity(alert);
              const count = episodeCounts[alert.id] ?? 0;
              return (
                <article className={`alert-item${selected ? " alert-item-selected" : ""}`} key={alert.id}>
                  <button className="alert-select" onClick={() => selectAlert(alert.id)} aria-pressed={selected}>
                    <span className={`severity-rail severity-${level}`} />
                    <span className="alert-copy">
                      <span className="alert-overline"><span className={`severity-tag severity-tag-${level}`}>{level}</span><span>{formatTime(String(alert.properties.timestamp ?? ""))}</span></span>
                      <strong>{titleCase(String(alert.properties.type ?? "alert"))}</strong>
                      <span className="alert-description">{String(alert.properties.description ?? "")}</span>
                      <span className="alert-meta"><span>{shortId(alert.id)}</span><span className={count ? "memory-count" : ""}>{count ? `${count === 100 ? "100+" : count} saved` : "NEW"}</span></span>
                    </span>
                  </button>
                  <button className={`investigate-row-button${selected && investigating ? " is-loading" : ""}`} onClick={() => { selectAlert(alert.id); void runInvestigationFor(alert.id); }} disabled={investigating} title="Investigate this alert">
                    {selected && investigating ? <LoaderCircle size={14} className="spin" /> : <ArrowRight size={14} />}
                  </button>
                </article>
              );
            })}
          </div>
          <div className="rail-footer"><span className={`footer-pulse ${apiState}`} />{apiState === "connected" ? "Live data from GraphSentinel API" : "Waiting for graph API"}</div>
        </aside>

        <section className="center-column">
          <section className="graph-section">
            <div className="section-bar graph-section-bar">
              <div className="section-title-wrap"><span className="section-icon"><Network size={16} /></span><div><span className="eyebrow">INVESTIGATION MAP</span><h2>{investigation ? "Observed graph context" : "Alert graph context"}</h2>{isNarrow && investigation && <small className="graph-focus-label">FOCUSED PATH / {selectedPathIndex + 1}</small>}</div></div>
              <div className="graph-toolbar">
                {investigation && <label className="path-selector"><GitBranch size={14} /><select aria-label="Highlight an attack path" value={selectedPathIndex} onChange={(event) => setSelectedPathIndex(Number(event.target.value))}>{investigation.attack_paths.map((path, index) => <option value={index} key={`${index}-${path.nodes.map((node) => node.id).join("-")}`}>Path {String(index + 1).padStart(2, "0")} / {path.relationships.length} hops</option>)}</select><ChevronDown size={13} /></label>}
                <span className="graph-count"><span>{graph.nodes.length}</span> nodes <span className="graph-count-sep">/</span> <span>{graph.relationships.length}</span> edges</span>
              </div>
            </div>
            <div className="graph-canvas" data-testid="investigation-graph">
              {!selectedAlertId ? (
                <div className="graph-empty"><Waypoints size={31} /><strong>Select an alert to begin</strong><span>Graph records appear here from the backend.</span></div>
              ) : loadingContext && graph.nodes.length === 0 ? (
                <div className="graph-empty"><LoaderCircle size={24} className="spin" /><span>Loading graph context</span></div>
              ) : graph.nodes.length === 0 ? (
                <div className="graph-empty"><Unplug size={24} /><strong>No graph context returned</strong><span>This alert has no connected records.</span></div>
              ) : (
                <ReactFlow
                  key={`${selectedAlertId ?? "none"}-${investigation ? "investigation" : "context"}-${selectedPathIndex}-${isNarrow ? "mobile" : "desktop"}`}
                  nodes={flow.nodes}
                  edges={flow.edges}
                  nodeTypes={stableNodeTypes}
                  onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                  fitView
                  fitViewOptions={{ padding: 0.18, maxZoom: 0.9 }}
                  minZoom={0.18}
                  maxZoom={1.4}
                  nodesConnectable={false}
                  nodesDraggable
                  elementsSelectable
                >
                  <Background color="#394640" gap={22} size={1} />
                  <Controls showInteractive={false} position="bottom-left" />
                  <MiniMap
                    position="bottom-right"
                    pannable
                    zoomable
                    nodeColor={(node) => LABEL_COLORS[(node.data as FlowNodeData).label] ?? "#81918a"}
                    maskColor="rgba(13, 19, 17, 0.74)"
                  />
                </ReactFlow>
              )}
              {investigating && <div className="graph-loading"><LoaderCircle size={15} className="spin" /> Tracing graph relationships</div>}
              <div className="graph-legend">{(["Alert", "Identity", "Device", "Service", "Vulnerability", "Evidence"] as NodeLabel[]).map((label) => <span key={label}><i style={{ background: LABEL_COLORS[label] }} />{label}</span>)}</div>
              <span className="graph-safety-label"><Waypoints size={12} /> PATHS ARE CONTEXT, NOT PROOF</span>
            </div>
            {investigation && investigation.attack_paths.length > 0 && (
              <div className="path-strip">
                <div className="path-strip-title"><GitBranch size={13} /><span>Path evidence</span></div>
                <div className="path-sequence">
                  {activePath?.nodes.map((node, index) => <span className="path-step-wrap" key={`${node.id}-${index}`}>
                    <button className={`path-step${selectedNodeId === node.id ? " path-step-selected" : ""}`} onClick={() => setSelectedNodeId(node.id)} title={`Inspect ${node.label}: ${node.id}`}><i style={{ background: LABEL_COLORS[node.label] }} />{nodeTitle(node)}</button>
                    {index < (activePath?.nodes.length ?? 0) - 1 && <ArrowRight size={12} className="path-arrow" />}
                  </span>)}
                </div>
              </div>
            )}
          </section>

          <div className="lower-grid">
            <section className="timeline-section">
              <div className="section-bar compact-section-bar"><div className="section-title-wrap"><span className="section-icon"><Clock3 size={15} /></span><div><span className="eyebrow">EVIDENCE TRAIL</span><h2>Investigation timeline</h2></div></div><span className="tiny-count">{timelineEntries(investigation, responseAction).length.toString().padStart(2, "0")}</span></div>
              <div className="timeline-list">
                {!investigation && !responseAction && <div className="inline-empty">Run an investigation to populate tool and evidence events.</div>}
                {timelineEntries(investigation, responseAction).map((entry, index) => <div className="timeline-entry" key={`${entry.key}-${index}`}>
                  <span className={`timeline-marker timeline-${entry.kind}`} />
                  <div className="timeline-entry-main"><strong>{entry.title}</strong><span>{entry.detail}</span></div>
                  <time>{entry.time}</time>
                </div>)}
              </div>
            </section>

            <section className="response-section">
              <div className="section-bar compact-section-bar"><div className="section-title-wrap"><span className="section-icon response-icon"><ShieldCheck size={15} /></span><div><span className="eyebrow">SIMULATED ONLY</span><h2>Response center</h2></div></div>{responseAction && <StatusBadge status={responseAction.status} />}</div>
              {!investigation ? (
                <div className="inline-empty response-empty"><LockKeyhole size={17} />An investigation is required before proposing a response.</div>
              ) : responseAction ? (
                <ActionProgress action={responseAction} busy={actionBusy} approvedBy={approvedBy} setApprovedBy={setApprovedBy} rejectedBy={rejectedBy} setRejectedBy={setRejectedBy} rejectionReason={rejectionReason} setRejectionReason={setRejectionReason} onAction={updateAction} onReset={() => setResponseAction(null)} />
              ) : investigation.recommended_action.action_type === "monitor_only" ? (
                <div className="monitor-only"><div className="monitor-icon"><ShieldCheck size={18} /></div><div><strong>Monitor and verify</strong><p>{investigation.recommended_action.rationale}</p><span>No containment action is recommended for this evidence level.</span></div></div>
              ) : (
                <ProposalForm investigation={investigation} graphNodes={graph.nodes} actionType={actionType} setActionType={setActionType} targetId={targetId} setTargetId={setTargetId} evidenceOptions={evidenceOptions} evidenceIds={evidenceIds} toggleEvidence={toggleEvidence} justification={justification} setJustification={setJustification} busy={actionBusy} onPropose={proposeAction} />
              )}
            </section>
          </div>
        </section>

        <aside className="inspector-column" aria-label="Investigation details">
          <div className="inspector-topbar">
            <div><span className="eyebrow">CASE WORKSPACE</span><h2>Findings &amp; context</h2></div>
            <button className="icon-button" aria-label="Run investigation" title={isSelectedAlertInvestigated ? "Run another investigation and retrieve memory" : "Investigate selected alert"} disabled={!selectedAlertId || investigating} onClick={() => void runInvestigation()}>{investigating ? <LoaderCircle size={15} className="spin" /> : isSelectedAlertInvestigated ? <RotateCcw size={15} /> : <ArrowRight size={15} />}</button>
          </div>

          {currentAlert && <div className="case-headline"><span className={`severity-tag severity-tag-${severity(currentAlert)}`}>{severity(currentAlert)}</span><span>{titleCase(String(currentAlert.properties.type ?? "alert"))}</span><time>{formatTime(String(currentAlert.properties.timestamp ?? ""))}</time><p>{String(currentAlert.properties.description ?? "")}</p></div>}

          {!investigation ? (
            <div className="pre-investigation">
              <span className="pre-investigation-icon"><CircleDot size={20} /></span>
              <strong>{selectedAlertId ? "Alert context loaded" : "Select an alert"}</strong>
              <p>{selectedAlertId ? "Run the investigator to calculate risk, collect evidence provenance, and retrieve historical memory." : "Choose an alert from the inbox to inspect its graph context."}</p>
              {selectedAlertId && <button className="primary-button" onClick={() => void runInvestigation()} disabled={investigating}>{investigating ? <LoaderCircle size={15} className="spin" /> : <Search size={15} />}{investigating ? "Investigating" : "Investigate alert"}</button>}
              {recentEpisodes.length > 0 && <div className="saved-episodes"><SectionHeading icon={<History size={14} />} label="Saved episodes" count={recentEpisodes.length} />{recentEpisodes.map((episode) => <button className="saved-episode-row" key={episode.episode_id} onClick={() => void reopenEpisode(episode.episode_id)}><span className="saved-episode-score">{episode.risk_score}</span><span><strong>{episode.risk_level} / {episode.outcome.toLowerCase()}</strong><small>{episode.summary}</small></span><ArrowUpRight size={13} /></button>)}</div>}
            </div>
          ) : (
            <div className="inspector-scroll">
              <section className="risk-panel">
                <div className="risk-score-block">
                  <div className={`risk-ring risk-${riskColor(investigation.risk_level)}`} style={{ "--score": `${investigation.risk_score * 3.6}deg` } as React.CSSProperties}>
                    <div><strong>{investigation.risk_score}</strong><small>/100</small></div>
                  </div>
                  <div className="risk-grade"><span className={`risk-level risk-text-${riskColor(investigation.risk_level)}`}>{investigation.risk_level}</span><span>DETERMINISTIC SCORE</span><small>{investigation.mode === "fallback" ? "Local graph investigation agent" : "LLM + rules engine"}</small></div>
                </div>
                <p className="risk-summary">{investigation.summary}</p>
                <div className="confidence-grid">
                  <div><span>Confidence</span><strong>{Math.round(investigation.confidence * 100)}%</strong><div className="metric-track"><i style={{ width: `${investigation.confidence * 100}%` }} /></div></div>
                  <div><span>Evidence coverage</span><strong>{Math.round(investigation.evidence_completeness * 100)}%</strong><div className="metric-track metric-coverage"><i style={{ width: `${investigation.evidence_completeness * 100}%` }} /></div></div>
                </div>
              </section>

              <section className="inspector-section factor-section">
                <SectionHeading icon={<Activity size={14} />} label="Risk factors" count={investigation.risk_factors.length} />
                {investigation.risk_factors.length === 0 ? <p className="subtle-empty">No evidence-backed scoring factors were found.</p> : investigation.risk_factors.map((factor) => <button className="factor-row" key={factor.name} onClick={() => selectEvidenceFactor(factor, investigation, setSelectedPathIndex, setSelectedFindingId, setSelectedNodeId, graphNodeById)}>
                  <span className={`factor-score ${factor.score < 0 ? "factor-negative" : ""}`}>{factor.score > 0 ? "+" : ""}{factor.score}</span>
                  <span><strong>{titleCase(factor.name)}</strong><small>{factor.explanation}</small><em>{factor.evidence_ids.map(shortId).join(" / ")}</em></span>
                  <ArrowUpRight size={13} />
                </button>)}
              </section>

              <section className="inspector-section findings-section">
                <SectionHeading icon={<Fingerprint size={14} />} label="Evidence & findings" count={allFindings.length} />
                <div className="findings-groups">
                  {investigation.observed_facts.length > 0 && <div className="finding-group"><span className="group-label">OBSERVED FACTS</span>{allFindings.filter((entry) => entry.kind === "fact").map((entry) => <FindingRow key={entry.key} finding={entry.finding} kind={entry.kind} selected={selectedFindingId === entry.key} onClick={() => chooseFinding(entry.key, entry.finding)} />)}</div>}
                  {investigation.inferences.length > 0 && <div className="finding-group"><span className="group-label">INFERENCES</span>{allFindings.filter((entry) => entry.kind === "inference").map((entry) => <FindingRow key={entry.key} finding={entry.finding} kind={entry.kind} selected={selectedFindingId === entry.key} onClick={() => chooseFinding(entry.key, entry.finding)} />)}</div>}
                  {investigation.contradictory_evidence.length > 0 && <div className="finding-group"><span className="group-label">COUNTER-EVIDENCE</span>{allFindings.filter((entry) => entry.kind === "contradiction").map((entry) => <FindingRow key={entry.key} finding={entry.finding} kind={entry.kind} selected={selectedFindingId === entry.key} onClick={() => chooseFinding(entry.key, entry.finding)} />)}</div>}
                  {allFindings.length === 0 && <p className="subtle-empty">No evidence records were returned for this alert.</p>}
                </div>
                {investigation.missing_evidence.length > 0 && <div className="missing-evidence"><span>Missing evidence categories</span><p>{investigation.missing_evidence.map(titleCase).join(" / ")}</p></div>}
              </section>

              <section className="inspector-section memory-section">
                <SectionHeading icon={<History size={14} />} label="Historical memory" count={investigation.historical_episodes.length + investigation.historical_incidents.length} />
                {investigation.historical_episodes.map((episode) => <article className="memory-entry" key={episode.episode_id}>
                  <div className="memory-entry-top"><span className="memory-type">SAVED EPISODE</span><time>{formatTime(episode.created_at)}</time></div>
                  <strong>{episode.risk_score} / 100 <span className={`risk-text-${riskColor(episode.risk_level)}`}>{episode.risk_level}</span></strong>
                  <p>{episode.summary}</p>
                  <small>{episode.relevance_reasons.join(" ")}</small>
                </article>)}
                {investigation.historical_incidents.map((incident) => <article className="memory-entry incident-memory" key={incident.incident.id}>
                  <div className="memory-entry-top"><span className="memory-type">PRIOR INCIDENT</span><time>{formatTime(String(incident.incident.properties.created_at ?? ""))}</time></div>
                  <strong>{String(incident.incident.properties.type ?? incident.incident.id)}</strong>
                  <p>{String(incident.incident.properties.summary ?? "")}</p>
                  <small>{incident.relevance_reasons.join(" ")}</small>
                </article>)}
                {investigation.historical_episodes.length + investigation.historical_incidents.length === 0 && <p className="subtle-empty">No relevant saved incidents or episodes matched this alert.</p>}
              </section>

              {selectedNode && <section className="inspector-section selected-node-panel">
                <SectionHeading icon={<Database size={14} />} label="Selected graph record" />
                <div className="selected-node-head"><span className="node-type-dot" style={{ background: LABEL_COLORS[selectedNode.label] }} /><div><strong>{nodeTitle(selectedNode)}</strong><small>{selectedNode.label} / {selectedNode.id}</small></div><button aria-label="Clear selected graph node" onClick={() => setSelectedNodeId(null)}><X size={13} /></button></div>
                <div className="property-list">{Object.entries(selectedNode.properties).slice(0, 8).map(([key, value]) => <div key={key}><span>{key}</span><strong>{String(value)}</strong></div>)}</div>
              </section>}

              {investigation.limitations.length > 0 && <div className="limitations-note"><AlertTriangle size={13} /><span>{investigation.limitations.join(" ")}</span></div>}
            </div>
          )}
        </aside>
      </main>
    </div>
  );

  async function runInvestigationFor(alertId: string) {
    selectAlert(alertId);
    setSelectedAlertId(alertId);
    setInvestigating(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api.investigate(alertId);
      setInvestigation(result);
      setSelectedPathIndex(0);
      setActionType(result.recommended_action.action_type === "monitor_only" ? "" : result.recommended_action.action_type);
      setTargetId(result.recommended_action.target_entity_id ?? "");
      setJustification(result.recommended_action.rationale);
      setEvidenceIds([]);
      setNotice(result.mode === "fallback" ? "Deterministic investigation saved to graph memory." : "Investigation saved to graph memory.");
      const [context, episodes] = await Promise.all([api.alertContext(alertId), api.episodes(alertId)]);
      setAlertContext(context);
      setRecentEpisodes(episodes);
      setEpisodeCounts((current) => ({ ...current, [alertId]: episodes.length }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Investigation failed.");
    } finally {
      setInvestigating(false);
    }
  }
}

function SectionHeading({ icon, label, count }: { icon: React.ReactNode; label: string; count?: number }) {
  return <div className="subsection-heading"><span className="subsection-icon">{icon}</span><strong>{label}</strong>{count !== undefined && <span className="subsection-count">{count}</span>}</div>;
}

function StatusBadge({ status }: { status: ActionStatus }) {
  return <span className={`action-status status-${status.toLowerCase()}`}><i />{titleCase(status)}</span>;
}

function ProposalForm({
  investigation,
  graphNodes,
  actionType,
  setActionType,
  targetId,
  setTargetId,
  evidenceOptions,
  evidenceIds,
  toggleEvidence,
  justification,
  setJustification,
  busy,
  onPropose,
}: {
  investigation: Investigation;
  graphNodes: GraphNode[];
  actionType: SimulatedActionType | "";
  setActionType: (value: SimulatedActionType | "") => void;
  targetId: string;
  setTargetId: (value: string) => void;
  evidenceOptions: { id: string; finding?: EvidenceFinding }[];
  evidenceIds: string[];
  toggleEvidence: (id: string) => void;
  justification: string;
  setJustification: (value: string) => void;
  busy: boolean;
  onPropose: () => void;
}) {
  const availableTargets = actionType ? graphNodes.filter((node) => node.label === ACTION_TARGET[actionType]) : [];
  const eligibleEvidence = evidenceOptions;
  const containRestricted = (actionType === "temporary_identity_restriction" || actionType === "device_isolation") && investigation.risk_score < 50;
  return (
    <div className="proposal-form">
      <div className="proposal-recommendation"><div className="recommendation-mark"><ShieldAlert size={16} /></div><div><span className="eyebrow">BACKEND RECOMMENDATION</span><strong>{titleCase(investigation.recommended_action.action_type)}</strong><p>{investigation.recommended_action.rationale}</p></div></div>
      <div className="form-grid">
        <label className="field-label">Action type
          <select value={actionType} onChange={(event) => { const value = event.target.value as SimulatedActionType | ""; setActionType(value); setTargetId(""); }}>
            <option value="">Choose a simulated action</option>
            {(Object.keys(ACTION_LABEL) as SimulatedActionType[]).map((type) => <option key={type} value={type}>{ACTION_LABEL[type]}</option>)}
          </select>
        </label>
        <label className="field-label">Target entity
          <select value={targetId} onChange={(event) => setTargetId(event.target.value)} disabled={!actionType || availableTargets.length === 0}>
            <option value="">{!actionType ? "Select an action first" : availableTargets.length ? "Select a discovered target" : `No ${ACTION_TARGET[actionType]} in returned graph`}</option>
            {availableTargets.map((node) => <option key={node.id} value={node.id}>{nodeTitle(node)} / {shortId(node.id)}</option>)}
          </select>
        </label>
      </div>
      {actionType && <div className="evidence-choice"><div className="evidence-choice-heading"><span>Supporting evidence</span><small>{evidenceIds.length} selected</small></div>
        {eligibleEvidence.length === 0 ? <p className="no-evidence-choice">No returned supporting evidence is linked to this target.</p> : eligibleEvidence.map((option) => <label className="evidence-checkbox" key={option.id}><input type="checkbox" checked={evidenceIds.includes(option.id)} onChange={() => toggleEvidence(option.id)} /><span className="checkmark" /><span><strong>{shortId(option.id)}</strong><small>{option.finding?.finding ?? "Evidence in the backend risk path"}</small></span></label>)}
      </div>}
      <label className="field-label justification-label">Justification
        <textarea value={justification} onChange={(event) => setJustification(event.target.value)} rows={2} maxLength={1000} placeholder="Why is this proportionate?" />
      </label>
      {containRestricted && <div className="policy-hint"><LockKeyhole size={13} />Containment proposals require a high-risk investigation. This alert scores below that threshold.</div>}
      <div className="proposal-footer"><span><LockKeyhole size={12} /> Proposal only. No change until approved.</span><button className="primary-button propose-button" onClick={onPropose} disabled={busy || !actionType || !targetId || evidenceIds.length === 0 || !justification.trim() || containRestricted}>{busy ? <LoaderCircle size={14} className="spin" /> : <ShieldCheck size={14} />}{busy ? "Saving proposal" : "Propose simulated action"}</button></div>
    </div>
  );
}

function ActionProgress({
  action,
  busy,
  approvedBy,
  setApprovedBy,
  rejectedBy,
  setRejectedBy,
  rejectionReason,
  setRejectionReason,
  onAction,
  onReset,
}: {
  action: ResponseAction;
  busy: boolean;
  approvedBy: string;
  setApprovedBy: (value: string) => void;
  rejectedBy: string;
  setRejectedBy: (value: string) => void;
  rejectionReason: string;
  setRejectionReason: (value: string) => void;
  onAction: (operation: "approve" | "reject" | "execute" | "verify") => Promise<void>;
  onReset: () => void;
}) {
  const steps: ActionStatus[] = ["PROPOSED", "APPROVED", "EXECUTED_SIMULATED", "VERIFIED"];
  const completedThrough = action.status === "REJECTED" ? 0 : steps.indexOf(action.status);
  return (
    <div className="action-progress">
      <div className="simulation-warning"><ShieldAlert size={14} /><span>Simulation only</span><small>FalkorDB simulation state; no live security control was changed.</small></div>
      <div className="action-summary"><div><span className="eyebrow">{ACTION_LABEL[action.action_type]}</span><strong>{shortId(action.target_entity_id)}</strong></div><StatusBadge status={action.status} /></div>
      <p className="action-justification">{action.justification}</p>
      <div className="state-track">{steps.map((step, index) => <div className={`state-step${index <= completedThrough ? " state-step-done" : ""}${action.status === "REJECTED" && index > 0 ? " state-step-muted" : ""}`} key={step}><span>{index < completedThrough || action.status === "VERIFIED" ? <Check size={11} /> : index + 1}</span><small>{step === "EXECUTED_SIMULATED" ? "SIMULATED" : titleCase(step)}</small></div>)}</div>
      {action.status === "PROPOSED" && <div className="action-controls">
        <label className="field-label">Approver identity<input value={approvedBy} onChange={(event) => setApprovedBy(event.target.value)} /></label>
        <div className="action-button-row"><button className="approve-button" disabled={busy || approvedBy.trim().length < 2} onClick={() => void onAction("approve")}><CheckCircle2 size={14} />Approve</button><button className="reject-button" disabled={busy || rejectedBy.trim().length < 2 || rejectionReason.trim().length < 3} onClick={() => void onAction("reject")}><Ban size={14} />Reject</button></div>
        <div className="reject-fields"><input aria-label="Rejecting analyst" value={rejectedBy} onChange={(event) => setRejectedBy(event.target.value)} placeholder="Rejecting analyst" /><input aria-label="Rejection reason" value={rejectionReason} onChange={(event) => setRejectionReason(event.target.value)} placeholder="Rejection reason" /></div>
      </div>}
      {action.status === "APPROVED" && <div className="approval-confirmation"><CheckCircle2 size={14} /><span>Approved by <strong>{action.approved_by}</strong>. Execution remains a separate explicit step.</span><button className="execute-button" disabled={busy} onClick={() => void onAction("execute")}><ShieldAlert size={14} />Execute simulation</button></div>}
      {action.status === "EXECUTED_SIMULATED" && <div className={`verification-panel${action.verification_status === "FAILED" ? " verification-failed" : ""}`}><div><span className="eyebrow">INDEPENDENT READ-BACK</span><strong>{action.verification_result || action.result}</strong></div><button className="verify-button" disabled={busy} onClick={() => void onAction("verify")}><RefreshCw size={13} />Verify state</button></div>}
      {action.status === "VERIFIED" && <div className="verified-panel"><CheckCircle2 size={15} /><div><strong>Outcome verified</strong><span>{action.verification_result}</span></div><button className="text-button" onClick={onReset}>New proposal</button></div>}
      {action.status === "REJECTED" && <div className="rejected-panel"><ShieldX size={15} /><div><strong>Proposal rejected</strong><span>{action.audit_events.find((event) => event.event_type === "REJECTED")?.details.reason?.toString() ?? "Rejected by reviewer. This action cannot execute."}</span></div><button className="text-button" onClick={onReset}>New proposal</button></div>}
      <div className="audit-line"><span>Audit trail</span>{action.audit_events.map((event) => <span className="audit-event" title={`${event.actor} / ${formatTime(event.timestamp)}`} key={event.id}>{event.to_state === "EXECUTED_SIMULATED" ? "SIMULATED" : event.to_state}</span>)}</div>
    </div>
  );
}

function selectEvidenceFactor(
  factor: RiskFactor,
  investigation: Investigation,
  setSelectedPathIndex: (value: (current: number) => number) => void,
  setSelectedFindingId: (value: string | null) => void,
  setSelectedNodeId: (value: string | null) => void,
  graphNodeById: Map<string, GraphNode>,
) {
  setSelectedFindingId(`factor-${factor.name}`);
  if (factor.path_node_ids.length > 0) {
    setSelectedPathIndex((current) => {
      const index = investigation.attack_paths.findIndex((path) => factor.path_node_ids.some((id) => path.nodes.some((node) => node.id === id)));
      return index >= 0 ? index : current;
    });
  }
  const nodeId = factor.path_node_ids.find((id) => graphNodeById.has(id));
  if (nodeId) setSelectedNodeId(nodeId);
}

function timelineEntries(investigation: Investigation | null, action: ResponseAction | null) {
  type Entry = { key: string; kind: string; title: string; detail: string; time: string; rawTime: string };
  const entries: Entry[] = [];
  investigation?.tool_calls.forEach((call, index) => entries.push({
    key: `tool-${index}-${call.tool_name}`,
    kind: "tool",
    title: titleCase(call.tool_name),
    detail: call.result_summary,
    time: `STEP ${String(index + 1).padStart(2, "0")}`,
    rawTime: "",
  }));
  investigation?.observed_facts.slice(0, 4).forEach((fact, index) => entries.push({
    key: `evidence-${fact.evidence_ids[0]}`,
    kind: "evidence",
    title: fact.source ?? `Evidence ${index + 1}`,
    detail: `${fact.finding} / ${fact.evidence_ids.map(shortId).join(", ")}`,
    time: formatTime(fact.timestamp),
    rawTime: fact.timestamp ?? "",
  }));
  investigation?.historical_episodes.slice(0, 2).forEach((episode) => entries.push({
    key: `episode-${episode.episode_id}`,
    kind: "memory",
    title: "Historical episode matched",
    detail: episode.relevance_reasons[0] ?? episode.summary,
    time: formatTime(episode.created_at),
    rawTime: episode.created_at,
  }));
  investigation?.historical_incidents.slice(0, 2).forEach((incident) => entries.push({
    key: `incident-${incident.incident.id}`,
    kind: "memory",
    title: `Prior incident / ${String(incident.incident.properties.type ?? incident.incident.id)}`,
    detail: incident.relevance_reasons[0] ?? String(incident.incident.properties.summary ?? "Historical context retrieved."),
    time: formatTime(String(incident.incident.properties.created_at ?? "")),
    rawTime: String(incident.incident.properties.created_at ?? ""),
  }));
  action?.audit_events.forEach((event) => entries.push({
    key: `audit-${event.id}`,
    kind: event.event_type.includes("FAIL") ? "warning" : "action",
    title: event.event_type === "EXECUTED_SIMULATED" ? "Simulated response executed" : titleCase(event.event_type),
    detail: `${event.actor} / ${String(event.details.reason ?? event.details.simulated ?? "Response lifecycle event")}`,
    time: formatTime(event.timestamp),
    rawTime: event.timestamp,
  }));
  return entries.sort((left, right) => left.rawTime.localeCompare(right.rawTime));
}

export default App;