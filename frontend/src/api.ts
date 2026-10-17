import type {
  AlertContext,
  AlertList,
  ApiError,
  HistoricalEpisode,
  Investigation,
  ResponseAction,
  SimulatedActionType,
} from "./types";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...init?.headers,
      },
    });
  } catch {
    throw new Error("Cannot reach GraphSentinel API. Check that FastAPI is running.");
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const error = body as ApiError | null;
    throw new Error(error?.error?.message ?? `API request failed (${response.status}).`);
  }
  return body as T;
}

export const api = {
  health: () => request<{ status: "ok"; database: "connected" }>("/health"),
  alerts: () => request<AlertList>("/alerts?limit=100"),
  alertContext: (alertId: string) =>
    request<AlertContext>(`/alerts/${encodeURIComponent(alertId)}`),
  episodes: (alertId: string) =>
    request<HistoricalEpisode[]>(`/alerts/${encodeURIComponent(alertId)}/episodes`),
  investigate: (alertId: string) =>
    request<Investigation>("/investigations", {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId }),
    }),
  getInvestigation: (id: string) =>
    request<Investigation>(`/investigations/${encodeURIComponent(id)}`),
  propose: (
    investigationId: string,
    actionType: SimulatedActionType,
    targetEntityId: string,
    evidenceIds: string[],
    justification: string,
  ) =>
    request<ResponseAction>(
      `/investigations/${encodeURIComponent(investigationId)}/response-actions`,
      {
        method: "POST",
        body: JSON.stringify({
          action_type: actionType,
          target_entity_id: targetEntityId,
          evidence_ids: evidenceIds,
          justification,
        }),
      },
    ),
  getAction: (id: string) => request<ResponseAction>(`/response-actions/${encodeURIComponent(id)}`),
  approve: (id: string, approvedBy: string) =>
    request<ResponseAction>(`/response-actions/${encodeURIComponent(id)}/approve`, {
      method: "POST",
      body: JSON.stringify({ approved_by: approvedBy }),
    }),
  reject: (id: string, rejectedBy: string, reason: string) =>
    request<ResponseAction>(`/response-actions/${encodeURIComponent(id)}/reject`, {
      method: "POST",
      body: JSON.stringify({ rejected_by: rejectedBy, reason }),
    }),
  execute: (id: string) =>
    request<ResponseAction>(`/response-actions/${encodeURIComponent(id)}/execute`, {
      method: "POST",
    }),
  verify: (id: string) =>
    request<ResponseAction>(`/response-actions/${encodeURIComponent(id)}/verify`, {
      method: "POST",
    }),
};