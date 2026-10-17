import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../src/api";

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GraphSentinel API client", () => {
  it("loads real alert and context routes with stable identifiers", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ alerts: [] }))
      .mockResolvedValueOnce(jsonResponse({ alert: { id: "alert:one" }, nodes: [], relationships: [] }));
    vi.stubGlobal("fetch", fetchMock);

    await api.alerts();
    await api.alertContext("alert:one");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("http://127.0.0.1:8000/alerts?limit=100");
    expect(fetchMock.mock.calls[1]?.[0]).toBe("http://127.0.0.1:8000/alerts/alert%3Aone");
  });

  it("posts an investigation with the selected alert ID", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ investigation_id: "episode-1" }));
    vi.stubGlobal("fetch", fetchMock);

    await api.investigate("alert-2026-1015-001");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/investigations",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ alert_id: "alert-2026-1015-001" }),
      }),
    );
  });

  it("maps response proposal, approval, rejection, execution, and verification routes", async () => {
    const fetchMock = vi.fn().mockImplementation(async () => jsonResponse({ id: "action-1" }));
    vi.stubGlobal("fetch", fetchMock);

    await api.propose("episode-1", "temporary_identity_restriction", "id-ava-chen", ["ev-privilege-ava"], "Review login");
    await api.approve("action-1", "analyst");
    await api.reject("action-1", "analyst", "Rejected after review");
    await api.execute("action-1");
    await api.verify("action-1");

    const paths = fetchMock.mock.calls.map(([url]) => url);
    expect(paths).toEqual([
      "http://127.0.0.1:8000/investigations/episode-1/response-actions",
      "http://127.0.0.1:8000/response-actions/action-1/approve",
      "http://127.0.0.1:8000/response-actions/action-1/reject",
      "http://127.0.0.1:8000/response-actions/action-1/execute",
      "http://127.0.0.1:8000/response-actions/action-1/verify",
    ]);
    expect(JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string)).toEqual({
      action_type: "temporary_identity_restriction",
      target_entity_id: "id-ava-chen",
      evidence_ids: ["ev-privilege-ava"],
      justification: "Review login",
    });
  });

  it("surfaces the backend's structured error message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      jsonResponse({ error: { code: "database_unavailable", message: "Graph DB unavailable" } }, 503),
    ));

    await expect(api.alerts()).rejects.toThrow("Graph DB unavailable");
  });
});