# GraphSentinel Copilot Instructions

## Project summary

GraphSentinel is a local, synthetic-data security investigation demo built around a FalkorDB graph, a FastAPI backend, and a React + TypeScript + Vite dashboard. The system is intentionally graph-first: investigation decisions, evidence linkage, and saved memory all come from FalkorDB-backed records, not ad hoc in-memory state.

This repository contains:
- `graphsentinel/`: Python backend, repository layer, deterministic risk engine, MCP server, seed data, and API app.
- `tests/`: backend integration tests for API, repository, investigator, response simulator, and MCP behavior.
- `frontend/`: React 19 + Vite + TypeScript dashboard with Vitest tests.
- `data/demo_graph.json`: synthetic incident graph fixture used by the seed and evaluation flow.
- `docs/`: architecture, schema, risk model, MCP, setup, and evaluation documentation.

## Architecture and data flow

- Browser -> FastAPI API -> `Investigator` -> `GraphRepository` -> FalkorDB
- The API exposes read-only alert and investigation endpoints and the approval-gated simulated response lifecycle.
- The graph repository is the authoritative source for nodes, edges, alert context, evidence, incidents, and saved investigation episodes.
- The React frontend reads real API responses and renders graph context, evidence, risk factors, and response state; it does not fabricate findings.
- The MCP server is explicitly read-only and exposes a bounded set of graph investigation tools without arbitrary Cypher access or mutation endpoints.

## Graph schema and evidence model

The named graph is `graphsentinel`. Core labels include `Alert`, `Event`, `Identity`, `Device`, `Service`, `Evidence`, `Vulnerability`, `Incident`, `ResponseAction`, `InvestigationEpisode`, and `ActionAudit`.

Graph relationships are directional and represent possible context, not proof of compromise. Examples:
- `OBSERVED_ON`: `Alert -> Identity|Device|Service`
- `HAS_EVENT`: `Alert -> Event`
- `HAS_EVIDENCE`: `Alert|InvestigationEpisode -> Evidence`
- `ABOUT`: `Evidence -> Identity|Device|Service`
- `INVOLVES`: `Event|Incident|InvestigationEpisode -> Identity|Device|Service`
- `DISCOVERED`: `InvestigationEpisode -> Vulnerability`
- `HAS_AUDIT_EVENT`: `ResponseAction -> ActionAudit`

Evidence provenance is mandatory.
- Every investigation fact and recommendation must be traceable to graph evidence IDs or explicit historical record metadata.
- Findings must clearly separate observed facts, inferences, contradictory evidence, and missing evidence.
- Historical matches are contextual and must never be treated as proof of a shared attack.
- Paths are possible relationship chains, not verified compromise.

## Coding conventions

- Use the strict Pydantic models under `graphsentinel/models.py` for API and response validation.
- Keep graph access centralized in `graphsentinel/repository.py`; do not spread FalkorDB queries across the app.
- Keep risk scoring deterministic in `graphsentinel/risk.py` and application-owned; do not let an LLM override the numeric score.
- Prefer typed, schema-constrained database and request models over ad hoc dictionaries.
- Preserve the existing naming: `GraphRepository`, `Investigator`, `SimulatedResponseEngine`, `create_app`, `create_mcp_server`.
- Keep behavior consistent with the seeded synthetic graph and fixture-driven tests.
- Do not add functionality that bypasses the repository or the read-only MCP boundary.

## Security boundaries and trust rules

- FalkorDB must drive investigation decisions. If a fact is not represented in the graph, it is not treated as an observed fact.
- Evidence provenance is mandatory and must be surfaced in outputs, not implied.
- The MCP server is read-only and uses `GRAPH.RO_QUERY` access only. It does not expose arbitrary Cypher, writes, resets, approval flows, or response actions.
- Response actions are simulated only. They do not trigger real IAM, endpoint, network, or cloud changes.
- The supported action lifecycle is `PROPOSED -> APPROVED -> EXECUTED_SIMULATED -> VERIFIED`.
- Unapproved actions must never execute. Rejection is terminal.
- Execution before explicit approval is rejected.
- Simulated actions only change `simulation_state` and `simulation_version` on target nodes; the underlying state is not mutated.
- The presence of prior history or shared entities is contextual memory, not proof of current compromise.

## Test and validation commands

Run backend tests from the repo root:
- `./.venv/bin/python -m pytest -q`

Run frontend tests from `frontend/`:
- `npm test`

Run the strict frontend build from `frontend/`:
- `npm run build`

Run the synthetic evaluation from the repo root:
- `./.venv/bin/python -m graphsentinel.evaluate --output docs/evaluation-results.json`

Do not consider a phase complete until the relevant tests pass. A phase is not complete when there are failing backend tests, frontend tests, or build/type-check failures.

## Operational rules for implementation

- Use the checked-in demo seed and live FalkorDB; do not invent fake data or bypass the repository layer.
- Keep the API and frontend aligned with the implemented schema and response models in `graphsentinel/models.py` and `frontend/src/types.ts`.
- When working on investigations, prefer real graph queries and persisted episodes over local-only assumptions.
- If an action is proposed, it must carry target and evidence metadata and remain simulation-only until a separate approval path is completed.
- If a user request implies a real remediation or execution outside the simulator, treat it as out of scope unless the repository explicitly supports it.
- When updating the project, keep behavior consistent with the actual repo state in `README.md`, `docs/architecture.md`, `docs/graph-schema.md`, and the tests.

## Required implementation guardrails

1. FalkorDB remains the source of truth for investigation decisions.
2. Evidence provenance is required for every claim and recommendation.
3. All response actions are simulated, not real enforcement.
4. No unapproved action may execute.
5. Tests must pass before a phase is considered complete.
