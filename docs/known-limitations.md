# Known Limitations

- The environment, identities, events, evidence, vulnerabilities, incidents, and service relationships are deterministic synthetic fixtures. They are not live telemetry or customer data.
- Evaluation covers two hand-authored alerts and a deliberately simple severity-only comparator. It is a reproducibility check, not a general accuracy estimate or production security benchmark.
- Risk weights are illustrative design parameters, not calibrated probabilities.
- Without `OPENAI_API_KEY`, investigations use the deterministic fallback and report that mode. Automated tests use a fake model client; no live LLM provider call has been validated in this workspace.
- Response actions only change `simulation_state` and `simulation_version` properties in FalkorDB. There is no identity-provider, endpoint, network, cloud, or vulnerability-management integration.
- `approved_by`/`rejected_by` are explicit operator labels supplied to a demo API; this phase does not authenticate analyst identity or authorize real-world changes. Do not expose the response endpoints as a production control plane.
- Investigation results and episodes persist in the graph, and memory query responses are bounded (at most 100 by current application configuration). The evaluator marks capped memory counts; it does not report them as total graph inventory.
- Synthetic tests and repeated demos intentionally add persisted investigation episodes, actions, and audit events. There is no retention or pruning policy yet. Fixture reset deletes only the `graphsentinel` graph and is not part of routine test startup.
- The alert-only baseline maps only alert severity to illustrative points. Its latency is not comparable to full graph investigation latency because it performs no graph access or evidence work.
- The MCP process supports stdio transport and only the five GraphSentinel read tools. No standalone HTTP MCP endpoint, authorization layer, or browser frontend integration is configured.
- The React Flow graph is a bounded union of backend-returned paths on desktop. On narrow screens it focuses the selected path to preserve readable labels; path navigation remains available. A graph with many returned branches can still require zooming and panning.
- API endpoints are intended for a local demo. Authentication, rate limits, multi-user tenancy, and production deployment hardening are outside this phase.