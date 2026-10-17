# Why the Graph Changed the Investigation

## An alert is a starting point, not a story

A suspicious-login alert tells an analyst that an authentication event deserves attention. By itself, it does not tell them whether the identity is privileged, which device was involved, what that device can reach, whether recently changed network policy affects that route, or whether the route ends at a sensitive service. GraphSentinel makes those relationships explicit and keeps each observation attached to its source record.

The demo’s higher-risk case begins with an unusual successful login for a privileged platform identity. A bounded traversal follows the alert to Ava Chen, her managed laptop, Deploy Console, Artifact Registry, and a synthetic vulnerability record. The graph also associates a recent egress change and supporting network evidence with the investigation. This yields a useful possible-path explanation and a deterministic risk score. It does **not** establish that the vulnerability was exploited, the device was compromised, or the identity was malicious.

That distinction matters. Relationships answer “what could connect?” Evidence answers “what did a source record actually report?” GraphSentinel keeps these separate: paths carry node and edge IDs; findings cite evidence IDs, sources, and timestamps; an inference explicitly says when a route is only possible.

## The comparison

The checked-in evaluation uses two synthetic alerts and an intentionally simple alert-only baseline: a documented illustrative mapping from severity to points. On the privileged high-severity alert, the baseline scored 60/high. The graph-backed engine scored 85/critical, with the expected path and all five expected supporting records retrieved. On the standard-account medium-severity alert, the baseline scored 35/moderate; the graph-backed score was 0/low after considering healthy device posture and denied service access alongside the unusual-region signal.

These numbers are design parameters, not probabilities or calibrated detection accuracy. They demonstrate that graph context can move the recommendation in either direction: add corroboration in one case, or show mitigating evidence in another. The baseline has no graph queries and no evidence provenance; the graph-backed evaluation executed 15 and 13 FalkorDB repository queries for the two scenarios, respectively. Local end-to-end investigation times in the recorded run were about 950 ms and 293 ms. The measurements include this synthetic database and process environment only; they are not a production performance claim.

## Memory and response are separate concerns

Investigation episodes are persisted as graph records linked to their alert, entities, events, evidence, paths, and risk factors. A later investigation can retrieve one because it shares an observed entity or event type, and it reports that matching basis. Similarity is useful context, not proof that two alerts belong to the same attack. Historical evidence is not silently reused as current evidence or added to the new alert’s risk score.

Response is also explicit. GraphSentinel records a proposal, requires an analyst approval, performs only a simulated graph-state transition, then independently rereads the target to verify the expected simulation version and state. The MCP server has read-only tools and cannot approve or execute responses. No external security system is connected.

## What this proves—and what it does not

The two scenarios show how multi-hop graph context can produce a materially different and more explainable result than severity-only triage on the same alerts. They do not establish generalized accuracy, resistance to real attackers, or safety for enterprise containment. The evaluation is intentionally small and synthetic. Its value is that the expected paths, evidence IDs, risk scores, memory matches, query timings, and response verification are reproducible and inspectable rather than invented after the fact.

See [the recorded evaluation](evaluation-methodology.md) and [architecture](architecture.md) for the measurement contract and component boundaries.