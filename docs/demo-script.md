# Three-Minute Demo Script

## 0:00-0:25 | Start on the queue

Open the dashboard with FalkorDB, FastAPI, and Vite already running. Select the high-severity suspicious-login alert for Ava Chen. State the boundary up front: all telemetry is synthetic, and a graph path indicates a possible route, not proof of compromise.

## 0:25-0:55 | Investigate

Choose **Investigate alert**. Point to the graph edges from the alert to the privileged identity and managed device, then through Deploy Console and Artifact Registry toward the synthetic vulnerability record. Change the path selector and use the graph controls to zoom/pan. Explain that edges and nodes are loaded from FalkorDB responses.

## 0:55-1:20 | Show the evidence and score

Read the deterministic risk score and its factors. Open one factor to highlight its supporting path. Distinguish the unusual login, privilege inventory, recent egress change, network reachability, and vulnerability inventory as observed records from the possible-route inference. Point out the separate confidence and evidence-coverage values and the contradictory “no production write” evidence.

## 1:20-1:45 | Compare a quieter case

Select the standard-account suspicious login. Investigate it and show the lower risk recommendation: monitor rather than containment. Highlight the healthy device posture and denied restricted-service request as counter-evidence. Do not describe the unfamiliar login as a compromise.

## 1:45-2:20 | Simulate a response

Return to Ava’s high-risk episode. In Response Center, confirm the action target and cited evidence, then propose the temporary identity restriction. Attempting to execute before approval is rejected. Enter an analyst identity and explicitly approve; only then execute the simulation.

## 2:20-2:40 | Verify

Run independent verification. Show the audit progression `PROPOSED -> APPROVED -> EXECUTED_SIMULATED -> VERIFIED` and the target’s simulation state/version. Clarify that no identity provider, endpoint, or enterprise system was contacted.

## 2:40-3:00 | Reuse memory

Start another investigation of Ava’s alert. Open Historical Memory and show the saved episode matched by shared graph entities/event types, including the explanation that shared context does not prove a common attack. Close with the read-only MCP tool surface and its lack of response-action tools.