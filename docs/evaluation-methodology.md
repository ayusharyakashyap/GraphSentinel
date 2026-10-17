# Evaluation Methodology and Results

## Scope and method

Run the evaluator from the repository root:

```sh
./.venv/bin/python -m graphsentinel.evaluate --output docs/evaluation-results.json
```

It seeds the checked-in fixture idempotently, then evaluates the two scenarios named by `expected_paths` in `data/demo_graph.json`. For each scenario it runs the real deterministic investigator against FalkorDB and checks:

- exact expected node-ID and relationship-type path;
- all scenario-declared relevant evidence IDs in the structured findings;
- risk score against both fixture expectation and a fresh deterministic rescore;
- retrieval of the just-saved episode through a newly constructed repository connection;
- a narrow unsupported-assertion scan over structured output.

It also records actual repository query count and per-query durations during investigation, end-to-end investigation time, memory retrieval time, and actual LLM tool-call count. LLM access is deliberately disabled for this repeatable run; deterministic fallback therefore reports zero LLM tool calls. The repository query count is reported separately rather than mislabeled as LLM tool calls.

The alert-only baseline reads only the same alert’s severity. Its illustrative mapping is critical=85, high=60, medium=35, low=15; these are design points, not calibrated probabilities. Its measured latency includes the severity lookup and result construction but excludes database setup. That microsecond-scale baseline is not a fair service-latency comparison to a graph investigation that reads and persists records; it is included to report the actual method’s cost, not to imply a benchmark win.

The high-risk scenario also runs the response simulator: it confirms execution is blocked before approval, explicitly approves, executes in simulation, rereads the target, and records successful verification.

## Actual run

The checked-in [JSON report](evaluation-results.json) was produced against the local persistent `graphsentinel` graph on 2026-10-12 UTC. Both scenarios passed all declared checks; unsupported affirmative compromise/exploitation claims detected: zero.

| Scenario | Alert-only score | Graph score | Expected path | Expected evidence | Risk repeat | Memory | Repository queries | Query total / p95 | Investigation latency | LLM tool calls |
| --- | ---: | ---: | --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| Privileged login | 60 / high | 85 / critical | found | 5 / 5 | consistent | retrieved (count capped at 100) | 15 | 939.9 ms / 240.4 ms | 950.1 ms | 0 |
| Standard login | 35 / moderate | 0 / low | found | 3 / 3 | consistent | retrieved (count capped at 100) | 13 | 288.2 ms / 64.1 ms | 293.0 ms | 0 |

In that run, simulated response verification completed in 180.5 ms with `PROPOSED -> APPROVED -> EXECUTED_SIMULATED -> VERIFIED`; the unapproved-execution guard passed. The memory result limit was reached in both scenarios because this persistent development graph contains episodes from earlier test and browser runs, so `100` is a capped retrieved count, not the total stored episodes. This does not change the verified presence of each just-saved episode.

The timing values are one local run against Docker Desktop on the current machine, with warm process/database state. They are not a statistically stable latency benchmark. Re-run the command to obtain new measurements; it writes a new JSON report and appends new persistent synthetic investigation episodes.

## Alert-only comparison

The alert-only rule receives no graph path, event relationships, historical memory, or evidence provenance. On the privileged case it produces 60/high, missing the route corroboration that moves the graph score to 85/critical. On the lower-risk case it produces 35/moderate from severity alone; graph evidence of healthy posture and denied access offsets the single unusual-region signal and yields 0/low. These two examples show a directional difference on these fixtures, not an accuracy rate or generalized advantage.

## Limitations

- Two hand-authored synthetic cases are not representative of enterprise telemetry.
- Risk weights are illustrative parameters, not calibrated probability estimates.
- The severity-only baseline is intentionally simple and does not have equal information or work to the graph engine.
- The memory endpoint caps returned matches; the report flags when this cap is reached.
- No live LLM call is made in this reproducible evaluator run.
- Response verification measures only the simulated FalkorDB state store; no production control plane is connected.