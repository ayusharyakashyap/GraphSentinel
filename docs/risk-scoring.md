# Deterministic Risk Scoring

The risk engine is deterministic application code in `graphsentinel/risk.py`; an LLM does not set or override its score. The weights below are illustrative design parameters, not calibrated probabilities or a claim of production security effectiveness.

| Factor | Points | Evidence condition |
| --- | ---: | --- |
| Supporting suspicious authentication | +20, or +10 at confidence 0.75-0.89 | Supporting authentication evidence with confidence at least 0.75. |
| Privileged identity | +20 | Supporting identity-context evidence linked to an alert identity whose graph privilege is elevated. |
| Recent configuration change | +15 | Supporting configuration evidence timestamped within 24 hours before the alert. |
| Potential path to vulnerable production service | +15 | Bounded graph path, exploitable vulnerability node, matching service inventory evidence, and supporting network evidence. This is a possible route, not proof of exploitation. |
| Independent corroboration | +15 | At least three distinct supporting categories among authentication, configuration, network, and vulnerability inventory. |
| Confirmed compromise | +15 | Explicit supporting `compromise_confirmation` evidence with confidence at least 0.95. |
| Contradictory device/access evidence | -10 | At least one confidence-0.8 device-posture or access-control record that contradicts the finding. |

The score is the sum of applicable factors, clamped to 0-100. Risk levels are low (0-24), moderate (25-49), high (50-74), and critical (75-100). Every non-zero factor carries evidence IDs; graph-path factors also carry the path node IDs.

Evidence IDs are deduplicated before scoring; conflicting records under the same ID are rejected. Confidence is reported separately as the mean confidence of unique records. Evidence completeness is the fraction of eight tracked evidence categories present. Missing categories never add risk points, and contradictory evidence is reported separately from the score factors.