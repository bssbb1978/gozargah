# Adaptive Engine — Gozargah 2.10.0

## Existing decision stack retained

The Worker continues to use the 2.9 local policy stack: protocol capability filtering, measured profile health, bounded online learner, Bayesian reliability, predictive assessment, signal fusion, fallback diversity and D1-backed Adaptive Guard. Workers AI is not on the critical path.

The protocol-controller score is computed, not just described. It starts from capability score and adds/subtracts measured terms: health contributes up to 32% when observations are fresh; predictive forecast, local learner probability, Bayesian posterior, consensus and switch-risk provide bounded additions/penalties. Recent high family failure rates, quarantine, high volatility and poor freshness reduce priority. The controller emits selected profile, bounded fallback ladder, diversity, confidence, policy fingerprint and reason codes.

The scheduler refreshes configured path TCP probes every five minutes and recalculates protocol policy. Live dial outcomes update path/profile telemetry. Per-user preference remains a soft preference; the global health/guard layer still gates promotion.

## Promotion guard

`src/ai/adaptive-guard.ts` retains:

- 15-minute promotion hold;
- maximum 3 changes per 30-minute window;
- material confidence gain of 0.08 or forecast gain of 0.06;
- candidate volatility, consensus and switch-risk gates;
- promotion of a usable candidate if the active profile is failing;
- D1 persistence of active/previous/staged plans and rollback metadata.

A staged plan is not evidence of success. Candidate changes remain bounded and reason-coded.

## 2.10 addition: evidence-scoped condition

`src/ai/network-intelligence.ts` classifies recent configured-path observations and the existing `/api/network/state` response now includes `condition`. It is scoped to `WORKER_EGRESS_CONFIGURED_PATHS`; the scheduler also stores the current condition code in existing `network_state.reason_codes` and emits a bounded transition event. No table/schema change was required.

States: `HEALTHY`, `DEGRADED`, `SEVERELY_DEGRADED`, `PARTIALLY_UNREACHABLE`, `UPSTREAM_UNAVAILABLE`, `UNKNOWN`. Every result has confidence (capped at 0.8), evidence, a recommendation, source, freshness counts, observation-source labels, and explicit `dpiProven=false` / `physicalUpstreamDisconnectionProven=false`.

`UPSTREAM_UNAVAILABLE` means at least three configured paths, all fresh and failing from this Worker egress vantage. It is not proof that all international connectivity or a user's ISP is down. An opaque timeout remains `UNKNOWN` as a cause.

## Deliberate boundaries / not implemented

This release does not introduce a new contextual graph, per-user model, autonomous AI policy, fragmentation tuner, client telemetry endpoint, origin adapter, POP/region inference, or per-domain registry. Those require trustworthy observations and/or client/origin implementations that this repository does not currently have. No profile is selected solely because an LLM recommends it.
