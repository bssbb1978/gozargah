# AI Engine — Gozargah 2.11.0

## Primary intelligence is local and deterministic

`edge-learner.ts` maintains a small bounded logistic learner from aggregate connection outcomes. It has six bounded features, fixed bounded learning rate/weights and no traffic-payload input. `ensemble.ts` supplies Jeffreys-smoothed Bernoulli reliability with a conservative lower-bound score. `predictive-mesh.ts` evaluates at most 24 samples for EWMA, volatility, slopes, drift, forecast and confidence. `signal-fusion.ts` gates policy changes when signals disagree or evidence is stale.

This is lightweight statistical learning, not a large language model and not a DPI classifier. It continues operating without Workers AI.

## Workers AI is optional and read-only

`diagnostics.ts` invokes Workers AI only for an authenticated, rate-limited aggregate operations-advice action. It receives aggregate panel counters; it does not receive user credentials, UUIDs, subscription links, packet contents, or private keys. Model output is text advice, not a network configuration, and does not affect the adaptive controller.

When `AI_CATALOG_ACCOUNT_ID` and `AI_CATALOG_API_TOKEN` are set, a Cloudflare model-catalog query is cached for six hours and candidate text models are ranked from available catalog metadata. `AI_MODELS` can explicitly prioritize IDs. Existing fallback model IDs remain a compatibility fallback if catalog discovery is unavailable; availability and plan eligibility are not guaranteed. D1 records per-model success/failure/quarantine where available; failures fall back to local deterministic advice.

## 2.11 DNS resolver ranking

DoH upstream ordering uses a bounded isolate-local EWMA latency and smoothed success/failure rate, with a short exponential quarantine, ten-minute stale-health expiry, and sequential HTTPS fallback. The resolver observes only resolver outcome and latency; it never inspects DNS payload contents for censorship labels, does not feed the main protocol learner, and is not persisted as a cross-user model. It is operational failover, not AI or DPI evasion.

## Non-claims

- No AI model identifies DPI or proves censorship.
- No AI output activates profiles, changes transports or overrides the capability matrix.
- No AI inference is required for health scoring or recovery.
- This release adds no runtime model capability benchmarking, end-to-end inference cancellation, AI recommendation schema, or AI-driven network-profile ranking.
- This Worker cannot restore connectivity when the user's network has no route to the Worker/Cloudflare edge.
- DNS64 creates synthetic AAAA answers only; a reachable NAT64 translator is still required.
