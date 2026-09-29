# AI Engine — Gozargah 2.13.0

## 2.13 hardened dynamic layer (all local, no model runtime)

- **Internal decision view** (`src/ai/decision.ts`): a pure synthesis of network state, condition estimator, regime label, probe state machine, traffic shape, protocol plan and the emergency entry ladder into one bounded verdict — `stable | watch | degraded | critical` — with a 0–100 score, reason codes and honest bilingual advice. Served at `GET /{panelPath}/api/network/decision` (authenticated). It is a read-only composition; it never acts on its own.
- **Client fingerprint rotation** (`src/sub/fp-rotation.ts`): the generated configs rotate the neutral uTLS identity (chrome/firefox/safari — the intersection supported by Xray, Sing-box and Clash-Meta) per user and 6h window, in step with the rotating WS path. This is ClientHello *input* selected by the client's uTLS stack (JA3/JA4 diversity); TLS terminates at the Cloudflare edge and the Worker never sees or mutates the ClientHello.
- **In-tunnel traffic shaping** (`src/utils/shape.ts`): bounded downlink segmentation (≤8 segments, conservative default) with randomized inter-frame micro-gaps and bounded handshake-timing jitter. It changes only size/timing statistics of the already-encrypted stream; zero protocol-byte change, fully stock-client-compatible. `TRAFFIC_SHAPE=conservative|aggressive|off`.
- **Aggressive probing state machine** (scheduler): after a degraded cycle, the next cycle probes backup entries with full-path HTTPS (DNS+TCP+TLS+HTTP); transitions are audited (`probe_mode_changed`).
- **Smart client reconnection**: the Xray-core observatory probe interval is emitted as 30s during engine recovery (90s otherwise); the live bundle advertises `client_behavior.reconnect` (observe-and-failover, backoff, ladder-ordered failover, immediate resume on route reopen).
- **Stealth decoy variance**: rotated wording + random padding per response (byte-hash variance), no state leaked.

## Primary intelligence is local and deterministic

`edge-learner.ts` maintains a small bounded logistic learner from aggregate connection outcomes. It has six bounded features, fixed bounded learning rate/weights and no traffic-payload input. `ensemble.ts` supplies Jeffreys-smoothed Bernoulli reliability with a conservative lower-bound score. `predictive-mesh.ts` evaluates at most 24 samples for EWMA, volatility, slopes, drift, forecast and confidence. `signal-fusion.ts` gates policy changes when signals disagree or evidence is stale.

### 2.12 regime intelligence (fast reflex layer)

`regime.ts` adds a bounded, deterministic change-point detector on the aggregate outcome stream of configured probes and dials (ok/fail + latency only):

- dual timescale: 30-minute recent window vs the previous 60-minute baseline, with minimum sample floors;
- step-change rule: baseline success ≥ 0.55 and recent ≤ 0.20 → `suspected_change` (symmetric rule → `recovering`);
- one-sided bounded CUSUM for gradual drift;
- output: `stable | watch | suspected_change | recovering` with confidence, deterioration, CUSUM statistic and reason codes, persisted as `predictive_state(kind='regime', subject_id='global')` and audited via the `network_regime_changed` event.

Effect on policy: a `suspected_change` label upgrades a calm controller strategy from `stable` to `diversify` (wider transport/protocol diversity in the emitted fallback ladder) and is reported in the live subscription bundle, `/api/network/state`, the user status page, and the diagnostics advisor. It is explicitly **not** a DPI classifier or a censorship proof: a step change also matches a network incident or an operator fault, and no payload is ever inspected.

This is lightweight statistical learning, not a large language model and not a DPI classifier. It continues operating without Workers AI.

## Workers AI is optional and read-only

`diagnostics.ts` invokes Workers AI only for an authenticated, rate-limited aggregate operations-advice action. It receives aggregate panel counters — including 2.12's `regimeState`/`regimeConfidence` (aggregate statistics labels) and `backupEntryCount` — but never user credentials, UUIDs, subscription links, packet contents, or private keys. The advisor is instructed that `regimeState` must not be interpreted as DPI detection. Model output is text advice, not a network configuration, and does not affect the adaptive controller.

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
