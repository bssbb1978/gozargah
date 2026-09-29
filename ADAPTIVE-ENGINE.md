# Adaptive Engine — Gozargah 2.11.0

## Existing decision stack retained

The Worker continues to use the local policy stack: protocol capability filtering, measured profile health, bounded online learner, Bayesian reliability, predictive assessment, signal fusion, fallback diversity and D1-backed Adaptive Guard. Workers AI is not on the critical path.

The protocol-controller score is computed, not just described. It starts from capability score and adds/subtracts measured terms: health contributes up to 32% when observations are fresh; predictive forecast, local learner probability, Bayesian posterior, consensus and switch-risk provide bounded additions/penalties. Recent high family failure rates, quarantine, high volatility and poor freshness reduce priority. The controller emits selected profile, bounded fallback ladder, diversity, confidence, policy fingerprint and reason codes.

The scheduler refreshes configured path TCP probes every five minutes and recalculates protocol policy. Live dial outcomes update path/profile telemetry. Per-user preference remains a soft preference; the global health/guard layer still gates promotion.

## DNS upstream failover

RFC 8484 requests use a separate bounded resolver selector: EWMA latency, smoothed success rate, a short exponential quarantine, and sequential fallback over at most four configured HTTPS URLs. Health is isolate-local and concerns resolver request success only; it does not inspect payload contents, infer DPI, or affect the protocol-controller ranking. D1 independently enforces a per-user request budget.

## Promotion guard

The Adaptive Guard retains:

- 15-minute promotion hold;
- maximum 3 changes per 30-minute window;
- material confidence gain of 0.08 or forecast gain of 0.06;
- candidate volatility, consensus and switch-risk gates;
- promotion of a usable candidate if the active profile is failing;
- D1 persistence of active/previous/staged plans and rollback metadata.

A staged plan is not evidence of success. Candidate changes remain bounded and reason-coded.

## Evidence-scoped network condition

`src/ai/network-intelligence.ts` classifies recent configured-path observations and `/api/network/state` includes `condition`. It is scoped to configured Worker-egress paths. No table/schema migration is needed for these existing health signals.

States: `HEALTHY`, `DEGRADED`, `SEVERELY_DEGRADED`, `PARTIALLY_UNREACHABLE`, `UPSTREAM_UNAVAILABLE`, `UNKNOWN`. Every result has bounded confidence, evidence, a recommendation, source, freshness counts, observation-source labels, and explicit `dpiProven=false` / `physicalUpstreamDisconnectionProven=false`.

`UPSTREAM_UNAVAILABLE` means at least three configured paths, all fresh and failing from this Worker egress vantage. It is not proof that all international connectivity or a user's ISP is down. An opaque timeout remains `UNKNOWN` as a cause.

## Deliberate boundaries

This release does not introduce a new contextual graph, per-user model, autonomous AI policy, traffic fingerprint rewriting, IP-range scanning, client telemetry endpoint, POP/region inference, or per-domain registry. It adds no origin validation adapter. No profile is selected solely because an LLM recommends it. Shadowsocks AEAD is SIP004 AES-256-GCM over a WebSocket plugin transport; generic Shadowsocks UDP remains unsupported. VLESS UDP is accepted only for DNS port 53 and forwarded through DoH. DNS64 synthesis requires an external/reachable NAT64 translator. A Worker cannot be reached from a network with no route to the Worker/Cloudflare edge.
