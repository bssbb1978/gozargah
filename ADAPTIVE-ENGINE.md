# Adaptive Engine — Gozargah 2.13.0

## 2.13 hardened dynamic layer

- **Fingerprint rotation:** `fpFor(opts, seed)` rotates the neutral uTLS identity (chrome/firefox/safari) per (uuid | 6h window) across every generated format; explicit operator presets keep precedence. The identity a user presents at the TLS layer is therefore window-varying even though the edge TLS stack is Cloudflare's (the Worker neither sees nor mutates the ClientHello).
- **In-tunnel shaping:** the WS downlink segments large bursts (bounded count/size) with randomized micro-gaps and the first protocol response carries bounded timing jitter. Pure size/timing entropy inside the encrypted tunnel; `TRAFFIC_SHAPE` env selects conservative (default) / aggressive / off.
- **Probe state machine:** the scheduler is a two-state machine — `normal` (periodic TCP probes) and `aggressive` (full-path HTTPS probes of every backup entry) — entered when the previous cycle was degraded, with `probe_mode_changed` audit events.
- **Internal decision view:** `/api/network/decision` composes the engine signals into one bounded verdict with honest advice; it informs operators and is exposed in the panel.
- **Client reconnection:** Xray observatory cadence (30s recovery / 90s normal) and the bundle's `client_behavior.reconnect` block (observe-and-failover, backoff, ladder order, immediate resume) close the loop client-side.

## 2.12 dynamic path rotation

The Worker accepts WebSocket upgrades on any path (authentication is in-band per protocol), so the request path is a free entropy dimension. Every generated link (raw links, Base64, Clash-Meta, Sing-box, Xray-core) now uses a deterministic 6-hour-rotating path base `/<uuid>/g/<16 hex>` (`src/sub/path-rotation.ts`). The same uuid in the same window always yields the same path across all formats and entry hosts; previous windows remain valid, so installed clients are never stranded, while static path fingerprints in a blocklist age out every window. The live bundle advertises the current window via `dynamic_path`.

## 2.12 emergency entry ladder

Operators can register up to four `backupEntryHosts` — other domains that point at the same Worker (e.g. a second Cloudflare domain). The five-minute scheduled health loop probes them on port 443 (`entry:<host>` rows) alongside the ProxyIP chain, and the ladder surfaces in:

- the live adaptive bundle as `emergency_ladder` (primary + backup entries with measured/unmeasured status, last latency, and an explicit `honest_limit` statement),
- every client format as same-credentials outbounds on the backup hosts (Xray-core joins the `auto-best` balancer so the observatory probes reachability itself; Clash-Meta adds them to the select group; Sing-box to the selector; Base64 appends the VLESS links),
- the per-user status page with per-host subscription tokens and an honest network alert when the engine is in `recovery` / `no_healthy_path`.

The ladder is diversity, not resurrection: it raises the probability that at least one route survives a partial block or outage. When no route from the user's network reaches the Worker/Cloudflare edge at all, no Worker code can create a new route remotely.

## 2.12 regime-driven strategy

The protocol controller now consumes the aggregate regime label (see `AI-ENGINE.md`): `suspected_change` upgrades a calm `stable` strategy to `diversify` (wider transport/protocol spread in the fallback ladder) with the `suspected_regime_change` reason code; the plan fingerprint includes the regime state so the Adaptive Guard can see regime-aware candidates. The label is aggregate statistics only — never a DPI claim.

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
