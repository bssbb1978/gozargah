# Gozargah 2.17.0 — AXR-v3.1 Deep Evasion: Closed-Loop Fleet Pressure + Ensemble AI + net-e-melli Reflex

## 2.17.0 — AXR-v3.1 Deep Evasion (advanced increment)

### Highlights
- **Closed-loop fleet pressure (fully automatic, no human in the loop)** — the client's new **canary** liveness loop (plain TLS probe of the operator's `AXR_CANARY_HOST`, HMAC-signed into the manifest's `entries` field) reports ok/fail to the harvest endpoint (`kind: "canary"`); the new Worker **pressure engine** (`src/ai/pressure.ts`) fuses fleet canary evidence + clean-IP harvest freshness + the aggregate regime label into a 0–3 level that **dynamically** re-tunes every manifest: probe cadence 90 s → 15 s, outflow-profile floor web → video, entry diversity 4 → 6. A filter change degrades the fleet canary → pressure rises → the next (HMAC-verified) manifest makes all clients probe faster, morph harder, and have more options — and it decays automatically on recovery. Absence of evidence is never pressure (fresh installs stay at level 0).
- **net-e-melli reflex (`netstate`, Go)** — a 12-observation hysteresis state machine (stable ⇄ degraded ⇄ cut ⇄ recovering) over the client's own tunnel outcomes + canary probes. The net-e-melli signature (international primaries failing while the domestic fronting entry still succeeds) is recognized within two failed connections and triggers **automatic priority inversion**: the fronting entry jumps to the front of the ladder (priority 50 → 10, → 0 under full cut) and the probe cadence goes aggressive — instead of waiting for the bandit to quarantine dead entries one by one. A live canary vetoes any "cut" verdict (it travels the same international pipe).
- **Ensemble internal AI (`bandit`, Go)** — the 16-dim LinUCB is now joined by a per-arm **Beta-Bernoulli Thompson sampler**, with a **meta-learned arbitration weight** (realized-reward EMAs, tanh-combined): after each pull, credit goes to whichever member's deterministic ranking picked the arm that carried, so the hedge between condition-aware and outcome-aware learning is itself learned. Seeded draws keep selection deterministic; 2.16 snapshots restore to the neutral ensemble; the decision audit gains `model: "lin"|"ts"`.
- **Surgery v2 (`surgery`, Go)** — the multi-segment ClientHello surgery now extends across the **first 1–3 client-flight writes** (`frag_writes`, not just the ClientHello — certificate/key-encipherment/CCS/finished records carry the shape too), and the inter-segment micro-gaps are drawn from a **non-linear skewed distribution** (`SkewGap`, u² — heavy toward the small end, like real interactive traffic; a uniform draw is statistically distinguishable).
- **Flow-profile floor (`flowprofile`, Go)** — the manifest's (now pressure-driven) `flow_profile.mode` can only **escalate** the client's local regime-driven profile (web < chat < video): the client never morphs below what the fleet evidence asks for.
- **Version** — Worker `VERSION 2.17.0` / `SCHEMA_VERSION 17`; manifest keeps the pinned 11-field HMAC canonical (the canary rides inside the signed `entries` field — a tampered canary fails the signature); client core updated.

### Honest platform boundary (restated)
The canary is a liveness signal, never a DPI detector — its outputs are pressure levels and priority policies, not identifications; the Worker still performs no active probing. eBPF/TC/XDP, UDP-noise, DoH/ICMP steganography are **not shipped** (roadmap, as in 2.16 — 0-RTT session-ticket resumption is the documented v3.2 candidate). Nothing here is a guarantee: a fully cut route is reported, not looped.

### Verification status
Worker side: `npm run typecheck`, `npm run test:engine` (12 suites incl. the new `pressure` suite, 14 checks: engine rules, evidence reduction, canary manifest wiring + HMAC coverage) and `npm run test:integration` (22 tests incl. canary harvest auth/shape and fleet-failure → level 3 → dynamic manifest levers) all pass; bundle 521.09 KiB / 135.92 KiB gzip. Go core: complete source + unit tests (netstate 7, bandit 20 incl. sampler moments + arbitration + determinism + 2.16-compat restore, surgery 14 incl. multi-write + skew gaps), **not compiled in the authoring sandbox** (no Go toolchain) — the gate is automated in [CI v3.1](.github/workflows/ci-v31.yml) (matrix: linux/darwin/windows + Android NDK; `go vet` + staticcheck on both TLS identities, `go test -race`, stripped cross-builds; full checklist in [CI-EXECUTION-CHECKLIST](docs/CI-EXECUTION-CHECKLIST.md)) and locally `go vet && go build && go test -race ./...` per [AXR-DEPLOY](docs/AXR-DEPLOY.md).

### Engineering documents
- [AXR-v3.1 Deep Evasion (2.17) — closed-loop spec, wire contracts, verification matrix](docs/AXR-V31-DEEP-EVASION.md)
- [AXR-v3 Hyper-Resilience (2.16) — spec mapping, wire contracts, roadmap](docs/AXR-V3-HYPER-RESILIENCE.md)
- [AXR-v2 Enterprise Core — Advanced Features (2.15)](docs/AXR-V2-ADVANCED.md)
- [AXR Protocol Specification](docs/AXR-SPEC.md)
- [AXR Cross-Compile & Deploy Guide](docs/AXR-DEPLOY.md)
- [Client Core README](client/README.md)
- [Test Report 2.17.0](TEST-REPORT-2.17.0.md)
- [Persian Upgrade Report 2.17.0](UPGRADE-REPORT-FA-2.17.0.md)

## 2.16.0 — AXR-v3 Hyper-Resilience (advanced increment)

### Highlights
- **Fully-automatic clean-IP loop (Worker + Go client)** — the CFScanner capability set from the production Rust scouting scripts is now first-class and *swapped into the platform, with no capability deleted*: new `client/internal/cfscan` (Cloudflare API CIDRs with offline snapshot fallback, operator priority /24 ranges, blocked-range exclusion, SNI-anchored TLS probes ×3 with **real cert verification**, median RTT + loss, `/cdn-cgi/trace` **colo validation**, top-N ranking, JSON+CSV reports) and a new Worker endpoint `POST /{panelPath}/api/network/harvest` (token-gated: any valid subscription token or `HARVEST_TOKEN`; IPv4 validate → dedup → cap 32 → D1-persist). `axr scan [-upload]` probes from the local network, refreshes `~/.axr/clean-ips.json` (auto-merged into the failover ladder at startup, 30-day freshness guard), and publishes the survivors to the Worker; the manifest then serves `clean_ip_hints = env ∪ D1` to **every** client. Cron-ready, zero human in the loop.
- **Manifest v3 with HMAC integrity** — `manifest_sig` = HMAC-SHA256 over a canonical 11-field string, keyed by the user's subscription token (shared pinned test vector in both test suites + [docs/AXR-V3-HYPER-RESILIENCE](docs/AXR-V3-HYPER-RESILIENCE.md) §5). The Go client verifies in constant time: tampered manifest → **rejected**, last-known-good state kept + raw JSON persisted for audit; absent signature (older workers) → documented unverified mode.
- **Domestic-CDN fronting hint** — operator env `FRONTING_RELAY_HOST` (validated hostname) is published as `fronting_hint` and joined by every client as a priority-50 ladder entry (ws + ws-alt arms) — deploy the same Worker to a domestic CDN domain and it becomes a reachable second entry automatically.
- **16-dim LinUCB context (was 7)** — measured, not assumed: real tunnel **throughput** (bytes/sec EWMA from pump accounting), **loss velocity** (recent-vs-baseline drop rate), **TLS error rate**, **entry churn** (dial-address change = BGP-flap/anyshift proxy), **time-of-day sin/cos**, **session longevity**, **regime ordinal**, and the **flow-profile KL divergence** below. Per-arm 16×16 ridge state; 2.15 snapshots restore stats with the ridge prior rebuilt (dim migration unit-tested).
- **KL-divergence self-monitoring** — new `flowprofile.KLDiv` + `TargetBins` + shared frame buckets: the pump buckets every outflow WS frame live, and the core continuously measures `KL(empirical outflow ‖ target app-class profile)` feeding bandit feature f11 — the client *knows* when its morph is drifting from its own target.
- **Multi-segment ClientHello surgery (fragA/fragB style)** — `surgery.MultiSplitConn`: the first write is cut at randomized **2–3 split points** inside the **SNI region** (40–90 % window) with **1–8 ms micro-gaps** (per-connection randomization; deterministic seeded tests). Same honest boundary: TCP-level segmentation of TLS-produced bytes — no record padding, no extension rewriting.
- **Version** — Worker `VERSION 2.16.0` / `SCHEMA_VERSION 16`; client core updated; decoy layer and 0-RTT early data (2.15) retained unchanged.

### Honest platform boundary (restated)
eBPF/TC/XDP, UDP-noise, DoH/ICMP steganography are **not shipped** (root+Linux/raw-socket deployment cost; socket-level segmentation already produces the same on-wire TCP effect for this client) — documented with the v3.1 roadmap in [AXR-v3 Hyper-Resilience](docs/AXR-V3-HYPER-RESILIENCE.md) §1/§10. Nothing here is DPI detection; a probe success is "this edge IP answers the relay's TLS handshake from *your* network now"; a fully cut route cannot be created from the client and is reported, not looped.

### Verification status
Worker side: `npm run typecheck`, `npm run test:engine` (36 checks incl. new `manifest-integrity` vector suite) and `npm run test:integration` (20 tests incl. new HMAC-verify, fronting-hint, harvest-ingest suites) all pass. Go core: complete source + unit tests (cfscan pure logic, 16-dim LinUCB incl. dim-migration, KLDiv/TargetBins, PlanCuts/MultiSplitConn, manifest HMAC vector), **not compiled in the authoring sandbox** (no Go toolchain) — deploy gate `go vet && go build && go test ./...` per [AXR-DEPLOY](docs/AXR-DEPLOY.md).

### Engineering documents
- [AXR-v3 Hyper-Resilience (2.16) — spec mapping, wire contracts, roadmap](docs/AXR-V3-HYPER-RESILIENCE.md)
- [AXR-v2 Enterprise Core — Advanced Features (2.15)](docs/AXR-V2-ADVANCED.md)
- [AXR Protocol Specification](docs/AXR-SPEC.md)
- [AXR Cross-Compile & Deploy Guide](docs/AXR-DEPLOY.md)
- [Client Core README](client/README.md)
- [Test Report 2.16.0](TEST-REPORT-2.16.0.md)
- [Persian Upgrade Report 2.16.0](UPGRADE-REPORT-FA-2.16.0.md)

## 2.15.0 — AXR-v2 Enterprise Core (advanced increment)

### Highlights
- **LinUCB contextual bandit (Go client, M1)** — the decision core upgrades from UCB1 to a zero-dependency **LinUCB** contextual bandit: per-arm ridge state (7×7 `A`, 7-dim `b`, pure-Go Gauss-Jordan inverse) scored against a **7-dim context** (RTT level, RTT variance, RST frequency, TLS drop delta, CUSUM loss step, protocol anomaly, bias) measured from the client's own outcomes. Same entry can be preferred or avoided as conditions change. Unchanged: [0,1] reward shaping, quarantine backoff, auto-prune (≥2 live arms), deterministic tie-breaks, atomic persistence (legacy 2.14 snapshots restore with the ridge prior rebuilt).
- **App-class flow morphing (Go client, M2)** — new `internal/flowprofile`: post-handshake writes are split by a **packet-length histogram** toward a target app class (`web`/`video`/`chat`) with **lognormal inter-packet delays**; regime-driven (stable→web, watch→chat, suspected_change→video). Wired into `surgery.ChunkConn` via a `Slicer` interface. New `internal/sockopt`: **Nagle off + per-connection randomized `SO_SNDBUF`** (64–512 KB), build-tagged linux/darwin/windows, no-op elsewhere.
- **Clean edge-IP harvesting (Go client, M3)** — `failover.HarvestedIPs` / `Engine.HarvestEntries` merge each entry's live **A records** (injectable resolver, IPv4-only, deduped, capped at 8, explicit operator IPs first) into the endpoint matrix at startup; the manifest's new `clean_ip_hints` (operator `CLEAN_EDGE_IPS`, validated) merge the same way.
- **Session reuse + decision audit (Go client, M4 half)** — a tunnel ending on a clean local close keeps its WS **warm ≤ 30 s** for same-destination adoption (zero re-dial/re-handshake; stale sessions auto-fall-back to a fresh dial). Every decision appends to `~/.axr/decision.jsonl` (context, chosen arm, full score table, attempts tried, outcome; 4 MB rotation). Every entry now also runs a **`ws-alt`** arm — same host over the `gz_profile=fragmented` path/query shape — so the bandit learns the healthier shape.
- **Scanner decoy layer (Worker, M4 half)** — new `src/panel/decoy.ts`: unmatched GET/HEAD requests with scanner path shapes (`/.env`, `/.git/…`, `/wp-login.php`, `/admin`, `/api/…`, `/config.json`, `/axr*`, `/sub/<bad>/…`, …) receive **benign variants** — 3 small-business HTML product pages (random 32-hex padding per response) or 2 benign JSON API shapes for JSON-typed probes — before the stealth landing. No user enumeration, no constant signature, real routes untouched, POST never decoyed.
- **Manifest v2 fields (Worker)** — `transports: ["ws","ws-alt"]`, `flow_profile.mode` (regime-escalated web/chat/video from D1 state), `clean_ip_hints[]`.
- **Reserved stubs, documented** — HTTP-chunked duplex relay measured untestable in CI (miniflare buffers request bodies → would ship unverified), so gRPC and HTTP/3 remain arm-set placeholders with documented status; WS (+ws-alt) is the shipped data plane.

### Honest platform boundary (restated)
Flow morphing shapes the client's own write segmentation — no payload inspection, no replayed traffic, no invisibility guarantee. The decoy layer changes *unmatched* probe responses only. A fully cut route (no path from the local network to any entry) cannot be created by client or Worker code; the core reports it instead of looping. See [AXR-v2 Advanced Features](docs/AXR-V2-ADVANCED.md).

### Verification status
Worker side: `npm run typecheck`, `npm test` (engine checks + 10 pure-logic suites incl. new `decoy` + 17 integration tests incl. new decoy/manifest-v2), and `npm run build` all pass. Go core: complete source + unit tests (LinUCB closed-form context tests, flowprofile distribution tests, sockopt, harvest), **not compiled in the authoring sandbox** (no Go toolchain) — deploy gate `go vet && go build && go test ./...` per [AXR-DEPLOY](docs/AXR-DEPLOY.md).

### Engineering documents
- [AXR-v2 Enterprise Core — Advanced Features (2.15)](docs/AXR-V2-ADVANCED.md)
- [AXR Protocol Specification](docs/AXR-SPEC.md)
- [AXR Cross-Compile & Deploy Guide](docs/AXR-DEPLOY.md)
- [Client Core README](client/README.md)
- [Test Report 2.15.0](TEST-REPORT-2.15.0.md)
- [Persian Upgrade Report 2.15.0](UPGRADE-REPORT-FA-2.15.0.md)

## 2.14.0 — AXR Protocol Framework

### Highlights
- **AXR native client core (Go, `client/`)** — a production SOCKS5 TCP inbound that tunnels every stream over a **bandit-selected VLESS-over-WebSocket** path. All TLS-identity morphing and ClientHello surgery is **client-side** (TLS terminates at the Cloudflare edge — the Worker never sees the ClientHello).
  - **M1 decision core** (`internal/bandit` + `internal/measure`): a zero-dependency contextual **UCB1** learner over (host, transport, fingerprint) arms with throughput-stability + RTT reward shaping, quarantine backoff, and **auto-prune** of degraded arms (always ≥ 2 live). A deterministic state vector — RTT/jitter EWMA, RST & TLS-timeout rates, CUSUM step-change, HTTP anomaly codes — drives a regime label (`stable|watch|suspected_change|recovering`) that boosts exploration ×1.8 during suspected change.
  - **M2 low-level surgery** (`internal/surgery`): the TLS **ClientHello is split into two TCP segments** at a randomized offset (25–85 % of the record, bias crossing the SNI extensions block) with a randomized 20–120 ms gap; post-handshake writes are **TCP-chunked** in randomized 512–1400 B pieces. uTLS identity rotation (`chrome/firefox/safari/randomized`) via the single pinned dependency `refraction-networking/utls v1.6.7`, opt-in with `-tags axr_utls` (default build is 100 % stdlib).
  - **M3 national-intranet failover** (`internal/failover`): an endpoint matrix (host × clean-IP × transport × fp) with a **persistent routing cache** and live per-IP health, a `normal⇄aggressive` probe state machine (2 all-fail rounds → aggressive cadence), and instant zero-control-plane failover ordered by bandit score then IP health.
  - **M4 Worker edge relay** (existing): zero-copy WS/chunked streaming, multi-domain routing, 0-RTT VLESS early data, dynamic fallback responses — now plus a new machine feed (below).
- **AXR machine feed (Worker, 2.14 new)** — `GET /{subPath}/{token}/axr-manifest` returns `gozargah-axr-manifest/v1`: rotated WS path base, fingerprint window, regime/strategy/probe mode, network state, measured entry ladder (primary + backups), reconnect cadence (30 s in recovery), and an explicit `honest_limit`. Aggregate intelligence only; authenticated by the subscription token; unknown tokens fall through to the stealth landing.
- **Native VLESS-WS tunnel** (`internal/vlessws`): VLESS v1 header byte-compatible with the Worker parser; 0-RTT early data via `Sec-WebSocket-Protocol` (the mechanism the Worker already consumes); full RFC 6455 client codec (mask, ping→pong, close, fragmentation).

### Honest platform boundary (unchanged, restated)
The client core is transport obfuscation and adaptive path selection — **not** payload inspection, **not** a DPI "detector", and **not** a bypass guarantee: its regime labels describe the client's own delivery quality. Post-handshake fragmentation is **TCP-level chunking**, not TLS record padding. The core is TCP-only (SOCKS5 CONNECT; UDP rejected, matching the no-UDP-relay boundary). And a fully cut route — no path from the user's network to any entry — cannot be created by client or Worker code; the core reports `no healthy candidate` instead of looping.

### Verification status
Worker side: `npm run typecheck`, `npm test` (36 engine checks + 9 pure-logic suites + 16 integration tests), and `npm run build` all pass (504.35 KiB / 131.51 KiB gzip). Go core: complete source + unit tests with a pinned `go.mod`, **not compiled in the authoring sandbox** (no Go toolchain) — the deploy gate is `go vet && go build && go test` per [AXR-DEPLOY](docs/AXR-DEPLOY.md).

### Engineering documents
- [AXR Protocol Specification](docs/AXR-SPEC.md)
- [AXR Cross-Compile & Deploy Guide](docs/AXR-DEPLOY.md)
- [Client Core README](client/README.md)
- [Test Report 2.14.0](TEST-REPORT-2.14.0.md)
- [Persian Upgrade Report 2.14.0](UPGRADE-REPORT-FA-2.14.0.md)

## 2.13.0 — Hardened dynamic layer

### Highlights
- **Client fingerprint rotation** (`src/sub/fp-rotation.ts`): generated configs rotate the neutral uTLS identity (chrome/firefox/safari — the set every format supports) deterministically per user and 6h window, in step with the rotating WS path. Static JA3/JA4 blocklist entries go stale across windows. Explicit operator presets always win. TLS itself terminates at the Cloudflare edge — the Worker never sees or mutates the ClientHello.
- **In-tunnel traffic shaping** (`src/utils/shape.ts`, WS pipeline): bounded downlink segmentation (≤8 segments, conservative default) with randomized inter-frame micro-gaps plus bounded handshake-timing jitter. Pure size/timing entropy inside the edge TLS tunnel; zero protocol-byte change; fully stock-client-compatible. `TRAFFIC_SHAPE=conservative|aggressive|off`.
- **Aggressive probing state machine**: when the previous cycle was `recovery`/`no_healthy_path`/`UPSTREAM_UNAVAILABLE`/`SEVERELY_DEGRADED`, the next cycle probes backup entries with full-path HTTPS (DNS+TCP+TLS+HTTP on `/healthz`) so a reopening route is detected and selected immediately. Transitions audited via `probe_mode_changed`.
- **Internal decision view**: `GET /{panelPath}/api/network/decision` — one bounded verdict (`stable|watch|degraded|critical`) with score, regime label, controller strategy, probe mode, traffic shape, active profile, fallback ladder, emergency entries and honest bilingual advice. Synthesized from the existing engines; no external model required.
- **Smart client reconnection**: Xray-core `observatory.probeInterval` is emitted as 30s during engine recovery and 90s otherwise; the live bundle gains `client_behavior.reconnect` (observe-and-failover, backoff schedule, ladder-ordered failover, immediate resume on route reopen) plus `fingerprint` and `traffic_shape` metadata blocks.
- **Stealth decoy hardening**: the landing page now serves rotated wording variants + random padding per response (byte-hash/length variance) while still leaking no state.

### Honest platform boundary (unchanged, restated)
The Worker cannot create or mutate the TLS ClientHello, cannot add FEC, and does not mutate protocol framing — VLESS/Trojan/Shadowsocks remain stock-client-compatible. Shaping, fingerprint rotation, path rotation and entry diversity raise the odds a route survives partial filtering; they are aggregate-statistics adaptation, not a DPI classifier, and no bypass is guaranteed. A fully cut route (no path from the user's network to the Worker/Cloudflare edge) cannot be restored remotely by any Worker code.

### Engineering documents
- [Test Report 2.13.0](TEST-REPORT-2.13.0.md)
- [Persian Upgrade Report 2.13.0](UPGRADE-REPORT-FA-2.13.0.md)
- [Adaptive Engine](ADAPTIVE-ENGINE.md)
- [AI Engine and limits](AI-ENGINE.md)

## 2.12.0 — Fully dynamic adaptive layer

### Highlights
- **Internal AI regime detection** (`src/ai/regime.ts`): a bounded, deterministic change-point detector (dual-timescale windows + step-change rule + one-sided CUSUM) over the aggregate probe/dial outcome stream. A suspected regime change automatically upgrades the protocol controller from `stable` to `diversify` so the emitted fallback ladder spans more transport/protocol families. States are `stable | watch | suspected_change | recovering` with confidence and reason codes; persisted in D1 and audited via the `network_regime_changed` event.
- **Dynamic rotating WebSocket path**: every generated link uses a deterministic 6-hour-rotating path base (`/<uuid>/g/<16hex>`). The Worker accepts any path, so previous windows stay valid — installed clients are never stranded — while static path fingerprints go stale each window. All client formats (raw, Base64, Clash-Meta, Sing-box, Xray-core) rotate at generation time.
- **Emergency entry ladder**: up to four `backupEntryHosts` (other domains pointing at the same Worker) configured in the panel. The scheduled health loop probes them on 443; the live bundle publishes `emergency_ladder` with measured status and an explicit honest-limit statement; every client format emits same-credentials outbounds for the backup hosts (Xray-core joins the `auto-best` balancer so its observatory probes reachability); the user status page lists per-host tokens/links and shows an honest network alert in `recovery`/`no_healthy_path`.
- **Read-only advisor extended**: the optional Workers AI advisor now receives `regimeState`, `regimeConfidence` and `backupEntryCount` (aggregate only) and is explicitly instructed not to interpret the regime label as DPI detection; local rule-based advice gains honest regime/backup notes.
- **Panel**: `/api/network/state` returns the regime label and configured backup entries; the settings form gains the backup-entry field (fa/en).

### Honest platform boundary (unchanged, restated)
The regime label is aggregate statistics — not a DPI classifier, not a censorship proof; no payload is inspected and no bypass is guaranteed. Rotating paths and entry diversity raise the odds a route survives a partial block or outage. The emergency ladder only helps while at least one entry point (primary or backup domain) is still reachable from the client network: if no route to the Worker/Cloudflare edge remains, no Worker code can create a new route remotely. Shadowsocks remains TCP-only `aes-256-gcm`/SIP004 over WebSocket, VLESS UDP remains DNS-only on port 53, and DNS64 still requires a reachable NAT64 translator.

### Engineering documents
- [Test Report 2.12.0](TEST-REPORT-2.12.0.md)
- [Persian Upgrade Report 2.12.0](UPGRADE-REPORT-FA-2.12.0.md)
- [Adaptive Engine](ADAPTIVE-ENGINE.md)
- [AI Engine and limits](AI-ENGINE.md)

## 2.11.0 — Protocol and DNS data-plane additions

### Highlights
- Adds Shadowsocks SIP004 AEAD (`aes-256-gcm`) over TLS/WebSocket using the SIP003 `v2ray-plugin`; generated as a third native profile in share links, Base64, Clash Meta, Sing-box, and the adaptive manifest.
- Adds an authenticated RFC 8484 endpoint at `/{subPath}/{token}/dns-query` (GET and POST), with a per-user D1 rate budget and real byte accounting.
- Adds DNS-only VLESS UDP handling for destination port 53. VLESS datagrams travel inside the existing WebSocket session and are forwarded through HTTPS DoH; arbitrary UDP is not relayed and no raw UDP socket is opened.
- Adds optional DNS64 AAAA synthesis for RFC 6052 NAT64 prefixes, defaulting to `64:ff9b::/96`. DNSSEC-DO queries are not synthesized; NAT64 translation still requires a reachable translator on the client/egress network.
- DoH resolvers have bounded, local EWMA/reliability ranking, a 10-minute stale-health reset, timeout, and fallback. The ranking is deterministic operational telemetry—not a DPI classifier or an autonomous AI policy.
- Reuses the D1-backed Telegram FSM and Vitest + Miniflare suite; adds integration coverage for authenticated DoH, DNS64, rate budgets, and usage accounting.
- No `ALTER TABLE` migration is needed; `dns_throttle` is created by the existing guarded D1 schema initializer.

### Honest platform boundary
Cloudflare Workers does not expose a raw UDP/53 listener here. “UDP DNS forwarding” means VLESS UDP DNS encapsulated over WebSocket and resolved through DoH, not general UDP tunneling. Shadowsocks is TCP-only and requires a compatible SIP003 client plugin. DNS64 synthesizes AAAA records but does not create a NAT64 gateway. A Worker cannot restore access if the client has no route to the Worker/Cloudflare edge; no AI can manufacture a missing network path or guarantee DPI bypass.

### Existing 2.10 network intelligence retained
- `/api/network/state` classifies configured Worker-egress observations conservatively (`HEALTHY`, `DEGRADED`, `SEVERELY_DEGRADED`, `PARTIALLY_UNREACHABLE`, `UPSTREAM_UNAVAILABLE`, `UNKNOWN`).
- Opaque timeouts remain `UNKNOWN`; failure of configured Worker-egress paths is not proof of DPI or a physical international outage.
- Local deterministic selection remains primary; optional Workers AI cannot override capability checks.
- Adaptive protocol policy combines measured health, local learner, Bayesian reliability, predictive assessment, signal fusion and D1-backed promotion guards.
- Canary staging, bounded promotions, rollback history and failure-domain isolation remain in place.

### Engineering documents
- [Capability Matrix](CAPABILITY-MATRIX.md)
- [DNS data plane and limits](DNS-DATA-PLANE.md)
- [Adaptive Engine](ADAPTIVE-ENGINE.md)
- [AI Engine and limits](AI-ENGINE.md)
- [Failure Domains](FAILURE-DOMAINS.md)
- [Recovery Model](RECOVERY-MODEL.md)
- [2.11.0 Test Report](TEST-REPORT-2.11.0.md)
- [Persian Upgrade Report](UPGRADE-REPORT-FA-2.11.0.md)

New endpoints:
- `GET /{panelPath}/api/network/autoplan`
- `GET /{panelPath}/api/network/policy-state`
- `GET /{panelPath}/api/network/guard`
- `GET /{subPath}/{token}/adaptive`
- `GET|POST /{subPath}/{token}/dns-query`

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/hero-light.svg">
  <img src="docs/hero.svg" alt="گذرگاه — Gozargah · دروازهٔ امن عبور روی Cloudflare Workers" width="100%">
</picture>

# گذرگاه · Gozargah

**دروازهٔ امن عبور — پنل پروکسی چندکاربره روی Cloudflare Workers**

<sub>بدون سرور · بدون هزینه · بدون وابستگی — کل پنل در یک فایل</sub>

[![Release](https://img.shields.io/github/v/release/panelgozargah/gozargah?style=flat-square&labelColor=0B1020&color=00D9FF)](https://github.com/panelgozargah/gozargah/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-2563EB?style=flat-square&labelColor=0B1020)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/panelgozargah/gozargah/test.yml?branch=main&style=flat-square&labelColor=0B1020&label=tests)](https://github.com/panelgozargah/gozargah/actions/workflows/test.yml)
[![Deploy](https://img.shields.io/github/actions/workflow/status/panelgozargah/gozargah/deploy.yml?branch=main&style=flat-square&labelColor=0B1020&label=deploy)](https://github.com/panelgozargah/gozargah/actions/workflows/deploy.yml)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fgozargah.dpdns.org%2F&style=flat-square&labelColor=0B1020&up_color=7C3AED)](https://gozargah.dpdns.org/)
[![Platform](https://img.shields.io/badge/☁️_Cloudflare_Workers-native-7C3AED?style=flat-square&labelColor=0B1020)](#-چرا-گذرگاه)
[![Storage](https://img.shields.io/badge/storage-D1_Relational-D946EF?style=flat-square&labelColor=0B1020)](#-سفر-یک-درخواست)
[![Protocols](https://img.shields.io/badge/protocols-VLESS_·_Trojan_·_SS_AEAD-00D9FF?style=flat-square&labelColor=0B1020)](#-چرا-گذرگاه)
[![Operators](https://img.shields.io/badge/operators-MCI_·_Irancell_·_Rightel_·_Shatel_·_TCI-22C55E?style=flat-square&labelColor=0B1020)](#-تیون-عمیق-اپراتور)
[![Xray](https://img.shields.io/badge/Xray-auto--best_leastPing-00D9FF?style=flat-square&labelColor=0B1020)](#-فرمت-xray--اتصال-خودکار-بهترین-مسیر)
[![UI](https://img.shields.io/badge/UI-Gozargah_Nexus-7C3AED?style=flat-square&labelColor=0B1020)](#-رابط-کاربری--gozargah-nexus-ui)
[![Runtime Deps](https://img.shields.io/badge/runtime_deps-zero-22C55E?style=flat-square&labelColor=0B1020)](#-چرا-گذرگاه)
[![i18n](https://img.shields.io/badge/i18n-FA_·_EN_RTL-2563EB?style=flat-square&labelColor=0B1020)](#-رابط-کاربری--gozargah-nexus-ui)

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/stats-light.svg">
  <img src="docs/stats-dark.svg" alt="یک فایل · صفر وابستگی · چهار فرمت · پنج اپراتور · صد درصد رایگان" width="100%">
</picture>

<img src="docs/divider.svg" width="60%">

</div>

**گذرگاه** یک پنل پروکسی چندکاربرهٔ کامل است که به‌صورت بومی روی Cloudflare Workers زندگی می‌کند: یک فایل جاوااسکریپت که همه‌چیز داخلش تعبیه شده — پنل مدیریت، موتور پروکسی، اشتراک‌ساز، صفحهٔ وضعیت کاربر و تمام دارایی‌های رابط کاربری. نه سرور می‌خواهد، نه نصب، نه هزینه؛ یک اکانت رایگان کلودفلر و پنج دقیقه وقت کافی است تا یک پنل کامل با دیتابیس اختصاصی، داشبورد فارسی/انگلیسی و لینک اشتراک برای هر کاربر داشته باشید.

طراحی گذرگاه از روز اول با سه قاعده پیش رفته: **امنیت واقعی به‌جای نمایشی**، **حسابداری دقیق به‌جای تخمین**، و **تصمیم‌گیری محلیِ قابل‌توضیح**. قابلیت‌های قدیمی‌تر مانند پریست اپراتورها، کانفیگ تطبیقی و صفحهٔ وضعیت حفظ شده‌اند. در نسخهٔ **2.13.0**، لایهٔ سخت‌افزای‌شده اضافه شد: چرخش فینگرپرینت کلاینت (uTLS/JA4) هر ۶ ساعت، شکل‌دهی ترافیک درون تونل (سایز/زمان‌بندی)، ماشین حالت پروب تهاجمی، و نمای تصمیم هوش مصنوعی داخلی. در نسخهٔ **2.12.0**، لایهٔ داینامیک و پویا اضافه شده: تشخیص تغییر رژیم با هوش مصنوعی داخلی (آمار تجمیعی، بدون payload)، مسیر چرخشی WebSocket هر ۶ ساعت، و پلهٔ اضطراری نقاط ورود جایگزین — که در قطع‌های موضعی شانس بقای مسیر را بالا می‌برند اما قطع کامل مسیر را از راه دور رفع نمی‌کنند. در نسخهٔ **2.11.0**، Shadowsocks AEAD روی WebSocket/TLS، DNS-over-HTTPS احراز هویت‌شده، فوروارد DNS از VLESS UDP پورت ۵۳ و DNS64 اضافه شده‌اند. این قابلیت‌ها مرزهای واقعی Worker را تغییر نمی‌دهند: UDP عمومی و NAT64 gateway ارائه نمی‌شود و هیچ مدل AI نمی‌تواند مسیر شبکه‌ای ازدست‌رفته یا عبور تضمینی از DPI ایجاد کند.

## ✨ چرا گذرگاه؟

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/features-light.svg">
  <img src="docs/features-dark.svg" alt="دوازده ویژگی کلیدی گذرگاه — از یک‌فایلی بودن تا تیون اپراتور و اتصال خودکار بهترین مسیر" width="100%">
</picture>

</div>

ایدهٔ پشت این دوازده کارت ساده است: هر چیزی که می‌تواند یک وابستگی، یک سرور یا یک نقطهٔ شکست باشد، حذف شده؛ و هر چیزی که تجربهٔ کاربر ایرانی را بهتر می‌کند، با دروازهٔ صداقت اضافه شده. پنل به هیچ CDNای برای دارایی‌هایش درخواست نمی‌زند، مصرف را تخمین نمی‌زند و امنیت را به ظاهر رابط کاربری گره نمی‌زند. حتی QR و فونت و آیکون‌ها داخل همان یک فایل زندگی می‌کنند.

## 🧠 موتور داخلی 2.0 — Edge Learner

نسخهٔ 2.0 علاوه بر policy deterministic، یک مدل کوچک online داخل Worker دارد که از latency، reliability، freshness، trend و continuity یاد می‌گیرد. نتیجه در D1 نگه‌داری می‌شود و برای انتخاب مسیر و پروفایل استفاده می‌شود؛ بدون نیاز اجباری به Workers AI.

وقتی همهٔ مسیرها unhealthy باشند، موتور recovery حداکثر دو مسیر را half-open دوباره امتحان می‌کند.

### حافظهٔ per-user
وضعیت ترجیح مسیر/پروفایل هر کاربر در D1 جداگانه ذخیره می‌شود تا یک کاربر مسیر خراب را روی سایر کاربران تحمیل نکند.

### سلامت مدل‌های Workers AI
نتیجهٔ واقعی inference برای هر model ID ذخیره می‌شود؛ مدل خراب موقتاً quarantine می‌شود و fallback بعدی انتخاب می‌شود.

### Cloudflare Pages
ساخت Pages Advanced Mode با `npm run build:pages` و `wrangler.pages.toml` اضافه شده است.

## 📱 صفحهٔ وضعیت کاربر — یک نگاه برای «وصل شم؟»

هر کاربر یک لینک شخصی دارد؛ وقتی در مرورگر بازش کنید، به‌جای خروجی خام اشتراک، یک صفحهٔ زنده و شیشه‌ای می‌بینید: حلقهٔ مصرف با اعداد واقعی، وضعیت اتصال، انقضا، و هاب ایمپورت با دکمه‌های یک‌کلیکی برای v2rayNG، Hiddify، Clash-Meta و Sing-box. کلاینت‌های پروکسی همچنان همان خروجی خام را می‌گیرند — تشخیص خودکار از روی User-Agent.

## 🧠 موتور تطبیقی 2.0 — Local Policy Brain + Profile Ensemble

نسخهٔ 2.0 علاوه بر سلامت ProxyIP، سلامت **پروفایل اتصال** را نیز با telemetry واقعی ثبت می‌کند. چهار حالت محدود و صریح وجود دارد: `standard`، `fragmented`، `alt-port` و `fragmented-alt`؛ این‌ها از preset انتخاب‌شده ساخته می‌شوند و موتور مقادیر تصادفی یا خارج از محدوده تولید نمی‌کند. Xray با observatory و `leastPing` این مجموعه را به‌صورت دوره‌ای مقایسه می‌کند و پنل، نتیجهٔ آن را در D1 نگه می‌دارد.

لایهٔ `Local Policy Brain` حتی بدون Workers AI کار می‌کند: با latency، نرخ خطا، تازگی داده، روند موفقیت/شکست و quarantine تصمیم می‌گیرد. این موتور جای مدل زبانی را نمی‌گیرد و «AI واقعی» نیست؛ مزیتش این است که با قطع سرویس مدل، لایهٔ تصمیم‌گیری شبکه از کار نمی‌افتد. endpoint مدیریت‌شدهٔ `network/profiles` نیز وضعیت پروفایل‌ها و انتخاب فعلی را نشان می‌دهد.

این معماری **adaptive** است، نه تضمین‌کنندهٔ عبور از هر نوع فیلترینگ. اگر upstream بین‌المللی واقعاً قطع باشد، Worker نمی‌تواند مسیر فیزیکی جدید ایجاد کند؛ فقط می‌تواند از مسیرها و پروفایل‌هایی استفاده کند که از شبکهٔ کاربر واقعاً قابل دسترسی‌اند.

## 🧠 مشاور عملیات Workers AI (اختیاری و فقط‌خواندنی)

داشبورد یک تحلیل‌گر اختیاری دارد که با binding بومی `AI` روی Workers AI اجرا می‌شود. ورودی مدل فقط شمارنده‌های تجمیعی پنل است (تعداد کاربران فعال/غیرفعال، فعالیت ۲۴ساعته، شمار کاربران دارای سهمیه و تعداد مسیرهای پشتیبان). **هیچ IP، نام کاربر، UUID، رمز، لینک اشتراک یا محتوای ترافیک ارسال نمی‌شود.** خروجی صرفاً توصیهٔ تشخیصی است؛ مدل هیچ تنظیمی را تغییر نمی‌دهد و نمی‌تواند تضمین کند فیلتر یا DPI دور زده می‌شود.

در `wrangler.toml`، binding `[ai]` با نام `AI` آماده است. برای کشف فهرست جاری مدل‌های متنی Cloudflare، شناسهٔ اکانت را به‌صورت متغیر `AI_CATALOG_ACCOUNT_ID` و یک Secret با نام `AI_CATALOG_API_TOKEN` (حداقل مجوز **Workers AI Read**) تنظیم کنید. فهرست از API رسمی Cloudflare گرفته، مدل‌های متنی نامعتبر/آزمایشی/منسوخ فیلتر و حداکثر هشت مورد نگه‌داری می‌شوند؛ وقتی تاریخ انتشار/به‌روزرسانی موجود باشد، جدیدترها زودتر امتحان می‌شوند. نتیجه در isolate حداکثر ۶ ساعت cache می‌شود. این یک **ترتیب ترجیح عملیاتی** است، نه بنچمارک یا اثبات «هوشمندترین مدل»؛ دسترسی، هزینه و کیفیت مدل باید در حساب خودتان بررسی شود، و ممکن است فراخوانی مدل پولی هزینه داشته باشد. با `AI_MODELS` می‌توانید شناسه‌های دلخواه را به‌ترتیب اولویت مشخص کنید؛ این مقدار بر کشف خودکار مقدم است. اگر توکن کاتالوگ تنظیم نشود یا API در دسترس نباشد، فهرست fallback داخلی به‌کار می‌رود. اگر خود inference در دسترس نباشد، یک عیب‌یاب قاعده‌محورِ سبک روی Worker جایگزین می‌شود؛ این مدل زبانی یا ضد DPI نیست. برای جلوگیری از مصرف ناخواسته، سقف درخواست با D1 و به‌ازای IP به ۵ درخواست در هر ۱۰ دقیقه محدود شده است. حذف binding قابلیت را خاموش می‌کند.

```bash
npx wrangler secret put AI_CATALOG_API_TOKEN
# در wrangler.toml یا تنظیمات Worker: AI_CATALOG_ACCOUNT_ID = "<Cloudflare account ID>"
```

<div align="center">

<img src="docs/preview-status.png" alt="صفحهٔ وضعیت کاربر گذرگاه — تم تاریک شیشه‌ای با حلقهٔ مصرف و هاب ایمپورت" width="86%">

</div>

- **هاب ایمپورت:** لینک عمیق مخصوص هر کلاینت + کپی + QR تعبیه‌شده (بدون هیچ CDN)
- **سوییچ قالب:** خودکار / Base64 / Clash-Meta / Sing-box / Xray — همه با حفظ تیون اپراتور
- **چیپ‌های اپراتور:** با یک کلیک، کل صفحه و همهٔ لینک‌ها با پریست اپراتور بازسازی می‌شوند
- **درگاه‌های جایگزین:** اگر ۴۴۳ مسدود بود، لینک آمادهٔ ۲۰۵۳ / ۲۰۸۳ / ۲۰۸۷ / ۸۴۴۳
- تم روشن/تاریک، فارسی/انگلیسی، و احترام کامل به `prefers-reduced-motion`

## 🎚 تیون عمیق اپراتور

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/operators-light.svg">
  <img src="docs/operators-dark.svg" alt="پریست اختصاصی پنج اپراتور ایران — فینگرپرینت، فرگمنت و چرخ پورت" width="100%">
</picture>

هر اپراتور ایرانی رفتار DPI متفاوتی دارد؛ یک کانفیگ ثابت نمی‌تواند برای همه بهینه باشد. گذرگاه برای **همراه اول، ایرانسل، رایتل، شاتل و مخابرات** یک پریست اختصاصی ساخته: فینگرپرینت uTLS مناسب همان شبکه، پریست فرگمنت TLS داخل کپ‌های مستند Xray، و چرخ پورت‌های HTTPS کلادفلر. کافی است به لینک اشتراک `?op=mci` (یا هر اپراتور دیگر) اضافه شود.

قاعدهٔ **صداقت** سرنوشت‌ساز است: پریست فقط با انتخاب صریح کاربر اعمال می‌شود. بدون `?op=`، خروجی کاملاً خنثی و بی‌برند است — هیچ حدس ASN، هیچ برچسب غیرواقعی. و طبق درس میدانی، **ECH همیشه opt-in است** (`?ech=1`) چون DPI ایران با هندشیک‌های ECH مشکل دارد؛ پیش‌فرض در همهٔ فرمت‌ها خاموش است.

## 🧭 سفر یک درخواست

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/pipeline-light.svg">
  <img src="docs/pipeline-dark.svg" alt="سفر یک درخواست در گذرگاه — کلاینت، لبهٔ کلودفلر، دروازه، D1 و مقصد" width="100%">
</picture>

</div>

هر اتصال با یک هندشیک سبک در ورکر احراز می‌شود، مسیر کاربر از روی هاست تشخیص داده می‌شود و سپس ترافیک یا مستقیم به مقصد می‌رود یا در صورت نیاز از رلهٔ ProxyIP عبور می‌کند. همهٔ داده‌های پایدار (کاربران، مصرف، سشن‌ها، تنظیمات) در دیتابیس D1 خودتان می‌مانند و ورکر هیچ تله‌متری‌ای به بیرون نمی‌فرستد.

## ⚡ فرمت Xray — اتصال خودکارِ بهترین مسیر

فایل `xray` خروجی گذرگاه فقط لینک نیست؛ یک موتور انتخاب مسیر است. پروفایل شامل **observatory** است که هر ۳ دقیقه همهٔ مسیرها را probe می‌کند و بالانسر **leastPing** با تگ `auto-best` مسیر پیش‌فرض را به زنده‌ترین و سریع‌ترین outbound می‌برد — اگر یک مسیر throttle یا فیلتر شود، بدون هیچ دخالتی کنار می‌رود. با `?op=` یک کلون فرگمنت‌دار هم به خانواده اضافه می‌شود تا observatory آن را هم بسنجد.

## 🚀 استقرار در ۵ دقیقه

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/terminal-light.svg">
  <img src="docs/terminal-dark.svg" alt="استقرار گذرگاه در سه دستور — wrangler d1 create و npm run deploy" width="92%">
</picture>

</div>

فقط یک اکانت Cloudflare لازم است. (روش توسعه و استقرار با Wrangler به Node.js 22.12+ نیاز دارد؛ روش Paste به Node نیاز ندارد.)

### روش ۱ — Paste در داشبورد (بدون هیچ ابزاری)

1. فایل آمادهٔ `dist/gozargah-worker.js` را از [Releases](../../releases/latest) بردارید (یا خودتان با `npm run build` بسازید).
2. در داشبورد Cloudflare: **Workers & Pages → Create → Worker** — نام دلخواه (مثلاً `gozargah`) و Create.
3. دکمهٔ **Edit code** → محتوای فایل را جایگزین کنید → **Deploy**.
4. **ساخت دیتابیس:** **Storage & Databases → D1 → Create** — نام: `gozargah`.
5. در Worker: **Settings → Bindings → Add → D1 Database** — Variable name: دقیقاً `GZ_DB` — دیتابیس `gozargah` → Deploy.
6. صفحهٔ `https://<worker>.workers.dev/gozargah` را باز کنید — تمام! (ورود با `admin`)

> تا قبل از اتصال D1، پنل «راهنمای اتصال دیتابیس» را نشان می‌دهد و Worker در حالت بی‌دیتابیس هم پروکسی می‌کند (UUID قطعی از روی هاست).

### روش ۲ — wrangler (برای توسعه)

```bash
git clone https://github.com/panelgozargah/gozargah.git
cd gozargah
npm install
npx wrangler d1 create gozargah     # database_id را در wrangler.toml جای‌گذاری کنید
npm run deploy
```

> 🔄 **به‌روزرسانی خودکار:** در فورک خودتان دو Secret تعریف کنید — `CLOUDFLARE_API_TOKEN` و `CLOUDFLARE_ACCOUNT_ID` — از این به بعد هر push به `main` خودکار دیپلوی می‌شود.

## 🔑 ورود اولیه

| مورد | مقدار پیش‌فرض |
|------|----------------|
| آدرس پنل | `https://<worker>.workers.dev/gozargah` |
| رمز عبور | `admin` |

> ⚠️ پنل تا تغییر رمز پیش‌فرض، نوار هشدار زرد نشان می‌دهد. اولین کار بعد از ورود: **تنظیمات → رمز جدید**.
> مسیر پنل و مسیر اشتراک هم از همان‌جا قابل تغییر است.

## 👥 کاربران و اشتراک

- هر کاربر: **UUID اختصاصی + رمز Trojan + سهمیه (GB) + تاریخ انقضا + فعال/غیرفعال**؛ دکمهٔ قطع دسترسی در کارت کاربر، نشست جدید را فوراً رد می‌کند و نشست موجود حداکثر طی ۲ دقیقه با بازبینی D1 بسته می‌شود.
- **دو حالت انقضا:** تاریخ ثابت، یا «از اولین اتصال» — ساعت فقط وقتی شروع می‌شود که کاربر واقعاً وصل شود
- **ریست دوره‌ای مصرف:** روزانه / هفتگی / ۳۰ روزه — پنجرهٔ چرخشی بدون نیاز به Cron Worker
- مصرف واقعی up/down هر کاربر زنده در کارت او نمایش داده می‌شود (نوار گرادیانی)؛ نشست‌های فعال حداکثر هر ۲ دقیقه سهمیه/انقضا/وضعیت را با D1 بازبینی می‌کنند و در صورت لغو دسترسی بسته می‌شوند
- برای هر کاربر: لینک‌های VLESS/Trojan/Shadowsocks AEAD + QR + پنج قالب اشتراک + endpoint اختصاصی DoH + صفحهٔ وضعیت شخصی

| مسیر | توضیح |
|------|-------|
| `/{subPath}/{token}` | مرورگر ← صفحهٔ وضعیت · کلاینت ← اشتراک خودکار (UA-sniff) |
| `/{subPath}/{token}/clash` | پروفایل Clash-Meta |
| `/{subPath}/{token}/singbox` | پروفایل Sing-box |
| `/{subPath}/{token}/xray` | پروفایل Xray-core با auto-best |
| `/{subPath}/{token}/v2ray` | Base64 لینک‌ها (VLESS / Trojan / Shadowsocks) |
| `/{subPath}/{token}/dns-query` | DoH احراز هویت‌شده با GET یا POST؛ سهمیه و حسابداری D1 |
| `?op=mci` | پریست اپراتور: `mci` · `irancell` · `rightel` · `shatel` · `tci` |
| `?ech=1` | فعال‌سازی ECH (opt-in — پیش‌فرض خاموش) |
| `/gozargah` | پنل (قابل تغییر) |
| `/healthz` | سلامت Worker |

## ⚙️ تنظیمات پنل

| تنظیم | پیش‌فرض | توضیح |
|-------|---------|-------|
| ProxyIPs | `proxyip.cmliussss.net` | برای اتصال به سایت‌های پشت کلادفلر؛ هر خط یک مورد. انتخاب IP برای هر کاربر پایدار است |
| مسیر اشتراک | `sub` | پیشوند لینک اشتراک |
| مسیر پنل | `gozargah` | مسیر مخفی پنل |
| ریست دوره‌ای | خاموش | صفر شدن خودکار مصرف در بازهٔ انتخابی |
| رمز عبور | `admin` | حداقل ۸ کاراکتر |

### تنظیم resolver DNS

| متغیر | پیش‌فرض | کاربرد |
|-------|---------|--------|
| `DNS_UPSTREAMS` | Cloudflare و Google DoH | فهرست جداشده با ویرگول از حداکثر چهار URL HTTPS برای RFC 8484 |
| `DNS64_ENABLED` | فعال | مقدار `false`، ساخت AAAA مصنوعی را خاموش می‌کند |
| `DNS64_PREFIX` | `64:ff9b::/96` | پیشوند RFC 6052؛ طول‌های `/32`, `/40`, `/48`, `/56`, `/64`, `/96` |

## 🤖 ربات تلگرام اختیاری (FSM روی D1)

ربات، اگر تنظیم شود، فقط به شناسه‌های عددیِ مجاز در چت خصوصی پاسخ می‌دهد. حالت مکالمه در D1 نگه‌داری می‌شود (با انقضای ۱۵ دقیقه‌ای)، شناسهٔ هر update برای جلوگیری از اجرای مجدد ثبت می‌شود، و حساب مدیریتی از تغییر وضعیت محافظت شده است. فرمان‌ها: `/status`، `/users`، `/disable`، `/enable`، `/cancel`. ربات هیچ‌وقت رمز پنل، UUID یا لینک اشتراک را ارسال نمی‌کند. غیرفعال‌سازی فوراً اتصال‌های جدید را رد می‌کند؛ نشست‌های برقرار حداکثر هر ۲ دقیقه با D1 دوباره بررسی و در صورت غیرفعال‌شدن، اتمام سهمیه، انقضا یا حذف کاربر بسته می‌شوند. این بررسی دوره‌ای مصرف خواندن/نوشتن D1 دارد.

1. در Cloudflare برای هر مقدار یک Secret بسازید: `TELEGRAM_BOT_TOKEN`، `TELEGRAM_WEBHOOK_SECRET` و `TELEGRAM_ADMIN_IDS` (شناسه‌های عددی تلگرام با ویرگول، مثل `12345678,87654321`).
2. پس از Deploy، در محیط امنی که متغیرها در آن تعریف شده‌اند، webhook را ثبت کنید:

```bash
curl -fsS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
  -d "url=https://${WORKER_HOST}/_telegram/webhook" \
  -d "secret_token=${TELEGRAM_WEBHOOK_SECRET}"
```

Webhook با هدر محرمانهٔ Telegram، allowlist فرستنده و الزام چت خصوصی بررسی می‌شود. برای خاموش‌کردن ربات، Secretها را حذف و دوباره Deploy کنید. توکن‌ها را در Git یا چت قرار ندهید.

## 📱 کلاینت‌های همخوان

v2rayNG · v2rayN · Streisand · Shadowrocket · Hiddify · Clash-Meta/Stash · Sing-box · Karing · Nekobox

## 🔐 امنیت در معماری

- رمز با **PBKDF2-SHA256** و ۱۰۰٬۰۰۰ دور هش می‌شود؛ salt تصادفی ۱۶ بایتی — هیچ رمز plaintext ای در دیتابیس نیست
- سشن‌ها با **HMAC-SHA256** امضا و ۷ روزه منقضی می‌شوند؛ کوکی `HttpOnly; Secure; SameSite=Lax` — تغییر رمز همهٔ سشن‌ها را باطل می‌کند
- ورود: حداکثر ۵ تلاش در ۱۵ دقیقه — قفل **ماندگار در D1** (بر اساس هش IP)، نه حافظهٔ فرّار
- UUID و رمز Trojan هر کاربر با یک کلیک قابل چرخش است
- پاسخ همهٔ مسیرهای ناشناخته یک صفحهٔ بی‌اثر است — وجود پنل از رفتار HTTP قابل کشف نیست
- `robots.txt` بسته و همهٔ دارایی‌های UI تعبیه‌شده — هیچ ردی به سرویس ثالث

## 🧪 توسعه

```bash
npm install          # نصب وابستگی‌های توسعه
npm run typecheck    # بررسی تایپ TypeScript
npm test             # چک‌های موتور/پروتکل + تست Worker/D1 با Vitest و Miniflare
npm run preview      # پیش‌نمایش آفلاین پنل با دادهٔ ماک (preview.html)
npm run build        # اعتبارسنجی و باندل Worker با Wrangler 4
```

<details>
<summary><b>🌐 English</b></summary>

**Gozargah** (Persian for *gateway*) is a complete multi-user proxy panel that runs natively on Cloudflare Workers — the entire product lives in a single JS file: admin dashboard, proxy engine, subscription generator, per-user status page and all UI assets are embedded.

- **Protocols:** VLESS, Trojan, and Shadowsocks SIP004 AES-256-GCM over TLS/WebSocket (SIP003 `v2ray-plugin`; TCP only); VLESS UDP is limited to DNS on port 53
- **Storage:** Cloudflare D1 (relational — users / events / throttle), in-isolate cache, promise-dedup, optimistic locking
- **Accounting:** real byte counting per user (up/down), live usage bars, quotas & expiry; active sessions revalidate account state and persist usage every 2 minutes (D1 usage/cost trade-off)
- **Expiry modes:** fixed date **or** days-from-first-use (the clock starts on the first actual connection) + rolling auto-reset cycles (daily / weekly / 30d) — no Cron worker needed
- **Operator tuning:** explicit `?op=` presets for MCI, Irancell, Rightel, Shatel & TCI — per-ISP uTLS fingerprint, Xray-capped TLS-fragment preset and an HTTPS port wheel. Honesty gate: no preset is applied unless the user asks; ECH is strictly opt-in (`?ech=1`)
- **Xray format:** profile with observatory + leastPing balancer (`auto-best`) — a throttled path is demoted automatically; fragment clone included for operator presets
- **User status page:** browsers opening the sub link get a glassmorphic live page (real usage ring, one-tap imports, embedded QR, format switcher, operator chips, alt-port links); proxy clients keep raw configs via UA sniffing
- **Security:** PBKDF2-SHA256 (100k iterations), HMAC-signed expiring sessions, persistent D1-backed rate limiting
- **Subscriptions:** Base64 / Clash-Meta / Sing-box / Xray-core generated in-worker, auto `User-Agent` detection; SS plugin profiles appear where the client format supports them
- **DNS:** Per-user-token RFC 8484 endpoint with D1 rate limiting/accounting, VLESS UDP DNS forwarding over WebSocket, adaptive DoH failover, and optional RFC 6052 DNS64 (not a raw UDP listener or NAT64 gateway)
- **UI:** Gozargah Nexus UI — cinematic dark glassmorphism, full RTL, FA/EN
- **Telegram admin bot:** opt-in, allowlisted private-chat commands with D1-backed FSM, update deduplication, short state TTL and protected admin accounts
- **Workers AI advisor (optional):** aggregate-only diagnostics, optional Cloudflare catalog discovery with model fallback, no user identifiers/configs/traffic sent, and an atomic D1 per-IP request budget; not an anti-DPI feature
- **Tests:** `npm test` — engine checks plus Vitest/Miniflare Worker+D1 integration tests

**Deploy:** grab `dist/gozargah-worker.js` from [Releases](../../releases/latest), paste it into a new Worker, create a D1 database bound as `GZ_DB`, open `https://<worker>.workers.dev/gozargah` — login `admin`. Free plan is enough.

</details>

## ⚠️ مرزهای واقعی پلتفرم و صداقتِ قابلیت‌ها

- **Shadowsocks AEAD:** روش `aes-256-gcm` با framing استاندارد SIP004، فقط روی WebSocket/TLS و با افزونهٔ سمت کلاینت `v2ray-plugin` (SIP003). UDP عمومی Shadowsocks پشتیبانی نمی‌شود.
- **DNS روی UDP:** فقط datagramهای DNS در فرمان UDP پروتکل VLESS و مقصد پورت ۵۳ پذیرفته می‌شوند. دیتاگرام داخل WebSocket می‌آید و Worker آن را از طریق HTTPS DoH به یکی از resolverهای تنظیم‌شده می‌فرستد. Worker روی UDP/53 گوش نمی‌دهد و relay عمومی UDP ندارد.
- **DoH کاربر:** مسیر `/{subPath}/{token}/dns-query` به توکن اشتراک همان کاربر وابسته است، نرخ درخواست در D1 محدود می‌شود و بایت پرس‌وجو/پاسخ در مصرف کاربر حساب می‌شود. resolverها با timeout و failover محدود انتخاب می‌شوند؛ یادگیری این بخش EWMA آماری محلی است، نه تشخیص DPI.
- **DNS64/NAT64:** در پاسخ AAAA بدون رکورد IPv6، در صورت فعال بودن، Worker می‌تواند از A پاسخ AAAA مطابق RFC 6052 بسازد. پیشوند پیش‌فرض `64:ff9b::/96` است و با `DNS64_PREFIX` قابل تغییر است؛ `DNS64_ENABLED=false` آن را خاموش می‌کند. DNS64 خودش مبدل NAT64 یا مسیر خروجی IPv4-to-IPv6 ایجاد نمی‌کند و فقط وقتی کاربرد دارد که سمت کلاینت/شبکه یک NAT64 translator قابل دسترس داشته باشد. درخواست‌های دارای EDNS DO دست‌کاری نمی‌شوند.
- **هوش مصنوعی و فیلترینگ:** learner داخلیِ محدود و deterministic از آمار تجمیعی latency/reliability برای انتخاب محافظه‌کارانه استفاده می‌کند. Workers AI اختیاری فقط مشاور خواندنی است. هیچ‌کدام classifier DPI نیستند، payload را بررسی نمی‌کنند و عبور از فیلترینگ را تضمین نمی‌کنند.
- **قطع کامل مسیر:** اگر از شبکهٔ کاربر هیچ مسیری تا Worker/Cloudflare یا نقطهٔ ورودی مستقل باقی نمانده باشد، کد داخل Worker نمی‌تواند اینترنت یا مسیر شبکه‌ای تازه بسازد؛ قطع کامل دسترسی بین‌المللی از راه دور قابل دورزدن نیست. برای آن وضعیت، نقطهٔ ورودِ از قبل در دسترس یا یک کانال ارتباطی مستقل لازم است.

## 🛣 نقشهٔ راه

- [x] ربات تلگرام اختیاری با FSM پایدار در D1، allowlist و dedupe — v1.3
- [x] مشاور خواندنی Workers AI با fallback مدل و محدودیت اتمیک درخواست در D1 — v1.4
- [x] دکمهٔ قطع/فعال‌سازی هر کاربر از کارت پنل — v1.4
- [x] تست یکپارچگی Worker/D1 با Vitest + Miniflare — v1.3 و گسترش DNS در 2.11
- [x] پریست‌های اپراتورهای ایران + فرگمنت داخل کپ‌های Xray — v1.2
- [x] خروجی Xray-core با observatory و بالانسر leastPing — v1.2
- [x] صفحهٔ وضعیت کاربر با QR و ایمپورت یک‌کلیکی — v1.2
- [x] انقضای «از اولین اتصال» + ریست دوره‌ای مصرف — v1.2
- [x] ECH به‌صورت opt-in در فرمت‌های پشتیبانی‌شده — v1.2
- [x] Shadowsocks AEAD به‌عنوان پروتکل سوم (SIP004 AES-256-GCM + v2ray-plugin) — 2.11
- [x] فوروارد DNS با VLESS UDP روی پورت ۵۳، DoH و DNS64 — 2.11
- [x] هوش مصنوعی داخلیِ تشخیص تغییر رژیم + استراتژی پویای diversify — 2.12
- [x] مسیر چرخشی deterministicِ WebSocket (هر ۶ ساعت، سازگار با عقب) — 2.12
- [x] پلهٔ اضطراری: نقاط ورود جایگزین با پروب سلامت و آوتباند در همهٔ قالب‌ها — 2.12

## 📄 لایسنس

MIT — آزاد برای استفاده، تغییر و توسعه. جزئیات در [LICENSE](LICENSE).

<div align="center">

<img src="docs/divider.svg" width="60%">

<sub><b>گذرگاه</b> — دروازهٔ امن عبور · ساخته‌شده برای سرعت، سادگی و آزادی</sub>

</div>

## 2.3.0 — Adaptive Health Loop

- Scheduled health loop every 5 minutes for only D1-configured fallback endpoints.
- D1 `network_state` quorum classifier: healthy / degraded / recovery / no_healthy_path.
- Authenticated `GET /{panelPath}/api/network/state`.
- Configurable probe ports via `HEALTH_PROBE_PORTS` (default: 443,2053,2083,2087,8443).
- No arbitrary network scanning; probes are bounded to endpoints already present in settings.
- The classifier is observational and does not claim to prove DPI or an international outage.


## Protocol capability matrix (current: 2.12.0)

Every protocol/transport pair is returned with an explicit boundary: `WORKER_NATIVE`, `ORIGIN_ENGINE_REQUIRED`, or `UNSUPPORTED`. The matrix is conservative: a profile is `ready` only if this repository has a matching generator. `ORIGIN_ENGINE_HOST` is a declaration, not a remote validation or health check. VLESS/Trojan WebSocket and Shadowsocks AEAD WebSocket profiles are Worker-native; Shadowsocks uses the v2ray-plugin and is TCP-only. UDP-only WireGuard/Hysteria2, generic Shadowsocks UDP, generic HTTP proxying, and unimplemented transports remain `UNSUPPORTED`. Separately, VLESS UDP is supported only for DNS destination port 53 via the DoH adapter; it is not a generic UDP capability.


### 2.3.0 capability endpoints
- `GET /<panel>/api/network/capabilities` — authenticated protocol/transport matrix.
- `GET /<sub>/<token>/profiles` — adaptive profile manifest.
- `GET /<sub>/<token>/capabilities` — public capability metadata for the current subscription token.

Optional env: `ORIGIN_ENGINE_HOST`, `ORIGIN_ENGINE_PORT`, and `ORIGIN_ENGINE_TRANSPORTS` enable template generation for the supported subset (VMess/WebSocket, VLESS/gRPC/XHTTP/HTTPUpgrade, and Trojan/XHTTP as allowed by the transport list). These entries are marked `declared-not-tested` because the Worker has no origin-engine validation adapter. Without an origin engine, Worker-native VLESS/Trojan and Shadowsocks AEAD over WebSocket are marked ready. WireGuard, Hysteria2, and generic UDP remain unsupported; the separately documented VLESS DNS-only adapter does not advertise arbitrary UDP.

## Gozargah 2.3.0 — Adaptive Protocol Orchestrator

2.3.0 adds a capability-aware protocol policy layer. It distinguishes Worker-native
HTTP/WebSocket profiles from origin-engine profiles and emits a bounded, diverse
preference list instead of pretending every transport is native to Workers.

New optional origin-engine variables:
- ORIGIN_ENGINE_HOST
- ORIGIN_ENGINE_PORT
- ORIGIN_ENGINE_SNI
- ORIGIN_ENGINE_PATH
- ORIGIN_ENGINE_GRPC_SERVICE
- ORIGIN_ENGINE_TRANSPORTS (default: xhttp,grpc,httpupgrade,ws)

New endpoint:
- GET /<panelPath>/api/network/policy

The /sub/<token>/profiles manifest now includes an adaptive policy with protocol,
transport, security, ALPN, readiness, and a bounded score. Xray output also emits
origin-engine profiles when an origin is explicitly configured and routes them
through observatory/leastPing. UDP-only protocols remain origin-engine capabilities;
the Worker itself does not claim to terminate inbound raw TCP/UDP.
