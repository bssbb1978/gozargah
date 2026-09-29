# AXR-v2 Enterprise Core — Advanced Features (2.15)

This document covers the 2.15 increment on top of the [AXR Protocol
Framework](AXR-SPEC.md) (v2.14): the **contextual bandit upgrade (LinUCB)**,
**app-class flow morphing**, **TCP socket surgery**, **clean edge-IP
harvesting**, **session reuse**, **scanner decoy layer**, and the **decision
audit log** — plus the reserved transport stubs (HTTP-chunked duplex, gRPC,
HTTP/3) and their documented status.

---

## 1. Client core: LinUCB contextual bandit (M1)

`client/internal/bandit` is upgraded from UCB1 to **LinUCB** — a zero-dependency
contextual bandit (pure Go, no external math packages).

### 1.1 Why contextual

UCB1 scores an arm by one mean reward plus a pull-count bonus: it cannot
express *"this entry is great on a clean pipe but dies when RSTs spike"*.
Iran's filtering is non-stationary and regime-dependent, so the core scores
each arm as a **linear function of a 7-dim context vector** measured from the
client's own last 40 connection outcomes (`internal/measure`):

| idx | feature | source (measure.Vector) | normalisation |
| --- | --- | --- | --- |
| 0 | bias | constant | 1.0 |
| 1 | RTT level | `RTTMS` (EWMA) | ÷ 2000 ms, clamp [0,1] |
| 2 | RTT variance | `JitterMS` (EWMA \|Δrtt\|) | ÷ 500 ms, clamp [0,1] |
| 3 | RST frequency | `RSTRate` (window fraction) | clamp [0,1] |
| 4 | TLS drop delta | `TimeoutRate` (handshake-drop fraction) | clamp [0,1] |
| 5 | loss step | `StepDelta` (CUSUM accumulator) | ÷ 6, clamp [0,1] |
| 6 | HTTP/protocol anomaly | `LastAnomaly ≠ 0` | 0/1 |

### 1.2 Per-arm state and scoring

Per arm `a` (host × transport × fingerprint):

```
A_a = λI + Σ x xᵀ        7×7, SPD (λ = 1.0 ridge)
b_a = Σ r x              7-dim
θ_a = A_a⁻¹ b_a
score_a(x) = xᵀθ_a + α·√(xᵀ A_a⁻¹ x)      α = 1.0 (× 1.8 in suspected_change)
```

- `A⁻¹` via **partial-pivot Gauss-Jordan in pure Go** (49 floats — trivial cost).
- Reward `r ∈ [0,1]` unchanged from 2.14 (0.5 base + throughput-stability
  bonus + RTT penalty; failures = 0).
- **Untried arms get `1 + α`** (the maximum possible), deliberately: the core
  must *try* every entry at least once or failover can never discover a
  currently-live path; it also keeps the first pick deterministic.
- Preserved unchanged: consecutive-failure **quarantine** (60 s → 2 min →
  5 min → 15 min backoff), **auto-prune** (≥ `PruneKeepAlive = 2` live arms,
  arm prunable only after 12 pulls and mean < 0.10), weakest-transport nudge,
  diversity bonus during `suspected_change`, `ErrNoArm` semantics, atomic
  JSON persistence (now including the `A`/`b` state; legacy 2.14 snapshots
  restore cleanly — missing Lin state rebuilds the λI prior).

`Observe` now takes the context that was current at selection time, so each
update lands on the right feature vector.

## 2. Client core: app-class flow morphing (M2)

`client/internal/flowprofile` (new) + `internal/surgery` extension.

### 2.1 Length-histogram morphing

Each profile is a **piecewise length histogram** (chunk ranges × weights) —
the post-handshake writes are split so their *length distribution*
approximates the chosen application class instead of the synthetic
"constant 1400 B bursts" signature:

| class | length bins (bytes, weight) | lognormal IPD (median, σ) |
| --- | --- | --- |
| `web` | 300–500 (0.34), 500–800 (0.30), 800–1200 (0.22), 1200–1400 (0.14) | 30 ms, 0.9 |
| `video` | 500–900 (0.18), 900–1200 (0.30), 1200–1400 (0.52) | 4 ms, 0.7 |
| `chat` | 100–250 (0.46), 250–500 (0.34), 500–900 (0.20) | 300 ms, 1.0 |

Inter-packet delays are **lognormal** (Box–Muller from the core's seeded
RNG), clipped per class. `surgery.ChunkConn` now accepts a `Slicer`
(`NewChunkConnWith`); the legacy `NewChunkConn` (uniform 512–1400 B) is
unchanged. The slicer is **stateless** — `ChunkConn` skips the gap before the
first chunk of each Write.

### 2.2 Regime → profile selection

| regime | profile |
| --- | --- |
| `stable` / `recovering` | `web` (the boring baseline) |
| `watch` | `chat` (small, bursty, human-paced) |
| `suspected_change` | `video` (sustained bulk-flow shape) |

### 2.3 TCP socket surgery

`client/internal/sockopt` (new): on every fresh dial the core sets
**`TCP_NODELAY` (Nagle off)** — so kernel coalescing never re-merges the
morphed chunk pattern — and **randomizes `SO_SNDBUF`** per connection from
{64 KB, 128 KB, 256 KB, 512 KB} (the send buffer leaks into window/segment
behaviour; varying it de-tunes stock-kernel-default classifiers). Build-tagged
implementations for Linux/Darwin/Windows (stdlib `syscall` only); every other
platform is a documented no-op.

### 2.4 What this is *not*

Length/timing morphing shapes the **client's own write segmentation**. It does
not inspect payloads, does not replay any real user's traffic, and is not an
invisibility guarantee — it moves the observed length/arrival histogram away
from a synthetic relay toward a plausible app class.

## 3. Client core: clean edge-IP harvesting (M3)

`client/internal/failover`:

- `Resolver` interface (injectable; `DefaultResolver` = system resolver,
  **IPv4 A-records only** — matching the Worker's IPv4 `clean_ip_hints`).
- `HarvestedIPs(ctx, explicit, host, r)`: merges operator IPs (kept first,
  trusted) with harvested A records — **deduped, IPv4-validated, capped at
  8**. Resolver errors leave the existing list untouched (harvesting is an
  enhancement, never a regression).
- `Engine.HarvestEntries(ctx, r)`: applies the merge to the whole matrix at
  startup.
- The Worker's manifest `clean_ip_hints` (operator `CLEAN_EDGE_IPS` env,
  validated, ≤ 8) are merged into every entry the same way.

## 4. Client core: session reuse + decision audit (M4 client half)

- **Warm session reuse**: when a tunnel ends on a *clean local close* (the
  app closed its side; the WS may still be healthy), the core keeps the
  WS open for up to **30 s**. The next SOCKS CONNECT to the **same
  destination** adopts it — zero dial/TLS/WS/handshake (a WS session carries
  exactly one backend stream, so adoption is strictly same-destination).
  A stale session fails the first pump operation and is discarded with an
  automatic fresh dial. One warm session is kept; expiry and replacement
  close the previous one.
- **`~/.axr/decision.jsonl` audit log**: one JSON line per tunnel decision —
  timestamp, regime, flow profile, full 7-dim context, chosen arm, the whole
  LinUCB score table, candidates tried (host/IP/shape), outcome (ok/rtt/
  reason/dial addr), and warm-adoption flag. Rotated at ~4 MB
  (`decision.jsonl.old`). Best-effort: logging never breaks a tunnel.
- **`ws-alt` second arm per entry**: every entry runs the standard WS arm
  *and* a `ws-alt` arm — same host, `gz_profile=fragmented` path/query shape
  (the Worker's 2.14 4-way profile telemetry already scores it). The bandit
  learns which shape is healthier under current conditions.

## 5. Worker edge: scanner decoy layer (M4 worker half)

`src/panel/decoy.ts` (new), wired into the final routing fallthrough
(`src/index.ts`) **before** the stealth landing:

- Any unmatched **GET/HEAD** whose path matches scanner shapes
  (`/.env`, `/.git/…`, `/wp-login.php`, `/admin`, `/api/…`, `/phpmyadmin`,
  `/config.json`, `/axr*`, `/vless*`, `/sub/…`, …) receives a
  **benign product page** — one of 3 realistic small-business HTML variants
  (logistics / architecture studio / consulting), each carrying a random
  32-hex padding comment so byte length varies per response.
- JSON-typed probes (`Accept: application/json` or `*.json`) against those
  shapes receive one of **2 benign JSON API shapes** (edge-cache status,
  v2 service health).
- Unknown-token machine-feed shapes (e.g. `/sub/<bad>/axr-manifest`) get the
  same treatment — **no user enumeration, no constant 404/landing
  signature**.
- Everything else falls through to the existing stealth landing. Real
  authenticated routes are handled *before* the decoy layer; POST is never
  decoyed.

## 6. Worker edge: manifest extensions (M4)

`gozargah-axr-manifest/v1` gains (2.15):

- `transports: ["ws", "ws-alt"]` — declared data-plane shapes.
- `flow_profile: { mode: "web"|"chat"|"video", … }` — regime-escalated on
  the Worker (D1 state): `video` under `suspected_change`/`recovery`/
  `no_healthy_path`, `chat` under `watch`, `web` otherwise. The client maps
  its *own* regime to a profile (same table), so both sides converge.
- `clean_ip_hints: string[]` — operator `CLEAN_EDGE_IPS` (comma-separated
  IPv4, validated, ≤ 8) for client-side harvest merging.

## 7. Reserved transport stubs — documented status

| transport | status | why not shipped |
| --- | --- | --- |
| **VLESS-over-WS** | **shipped** (2.14) | the only data plane verifiable end-to-end in this repo's CI (miniflare WS works) |
| `ws-alt` (fragmented path/query shape) | **shipped** (2.15, client) | same WS engine, different shape — learnable by the bandit |
| HTTP-chunked bidirectional relay | **reserved stub** | measured: miniflare 4.x buffers the *request* body (a never-ending stream hangs the worker); a duplex HTTP relay would ship **untested** — the WS plane covers the same requirement |
| gRPC over WS | **reserved stub** | interface exists in arm set (`Transport` field accepts `grpc`); no codec implemented — zero production value without a real implementation |
| HTTP/3 (QUIC) | **reserved stub** | arm-set placeholder only; QUIC needs UDP, which the core rejects by design (no UDP relay boundary) |

## 8. Verification

- Worker: `tsc --noEmit`, pure-logic suites (incl. new `decoy`), and the
  miniflare + D1 integration suite (incl. new decoy + manifest-v2 tests) — see
  [TEST-REPORT-2.15.0](../TEST-REPORT-2.15.0.md).
- Go core: complete source + unit tests (bandit incl. LinUCB context-
  sensitivity and closed-form checks, flowprofile distribution/ordering,
  sockopt, failover harvest). **Not compiled in the authoring sandbox**
  (no Go toolchain reachable); the deploy gate is
  `go vet && go build && go test ./...` per [AXR-DEPLOY](AXR-DEPLOY.md).
