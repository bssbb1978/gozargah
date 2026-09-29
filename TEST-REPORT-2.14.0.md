# Gozargah 2.14.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository (Worker) tests, TypeScript checks, and the Wrangler dry-run
build pass on the 2.14.0 working tree. The Go client core ships as complete
source + unit tests with a pinned `go.mod`; it was **not compiled in the
authoring sandbox** (no Go toolchain reachable), so its gate is the deploy
checklist in `docs/AXR-DEPLOY.md`.

| Command | Result |
|---|---|
| `npm test` | Pass — 36 engine checks, 9 supplemental pure-logic suites (predictive-mesh, protocol-catalog, protocol-controller, network-intelligence, regime, path-rotation, fp-rotation, shape, decision), and **16** Vitest + Miniflare integration tests |
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; 504.35 KiB upload, 131.51 KiB gzip |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live
Cloudflare deployment or external-client interoperability session was
performed.

## Coverage added or extended

- **AXR machine feed (Worker, `src/subscription.ts#buildAxrManifest` +
  `src/index.ts` route):** two new integration tests — (1) authenticated
  `GET /sub/<token>/axr-manifest` returns 200 JSON with schema
  `gozargah-axr-manifest/v1`, host, `ws_path_base`, neutral fingerprint set
  containing `chrome`, a primary `entries[]` row, and a numeric
  `reconnect.probe_interval_ms`; (2) an unknown token on the same path falls
  through to the stealth HTML landing (no user enumeration).
- **Go client core (unit tests, not executed here — no toolchain):**
  - `internal/bandit` — reward bounds in [0,1]; deterministic untried-arm
    exploration; exploitation of a clear winner after sufficient pulls;
    quarantine backoff schedule (60 s/2 min/5 min) + clear-on-success +
    lone-quarantined-arm still selectable; prune keeps ≥ 2 live arms;
    suspected_change exploration scaling ≈ ×1.8 (score-table ratio);
    JSON persistence round-trip (C + stats); atomic-save leaves no temp files;
    empty-snapshot rejection; `AddArm` default-fp + no-duplicate.
  - `internal/measure` — stable stream → `stable` with flat jitter; sustained
    RST → `suspected_change` + CUSUM alarm; long bad → long good →
    `recovering` (re-baseline on the actual recovery crossing); 50%
    alternating loss → `watch`; timeout/RST rate accounting; per-transport
    weakest detection; anomaly-code carry; jitter EWMA tracks ~400 ms
    swings; ring-window slides past stale failures.
  - `internal/surgery` — `PlanHelloSplit` bounds + tiny-record/nil-rng
    rejection; `SplitConn` emits exactly 2 segments for the first write and
    passes the second write through, byte-identical reassembly; read/close
    delegation; `ChunkConn` fragments 10 000 B into ≥ 8 pieces within
    512–1400 B with byte-identical reassembly; small-write passthrough;
    gap bounds [20 ms, 120 ms].
  - `internal/failover` — probe round stops at first healthy candidate;
    health scoring (failed < healthy, low-RTT high score, streak
    accounting); `CandidatesFor` health ordering; normal→aggressive after
    two all-fail rounds and back on success; aggressive uses the 5 s timeout;
    cache persistence round-trip + missing-file no-op + no temp leftovers;
    bandit-score ordering beats priority; `AddEntry` replacement; `Best`
    still returns the top candidate when all are dead.
  - `internal/vlessws` — VLESS header byte-exactness for domain/IPv4/IPv6 +
    UDP cmd + bad-uuid rejection; UUID parse (dashed/plain); early-data
    base64url round-trip + 2048 B limit; client frame encode (mask placement,
    16-bit length) and decode (7/16/64-bit length paths, masked-server-frame
    rejection, short-buffer); 70 000 B round-trip; RFC 6455
    `Sec-WebSocket-Accept` vector (`dGhlIHNhbXBsZSBub25jZQ==` →
    `s3pPLMIBIZlLFOJHzqTBDOn7nPA=`).

## Verification status (Go core)

- **Not compiled, not test-executed in the authoring sandbox.** No Go
  toolchain was installable there (go.dev/dl, dl.google.com, and the
  CN/Alibaba mirrors are all unreachable from the sandbox; no root for apt).
- The tree is written against verified APIs: the refraction-networking/utls
  v1.6.7 surface (`UClient(conn, *Config, ClientHelloID)`,
  `HelloChrome_Auto`/`HelloFirefox_Auto`/`HelloSafari_Auto`/
  `HelloRandomized`) was checked against the tagged upstream source, and the
  VLESS wire format + early-data contract were checked against
  `src/protocols/vless.ts` and `src/handlers/websocket.ts` in this repo.
- **Mandatory gate before first use:** `cd client && go mod tidy &&
  go vet ./... && go build ./... && go test ./...` (plus the tagged build).

## Platform boundaries (what 2.14 does and does not change)

- TLS terminates at the Cloudflare edge; the Worker still never sees or
  mutates the ClientHello. All identity morphing and ClientHello
  segmentation live in the native client core.
- The new `axr-manifest` route exposes **aggregate** server-side
  intelligence only (regime, strategy, probe mode, measured entry health,
  rotation windows, reconnect cadence). No user payload data, no DPI
  detection, no bypass guarantee — stated in the payload's `honest_limit`.
- The VLESS wire format is unchanged; the native client is byte-compatible
  with the Worker's existing `parseVless`/`acceptWebSocket` (0-RTT early
  data via `Sec-WebSocket-Protocol` is the mechanism the Worker already
  consumes).
- TCP-only: the client core rejects SOCKS5 UDP ASSOCIATE (no UDP relay, per
  the platform boundary). Post-handshake fragmentation is TCP-level chunking,
  explicitly not TLS record padding.
- A fully cut route remains unrestorable from client or Worker; the core
  reports `no healthy candidate` instead of looping.
