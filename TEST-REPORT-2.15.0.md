# Gozargah 2.15.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository (Worker) tests, TypeScript checks, and the Wrangler dry-run
build pass on the 2.15.0 working tree. The Go client core ships as complete
source + unit tests with the pinned `go.mod`; it was **not compiled in the
authoring sandbox** (no Go toolchain reachable — go.dev/dl.google.com/
aliyun/tuna all TLS-blocked, no root for apt), so its gate remains the deploy
checklist in `docs/AXR-DEPLOY.md` (`go vet && go build && go test ./...`).

| Command | Result |
|---|---|
| `npm test` | Pass — 36 engine checks, **10** supplemental pure-logic suites (predictive-mesh, protocol-catalog, protocol-controller, network-intelligence, regime, path-rotation, fp-rotation, shape, decision, **decoy** — new), and **17** Vitest + Miniflare integration tests (16 → 17) |
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; **511.03 KiB upload, 133.49 KiB gzip** (2.14: 504.35 / 131.51) |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live
Cloudflare deployment or external-client interoperability session was
performed.

## Coverage added or extended

### Worker — scanner decoy layer (new `src/test/decoy.ts` pure suite, 7 blocks)
- Legitimate shapes (`/`, ordinary paths, WS-shaped paths) fall through
  (`decoyResponse` → null) to the normal stealth landing.
- 9 scanner path shapes (`/.env`, `/.git/config`, `/api/v1/users`,
  `/wp-login.php`, `/admin`, `/axr`, `/status`, `/phpmyadmin/index.php`,
  `/.well-known/security.txt`) each return **200 text/html** with a real
  `<title>` and copyright line.
- JSON-typed probe (`/api/status` + `Accept: application/json`) returns
  `application/json` with ≥ 3 keys.
- Two responses for the same path differ byte-wise (random 32-hex padding).
- HEAD is decoyed; POST is never decoyed.
- Unknown-token machine-feed shape + JSON accept → benign JSON.
- `cleanIpHints()`: empty input → `[]`; mixed valid/invalid/whitespace
  input → validated + trimmed IPv4 list; > 8 entries cap at 8.

### Worker — integration (miniflare + D1) new/extended
- **Scanner probes via the real router**: `GET /.env` → 200 HTML product
  page with `<title>`; `GET /api/status` + JSON accept → benign JSON;
  `GET /sub/unknown-token-abc/axr-manifest` + JSON accept → benign JSON
  (no enumeration); ordinary unknown path → stealth landing containing
  "Gozargah".
- **Manifest v2 fields**: authenticated manifest now asserts
  `version == VERSION`, `transports == ["ws","ws-alt"]`,
  `flow_profile.mode == "web"` (stable regime), and
  `clean_ip_hints == ["203.0.113.10","203.0.113.11"]` — with the test
  binding `CLEAN_EDGE_IPS` deliberately containing the invalid
  `999.1.1.1` to prove filtering. (The manifest user is created in
  `beforeAll` because the Worker bundles its own module copy with a short
  users-list cache; users created after the Worker's first list read can be
  stale — documented inline.)

### Go client core (unit tests, not executed here — no toolchain)
- `internal/bandit` — **rewritten for LinUCB**: reward bounds in [0,1];
  Gauss-Jordan inverse round-trip (`A·A⁻¹ ≈ I` on a real observation
  matrix); deterministic untried-arm first pick (ID tie-break);
  exploitation of a clear winner after the untried arm is explored;
  **context-conditioning closed-form test** (successes under a clean
  context vs failures under a high-RST context → conditional means
  ≈ 0.83 / ≈ 0.10, asserted > 0.6 / < 0.4); quarantine backoff schedule +
  clear-on-success + lone-quarantined-arm selectable; prune keeps ≥ 2
  live arms and is idempotent; suspected_change exploration scaling
  ≈ ×1.8 (score-table ratio); persistence round-trip now including the
  per-arm `A`/`b` matrices and post-restore score equality; **legacy
  2.14 snapshot (no Lin state) restores with the λI prior rebuilt**;
  empty-snapshot rejection; `AddArm` default-fp + fresh ridge prior;
  atomic-save leaves no temp files.
- `internal/flowprofile` (new) — length draws within `[1, remaining]`;
  class ordering video (≈1117 B) > web (≈733 B) > chat (≈348 B) with
  sanity bounds; lognormal IPD within per-class `[min,max]` and ordering
  chat (≈497 ms) > web (≈45 ms) > video (≈5 ms); same-seed determinism;
  Box–Muller finiteness; regime→profile mapping (stable→web, watch→chat,
  suspected_change→video, unknown→web); unknown profile falls back to
  web; `Slicer.Next` bounds + structural satisfaction of the
  `surgery.Slicer` interface; nil-RNG fallback.
- `internal/surgery` — unchanged legacy behaviour (uniform 512–1400 B
  chunks, fixed gap) plus the new `Slicer`-driven path (first chunk of a
  Write never waits; size clamps to remaining; progress guaranteed).
- `internal/sockopt` (new) — `SelectSendbuf` stays in the allowed set and
  varies; nil-rand deterministic default; `Apply`/`ApplyWithSeed` no-op
  (not error) on non-TCP conns and succeed/no-op on a loopback TCP socket
  per platform.
- `internal/failover` — harvest: explicit-first + dedupe + order
  preservation; cap at 8 with explicit IPs keeping the front; invalid
  (non-IP) records dropped; resolver error keeps the existing list;
  nil-resolver dedupes explicit only; `Engine.HarvestEntries` merges one
  new IP per entry and is idempotent on re-run.
- `cmd/axr` — wiring (LinUCB context from the measure vector, dual
  ws/ws-alt arms, `gz_profile=fragmented` path for ws-alt, regime-driven
  slicer, sockopt on dial, warm-session adoption with same-destination
  only, decision.jsonl rotation) is covered by the package-level
  behaviour above; the binary itself is exercised by the deploy checklist.

## Known unverified items (honest)

- **Go core compilation/tests** — no toolchain in the sandbox; code was
  reviewed line-by-line for type/signature consistency (fixed-type array
  conversions, struct field types, import usage, interface satisfaction)
  but must pass `go vet && go build && go test ./...` before deploy.
- **Warm-session reuse end-to-end** — logic is unit-covered where possible,
  but the live "second CONNECT adopts the first WS" path needs a real
  entry; the fallback (stale → fresh dial) is total, so worst case is no
  reuse, never a broken tunnel.
- **HTTP-chunked duplex / gRPC / HTTP/3** — remain reserved stubs by
  decision (miniflare cannot verify a duplex request-body relay; measured
  and documented in `docs/AXR-V2-ADVANCED.md` §7).
