# Gozargah 2.16.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository (Worker) tests, TypeScript checks, and the Wrangler dry-run
build pass on the 2.16.0 working tree. The Go client core ships as complete
source + unit tests with the pinned `go.mod`; it was **not compiled in the
authoring sandbox** (no Go toolchain reachable — go.dev and the CN mirrors
are TLS-blocked, no root for apt), so its gate remains the deploy checklist
in `docs/AXR-DEPLOY.md` (`go vet && go build && go test ./...`). The Go
delta this round was additionally subjected to a line-level static review
(see §Static review notes).

| Command | Result |
|---|---|
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run test:engine` | Pass — 36 engine checks + **11** supplemental pure-logic suites (predictive-mesh, protocol-catalog, protocol-controller, network-intelligence, shadowsocks, dns-wire, dns-resolver, vless-dns, regime, path-rotation, fp-rotation, shape, decision, decoy, **manifest-integrity** — new) |
| `npm run test:integration` | Pass — **20** Vitest + Miniflare integration tests (17 → 20; new: manifest-HMAC verify, fronting hint, harvest ingest) |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; **516.40 KiB upload, 134.58 KiB gzip** (2.15: 511.03 / 133.49) |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live
Cloudflare deployment or external-client interoperability session was
performed.

## Coverage added or extended

### Worker — manifest v3 integrity (new `src/test/manifest-integrity.ts` engine suite)
- **Pinned shared test vector** — the exact canonical string
  `gozargah-axr-manifest/v3|2.16.0|example.com|/abc123|360|ws,ws-alt|backup.example.com:backup,example.com:primary|104.16.13.37,172.67.0.1||web|90000`
  under token `0123456789abcdef0123` must HMAC-SHA256 to
  `996daa7821aa8eae4b89608bff2b61a37cbf590f29826467006d80fbb7e952ac`
  (WebCrypto path). The identical vector is asserted by the Go client
  (`client/cmd/axr/manifest_sig_test.go`) — a mismatch on either side fails
  CI on that side.
- Canonical builder: entry order independence (shuffled entries → same
  string), fronting-hint slot position, empty-manifest degradation to 11
  empty slots, `frontingHint()` validation (scheme strip, lowercase,
  must-contain-dot, no leading dash, no spaces, undefined → empty),
  `cleanIpHints()` regression (invalid octets filtered, 8-cap).
- HMAC: determinism, key-sensitivity, message-sensitivity.

### Worker — integration (miniflare + D1) new
- **Manifest HMAC end-to-end**: fetch the authenticated manifest, assert
  `schema == v3` + `manifest_sig` is 64-hex, then **recompute the canonical
  string in the test exactly as the Go client does** (same field order,
  same number formatting) and assert equality with the signature. A
  one-field tamper must break the signature.
- **Fronting hint**: `FRONTING_RELAY_HOST=relay.example-iran.net` binding →
  manifest `fronting_hint` equals the validated hostname.
- **Harvest ingest**: `POST /gozargah/api/network/harvest` —
  bad token → **401**; valid token with
  `["203.0.113.99","203.0.113.100","203.0.113.99","999.1.1.1","203.0.113.10"]`
  → `accepted == 3` (dedup + invalid filtered); the manifest then serves
  `clean_ip_hints == ["203.0.113.10","203.0.113.11","203.0.113.99","203.0.113.100"]`
  (env ∪ D1, env order first), and the **signature still verifies** after
  the union (structural fields changed coherently).
- Existing manifest test updated: `schema` assertion v1 → v3.

### Go client — pure-logic unit tests (new/extended; run at deploy gate)
- **`internal/cfscan`** (new package):
  - `SampleCandidates`: /32 → itself; /24 → `per` distinct usable hosts
    (network/broadcast skipped, incl. non-zero-based networks); priority
    CIDRs sampled first with double budget; blocked CIDRs (and bare IPs as
    /32) excluded; dedup across CIDRs; determinism for fixed rng.
  - `Median` (empty/odd/even), `TopN` ranking (OK → loss → RTT → IP;
    failed results always sink), `ReportJSON` round-trip, `ReportCSV`
    shape + newline flattening.
  - `Run` orchestration with an injected fake `Prober` (network-free):
    source label `explicit`, blocked candidates never sampled/probed,
    top-N all-OK when OK candidates exist, tie-break by IP.
  - `Run` without a relay host errors.
  - Live `DefaultProber` (SNI-anchored TLS + `cdn-cgi/trace` colo) is the
    network-gated half: interface-isolated, not exercised in CI.
- **`internal/bandit`**: `dim` 7 → 16 (features table in the package doc);
  persistence `LinState` now shape-flexible with `Snapshot.Dim` +
  `validLin` guard; new `TestRestoreDimMigration` — a forged 7-dim
  snapshot restores **stats** (pulls/reward) but rebuilds the 16×16 ridge
  prior (checked at [0][0] and [5][5]); same-dim round-trip still exact.
  `TestSuspectedChangeBoostsExploration` reworked to assert **exploration-
  term amplification** (Ucb − Mean ≥ 1.3×) plus the regime-ordinal feature
  actually moving the vector — the old fixed 1.8× gap ratio is no longer
  the right assertion once the regime ordinal legitimately widens the
  interval for a novel regime (by design).
- **`internal/flowprofile`**: `TargetBins` sums to 1 for all three
  profiles with the correct bucket count; class separation (video peak
  bucket index > chat peak); `KLDiv` basics (KL(p,p)=0, empty/mismatch → 0,
  zero target mass stays finite via epsilon floor, never negative);
  drift detection (matching histogram ≈ 0, fully shifted histogram ≥ 1).
- **`internal/surgery`**: `PlanCuts` bounds (ascending, inside the
  [40 %,90 %] SNI window, ≥8 B apart, deterministic per seed, infeasible
  for tiny records, degenerate window self-widens);
  `MultiSplitConn` — first write with 2 cuts produces exactly 3
  byte-exact segments over a net.Pipe recorder, second write passes
  through unsplit; infeasible tiny write stays whole.
- **`cmd/axr`**: manifest HMAC shared vector (Go crypto path), canonical
  builder matches the vector, `verifyManifestSig` (valid / tampered field /
  wrong key / absent → unverified / uppercase hex accepted),
  `subTokenFromURL` (5 cases), `harvestURLFromManifest`, `jsNumber`
  formatting parity with JS `String()`.

### Static review notes (Go, since the sandbox cannot compile)
The Go delta was reviewed line-by-line for: unused/missing imports,
struct-field type mismatches (two caught and fixed pre-commit: an
int→float64 assignment in `fragParams`; a `verifyColo` pointer variable
renamed mid-file), net.Pipe test semantics (per-Write read isolation),
constant-rng sampling collisions (test switched to a varying rng),
network-address leakage in /24 sampling (skip condition corrected), and
the 7→16 persistence migration path. Remaining risk is ordinary: a
`go vet && go build && go test ./...` run is still mandatory before deploy
(see `docs/AXR-DEPLOY.md`).

## What is NOT tested (honest scope)
- Live CF edge probing (`DefaultProber`) — requires real network egress to
  Cloudflare; CI exercises the identical orchestration with a fake prober.
- Cross-compile matrix and real VLESS-WS interop with the deployed Worker —
  unchanged from 2.15 (deploy-gate items).
- eBPF/UDP-noise/DoH·ICMP steganography — **not shipped** in 2.16 by design
  (root/Linux/raw-socket class); see
  `docs/AXR-V3-HYPER-RESILIENCE.md` §1/§10.
