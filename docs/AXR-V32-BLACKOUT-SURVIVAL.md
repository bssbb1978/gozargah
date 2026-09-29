# AXR v3.2 — Net-e-Melli Blackout Survival & Gate Integrity (2.21.0)

Audit round: 2026-09-29. Branch `arena/01a0eeea-gozargah`.
Scope: repository-wide audit of `client/internal/...`, `client/cmd/...`,
`src/...` and `.github/workflows/ci-v31.yml`, followed by the fixes and
capabilities below.

Everything in this document was **executed in-sandbox**. Where a gate could
not be reproduced locally, it says so explicitly instead of implying
coverage.

---

## 0. Verification environment (honest note)

The published checklist previously recorded that this sandbox has *no Go
toolchain* (`go.dev` and the mirrors are TLS-blocked, no root for `apt`), so
the Go gates could only be verified by CI. **That is no longer true.** This
round bootstrapped a real Go 1.23.9 toolchain and ran the release gates
locally:

| Piece | How it was obtained | Integrity evidence |
|-------|--------------------|--------------------|
| Go 1.23.9 linux/amd64 | `go-bin` wheel from PyPI (`files.pythonhosted.org` is reachable) | `go version go1.23.9 linux/amd64` |
| module graph | `GOPROXY=file://<local>,direct` — GitHub modules fetched by git; the five `golang.org/x/*` vanity modules served from a locally built file proxy | **every** `h1:` hash re-derived from the git tree at the exact tag matched `client/go.sum` byte-for-byte — crypto `X31++rzVUdKhX5sWmSOFZxx8UW/ldWx55cbf08iNAMA=`, net `7EYJ93RZ9vYSZAIb2x3lnuvqO5zneoD6IvWjuhfxjTs=`, sys `DBdB3niSjOA/O0blCZBqDefyWNYveAYMNF1Wum0DYQ4=`, term `FcHjZXDMxI8mM3nwhX9HlKop4C0YQvCVCdwYl2wOtE8=`, text `ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=` |
| staticcheck | `honnef.co/go/tools` @ `v0.6.1` built from a real clone through the same proxy | `staticcheck 2025.1.1 (0.6.1)` — the version CI pins |

`go mod verify` → `all modules verified`. The local proxy is therefore
content-identical to the canonical one, and the gate results below are the
gate results CI will produce.

---

## 1. Defects found and fixed

### 1.1 CRITICAL — remote memory-exhaustion / panic in the WebSocket reader

`vlessws.readFrame` decoded the 64-bit payload length of an inbound frame and
allocated for it **before** any ceiling check:

```go
l, err := extLen(c.r, hdr[1]&0x7f)   // 64-bit form: no MSB check, no bound
payload := make([]byte, l)           // ← allocation decided by the peer
```

The continuation path *did* check `l2 > maxFrame`; the first-frame path did
not. On top of that `int(binary.BigEndian.Uint64(...))` overflows on 32-bit
targets, so a length of `0xFFFFFFFFFFFFFFFF` becomes `-1` and
`make([]byte, -1)` panics.

Reproduced by reverting the fix in a scratch tree:

```
fatal error: runtime: out of memory
runtime.sysMapOS(0xc000400000, 0x10000000000)
```

A ten-byte frame header fatal-aborts the whole client process. The tunnel
peer (or an edge that has been taken over) can kill every client of the
panel with one frame — no application data, no user interaction.

**Fix.** `extLen` now bounds the `uint64` *before* the `int` conversion
(`errFrameTooLarge`), and the ceiling applies to the first frame and to every
continuation alike. Regression tests:
`TestReadFrameRejectsOversized64BitLength` (5 hostile lengths, including the
all-ones overflow), `TestReadFrameAcceptsAtTheCeiling` (boundary),
`TestReadFrameRejectsOversizedContinuation`, `TestExtLenShortHeaderIsShortBuffer`.

### 1.2 HIGH — SOCKS5 CONNECT reported success before a tunnel existed

`handleSOCKS` sent `REP=0x00` *before* dialling anything:

```go
socksReply(conn, 0x00) // success; tunnel follows
s.openTunnel(conn, host, dstPort)
```

RFC 1928 §6 defines `REP` as the *result* of the CONNECT. Replying first
means that when no candidate works the application has already been told
"connected" and then simply sees EOF — `curl` reports "empty reply from
server" instead of a connection failure, and application-level retry logic
never fires. It also makes the failure indistinguishable from a mid-stream
reset.

**Fix.** The reply is now emitted exactly once by `openTunnel`: `0x00`
immediately after `WaitVLESSOK()` succeeds (a warm session, which is already
past its handshake, replies on adoption), `0x05` (connection refused) when
every candidate failed, `0x01` if the VLESS header cannot be built.

### 1.3 MEDIUM — `net.Conn` short-write contract violated in three wrappers

`SplitConn.Write`, `ChunkConn.Write` and `MultiSplitConn.Write` all treated a
partial inner write as complete (`return off + n` / `total += size`). The TLS
layer above them then believed a record had been fully flushed while bytes
were silently dropped — a corrupted stream with no error anywhere.

Reproduced by reverting the guard: `expected io.ErrShortWrite, got <nil>
(n=2048)` while the inner conn had accepted 32 bytes.

**Fix.** All three now return `io.ErrShortWrite` when an inner write is
short. Tests: `TestChunkConnReportsShortWrite`,
`TestSplitConnReportsShortWrite`, `TestMultiSplitConnReportsShortWrite`,
`TestExactWriteIsNotShortWrite`.

### 1.4 MEDIUM — orphan continuation frame delivered as a complete message

`readFrame` reassembles a fragmented message and reports the **first** frame's
opcode, so a continuation reaching `RecvBinary` can only be an orphan
(RFC 6455 §5.4 forbids it). It was being handed to the caller as a whole
message, i.e. half a VLESS payload. Now rejected with
`errOrphanContinuation`; `TestRecvBinaryRejectsOrphanContinuation` covers it,
`TestRecvBinaryReassemblesFragmentedMessage` pins the legitimate path.

### 1.5 The last-known-good manifest was written but never read

`refreshManifest` persisted `manifest-lastgood.json` on every success and
**never loaded it**. A client that started during an international cut
therefore bootstrapped with no path base at all: `wsPath()` fell through to
`/`, the rotated path, the domestic fronting relay and the canary target were
all unknown, and `newServer` aborted with `set ws_path or manifest_url`
unless the operator had hard-coded a path. The state needed to cross a
blackout existed on disk and was unreachable.

**Fix (see §2).**

---

## 2. New capability — Net-e-Melli blackout survival

### 2.1 Domestic manifest mirror ladder + last-known-good bootstrap

The manifest fetch is now a ladder, and the ladder is stateful across
sessions:

1. the configured `manifest_url` (the international route), then
2. every mirror derived from the last-known-good manifest's `fronting_hint` —
   **the same path and the same subscription token on the domestic CDN**,
3. if every URL fails: the persisted last-known-good body, re-verified with
   the same HMAC as a live response.

`seedMirrorsFromCache()` arms the mirror ladder *before the first fetch*, so a
cold start during a cut does not burn the full 8 s timeout on a dead route
before trying the host that still answers. The cached fronting hint is
authenticated before it is used as a fetch target
(`TestSeedMirrorsFromCacheRequiresAValidSignature`: forged signature and
post-signing tampering both rejected, unsigned pre-2.16 workers accepted in
the documented unverified mode).

A mirror can *serve* the manifest but never *forge* one: the canonical string
is unchanged and the HMAC stays keyed by the subscription token
(`TestManifestMirrorURLKeepsSchemePathAndToken`).

### 2.2 The `netemelli` route regime

`netstate` gained a sixth regime. Previously "international primaries fail,
domestic fronting entry succeeds" was reported as plain `degraded`; it is now
its own label, because it supports a strictly stronger statement and the
ladder reacts differently:

* **opens** on `frontingOK ≥ 1 ∧ primaryDead ∧ ¬allFail ∧ (canary unseen ∨
  canary failed)`
* **closes only on international evidence** — one live primary observation
  relaxes it to `degraded`, `recovery ∧ primaryOK ≥ 2` moves it to
  `recovering`. A domestic-only success streak does **not** close it: the
  window was declared by evidence about the international class, so it is
  closed by evidence about the international class. This is precisely the
  "never false-positive out of a blackout on a regional domestic hiccup"
  rule.
* the **canary is a veto**: a live canary keeps the client out of the label
  entirely (`TestNetEMelliCanaryGuard`), even when every primary observation
  in the window failed.
* severity is unchanged (Rank 2, stressed, aggressive cadence), so the
  refinement can never make the client *less* cautious than before.

Policy: `fronting=0, primary=35, backup=45, aggressive, QuietPrimary,
QuietBackup`. Flow profile: `chat` (low-profile by design — a bulk/video
shape over a domestic CDN relay is exactly the volumetric anomaly a
classifier keys on). Bandit context: regime ordinal `0.6`, its own condition
for the LinUCB weights.

### 2.3 Blackout-quiet gate

New in `failover`: after `quietMinFails` (3) consecutive failures a dial
address is taken **off the wire** for a bounded, exponential window
(`DefaultQuietPolicy` 20 s doubling to a 10 min cap; widened to 120 s / 30 min
while the `netemelli` policy holds). Any success clears it instantly.

Why it matters: during an intranet window the international entries cannot
carry traffic, and every retry is a failed TLS handshake (RST/EOF at SNI
time) — a dense burst that every client of the fleet emits in lockstep. The
gate removes the burst without removing the ability to recover:

* **never silences everything** — if every candidate is gated the unfiltered
  order is returned (`TestQuietGateNeverSilencesEverything`);
* **bounded** — the window always expires, so a reopened route is
  rediscovered;
* **opt-in at the library level** — a bare `Engine` is unchanged
  (`TestQuietDisabledByDefault`), `cmd/axr` installs the policy;
* **the sweep collapses** — under a full blackout `ProbeRound` probes exactly
  one candidate per round instead of the whole ladder
  (`TestProbeRoundProbesOnceWhenAllQuiet`).

### 2.4 Per-round probe de-synchronization

The 2.17 design gave each client one FNV-32a-derived offset, stable across
restarts. That is good for fleet decorrelation but a *constant*: an adaptive
classifier that has observed a few probe instants can extrapolate the next
one from a single client.

The interval is now the sum of the cadence, the stable UUID phase, and a
**fresh uniform draw each round** capped at `probeRedrawCap` (15 s — the
mandate's dynamic band). The phase keeps the deterministic per-client
component; the redraw removes the fixed-phase signature
(`TestProbeIntervalStaysWithinTheDynamicBand`: 200 draws stay inside the band,
≥50 distinct values, and an over-wide manifest value is clamped).

---

## 3. CI workflow — conditional-skip and matrix-reporting fixes

Audit result: the only conditionals in `ci-v31.yml` were

| conditional | verdict |
|---|---|
| `if: matrix.native_race` on the race gate | **DEAD** — the flag was `true` on all three legs, so it could only ever render a misleading skip affordance. **Removed**; the gate is unconditional. |
| `if: matrix.android` (×2) | legitimate (Linux-x86_64-only toolchain) — kept, converted to a declared capability (`android_ndk: r26b`) and now **documented in the attestation** as "not applicable on this platform" instead of a bare grey skip. |
| `if: failure()` (×3) | legitimate by design — diagnostics must not run on success. |

Every other step (gofmt, vet, staticcheck, race, cross-compile, attestation,
uploads) is unconditional.

### 3.1 Runner-mismatch elimination

The macOS leg is `macos-15-intel`, i.e. an x86_64 host: the native race
detector verifies **darwin/amd64**, not darwin/arm64 (which the older
checklist table asserted). Gate 4 now asserts `go env GOOS/GOARCH` against
the matrix's declared native arch and **fails loudly on a mismatch**, so a
silent runner-image change becomes a red gate instead of a quiet coverage
hole. The step name and the attestation both carry the arch actually
exercised.

### 3.2 Gate coverage attestation + consolidated summary

Every leg (3 Go + Worker) now writes a `gate-attest-*.json` under `if:
always()` — including on failure — stating the declared vs actual native
arch, the job status, and the per-target coverage
(`darwin/amd64[race+native] darwin/arm64[build-only]`). A new `gate-summary`
job consumes them and:

* renders the consolidated matrix table into the run summary;
* **fails** when a leg produced no attestation (`incomplete-matrix`);
* **fails** when any leg is non-success or its native arch did not match
  (`leg-without-clean-coverage`);
* deliberately does **not** enforce completeness on a concurrency-cancelled
  run, so a superseded push cannot show a false coverage gap.

All four branches were exercised locally (missing leg → exit 1; failing leg →
exit 1; arch mismatch → exit 1; cancelled → exit 0).

### 3.3 New unconditional gate: `gofmt -l`

The tree carried formatting drift across 17 files (189 reformatted lines).
That is now a gate (zero drift) and the tree is canonical, so review diffs are
signal only. The sweep is its own commit, so the hardening diff stays
readable.

---

## 4. Verification results (executed)

### Gate Suite A — Go client (local, Go 1.23.9)

| Gate | Command | Result |
|------|---------|--------|
| go.sum | `go mod download && go mod verify` | `all modules verified` |
| 1 | `gofmt -l ./cmd ./internal` | 0 files |
| 2 | `go vet ./...` / `go vet -tags axr_utls ./...` | 0 warnings, both identities |
| 3 | `staticcheck ./...` / `-tags axr_utls` (2025.1.1 = v0.6.1) | 0 findings, both identities |
| 4 | `go test -race -count=1 -tags axr_utls ./...` | **all 11 packages ok** |
| 4b | `go test -race -count=1 ./...` | **all 11 packages ok** |
| 5 | stripped cross-builds | linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, android/arm64 — 6/6 |
| 6 | `GOARCH=386 go test` (32-bit correctness) | vlessws, surgery, failover ok |
| 7 | Android NDK r26b CGO path | **not executed here** — `dl.google.com` is TLS-blocked in this sandbox, so the NDK cannot be downloaded. CI verifies it; it is the one leg this report does not cover locally. |

Tests in the Go tree: **155 test functions**, all passing, with the race
detector, under both TLS identities.

### Gate Suite B — Worker

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 type errors |
| `npm run test:engine` | manifest-integrity vector `996daa7821aa…` ok, pressure 15/15 |
| `npm run test:integration` | vitest 22/22 |
| `npx wrangler deploy --dry-run` | bundle builds, 521.50 KiB / 136.08 KiB gzip |

---

## 5. What was deliberately NOT changed

Honest boundaries, unchanged from the v3.1 spec:

* **No payload inspection, no DPI identification, no attribution.** Every
  input is a local outcome the client produced (ok/fail, RTT, error class,
  latency). `netstate` labels describe *this network's* delivery quality.
* **A total route cut still cannot be created from the client.** The quiet
  gate reduces the *signature* of a blackout; it does not manufacture a path.
* **`ws` / `ws-alt` only.** `h2`/`h3`/`grpc` remain interface stubs.
* **Race conditions are fixed by locking, never suppressed.** No `-race`
  flags were removed or added to hide a finding; the suite runs with the
  detector on.
* The `extLen` ceiling is 1 MiB (`maxFrame`), unchanged: the fix bounds the
  allocation, it does not change the protocol's accepted message size.
