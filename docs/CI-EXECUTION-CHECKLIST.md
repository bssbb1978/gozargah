# CI v3.1 — Execution checklist (zero-defect gate)

Workflow: `.github/workflows/ci-v31.yml` — fires on push to `main` /
`arena/*`, on PRs, and manually. Concurrency-cancelled per ref.

## Job Suite A — Go client core engine verification

| Host (runner)   | Cross-compile targets             | go vet | staticcheck | `go test -race` (native) | Stripped builds | Android NDK |
|-----------------|-----------------------------------|:------:|:-----------:|:------------------------:|:---------------:|:-----------:|
| ubuntu-latest   | linux/amd64, linux/arm64, android/arm64 | 0 warn | 0 findings | linux/amd64 (native) | all 3 targets | r26b, arm64, CGO path |
| macos-latest    | darwin/arm64, darwin/amd64        | 0 warn | 0 findings | darwin/arm64 (native)  | both targets    | — |
| windows-latest  | windows/amd64                     | 0 warn | 0 findings | windows/amd64 (native) | windows/amd64   | — |

Gates, in order (any failure fails the run; nothing is skipped):

1. `go mod download && go mod verify` — go.sum integrity (the client's
   `go.sum` was reconstructed from the public Go checksum database,
   `sum.golang.org`, module graph: utls v1.6.7 → brotli, circl →
   go-ristretto, compress, x/crypto, x/net, x/sys, x/term, x/text).
2. `go vet ./...` — zero warnings (any output = failure).
3. `go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...` — zero
   findings.
4. `go test -race -v -count=1 ./...` — **native host arch only** (the race
   detector cannot cross-compile). This is the gate for the concurrent
   goroutines: netstate sliding window, bandit ensemble (LinUCB + Beta-TS
   + meta arbitration), surgery v2 splitters, canary background prober,
   and the shared per-entry `measure.Tracker` (locked in v3.1; see
   `TestConcurrentFeedVector` — 8 feeder goroutines × 200 feeds racing a
   Vector reader).
5. Cross-compile every matrix target: `GOOS/GOARCH … go build -trimpath
   -ldflags="-s -w" -o dist/axr-<os>-<arch> ./cmd/axr` (stripped symbol
   tables). Artifacts uploaded per host.
6. Android NDK (ubuntu leg): official `android-ndk-r26b` toolchain
   (cached via `actions/cache`), `CC/CXX = aarch64-linux-android24-clang`,
   `GOOS=android GOARCH=arm64 CGO_ENABLED=1 go build …` — the CGO/JNI
   toolchain path is verified end-to-end. Honest note: the current client
   is pure Go (no cgo/JNI files), so this binary is bit-identical to the
   CGO_ENABLED=0 android build; the step exists so any future JNI/CGO
   addition is build-verified on day one.

Race-condition policy (self-healing protocol, agent side):

- A flagged data race is **fixed by explicit synchronization**
  (`sync.Mutex` / `sync.RWMutex` / `sync/atomic`) on the shared structure.
  Races are never suppressed (no `-race` flags, no `//go:noescape` hacks,
  no test skips).
- v3.1 fix applied under this policy: `measure.Tracker` (per-entry state
  vector) is shared across tunnel goroutines (`trackerFor` hands out the
  same pointer for one host while several SOCKS connections pump);
  `Feed`/`Vector` now run under an internal mutex, plus the regression
  test above.
- Verified-locked shared state (static audit, re-checked v3.1):
  - `netstate.Detector` — all reads/writes under `d.mu`
  - `bandit.Bandit` — every public method locks `b.mu` (Select/Observe/
    Scores/Prune/Restore/Snapshot/Save); Thompson draws from a seeded,
    mutex-guarded RNG
  - `failover.Engine` — all public methods lock `e.mu`
  - `server` — `s.mu` (trackers map), `policyMu` (lastRegime), `churnMu`
    (dial-address pair), `frameMu` (frame histogram), `warmMu` (warm
    session), package `rngMu` (surgery RNG); canary/manifest fields are
    written once in `newServer` **before** any goroutine starts
    (happens-before via goroutine creation)
  - pump counters (`upBytes`/`downBytes`) written by exactly one
    goroutine each and read only after `wg.Wait()`

## Job Suite B — Cloudflare Worker edge relay

| Step | Command | Gate |
|------|---------|------|
| Setup | `npm ci` (Node 20, npm cache) | clean install |
| 1 | `npx tsc --noEmit` | 0 type errors |
| 2 | `npm run test:engine` | engine suites green (incl. pressure 14, pinned HMAC vector 996daa7821aa) |
| 3 | `npm run test:integration` | vitest 22/22 (incl. fleet-pressure end-to-end) |
| 4 | `npx wrangler deploy --dry-run` | bundle builds |

## Local verification CLI (per platform)

```bash
cd client

# Linux (amd64 + arm64)
go vet ./... && go build -o /tmp/axr . && go test -race -v -count=1 ./...
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o /tmp/axr-arm64 .

# macOS (arm64 + amd64)
go vet ./... && go build -o /tmp/axr . && go test -race -v -count=1 ./...
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o /tmp/axr-amd64 .

# Windows (amd64)
go vet ./... && go build -o axr.exe . && go test -race -v -count=1 .\...

# Android (from Linux, NDK toolchain)
export ANDROID_NDK_HOME=$HOME/android-ndk-r26b
export CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang
GOOS=android GOARCH=arm64 CGO_ENABLED=1 go build -ldflags="-s -w" -o axr-android .

# Worker (any platform, Node 18+)
npx tsc --noEmit && npm run test:engine && npm run test:integration && npx wrangler deploy --dry-run
```

## Status (honest)

- **Worker suite**: fully verified in-sandbox this round (tsc 0, engine
  green incl. pressure 14/14 + pinned vector, vitest 22/22).
- **Go suite**: the sandbox has **no Go toolchain** (go.dev and mirrors
  TLS-blocked, no root for apt), so `go vet` / `go test -race` / builds
  were **not executed in-sandbox** — this CI workflow is the live gate.
  Before the first CI run the Go tree was statically audited (brace/paren
  balance, call-site consistency, locking review above, go.sum
  reconstruction). The first CI run is the authoritative verification;
  any failure is fixed under the protocol above and re-pushed.
- **Zero-defect standard**: `go vet` 0 warnings, staticcheck 0 findings,
  `go test -race` 0 races, all cross-targets build, tsc 0, all worker
  suites green. A release is tagged only when every gate is green on
  every matrix leg.
