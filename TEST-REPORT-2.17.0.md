# Gozargah 2.17.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository (Worker) tests, TypeScript checks, and the Wrangler dry-run
build pass on the 2.17.0 working tree. The Go client core ships as complete
source + unit tests with the pinned `go.mod`; it was **not compiled in the
authoring sandbox** (no Go toolchain reachable — go.dev and the CN mirrors
are TLS-blocked, no root for apt), so its gate remains the deploy checklist
in `docs/AXR-DEPLOY.md` (`go vet && go build && go test -race ./...`). The
Go delta this round was additionally subjected to a line-level static
review (see §Static review notes).

| Command | Result |
|---|---|
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run test:engine` | Pass — 36 engine checks + **12** supplemental pure-logic suites (predictive-mesh, protocol-catalog, protocol-controller, network-intelligence, shadowsocks, dns-wire, dns-resolver, vless-dns, regime, path-rotation, fp-rotation, shape, decision, decoy, manifest-integrity, **pressure** — new) |
| `npm run test:integration` | Pass — **22** Vitest + Miniflare integration tests (20 → 22; new: canary harvest auth/shape, fleet-failure → pressure level 3 → dynamic manifest levers) |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; **521.09 KiB upload, 135.92 KiB gzip** (2.16: 516.40 / 134.58) |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live
Cloudflare deployment or external-client interoperability session was
performed.

## Coverage added or extended

### Worker — pressure engine (new `src/test/pressure.ts` engine suite, 14 checks)
- **`assessPressure` rule table** — baseline (no evidence → level 0, 360
  min, 90 s, web); **absence of evidence is not pressure** (canary
  configured-but-never-probed and never-harvested contribute no reasons);
  fleet canary failures ≥ 50 % recent → level 3 (45 min, 15 s, video);
  regime step-change → level 2 (90 min, 30 s, video); stale-but-once-fresh
  harvest > 6 h → level 2; watch regime + stale canary → level 1 (60 s,
  chat); level = MAX of independent signals, not a sum.
- **`canaryEvidence` reduction** — < 3 recent samples → null failFrac;
  age from the newest result; > 30 min results excluded from the window;
  empty list → (null, null).
- **Canary manifest wiring (no D1, env path)** — `AXR_CANARY_HOST` →
  entry `role: "canary"` **inside the HMAC canonical** (`...|host:canary|`
  present in the canonical string) + top-level `canary` pointer; signature
  verifies with the canary inside; no canary configured → no entry/field;
  unvalidated hosts dropped (junk chars, no dot, empty — a pasted
  `https://host/x` is intentionally normalized to `host`, same lenient
  parse as `FRONTING_RELAY_HOST`); baseline dynamics without D1 (90 s, web).

### Worker — D1 + API
- `src/db/store.ts`: `loadCanaryState` / `appendCanaryResult` — one
  predictive_state row (kind=`harvest`, subject=`canary`), newest-first,
  capped 64, host length + type validation on read and write.
- `src/panel/api.ts`: harvest endpoint accepts `kind: "canary"` with
  `{canaryHost, canaryOk}` — 401 unauthenticated (same gate as IP
  harvests), 400 malformed host, `stored` count in the response; the
  existing `kind`-less IP path is unchanged (default).
- `src/subscription.ts`: `buildAxrManifest` loads the canary state,
  computes `assessPressure`, and sets the dynamic levers —
  `reconnect.probe_interval_ms`, `flow_profile.mode`, `pressure:
  {level, reasons}`, backup-entry diversity (4 → 6 at level ≥ 2); the
  network-state machine still overrides cadence/profile on directly
  measured dead/recovering routes; `path_rotation_minutes` stays the real
  deterministic window (honesty: never advertised faster than it
  rotates). Canary entry + pointer are added outside the D1 block (env
  config works without a database).

### Worker — integration (miniflare + D1) new
- **Canary harvest** — bad host → **400**; valid report → 200 with
  `kind: "canary"` and `stored == 1`, second report → `stored == 2`
  (newest-first accumulation); anonymous report → **401** (same
  authorization as IP harvests).
- **Fleet pressure end-to-end** — three recent canary results with 2/3
  failing (≥ 0.5 floor, 3-sample floor met) → the authenticated manifest
  carries `pressure.level == 3` with reason `canary_fleet_failures`,
  `reconnect.probe_interval_ms == 15000`, `flow_profile.mode == "video"`,
  and the **HMAC signature still verifies** over the changed dynamics
  (recomputed in the test with the same 11-field canonical the Go client
  builds). The canary host is absent from `entries` when the env is not
  configured (no false entry).

### Go client — new/extended unit tests (static review; run by the deploy gate)
- **`internal/netstate` (new package, 7 tests)** — stable stays stable;
  net-e-melli signature (2 primary failures + live fronting → degraded,
  fronting-first policy, aggressive cadence); degraded → cut when the
  domestic route dies (all-fail 12-window, canary-veto free); **canary
  veto** (freshest canary success blocks cut; once the canary also fails,
  the cut lands); full recovery cycle cut → recovering (4-success streak)
  → stable (fresh primary successes) and relapse recovering → cut (12
  failures flush the recovery streak out of the window); policy table per
  regime; 8-goroutine concurrency hammer (for `-race`).
- **`internal/bandit` (14 → 20 tests)** — Beta sampler moments (Beta(2,1)
  mean ≈ 2/3 and variance ≈ 1/36; Beta(5,5) symmetric — 20 k draws,
  seeded); ensemble convergence to the persistently good arm (posterior
  separation + ≥ 36/40 picks); **arbitration** (metaW = 0.9 → LinUCB
  argmax carries 20/20 despite a proven TS favorite — the untried-boost
  tops the converged score; metaW = 0.2 → Thompson argmax carries ≥ 18/20;
  `model` stamped on the chosen score); meta-weight formula (tanh of the
  EMA gap, white-box); persistence round-trip (Ts/MetaW/EMAs exact) +
  **2.16-era snapshot compat** (no ensemble fields → fresh (1,1)
  posteriors, neutral metaW 0.5); determinism (same seed + call sequence →
  identical selections, draws included).
- **`internal/surgery` (9 → 14 tests)** — `SkewGap` bounds [min,max] +
  quadratic skew (mean fraction ≈ 1/3 ± 0.05 over 20 k draws) + degenerate
  bounds/nil-rng; V2 splits the first `writes` writes (2 cuts → ≥ 3
  segments each, byte integrity of the unsplit third write, budget
  respected); small write (< 96 B) keeps the split budget for the next
  eligible write; v1 constructor backward-compat (first write only);
  writes clamp [1,5].
- **`internal/flowprofile` (13 → 15 tests)** — rank ladder
  (`Rank` web < chat < video, unknown → 0; `ProfileByRank` incl. out-of-
  range ranks → web); floor semantics (`Escalate` never goes down:
  (video,web)→video, (web,chat)→chat, equal→same); the new `ForRegime`
  netstate labels (degraded → chat, cut → video; pre-2.17 labels
  unchanged, empty → web).
- **`cmd/axr`** — manifest v3 struct gains the `canary` field (absent →
  zero value; the pinned HMAC vector is unaffected: 11-field canonical
  unchanged).

## Static review notes (Go delta, line-level)
- `bandit.go` — no import cycle (`math/rand` added); seed mixing uses a
  constant that fits `int64` (0x5851F42D4C957F2D) — the initially drafted
  0x9E… constant overflows `int64` and was caught in review; `gammaSample`
  guards non-positive/NaN/Inf shapes and the shape<1 boost (log-0 guard);
  `pickLocked` never selects a pruned arm, falls back to quarantined only
  when nothing is live (unchanged contract); `Scores()` is draw-free
  (idempotent); TS credit uses deterministic rankings (posterior means),
  never the sampled draw.
- `netstate.go` — canary freshness uses the NEWEST canary observation
  (ascending scan, last wins); cut verdicts are vetoed by a fresh canary
  success but never *triggered* by canary silence; hysteresis requires ≥ 6
  filled observations from ≥ 2 distinct roles for cut.
- `main.go` — `policyMu` guards `lastRegime` (tunnel goroutines + canary
  goroutine); canary host/interval are written only during manifest
  bootstrap (before goroutine start — happens-before); `mergedRegime`
  ranks all labels (measure ∪ netstate); `roleOf`/`applyPolicy` use
  failover's copy-on-return `Entries()` and row-replacing `AddEntry` (IP
  sets preserved); flow floor is escalation-only (`Escalate`).
- `surgery.go` — split budget consumed only by a write that actually
  split; `SkewGap` bounded by construction (u² ∈ [0,1]); v1 constructor
  delegates to V2 with budget 1 (behavior preserved).
- `scan.go` — `postCanary` reuses the exact token/URL resolution of
  `uploadHarvest` (harvest_token → manifest URL token; harvest_url →
  derived).

## Not tested (honest scope)
- **No Go compilation, `go vet`, or `go test -race` execution** in the
  authoring sandbox (no toolchain). The Go core is a **deliverable, not a
  verified build** — the deploy gate is mandatory before distribution.
- **No live Cloudflare deployment** and no real net-e-melli window
  exercised; the canary/pressure loop is verified end-to-end against
  Miniflare D1 with synthetic reports, and the netstate/ensemble behavior
  against unit-level scripted observation streams.
- **No real canary host was probed** (the sandbox has no outbound 443 to
  a canary; `canaryProbe` is plain `crypto/tls` with real certificate
  verification — the same stdlib path the scan runner already uses).
- The **eBPF / UDP-noise / DoH·ICMP steganography** layers remain
  out-of-scope (roadmap, unchanged from 2.16).
