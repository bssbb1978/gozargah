# AXR-v3.1 Deep Evasion — Closed-Loop Fleet Pressure (2.17.0)

This document specifies the 2.17.0 increment on top of
[AXR-v3 Hyper-Resilience](AXR-V3-HYPER-RESILIENCE.md). It closes the loop
that 2.16 left open: the client already *measures* (cfscan, canary-shaped
liveness, tunnel outcomes) and the Worker already *distributes* (manifest
v3 + HMAC) — 2.17 makes the two halves **feedback each other fully
automatically**, and adds four client-side deep-evasion layers.

Nothing here is DPI detection. Every signal is bounded aggregate
statistics (ok/fail flags, latencies, freshness timestamps) with multiple
harmless explanations; every output is a *level* or a *policy*, never an
identification.

---

## 1. The closed loop

```
                 ┌──────────────────────────── Worker ────────────────────────────┐
                 │  canary reports (kind="canary") ──► D1 canary store            │
                 │  clean-IP harvests  ────────────► D1 harvest store             │
                 │  aggregate regime (regime.ts) ──────────────────────┐          │
                 │                                                     ▼          │
                 │                                    ┌── pressure.ts ──┐         │
                 │        fleet canary evidence       │  assessPressure │         │
                 │        + harvest freshness  ──────►│   0..3 level    │         │
                 │        + regime label             └───────┬──────────┘         │
                 │                                           ▼                    │
                 │   manifest v3 (HMAC-signed): probe cadence, flow-profile floor,│
                 │   entry diversity, canary target, pressure{level,reasons}      │
                 └───────────────────────────────────────────┬────────────────────┘
                                                             │ (verified by HMAC)
        ┌────────────────────────────────── Go client ───────▼───────────────────┐
        │  canary loop: plain TLS liveness probe (5 min) ──► reports ok/fail     │
        │  netstate: 12-obs hysteresis over (primary/fronting/canary) outcomes   │
        │     stable ⇄ degraded ⇄ cut ⇄ recovering                               │
        │     └─► priority inversion (fronting-first) + aggressive probe cadence  │
        │  bandit: LinUCB + Beta-TS ensemble, meta-learned arbitration           │
        │  flowprofile: local regime driver ∪ manifest floor (harsher wins)      │
        │  surgery v2: first 1–3 flight writes, SNI-region cuts, skewed gaps     │
        └────────────────────────────────────────────────────────────────────────┘
```

The loop is fully automatic and human-free: a filter change degrades the
fleet's canary success → the pressure engine raises the level → the next
manifest (HMAC-verified) carries a faster probe cadence, a harsher outflow
profile, and more entry diversity to every client → clients probe faster,
morph harder, and have more options → they report faster → the level falls
again when the canary recovers.

---

## 2. `netstate` — client route-regime hysteresis (Go)

**Problem.** During a net-e-melli window the international entries die
while the domestic-CDN fronting entry (and the clean-IP ladder) may still
carry traffic. A static priority ladder keeps trying the dead
international entries first.

**Design.** `client/internal/netstate` is a hysteresis state machine over
the client's OWN tunnel outcomes (one observation per CONNECT, tagged by
role: `primary` / `fronting` / `canary`) and the canary liveness probes.
Sliding window = last 12 observations; cut verdicts additionally require
≥ 6 filled observations from ≥ 2 distinct roles, and are **vetoed while
the newest canary observation in the window is a success** (the canary
travels the same international pipe — a total cut takes it down too).

| Transition | Rule |
| --- | --- |
| stable → degraded | ≥ 2 primary observations, ALL failed, and not all-fail (net-e-melli signature: international dead, something else live) |
| stable → cut | all-fail window AND newest canary not ok AND fronting dead |
| degraded → cut | all-fail window AND newest canary not ok |
| degraded/cut → recovering | last 4 observations all succeeded |
| recovering → stable | recovery streak AND ≥ 2 primary successes in window |
| recovering → cut | all-fail window AND newest canary not ok |

**Policy (failover priorities, lower = preferred):**

| Regime | fronting | primary | backup | probe cadence |
| --- | --- | --- | --- | --- |
| stable / unknown | 50 | 0 | 100 | normal |
| degraded / recovering | **10** | 20 | 40 | aggressive |
| cut | **0** | 30 | 40 | aggressive |

The policy is applied by the axr core on every regime change
(`applyPolicy`); the bandit remains the long-term learner — the policy is
the fast reflex, the bandit the memory. The regime label also feeds the
bandit context (f15 ordinal: degraded=0.5, cut=1.0 — unexplored
conditions deliberately widen the confidence interval) and the local flow
profile (`degraded→chat`, `cut→video`).

---

## 3. Canary + pressure — fleet liveness loop (Worker + Go)

### 3.1 Wire contract

- **Config:** operator env `AXR_CANARY_HOST` (validated bare hostname;
  same lenient parse as `FRONTING_RELAY_HOST`). When set, the manifest
  gains:
  - an entry `{host, role: "canary", status: "probe_target"}` — **inside
    the HMAC canonical** (entries field), so a tampered canary fails
    signature verification;
  - a top-level convenience pointer `canary: {host, expect: "ok",
    interval_ms}` (mirror of the signed entry).
- **Client:** every `canary.interval_ms` (default 5 min, clamped
  60 s–1 h) the core performs a plain TCP+TLS liveness check of
  `host:443` — SNI = host, real certificate verification, OS identity
  (deliberately NOT tunneled and NOT morphed: it measures the route, not
  the tunnel). The outcome (a) feeds `netstate` as `RoleCanary` and
  (b) is POSTed to the harvest endpoint:
  `POST /{panelPath}/api/network/harvest` with
  `{token, kind: "canary", canaryHost, canaryOk}` — same auth as IP
  harvests (valid subscription token or `HARVEST_TOKEN`; 401 otherwise),
  400 on malformed host.
- **Worker:** results persist newest-first, capped at 64
  (`predictive_state` kind=`harvest`, subject=`canary`).

### 3.2 Pressure engine (`src/ai/pressure.ts`)

Pure, deterministic, no model runtime. Inputs: fleet canary failure
fraction over the last 30 min (3-sample floor), canary age, harvest age
(once-fresh only — absence of evidence is NOT pressure: a fresh install
with no canary/harvest yet stays at level 0), and the aggregate regime
label.

| Level | Rule | probe cadence | probe jitter | flow profile | backup entries |
| --- | --- | --- | --- | --- | --- |
| 0 baseline | none | 90 s | 0 ms | web | 4 |
| 1 watch | regime watch OR canary configured-but-stale > 30 min | 60 s | 5 s | chat | 4 |
| 2 elevated | regime step-change OR harvest stale > 6 h | 30 s | 10 s | video | 6 |
| 3 critical | fleet canary fail-fraction ≥ 50 % (recent) | 15 s | 15 s | video | 6 |

The **probe jitter** is the width of a uniform offset each client adds to
its probe cadence, drawn deterministically from its own UUID (stable
across restarts, decorrelated across the fleet) — fleet-wide phase-locked
probing is itself a visible fingerprint, so the width grows with pressure
(at critical, a 15 s offset fully decorrelates a 15 s cadence). The width
rides in `reconnect.probe_jitter_ms`, deliberately outside the canonical
(advisory, like `backoff_ms` — tampering is harmless).

The manifest's `path_rotation_minutes` stays the **real** deterministic
window — the manifest never advertises a rotation faster than the path
actually rotates (honesty). The `pressure: {level, reasons}` field is
advisory (like `regime`) and deliberately outside the canonical.

---

## 4. Ensemble bandit (Go, `bandit`)

LinUCB is the **contextual** model (the same entry is good/bad depending
on conditions); a per-arm **Beta-Bernoulli Thompson sampler** is the pure
Bayesian bandit (robust when context is thin or misleading). Arbitration:

- After each pull, the realized reward is attributed to whichever member's
  **deterministic** ranking (LinUCB confidence-bound total; TS posterior
  mean) picked the arm that actually carried.
- `emaLin`/`emaTs` track the members' realized rewards (η=0.15);
  `metaW = 0.5 + 0.5·tanh(2·(emaLin − emaTs))`.
- `Select` uses LinUCB when `metaW ≥ 0.5`, else the Thompson draw
  (seeded per-bandit RNG; draws are consumed only by `Select`, so
  `Scores()` stays idempotent and the decision audit remains stable).
- Selection stays deterministic under a fixed seed + call sequence.

Persistence: `ts` (per-arm α/β), `meta_w`, `ema_lin`, `ema_ts` join the
snapshot; 2.16-era snapshots (no ensemble fields) restore to the neutral
ensemble (fresh (1,1) posteriors, metaW 0.5). The audit log
(`~/.axr/decision.jsonl`) gains `model: "lin"|"ts"` per decision.

---

## 5. Surgery v2 (Go, `surgery`)

- **Multi-write splitting** — `NewMultiSplitConnV2(c, cuts, writes, …)`:
  the first `writes` client-flight writes (default `frag_writes: [1,3]`)
  are each cut into `cuts+1` TCP segments at randomized SNI-region
  offsets (40–90 % window). DPI systems fingerprint the first bytes AFTER
  the handshake too (certificate / key-encipherment / CCS / finished
  records), so the fragmented shape now extends past segment one. A write
  too small to split does NOT consume budget. The v1 constructor is the
  same behaviour with `writes=1`.
- **Non-linear micro-gaps** — `SkewGap` replaces the uniform draw:
  `min + (max−min)·u²` — bounded, skewed toward the small end, matching
  the low-skew inter-packet gap statistics of real interactive traffic
  (a uniform draw is statistically distinguishable from them).
- `TCP_NODELAY` + randomized `SO_SNDBUF` (2.15) and the flowprofile
  slicer (post-handshake chunk sizes + IPD) are unchanged.

---

## 6. Flow-profile floor (Go, `flowprofile`)

`Rank`/`ProfileByRank`/`Escalate` order the morphing intensity
(web < chat < video). The client's local regime driver picks a profile;
the manifest's `flow_profile.mode` (now pressure-driven, §3.2) can only
**escalate** it — the client never morphs below what the fleet evidence
asks for.

### 6.1 WS frame-rhythm fragmentation (2.18)

Surgery v2 reshapes the traffic at the TCP layer (segment cuts + gaps),
but a passive engine that terminates/inspects WebSocket sees the *frame*
layer: stock VLESS clients (xray and friends) emit exactly **one masked
WS frame per application write** — a fixed, engine-recognizable rhythm.

`vlessws.Fragmenter` breaks that shape. Every binary message ≥ 512 B is
emitted as **2–4 masked continuation frames**:

- fragment sizes in [256 B, 16 KB], drawn per-connection from the
  per-session RNG (`Split` is deterministic for a seeded source);
- a fresh RFC 6455 masking key **per frame**;
- small **skewed** (u²) inter-frame gaps, 0–3 ms — bursts of tiny gaps
  with the occasional longer one, the shape real interactive traffic
  shows (same distribution family as the TCP-level `SkewGap`);
- first frame carries opcode 0x2 (FIN clear), continuations opcode 0x0,
  only the last frame sets FIN — RFC 6455 §5.4; control frames
  (ping/pong/close) are never fragmented (§5.5).

The Worker's WebSocket API reassembles continuation frames natively, so
the VLESS payload arrives byte-identical — **no Worker change**. Small
writes (< 512 B) and oversized writes pass through as single frames;
behaviour is gated by the existing `-surgery` flag along with the rest of
the evasion bundle.

Honest boundary: this is framing rhythm, not encryption — the fingerprint
no longer matches a single-frame-per-write VLESS client, but the stream
is still recognizably WebSocket.

---

## 7. Verification

Worker: `npm run typecheck && npm run test:engine && npm run test:integration`
(new `pressure` suite: 14 checks — engine rules, evidence reduction, canary
manifest wiring, HMAC coverage of the canary entry; integration: canary
harvest auth/shape, fleet-failure → level 3 → dynamic levers, signature
still verifies).

Go (deploy gate — the authoring sandbox has no Go toolchain; the CI
workflow below is the live gate, and the same commands run before any
distribution):

```sh
cd client
go vet ./... && go vet -tags axr_utls ./...
go build ./...
go test -race -count=1 -tags axr_utls ./...   # production uTLS identity
go test -race -count=1 ./...                  # stdlib-TLS variant
# full suite (110 test fns): bandit (20), netstate (7), surgery (14),
# flowprofile (15), cfscan (7), measure (11, incl. the concurrent
# Feed/Vector race regression), failover (14), sockopt (4), vlessws (12),
# cmd/axr (6, manifest HMAC vector)

# cross-compile matrix (full details in docs/AXR-DEPLOY.md)
GOOS=linux   GOARCH=amd64 go build -tags axr_utls -o axr-linux-amd64   ./cmd/axr
GOOS=linux   GOARCH=arm64 go build -tags axr_utls -o axr-linux-arm64   ./cmd/axr
GOOS=darwin  GOARCH=arm64 go build -tags axr_utls -o axr-darwin-arm64  ./cmd/axr
GOOS=darwin  GOARCH=amd64 go build -tags axr_utls -o axr-darwin-amd64  ./cmd/axr
GOOS=windows GOARCH=amd64 go build -tags axr_utls -o axr-windows-amd64.exe ./cmd/axr
GOOS=windows GOARCH=arm64 go build -tags axr_utls -o axr-windows-arm64.exe ./cmd/axr
```

**Automated gate (CI):** `.github/workflows/ci-v31.yml` — two job suites:
(A) Go client matrix (ubuntu → linux/amd64+arm64+android/arm64 with the
official NDK r26b toolchain path; macos → darwin/arm64+amd64; windows →
amd64) with `go mod verify`, `go vet` + `staticcheck` on BOTH TLS
identities (default stdlib / `-tags axr_utls` production uTLS),
`go test -race -count=1` on the native arch, and stripped
(`-s -w -trimpath`) cross-builds; (B) Worker (Node 20 + npm cache, tsc,
engine, integration, wrangler bundle). Full matrix, local CLI and the
self-healing race-fix protocol: `docs/CI-EXECUTION-CHECKLIST.md`.

---

## 8. Honest boundaries (2.17)

- **The canary is a liveness signal, never a DPI detector.** A canary
  failure has many explanations (incident, upstream, filter change); the
  output is a pressure level, not an attribution. A *success* is even
  weaker evidence — it only vetoes a client-side cut verdict.
- **The pressure engine never scans.** All Worker-side evidence comes
  from client reports and its own aggregate regime statistics; the
  Worker performs no active probing (unchanged boundary).
- **Ensemble ≠ oracle.** Two local estimators with learned arbitration
  beat either alone on non-stationary rewards, but both learn only from
  the client's own outcomes — no external intelligence, no guarantees.
- **Surgery v2 is still TCP-level segmentation** of TLS-produced bytes —
  not record padding, not extension rewriting (Go TLS and utls expose no
  record-padding control; honest naming retained).
- **Fronting-first under stress is a policy, not a route guarantee.** If
  no candidate is reachable, the core still reports `no healthy
  candidate` instead of pretending.
- **eBPF / UDP-noise / DoH·ICMP steganography remain out of scope**
  (roadmap, as in 2.16): root + Linux + raw-socket deployment cost; the
  socket-level effects already shipped cover the on-wire TCP surface for
  this client. 0-RTT session-ticket resumption (utls) is the next
  documented candidate (v3.2).
