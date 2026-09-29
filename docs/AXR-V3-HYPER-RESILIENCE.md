# AXR-v3 Hyper-Resilience (2.16)

This document is the engineering contract for the 2.16 increment on top of
the [AXR-v2 Enterprise Core](AXR-V2-ADVANCED.md) (2.15). It maps the
requested **v3 prompt** (eBPF/XDP layer, 16-dim neural bandit,
KL-divergence self-monitoring, domestic-CDN fronting, steganographic
fallbacks, HMAC manifest integrity, 0-RTT, scanner decoy) to what **actually
ships** in 2.16, what is **deliberately not shipped and why**, and the exact
wire contracts between the Cloudflare Worker and the native Go client.

Honesty rules (unchanged): every capability is labeled by what it can and
cannot do. Nothing here claims DPI detection, nothing guarantees a bypass,
and a total route cut cannot be created from the client — it is reported.

---

## 1. What ships in 2.16

| # | Capability | Where | Status |
| --- | --- | --- | --- |
| W1 | Clean-IP **harvest endpoint** `POST /{panelPath}/api/network/harvest` | Worker `src/panel/api.ts` | shipped |
| W2 | **Manifest v3** with `manifest_sig` (HMAC-SHA256), `fronting_hint`, D1-union `clean_ip_hints` | Worker `src/subscription.ts` | shipped |
| W3 | **D1 clean-IP persistence** (capped, source-tracked) | Worker `src/db/store.ts` | shipped |
| G1 | **CFScanner core** (CF API CIDRs, priority /24, blocked ranges, SNI-anchored TLS×3, median RTT/loss, `cdn-cgi/trace` colo, top-N, JSON+CSV) | `client/internal/cfscan` | shipped |
| G2 | **`axr scan`** subcommand (+`-upload` to the Worker) | `client/cmd/axr/scan.go` | shipped |
| G3 | **Multi-segment ClientHello surgery** (fragA/fragB style: randomized 1–3 cuts in the SNI region, 1–8 ms micro-gaps) | `client/internal/surgery` | shipped |
| G4 | **16-dim LinUCB context** (was 7) + measure extensions (throughput EWMA, loss velocity, TLS-error rate, RTT slope) + `flowprofile.KLDiv` self-monitoring | `client/internal/bandit`, `measure`, `flowprofile` | shipped |
| G5 | **Client-side manifest HMAC verification** + last-known-good persistence + reject-on-tamper | `client/cmd/axr/manifest_sig.go`, `main.go` | shipped |
| G6 | **Fronting entry merge** (domestic-CDN relay from `FRONTING_RELAY_HOST` → `fronting_hint` → high-priority ladder entry) | Worker env + client manifest path | shipped |
| — | Real measured **tunnel throughput** (bytes/sec EWMA) feeding reward + context | `main.go` pump accounting | shipped |
| — | **Entry-churn** feature (BGP-flap/anyshift proxy from dial-address changes) | `main.go` + bandit f10 | shipped |
| — | **Frame-size histogram → KL divergence** vs the target flow profile (self-monitoring) | `main.go` + flowprofile | shipped |

The Rust scouting scripts were **swapped, not deleted**: every CFScanner
capability (CIDR discovery, priority ranges, blocked ranges, SNI-anchored
probes, median/loss scoring, colo validation, top-N, dual-format reports)
exists in `client/internal/cfscan` with the pure logic unit-tested. The
ingest/persist/serve half now lives in the Worker (W1–W3), closing the
loop: **client probes → upload → D1 → manifest → every client's ladder**.

---

## 2. The v3 prompt, mapped honestly

| v3 prompt item | 2.16 status | Honest note |
| --- | --- | --- |
| eBPF TC/XDP socket shaping | **not shipped** | eBPF requires root + Linux and a kernel program — a deployment burden that negates the drop-in client. The same **on-wire effect** (arbitrary TCP segmentation of the ClientHello with per-segment timing) is already produced at socket level by `surgery.MultiSplitConn`: the kernel emits the segments; the receiver sees identical TCP behavior. eBPF would let *one* process shape *all* sockets — not needed for a dedicated proxy client. Roadmap: revisit if a system-wide mode is requested. |
| 16-dim neural/contextual bandit | **shipped** (§4) | 16-dim LinUCB, closed-form ridge state, zero external dependencies. "Neural" in the prompt is honored as *contextual learning*; a full NN would need a runtime dependency or a hand-rolled trainer with no accuracy win at this data scale. The composition and every data source are documented — nothing is a placeholder. |
| KL-divergence self-monitoring | **shipped** (§4.3) | The core continuously measures KL(empirical outflow frame-size histogram ‖ target flow profile) and feeds it to the bandit as f11. This is the client checking its *own* output shape — not DPI detection. |
| Domestic-CDN domain fronting | **shipped as config-level** (§6) | Deploy this same Worker script to a domestic CDN domain, set `FRONTING_RELAY_HOST` to it. The manifest carries `fronting_hint`; every client merges it as a priority-50 ladder entry. "Fronting" here = a second reachable entry domain, honest about being a *different domain*, not TLS-layer fronting against a censor. |
| UDP-noise / DoH / ICMP steganography | **not shipped** | The core is TCP-only by design (SOCKS5 TCP inbound; no UDP relay). Raw-socket UDP/ICMP noise needs root (same class of cost as eBPF) and, against a censor that can cut the route, unattributable noise from a root user's host is an *attack-surface* increase, not a resilience gain. Roadmap v3.1: opt-in, root-only, Linux-only module — deliberately not in the default path. |
| HMAC-SHA256 manifest manifest | **shipped** (§5) | Shared pinned test vector; constant-time verify; reject + last-known-good. |
| 0-RTT / 1-RTT early data | **shipped in 2.15, retained** | The VLESS header rides the WebSocket upgrade as early data (`EarlyData`); handshake is 1-RTT with 0-RTT app data. |
| Scanner decoy | **shipped in 2.15, retained** | Unknown-token AXR probes and scanner paths get the benign decoy layer. |
| "Fully automatic, no human in the loop" | **shipped** | The loop that used to be a manual Rust script run is now: `axr scan` (one command, or cron) → auto-upload → manifest union → auto-merge into every client's ladder at startup/refresh. No panel clicks, no config edits. |

---

## 3. Data flow (the fully-automatic clean-IP loop)

```
                         ┌────────────────────────────────────────────┐
                         │  Operator's Cloudflare Worker (this repo)  │
                         │                                            │
  axr.json ────────────► │  GET /sub/<token>/axr-manifest             │
    (host, uuid,         │   buildAxrManifest():                       │
     manifest_url)       │     clean_ip_hints = env ∪ D1(harvest)      │
                         │     fronting_hint  = FRONTING_RELAY_HOST    │
                         │     manifest_sig   = HMAC(token, canonical) │
  ◄──────────────────────│   (schema gozargah-axr-manifest/v3)         │
   client verifies sig   │                                            │
   (reject if mismatch)  │  POST /gozargah/api/network/harvest         │
                         │   auth: sub token OR HARVEST_TOKEN          │
                         │   validate IPv4 · dedup · cap 32 · D1       │
                         │   (predictive_state kind='harvest')         │
                         └────────────▲───────────────────────────────┘
                                       │
      axr scan [-upload] ──────────────┘
      client/internal/cfscan:
        CF API /client/v4/ips (or embedded snapshot offline)
        + priority /24s − blocked CIDRs → candidate IPs
        SNI-anchored TLS ×3 (SNI = relay host, real cert verify)
        median RTT + loss + /cdn-cgi/trace colo
        top-N → report.json / report.csv
              → ~/.axr/clean-ips.json  (merged into ladder at startup)
              → POST {token, ips, source:"client-scan"}
```

Why the split is the *correct* one (not a cop-out): a Cloudflare Worker
**cannot** disable TLS verification or do raw dials to arbitrary IPs for
probing — it can only fetch HTTPS origins with its managed cert store.
"Which edge IP can *your* network reach right now" is only measurable from
the client's network. So the Worker owns ingest/validate/persist/serve
(authority + distribution), the client owns the live measurement
(reachability). That is exactly the division the Rust scripts already
implied: scanner on the box, list shared by the operator.

---

## 4. The 16-dim LinUCB context (G4)

Per arm `a` (host × transport × fingerprint), the state is
`A_a = λI₁₆ + Σ x xᵀ`, `b_a = Σ r x`, scored as
`xᵀθ_a + α√(xᵀA_a⁻¹x)` with α boosted ×1.8 under `suspected_change`.
All inputs are the client's own measurements (`internal/measure` window of
40 outcomes + server-side accounting). No payload inspection, no DPI
claims.

| idx | feature | source | normalisation |
| --- | --- | --- | --- |
| 0 | bias | constant | 1.0 |
| 1 | RTT level | `RTTMS` (EWMA) | ÷2000 ms |
| 2 | RTT variance | `JitterMS` (EWMA \|Δrtt\|) | ÷500 ms |
| 3 | RST frequency | `RSTRate` (window fraction) | clamp |
| 4 | TLS/timeout drop | `TimeoutRate` (window fraction) | clamp |
| 5 | loss step | `StepDelta` (CUSUM) | ÷6 |
| 6 | protocol anomaly | `LastAnomaly ≠ 0` | 0/1 |
| 7 | **throughput level** | `ThroughputBPS` (EWMA of measured tunnel bytes/sec, both directions) | ÷10 MB/s |
| 8 | **loss velocity** | `LossVel` = recent-8 drop rate − window drop rate | (v+1)/2 |
| 9 | **TLS error rate** | `TLSErrRate` (window fraction failing at the handshake) | clamp |
| 10 | **entry churn** | 1 if the last two successful tunnels used different dial addresses (flap/anyshift proxy) | 0/1 |
| 11 | **flow-profile KL** | `KL(frame-size histogram ‖ target profile)` (self-monitoring, §4.3) | ÷4 nats |
| 12 | **time-of-day sin** | 24 h periodic, from wall clock | (sin+1)/2 |
| 13 | **time-of-day cos** | same | (cos+1)/2 |
| 14 | **session longevity** | core uptime | ÷24 h |
| 15 | **regime ordinal** | stable 0 / watch·recovering 0.35 / suspected_change 0.7 | — |

### 4.1 Throughput is now *measured*, not assumed

2.15 recorded throughput as a v2 TODO. The pump now counts bytes in both
directions and reports `bytes/elapsed` per stream; the tracker EWMA-izes
OK-sample throughput into `Vector.ThroughputBPS`, which feeds both the
reward (success bonus) and feature f7.

### 4.2 Regime ordinal is a feature on purpose

A regime the core has never observed under an arm has full ridge prior
width in that feature dimension — the confidence interval widens exactly
where it should (novel conditions ⇒ explore). This makes the ×1.8
exploration multiplier redundant in the long run; both are kept because the
multiplier acts immediately (first observation) while the feature acts as
evidence accumulates.

### 4.3 KL-divergence self-monitoring (flowprofile)

`flowprofile.FrameBucketEdges` (12 buckets, 128 B → 32 KiB) is shared by:
- the empirical outflow histogram (every WS frame the pump sends is
  bucketed live), and
- `TargetBins(profile)` — the profile's length histogram projected onto the
  same edges (byte-overlap proportional).

`KLDiv(p, q)` normalizes both, epsilon-floors q, and returns nats. Before
64 outflow frames the feature is 0 (honest: no distribution to compare).
A drifting morph (the app is really sending video-sized frames while the
profile says "web") shows up as growing f11 and the bandit can condition on
it — the core *knows* when it is not matching its target.

### 4.4 Persistence migration (2.15 → 2.16)

`Snapshot` now carries `Dim`. A 7-dim (2.15) snapshot restores **stats**
(pulls, rewards, quarantine) but rebuilds the ridge prior for the Lin state
(the matrices are the wrong shape). A same-dim snapshot restores Lin state
exactly. Both paths are unit-tested (`TestRestoreDimMigration`).

---

## 5. Manifest v3 integrity (W2 + G5)

### 5.1 Canonical string

`manifestCanonical()` (Worker, `src/subscription.ts`) and
`canonicalFromManifest()` (Go, `cmd/axr/manifest_sig.go`) build the **same
byte string** — 11 fields, fixed order, `|`-joined:

```
schema | version | host | ws_path_base | path_rotation_minutes |
transports(csv) | entries(host:role, sorted, csv) | clean_ip_hints(csv) |
fronting_hint | flow_profile.mode | reconnect.probe_interval_ms
```

Deliberately **not** signed: `generated_at` (time-dependent),
`honest_limit` (display text), `regime`/`network_state` (server
intelligence the client only observes). The signed fields are exactly the
ones the client *acts on* (routing, paths, hints).

`manifest_sig = HMAC-SHA256(key = subscription token, msg = canonical)`,
lowercase hex. The token is already the per-user secret on the URL path, so
an attacker who can rewrite the manifest can't forge the signature without
the user's token — and one with the token could just read the feed
directly, so the signature protects the *transport* (MITM/malicious CDN/misbehaving mirror), not the token holder.

### 5.2 Pinned shared test vector

Identical in `src/test/manifest-integrity.ts`,
`client/cmd/axr/manifest_sig_test.go`, and here:

```
token      = 0123456789abcdef0123
canonical  = gozargah-axr-manifest/v3|2.16.0|example.com|/abc123|360|ws,ws-alt|backup.example.com:backup,example.com:primary|104.16.13.37,172.67.0.1||web|90000
signature  = 996daa7821aa8eae4b89608bff2b61a37cbf590f29826467006d80fbb7e952ac
```

### 5.3 Client behavior

- valid signature → apply manifest, persist raw JSON to
  `~/.axr/manifest-lastgood.json` (audit), continue.
- signature present but mismatched → **reject everything**, log
  `manifest REJECTED: manifest_sig mismatch`, keep last-known-good state.
- signature absent (pre-2.16 worker) → unverified mode, one-time log note
  (backward compatibility).
- verify is constant-time (`hmac.Equal`); hex case-insensitive.

---

## 6. Domestic-CDN fronting (W3 + G6)

The Worker is domain-agnostic: the same script deploys to any host. The
operator deploys it to a domestic CDN domain that the censor has not (yet)
cut and sets:

```
FRONTING_RELAY_HOST = cdn-relay.example-domain.tld
```

Validation (`frontingHint()`): lowercase, scheme/path stripped, hostname
regex, must contain a dot. It appears in the manifest as `fronting_hint`
and joins the signed canonical string (tamper-visible). Every client merges
it at manifest time as a priority-50 endpoint (ws + ws-alt arms, same
credentials — it is the *same* Worker behind another domain), ranked above
ordinary backups (100) and below the operator's primary config entries.

Honest boundary: this is a **second reachable entry domain**, not
TLS-layer domain fronting. It helps exactly when the primary domain is
blocked but the relay domain is not — and it is only as strong as the
relay domain's own reachability, which the ladder's per-IP health ranks
continuously.

---

## 7. Multi-segment ClientHello surgery (G3)

The reference sing-box `Serverless-v51-fragA/B` configs split the
ClientHello at specific `finalmask` offset profiles (e.g. `[6,98,1]`,
`[0,104,1]`). AXR generalizes that into **randomized multi-segment
surgery**:

- `surgery.PlanCuts(n, cuts, lo, hi, rng)`: `cuts` split points (default
  range **2–3**, i.e. 3–4 TCP segments for one ClientHello), each inside
  the **SNI region** of the record (default window 40–90 % of the bytes —
  where the SNI extension lives in a typical 1.5–2.5 KB ClientHello),
  ≥8 bytes apart, infeasible requests degrade to passthrough.
- `surgery.MultiSplitConn`: only the **first** write is cut; inter-segment
  gaps are randomized **1–8 ms** micro-gaps (configurable); all later
  writes pass through (post-handshake morphing is `ChunkConn` +
  flowprofile, unchanged).
- Deterministic per seeded rng (testable); per-connection randomization in
  production via the crypto-seeded shared source.

Honest boundary (unchanged from 2.15): this is **TCP-level segmentation of
bytes the TLS stack already produced** — the kernel emits ≥3 segments for
one logical ClientHello with per-connection offset/timing jitter. No TLS
record padding, no extension rewriting. Against a passive "single clean
segment carrying SNI" filter this removes the match; against a stateful
reassembly-based DPI it does not.

Config (`axr.json`):

```json
{
  "frag_cuts": [2, 3],
  "frag_window": [40, 90],
  "frag_micro_gap_ms": [1, 8]
}
```

`frag_cuts: [0, 0]` (absent) keeps the legacy single cut with `split_gap_ms`.

---

## 8. `axr scan` (G2)

```
axr scan -config axr.json [-top 8] [-attempts 3] [-timeout 3s]
        [-cidrs a.b.c.0/24,...] [-priority /24-list] [-blocked list]
        [-no-api] [-relay host] [-concurrency 4] [-verify-colo]
        [-out DIR] [-upload] [-keep 20m]
```

- Candidate set: explicit `-cidrs` → CF API live list → embedded 2025
  snapshot (offline); operator `-priority` CIDRs sampled first (double
  budget); `-blocked` excluded (bare IPs accepted as /32).
- Probe: SNI-anchored TLS handshake to `ip:443` with `SNI = relay host`
  (default: first config entry), **real certificate verification** (no
  skip-verify — the address must present the relay's genuine edge cert),
  N attempts, median RTT + loss ratio.
- Colo validation: `GET https://ip/cdn-cgi/trace` (Host: relay, same SNI
  anchoring), `colo=` parsed — confirms the address is a real CF edge POP
  serving the relay (informational; a trace failure never fails the probe).
- Output: JSON report on stdout; `-out DIR` writes `report.json` +
  `report.csv`; `~/.axr/clean-ips.json` is **always** refreshed (the server
  merges it into the ladder at startup, 30-day freshness guard).
- `-upload`: POST `{token, ips, source:"client-scan"}` to the Worker
  harvest endpoint. Token: `harvest_token` config → manifest URL token.
  URL: `harvest_url` config → derived
  `https://<manifest-host>/gozargah/api/network/harvest`.

Suggested automation (fully automatic, no human in the loop):

```
# cron: refresh the clean-IP pool and publish it, a few times a day
0 6,18 * * *  axr scan -config /etc/axr/axr.json -top 16 -upload
```

---

## 9. Worker changes (reference)

- `src/config.ts`: `VERSION 2.16.0`, `SCHEMA_VERSION 16`, new env
  `FRONTING_RELAY_HOST`, `HARVEST_TOKEN`.
- `src/db/store.ts`: `loadCleanIPHarvest` / `saveCleanIPHarvest` over the
  existing `predictive_state` table (`kind='harvest'`, `subject_id=
  'clean_ips'`), capped at 32, source counts tracked.
- `src/panel/api.ts`: `network/harvest` (public route, token-gated):
  valid user subscription token **or** `HARVEST_TOKEN`; IPv4 validation,
  dedup, 32-cap, D1 union-persist, event log.
- `src/subscription.ts`: `buildAxrManifest(..., token)` → schema v3,
  `clean_ip_hints = env ∪ D1` (≤16), `fronting_hint`, `manifest_sig`.
- `src/index.ts`: passes the token to the manifest builder.

### 9.1 Decoy note (W4)

The v3 prompt's "diverse decoy status codes" item is **not** shipped: the
decoy layer's value is *uniform benign responses* (200 + plausible content)
so a scanner cannot distinguish probe targets from normal traffic. Random
status codes would *increase* distinguishability. The 2.15 decoy behavior
is retained unchanged.

---

## 10. Not shipped — roadmap v3.1 (explicit)

| Item | Why not now | Gate to ship |
| --- | --- | --- |
| eBPF TC/XDP socket shaping | root + Linux + kernel-prog deployment cost; socket-level segmentation already yields the same on-wire TCP effect for this client | request for system-wide mode; Linux-only packaging |
| UDP-noise relay | no UDP relay by design (TCP SOCKS5 core); raw UDP sockets need root; unattributable noise from a root host is an attack-surface increase | root-only opt-in module; threat-model review |
| DoH/ICMP steganography | same root/raw-socket class; also adds a parallel channel a censor can fingerprint noisily | v3.1 research; only if a concrete route-cut scenario demands it |
| Neural (NN) bandit | LinUCB's closed-form ridge state is exact at this data scale and auditable; an NN adds a runtime dependency or a hand-rolled trainer with no measured win | if arm count / feature interactions outgrow the linear model |
