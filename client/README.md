# AXR client core (Go)

Native client half of the gozargah **AXR Protocol Framework** (v2.17,
AXR-v3.1 Deep Evasion).
A SOCKS5 TCP inbound that tunnels every stream over an **ensemble-AI
selected VLESS-over-WebSocket** path (16-dim LinUCB + Beta-Bernoulli
Thompson ensemble with meta-learned arbitration, standard + `ws-alt` shape
arms), with client-side TLS-identity selection, **multi-segment flight
surgery** (fragA/fragB style: the first 1–3 client-flight writes cut at
randomized 2–3 SNI-region cuts with 1–8 ms *skewed* micro-gaps), **app-class
flow morphing** (length histogram + lognormal IPD) with **KL-divergence
self-monitoring** and a **fleet-pressure profile floor** from the manifest,
**TCP socket surgery** (Nagle off + randomized `SO_SNDBUF`), a persistent
routing cache with **clean-IP harvesting** (A-records + local `axr scan`
pool + manifest hints), a **route-regime hysteresis machine**
(`netstate`: stable/degraded/cut/recovering → automatic fronting-first
priority inversion under net-e-melli), a **canary liveness loop** (plain TLS
probe of the manifest's canary host → fleet pressure engine), **HMAC
manifest verification** (reject tampered feeds, keep last-known-good),
**fronting-entry merge** from the manifest, **measured throughput**
accounting, **session reuse** (warm WS ≤ 30 s, same destination), a
**decision audit log** (`~/.axr/decision.jsonl`, incl. which ensemble member
chose), and a normal/aggressive probe state machine.

TLS terminates at the Cloudflare edge — therefore **all** fingerprint
morphing, ClientHello surgery, and path/IP selection happens **here, locally**,
before the bytes leave the host. The Worker never sees plaintext and performs
no deep inspection.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/axr` | The binary: SOCKS5 → 16-dim LinUCB-selected VLESS-WS tunnel (ws + ws-alt arms), HMAC manifest verification, fronting merge, session reuse, decision.jsonl audit — **plus the `axr scan` subcommand** (clean-IP scanner, §Scan) |
| `internal/cfscan` | **2.16** — CFScanner core: CF API CIDRs (offline snapshot fallback), priority /24s, blocked ranges, deterministic sampling, SNI-anchored TLS×3 (real cert verify), median RTT/loss, `cdn-cgi/trace` colo, top-N, JSON+CSV reports; live probing behind an injectable `Prober` |
| `internal/bandit` | **Ensemble** (2.17): **LinUCB** contextual bandit + per-arm **Beta-Bernoulli Thompson sampler** with meta-learned arbitration (realized-reward EMAs, tanh weight; seeded draws, deterministic; `model: lin|ts` stamped on the decision). LinUCB: **16-dim context** (2.16: +throughput, loss velocity, TLS error rate, entry churn, flow KL, time-of-day, session age, regime ordinal — 2.17: +netstate `degraded`/`cut` labels), 16×16 ridge A/b per arm, pure-Go Gauss-Jordan; quarantine, prune, JSON persistence (2.15's 7-dim and 2.16's ensemble-less snapshots restore with neutral priors) |
| `internal/netstate` | **2.17** — route-regime hysteresis (net-e-melli reflex): 12-obs sliding window over (primary/fronting/canary) tunnel outcomes → stable/degraded/cut/recovering with a canary-freshness veto on cut; emits the fronting-first priority policy + aggressive cadence |
| `internal/measure` | Client state vector: RTT/jitter EWMA, RST & timeout rates, CUSUM step-change, anomaly code → regime label; **2.16: +throughput EWMA, signed RTT slope, loss velocity, TLS error rate** (feeds the 16-dim context) |
| `internal/flowprofile` | App-class flow morphing: length histograms + lognormal IPD for `web`/`video`/`chat`; regime-driven; implements `surgery.Slicer`; **2.16: +`KLDiv` / `TargetBins` / shared frame buckets (self-monitoring)**; **2.17: +`Rank`/`ProfileByRank`/`Escalate` (manifest fleet-pressure profile floor) + netstate labels in `ForRegime`** |
| `internal/surgery` | **`MultiSplitConn` v2 (2.17: first 1–3 client-flight writes → 2–4 TCP segments each, at randomized SNI-region cuts with 1–8 ms SKEWED micro-gaps via `SkewGap`, u² low-skew distribution)**, `SplitConn` (legacy 2-segment) and `ChunkConn` (post-handshake chunks; uniform 512–1400 B legacy, or a `Slicer`-driven app-class distribution) |
| `internal/sockopt` | TCP socket surgery: `TCP_NODELAY` (Nagle off) + randomized `SO_SNDBUF` (64–512 KB); linux/darwin/windows, no-op elsewhere |
| `internal/failover` | Endpoint matrix (host × clean-IP × transport × fp), live IP health cache (atomic JSON), normal/aggressive probe state machine, **clean-IP harvesting** (A-records + local scan pool + manifest hints, dedup/capped) |
| `internal/vlessws` | VLESS v1 header (byte-compatible with the Worker parser), 0-RTT early data via `Sec-WebSocket-Protocol`, minimal RFC 6455 client codec |

## Build

```sh
cd client
go mod tidy          # fetches the single pinned dep (refraction-networking/utls v1.6.7)
go build -o axr ./cmd/axr
# uTLS identity rotation (recommended):
go build -tags axr_utls -o axr ./cmd/axr
# cross-compile (full matrix in docs/AXR-DEPLOY.md):
GOOS=linux GOARCH=arm64 go build -tags axr_utls -o axr-linux-arm64 ./cmd/axr
```

Without the `axr_utls` tag the handshake uses the OS-native Go TLS identity
(the `fp` field is ignored); with it, `fp` selects `HelloChrome_Auto`,
`HelloFirefox_Auto`, `HelloSafari_Auto`, or `HelloRandomized`.

> Verification status: this tree was **not compiled in the authoring
> sandbox** (no Go toolchain available there). `go vet ./... && go test ./...`
> is part of the deploy checklist in `docs/AXR-DEPLOY.md`.

## Config (`axr.json`)

```json
{
  "uuid": "6b7c6e12-5038-4b4c-a11b-714c9e089d6e",
  "manifest_url": "https://entry.example.com/sub/<token>/axr-manifest",
  "entries": [
    { "host": "entry.example.com", "priority": 0 },
    { "host": "backup.example.com", "ips": ["104.16.0.1"], "fp": "firefox", "priority": 1 }
  ],
  "surgery": true,
  "split_gap_ms": [20, 120],
  "frag_cuts": [2, 3],
  "frag_writes": [1, 3],
  "frag_window": [40, 90],
  "frag_micro_gap_ms": [1, 8],
  "probes": { "normal_ms": 90000, "aggressive_ms": 30000 },
  "canary_interval_ms": 300000,
  "harvest_url": "https://entry.example.com/gozargah/api/network/harvest",
  "harvest_token": "…optional; defaults to the manifest URL token…",
  "cache_dir": "~/.axr"
}
```

`manifest_url` (preferred) bootstraps the rotated WS path, the current
neutral fingerprint, worker-measured backup entries, **clean-IP hints**
(env ∪ D1 harvest), and the **fronting hint** (merged as a priority-50
entry). The manifest v3 **`manifest_sig` is verified** (HMAC-SHA256 keyed by
the token): a tampered feed is rejected and the last-known-good state is
kept (`~/.axr/manifest-lastgood.json` persists the last verified raw JSON).
`ws_path` (`"/sub/<token>/<pathbase>?ed=2048"`) is the explicit alternative.

```sh
./axr -config axr.json -socks 127.0.0.1:1080 -v
```

Point any SOCKS5 client (browser, Hiddify, sing-box, v2rayN) at the listen
address. UDP ASSOCIATE is rejected (the Worker has no UDP relay — by design).

`frag_cuts` `[min,max]` is the per-connection cut count (2.16 default 2–3 →
3–4 TCP segments per write, the fragA/fragB shape); absent or `[0,0]` keeps
the legacy single cut with `split_gap_ms`. `frag_writes` `[min,max]` (2.17,
default `[1,3]` when `frag_cuts` is active) is how many of the FIRST
client-flight writes get the multi-segment treatment — the ClientHello
plus the next one or two flight writes; a write too small to split does not
consume the budget. `frag_window` [40,90] is the cut window as
percent-of-record (the SNI extension region). `frag_micro_gap_ms` [1,8]
bounds the inter-segment micro-gap, drawn from a skewed (u²) distribution
— heavy toward the small end, like real interactive traffic.

## Canary & fleet-pressure loop (2.17)

When the manifest carries a `canary` (operator env `AXR_CANARY_HOST` on the
Worker), the core probes it every `canary_interval_ms` (manifest
`canary.interval_ms` overrides when sane, clamped 60 s–1 h) as a **plain
TCP+TLS liveness check** of `host:443` — SNI = host, real certificate
verification, OS identity. It is deliberately NOT tunneled and NOT morphed:
it measures the route, not the tunnel. Each outcome (a) feeds the
`netstate` hysteresis (a fresh canary success vetoes any "cut" verdict —
the canary travels the same international pipe), and (b) is reported to the
Worker harvest endpoint (`kind: "canary"`, same token as `axr scan
-upload`), where the fleet pressure engine turns the aggregate into the
dynamic manifest levers (faster probe cadence, harsher outflow-profile
floor, more entry diversity). The manifest's probe cadence and
flow-profile fields are honored as an **escalation floor**: the client
never probes slower or morphs softer than the fleet evidence asks for.
`netstate` stress (degraded/cut) also forces the aggressive probe cadence
and inverts the ladder — the fronting entry jumps ahead of the
international entries (priority 50 → 10, and to 0 under a full cut) — so
during a net-e-melli window the core spends its budget on the domestic
route instead of the dead international one, automatically.

**Probe de-synchronization (2.17):** fleet-wide phase-locked probing is
itself a fingerprint, so the pressure engine also emits a jitter WIDTH
(`reconnect.probe_jitter_ms`: 0/5/10/15 s at levels 0–3, advisory —
outside the HMAC canonical like `backoff_ms`). The core draws its OWN
offset once, deterministically from its UUID (FNV-32a → uniform in
`[0, width]`, stable across restarts, decorrelated across the fleet) and
adds it to every probe cadence (normal and aggressive).

## Scan subcommand (2.16)

`axr scan` is the client-side clean-Cloudflare-edge scanner (the Rust
CFScanner capability set, ported with nothing dropped):

```sh
# probe from this network, print the JSON report, refresh ~/.axr/clean-ips.json
axr scan -config axr.json

# full control + publish to the Worker (every client then benefits)
axr scan -config axr.json -top 16 -attempts 3 -timeout 3s \
    -priority 104.16.13.0/24,172.67.42.0/24 -blocked 198.51.100.0/24 \
    -out /var/log/axr-scan -upload

# offline: skip the CF API, probe an explicit range
axr scan -relay entry.example.com -no-api -cidrs 104.16.0.0/13
```

Behavior: candidate set = `-cidrs` → CF API live list → embedded 2025
snapshot; `-priority` CIDRs sampled first (double budget); `-blocked`
excluded (bare IPs = /32). Each candidate gets SNI-anchored TLS handshakes
(`SNI` = relay host, **real certificate verification**, 3 attempts) →
median RTT + loss; `-verify-colo` (default on) confirms the address via
`GET /cdn-cgi/trace` (`colo=` field). Top-N ranked by OK → loss → median
RTT → IP. `~/.axr/clean-ips.json` is always refreshed (merged into the
ladder at the next `axr` startup; 30-day freshness guard). `-upload` POSTs
the survivors to the Worker harvest endpoint (token: `harvest_token` →
manifest URL token; URL: `harvest_url` → derived from the manifest host).

## Honest boundaries

- **No payload inspection, no DPI "detection".** The client only knows its
  own outcomes (ok / rtt / error class); the regime label describes delivery
  quality, not middlebox behavior.
- **Scan results are reachability, not safety.** A scan success means "this
  edge IP answered the relay's TLS handshake from *your* network now" — the
  ladder still ranks them by live local health before trusting them.
- **Manifest signature protects the transport, not the token.** The HMAC key
  is the user's own subscription token: it stops a MITM/malicious mirror
  from rewriting the feed; a holder of the token can already read the feed
  directly. Absent signature (pre-2.16 worker) = documented unverified mode.
- **Fronting hint = a second entry domain, not TLS fronting.** It is only as
  strong as that domain's reachability, which the ladder measures
  continuously.
- **The canary is a liveness signal, never a DPI detector.** Its ok/fail
  only shapes pressure levels and the client's cut verdicts; a failure has
  many explanations (incident, upstream, filter change) and a success only
  vetoes a cut. The netstate regime labels describe delivery quality as
  seen from this network, not middlebox behavior.
- **Ensemble = two local estimators, not external intelligence.** LinUCB +
  Thompson sampling both learn only from the client's own outcomes; the
  meta-arbitration hedges between them. Stronger adaptation, no oracle, no
  guarantee.
- **The pressure floor is advisory fleet statistics.** The manifest's
  probe cadence / flow-profile mode come from aggregate worker-side
  statistics (canary evidence, harvest freshness, regime) — bounded,
  time-stamped, multi-explanation signals, never packet-level evidence.
- **eBPF / UDP-noise / DoH·ICMP steganography are not in this client** (root
  + Linux + raw-socket deployment cost; the socket-level segmentation
  already produces the same on-wire TCP effect). See
  [`docs/AXR-V3-HYPER-RESILIENCE.md`](../docs/AXR-V3-HYPER-RESILIENCE.md)
  §1/§10 for the v3.1 roadmap.
- **TCP-level chunking, not TLS record padding.** Go's TLS stack and utls
  expose no record-padding control; `ChunkConn` fragments writes at the TCP
  level (honest naming in code and docs).
- **Obfuscation + adaptation, not a guarantee.** Statistical shaping and
  path selection raise the bar against passive/flow heuristics; an actively
  probing filter may still classify the flow.
- **Flow morphing shapes the client's own writes.** `flowprofile` changes
  chunk sizes and inter-packet delays of bytes this process sends — no
  payload inspection, no replayed traffic, no invisibility guarantee.
- **Session reuse is same-destination only.** A WS session carries exactly
  one backend stream; a warm session (≤ 30 s) is adopted only for the same
  host:port. A stale session fails fast and dials fresh — worst case is no
  reuse, never a broken tunnel.
- **Shipped data plane: VLESS-over-WS (+ `ws-alt` shape).** gRPC and HTTP/3
  are arm-set placeholders only; an HTTP-chunked duplex relay was measured
  untestable in CI and deliberately not shipped (see
  [`docs/AXR-V2-ADVANCED.md`](../docs/AXR-V2-ADVANCED.md) §7).
- **Total disconnection is not bypassable remotely.** If no candidate entry
  is reachable from the local network, the binary reports `no healthy
  candidate` instead of pretending.

Spec, threat model, and data-flow: [`docs/AXR-SPEC.md`](../docs/AXR-SPEC.md).
Cross-compile/deploy guide: [`docs/AXR-DEPLOY.md`](../docs/AXR-DEPLOY.md).
