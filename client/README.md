# AXR client core (Go)

Native client half of the gozargah **AXR Protocol Framework** (v2.16,
AXR-v3 Hyper-Resilience).
A SOCKS5 TCP inbound that tunnels every stream over a **16-dim LinUCB-selected
VLESS-over-WebSocket** path (standard + `ws-alt` shape arms), with
client-side TLS-identity selection, **multi-segment ClientHello surgery**
(fragA/fragB style: randomized 2–3 cuts in the SNI region, 1–8 ms
micro-gaps), **app-class flow morphing** (length histogram + lognormal IPD)
with **KL-divergence self-monitoring**, **TCP socket surgery** (Nagle off +
randomized `SO_SNDBUF`), a persistent routing cache with **clean-IP
harvesting** (A-records + local `axr scan` pool + manifest hints), **HMAC
manifest verification** (reject tampered feeds, keep last-known-good),
**fronting-entry merge** from the manifest, **measured throughput**
accounting, **session reuse** (warm WS ≤ 30 s, same destination), a
**decision audit log** (`~/.axr/decision.jsonl`), and a normal/aggressive
probe state machine.

TLS terminates at the Cloudflare edge — therefore **all** fingerprint
morphing, ClientHello surgery, and path/IP selection happens **here, locally**,
before the bytes leave the host. The Worker never sees plaintext and performs
no deep inspection.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/axr` | The binary: SOCKS5 → 16-dim LinUCB-selected VLESS-WS tunnel (ws + ws-alt arms), HMAC manifest verification, fronting merge, session reuse, decision.jsonl audit — **plus the `axr scan` subcommand** (clean-IP scanner, §Scan) |
| `internal/cfscan` | **2.16** — CFScanner core: CF API CIDRs (offline snapshot fallback), priority /24s, blocked ranges, deterministic sampling, SNI-anchored TLS×3 (real cert verify), median RTT/loss, `cdn-cgi/trace` colo, top-N, JSON+CSV reports; live probing behind an injectable `Prober` |
| `internal/bandit` | **LinUCB** contextual bandit over (host, transport, fp) arms — **16-dim context** (2.16: +throughput, loss velocity, TLS error rate, entry churn, flow KL, time-of-day, session age, regime ordinal), 16×16 ridge A/b per arm, pure-Go Gauss-Jordan; quarantine, prune, JSON persistence (2.15's 7-dim snapshots restore stats with the ridge prior rebuilt) |
| `internal/measure` | Client state vector: RTT/jitter EWMA, RST & timeout rates, CUSUM step-change, anomaly code → regime label; **2.16: +throughput EWMA, signed RTT slope, loss velocity, TLS error rate** (feeds the 16-dim context) |
| `internal/flowprofile` | App-class flow morphing: length histograms + lognormal IPD for `web`/`video`/`chat`; regime-driven; implements `surgery.Slicer`; **2.16: +`KLDiv` / `TargetBins` / shared frame buckets (self-monitoring)** |
| `internal/surgery` | **`MultiSplitConn` (2.16: first write = ClientHello → 2–4 TCP segments at randomized SNI-region cuts with 1–8 ms micro-gaps)**, `SplitConn` (legacy 2-segment) and `ChunkConn` (post-handshake chunks; uniform 512–1400 B legacy, or a `Slicer`-driven app-class distribution) |
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
  "frag_window": [40, 90],
  "frag_micro_gap_ms": [1, 8],
  "probes": { "normal_ms": 90000, "aggressive_ms": 30000 },
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

`frag_cuts` `[min,max]` is the per-connection ClientHello cut count
(2.16 default 2–3 → 3–4 TCP segments, the fragA/fragB shape); absent or
`[0,0]` keeps the legacy single cut with `split_gap_ms`. `frag_window`
[40,90] is the cut window as percent-of-record (the SNI extension region).
`frag_micro_gap_ms` [1,8] bounds the inter-segment micro-gap.

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
