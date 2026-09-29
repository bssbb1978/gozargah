# AXR client core (Go)

Native client half of the gozargah **AXR Protocol Framework** (v2.15,
AXR-v2 Enterprise Core).
A SOCKS5 TCP inbound that tunnels every stream over a **LinUCB-selected
VLESS-over-WebSocket** path (standard + `ws-alt` shape arms), with
client-side TLS-identity selection, ClientHello TCP segmentation,
**app-class flow morphing** (length histogram + lognormal IPD), **TCP
socket surgery** (Nagle off + randomized `SO_SNDBUF`), a persistent
routing cache with **clean-IP harvesting**, **session reuse** (warm WS
≤ 30 s, same destination), a **decision audit log**
(`~/.axr/decision.jsonl`), and a normal/aggressive probe state machine.

TLS terminates at the Cloudflare edge — therefore **all** fingerprint
morphing, ClientHello surgery, and path/IP selection happens **here, locally**,
before the bytes leave the host. The Worker never sees plaintext and performs
no deep inspection.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/axr` | The binary: SOCKS5 → LinUCB-selected VLESS-WS tunnel (ws + ws-alt arms), session reuse, decision.jsonl audit |
| `internal/bandit` | **LinUCB** contextual bandit over (host, transport, fp) arms — 7-dim context, ridge A/b per arm, pure-Go Gauss-Jordan; quarantine, prune, JSON persistence (legacy 2.14 snapshots restore) |
| `internal/measure` | Client state vector: RTT/jitter EWMA, RST & timeout rates, CUSUM step-change, anomaly code → regime label (feeds the LinUCB context) |
| `internal/flowprofile` | App-class flow morphing: length histograms + lognormal IPD for `web`/`video`/`chat`; regime-driven; implements `surgery.Slicer` |
| `internal/surgery` | `SplitConn` (first write = ClientHello → 2 TCP segments, randomized offset + 20–120 ms gap) and `ChunkConn` (post-handshake chunks; uniform 512–1400 B legacy, or a `Slicer`-driven app-class distribution) |
| `internal/sockopt` | TCP socket surgery: `TCP_NODELAY` (Nagle off) + randomized `SO_SNDBUF` (64–512 KB); linux/darwin/windows, no-op elsewhere |
| `internal/failover` | Endpoint matrix (host × clean-IP × transport × fp), live IP health cache (atomic JSON), normal/aggressive probe state machine, **A-record clean-IP harvesting** (injectable resolver) |
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
  "probes": { "normal_ms": 90000, "aggressive_ms": 30000 },
  "cache_dir": "~/.axr"
}
```

`manifest_url` (preferred) bootstraps the rotated WS path, the current
neutral fingerprint, and worker-measured backup entries. `ws_path`
(`"/sub/<token>/<pathbase>?ed=2048"`) is the explicit alternative.

```sh
./axr -config axr.json -socks 127.0.0.1:1080 -v
```

Point any SOCKS5 client (browser, Hiddify, sing-box, v2rayN) at the listen
address. UDP ASSOCIATE is rejected (the Worker has no UDP relay — by design).

## Honest boundaries

- **No payload inspection, no DPI "detection".** The client only knows its
  own outcomes (ok / rtt / error class); the regime label describes delivery
  quality, not middlebox behavior.
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
