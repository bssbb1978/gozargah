# AXR client core (Go)

Native client half of the gozargah **AXR Protocol Framework** (v2.14).
A SOCKS5 TCP inbound that tunnels every stream over a **bandit-selected
VLESS-over-WebSocket** path, with client-side TLS-identity selection,
ClientHello TCP segmentation, post-handshake TCP chunking, a persistent
routing cache, and a normal/aggressive probe state machine.

TLS terminates at the Cloudflare edge — therefore **all** fingerprint
morphing, ClientHello surgery, and path/IP selection happens **here, locally**,
before the bytes leave the host. The Worker never sees plaintext and performs
no deep inspection.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/axr` | The binary: SOCKS5 → bandit-selected VLESS-WS tunnel |
| `internal/bandit` | Contextual UCB1 learner over (host, transport, fp) arms; quarantine, prune, JSON persistence |
| `internal/measure` | Client state vector: RTT/jitter EWMA, RST & timeout rates, CUSUM step-change, anomaly code → regime label |
| `internal/surgery` | `SplitConn` (first write = ClientHello → 2 TCP segments, randomized offset + 20–120 ms gap) and `ChunkConn` (post-handshake 512–1400 B TCP chunks) |
| `internal/failover` | Endpoint matrix (host × clean-IP × transport × fp), live IP health cache (atomic JSON), normal/aggressive probe state machine |
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
- **Total disconnection is not bypassable remotely.** If no candidate entry
  is reachable from the local network, the binary reports `no healthy
  candidate` instead of pretending.

Spec, threat model, and data-flow: [`docs/AXR-SPEC.md`](../docs/AXR-SPEC.md).
Cross-compile/deploy guide: [`docs/AXR-DEPLOY.md`](../docs/AXR-DEPLOY.md).
