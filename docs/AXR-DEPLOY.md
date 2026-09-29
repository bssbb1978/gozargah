# AXR — Cross-Compile & Deploy Guide (v2.14)

Execution guide for building the AXR client core, deploying the Worker side,
and verifying the whole framework end-to-end.

> **Verification status (read first):** the Go tree in `client/` was written
> with unit tests but was **not compiled in the authoring sandbox** (no Go
> toolchain was reachable there). The checklist in §1 is the gate before
> first use: `go vet ./... && go build ./... && go test ./...` must be green.
> The Worker side (2.14 `axr-manifest` route) is typecheck/test/build-verified
> in-repo (`npm run typecheck && npm test && npm run build`).

---

## 1. Client core build (from any machine with Go ≥ 1.22)

```sh
cd client

# 1. fetch the single pinned dependency (refraction-networking/utls v1.6.7)
go mod tidy

# 2. static check + unit tests (the gate)
go vet ./...
go test ./...          # bandit / measure / surgery / failover / vlessws

# 3. native build — default (stdlib TLS identity)
go build -o axr ./cmd/axr

# 4. native build — uTLS identity rotation (recommended)
go build -tags axr_utls -o axr ./cmd/axr
```

### 1.1 Cross-compile matrix

```sh
# desktop Linux (x86_64)
GOOS=linux GOARCH=amd64   go build -tags axr_utls -o axr-linux-amd64   ./cmd/axr
# Linux SBC / ARM server / Raspberry Pi
GOOS=linux GOARCH=arm64   go build -tags axr_utls -o axr-linux-arm64   ./cmd/axr
GOOS=linux GOARCH=arm GOARM=7 go build -tags axr_utls -o axr-linux-arm ./cmd/axr
# macOS (Apple Silicon / Intel)
GOOS=darwin GOARCH=arm64  go build -tags axr_utls -o axr-darwin-arm64  ./cmd/axr
GOOS=darwin GOARCH=amd64  go build -tags axr_utls -o axr-darwin-amd64  ./cmd/axr
# Windows (no .exe needed by tools, plain binary)
GOOS=windows GOARCH=amd64 go build -tags axr_utls -o axr-windows-amd64.exe ./cmd/axr
# Android (requires NDK toolchain for CGO-free build it still works as
# pure-Go; cross-compiling from Linux:
GOOS=android GOARCH=arm64 CC=aarch64-linux-android21-clang \
  go build -tags axr_utls -o axr-android-arm64 ./cmd/axr
#   then run it inside Termux (provides the libc); Termux native packages
#   are the easier route: `pkg install golang`, then build locally in Termux.
```

Notes:
- The build is **pure Go** (no CGO), so cross-compilation is a single
  `GOOS/GOARCH` flag set.
- The uTLS tag only adds `refraction-networking/utls` (pure Go as well).
- Reproducibility: pin the Go version in CI (1.22.x); `go.mod` requires 1.22.

### 1.2 uTLS tag and the pinned dependency

- `go.mod` pins `github.com/refraction-networking/utls v1.6.7` — the only
  external dependency, and it is imported **only** by
  `internal/vlessws/tls_utls.go` (build tag `axr_utls`).
- The default (untagged) build never imports it: the handshake uses the
  OS-native Go TLS identity and the arm's `fp` field is ignored. This keeps
  the baseline build dependency-free and makes the uTLS path an explicit,
  auditable opt-in.
- If you upgrade utls, re-verify `tls_utls.go` against the release's API
  (`UClient(conn, *Config, ClientHelloID)`, `Hello*_Auto` presets).

---

## 2. Client configuration

`axr.json` (see `client/README.md` for the full schema):

```json
{
  "uuid": "<your VLESS user UUID>",
  "manifest_url": "https://<entry-host>/<subPath>/<token>/axr-manifest",
  "entries": [
    { "host": "<entry-host>", "priority": 0 },
    { "host": "<backup-host>", "ips": ["<clean-ip-1>"], "fp": "firefox", "priority": 1 }
  ],
  "surgery": true,
  "split_gap_ms": [20, 120],
  "probes": { "normal_ms": 90000, "aggressive_ms": 30000 },
  "cache_dir": "~/.axr"
}
```

- **`manifest_url` (preferred):** the client derives the rotated WS path
  (`/<subPath>/<token>/<ws_path_base>?ed=2048`) from the manifest URL itself,
  picks up the current neutral fingerprint, and registers worker-measured
  backup entries automatically.
- **`ws_path` (explicit alternative):** `"/<subPath>/<token>/<pathbase>?ed=2048"`
  — copy the WS path from any generated client config (v2ray/clash/sing-box).
- **`entries[].ips`:** clean Cloudflare edge IPs for that host (operator
  list). The client probes them and the hostname; live health decides order.
  Discover candidate IPs from your own resolver: `dig +short <host> A`.
- **`uuid`:** the VLESS user UUID from the user page (dashed or plain hex).

### 2.1 Run

```sh
./axr -config axr.json -socks 127.0.0.1:1080 -v
# -surgery=false disables ClientHello split + chunking (for A/B diagnosis)
# -timeout 12s per-tunnel dial+handshake budget
```

Point any SOCKS5 client at `127.0.0.1:1080`. Verify with:

```sh
curl --socks5 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
# look for the expected colo/region; exit code 0 and a trace body = path works
```

---

## 3. Worker side (no code changes required for 2.14)

The `axr-manifest` route ships in the Worker 2.14 build:

```sh
npm run typecheck && npm test && npm run build
npx wrangler deploy
```

Then, from the client's network:

```sh
curl -s "https://<entry-host>/<subPath>/<token>/axr-manifest" | jq .
```

Expect `schema: "gozargah-axr-manifest/v1"` with `ws_path_base`, `entries`,
`fingerprint`, and `honest_limit`.

---

## 4. End-to-end verification checklist

**Client gate (required first):**
- [ ] `go vet ./...` clean
- [ ] `go build ./...` and `go build -tags axr_utls ./...` succeed
- [ ] `go test ./...` all packages pass

**Live path:**
- [ ] `curl --socks5` through the core reaches Cloudflare (`/cdn-cgi/trace`)
- [ ] verbose log shows the score table, the chosen arm, and `tunnel OK ... via <dialaddr>`
- [ ] `~/.axr/routing.json` and `~/.axr/bandit.json` exist and update over time

**Surgery (diagnostic, optional):**
- [ ] With `-surgery=false`, a path that previously worked still works
      (isolates surgery from path selection)
- [ ] On a capture-capable host, the ClientHello arrives as ≥ 2 TCP segments
      with a 20–120 ms gap (split active) and the post-handshake stream is
      chunked in 512–1400 B pieces

**Failover (diagnostic, optional):**
- [ ] Blackhole the primary host locally (e.g. `iptables` DROP) → the core
      fails over to the next candidate/entry within the tunnel budget
- [ ] Two all-fail probe rounds flip the engine to `aggressive` (verbose log:
      `mode=aggressive`) and a success flips it back

**Honest limits (expected behavior, not bugs):**
- [ ] When *no* entry is reachable, logs report `no healthy candidate` and
      SOCKS streams fail cleanly — the framework does **not** loop forever
- [ ] A fully BGP-cut route stays cut; nothing client/Worker-side restores it
