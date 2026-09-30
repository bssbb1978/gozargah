# Transport and path diversity

## Capability boundary

The Cloudflare Worker data plane terminates native WebSocket profiles only. `axr`'s native VLESS tunnel adapter also speaks WebSocket (`ws` and `ws-alt`, where `ws-alt` is the alternate Worker path/profile shape), not gRPC, HTTP/2, or XHTTP. Those three transports are emitted only as direct-to-origin Xray profiles when `ORIGIN_ENGINE_HOST` is configured and each transport is enabled by `ORIGIN_ENGINE_TRANSPORTS`; their capability rows remain `declared-not-tested` because this repository cannot verify the operator's remote listener from a local dry-run.

The Xray `observatory` now probes both Worker (`gz-`) and configured origin (`origin-`) outbounds, and the `leastPing` balancer uses those live probe results for fallback. The emitted HTTP/2 profile uses Xray's `h2` network, ALPN `h2`, and the configured origin host/path. This is client-side Xray measurement, not a claim that a remote deployment has been tested here.

## AXR routing health

The native AXR failover cache identifies a path by host, transport/profile, and dial address. Outcomes from `ws` and `ws-alt` therefore no longer overwrite each other. Health evidence has a six-hour half-life toward the neutral score 0.5, so old success or failure does not remain a permanent ranking. Legacy cache entries keyed only by host and dial address seed the new transport-specific records as a temporary reachability prior.

Equal-health clean-IP candidates rotate using a cursor persisted in `routing.json`; a measured-health difference still takes precedence over rotation. When a candidate fails and another path is attempted, its measured failure is now recorded before fallback. A successful native tunnel is credited only after the VLESS-WS handshake succeeds. TCP/TLS probe successes are reachability evidence, not proof that an application transport works.

## Validation boundary

The SNI-block, RST, throttling, and partial/full-cut scenarios in `client/cmd/axr/simulated_dpi_test.go` inject synthetic probe outcomes. They are regression simulations only, not measurements from an Iranian ISP or any real filtered network. The `axr validate` live-socket harness and manual multi-ISP protocol are documented in [network-validation.md](network-validation.md); this repository run collected no inside-Iran or ISP measurements.
