# Transport and path diversity

## Capability boundary

The Cloudflare Worker data plane terminates native WebSocket profiles only. `axr`'s native VLESS tunnel adapter also speaks WebSocket (`ws` and `ws-alt`, where `ws-alt` is the alternate Worker path/profile shape), not gRPC, HTTP/2, or XHTTP. gRPC, HTTPUpgrade, and XHTTP templates are emitted only as direct-to-origin Xray profiles when `ORIGIN_ENGINE_HOST` is configured and each transport is enabled by `ORIGIN_ENGINE_TRANSPORTS`; their capability rows remain `declared-not-tested` because this repository cannot verify the operator's remote listener from a local dry-run. HTTP/2 (`h2`) is intentionally not generated: current Xray documentation directs users to XHTTP, and the repository has no validated `h2` profile.

The Xray `observatory` probes both Worker (`gz-`) and configured origin (`origin-`) outbounds, and the `leastPing` balancer uses live client-side probes for fallback. A passing probe only establishes reachability for that outbound at probe time; it does not certify an operator's deployment or end-to-end application behavior.

## AXR routing health

The native AXR failover cache identifies a path by host, transport/profile, and dial address. Outcomes from `ws` and `ws-alt` therefore no longer overwrite each other. Health evidence has a six-hour half-life toward the neutral score 0.5, so old success or failure does not remain a permanent ranking. Legacy cache entries keyed only by host and dial address seed the new transport-specific records as a temporary reachability prior.

Equal-health clean-IP candidates rotate using a cursor persisted in `routing.json`; a measured-health difference still takes precedence over rotation. When a candidate fails and another path is attempted, its measured failure is now recorded before fallback. A successful native tunnel is credited only after the VLESS-WS handshake succeeds. TCP/TLS probe successes are reachability evidence, not proof that an application transport works.

## Validation boundary

The SNI-block, RST, throttling, and partial/full-cut scenarios in `client/cmd/axr/simulated_dpi_test.go` inject synthetic probe outcomes. They are regression simulations only, not measurements from an Iranian ISP or any real filtered network. The `axr validate` live-socket harness and manual multi-ISP protocol are documented in [network-validation.md](network-validation.md); this repository run collected no inside-Iran or ISP measurements.
