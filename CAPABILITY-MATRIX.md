# Capability Matrix — Gozargah 2.10.0

## Source of truth

`src/protocols/catalog.ts` is the canonical protocol/transport registry. Each pair has exactly one `status`, plus the older `mode`/`boundary` fields for API compatibility. `src/protocols/policy.ts` derives selectable profiles from this registry; profile generators re-check the same ready capability rows. A ready origin row means **this code can emit a configured template**, not that the remote listener was verified.

Statuses:

- `WORKER_NATIVE`: implemented by the Worker data plane.
- `ORIGIN_ENGINE_REQUIRED`: matching generator exists but a compatible origin engine must be deployed; when `ready=true`, host and allowlisted transport are configured, still unverified.
- `UNSUPPORTED`: no working generator exists for this combination.
- `DISABLED`: compatible origin pair deliberately omitted from `ORIGIN_ENGINE_TRANSPORTS`.
- `EXPERIMENTAL`: reserved state; no profile is currently marked experimental.

All current pairs set `liveVerificationAvailable=false`; there is no external Xray/sing-box verification adapter or full protocol handshake probe.

## Current generated pairs

| Protocol | Transport | Current status | Required layer | Notes |
|---|---|---|---|---|
| VLESS | WebSocket + TLS | `WORKER_NATIVE` | Worker | Implemented Worker WebSocket ingress |
| Trojan | WebSocket + TLS | `WORKER_NATIVE` | Worker | Implemented Worker ingress; Xray also emits an optional direct-origin variant when `ws` is allowlisted and origin config is valid (still unverified) |
| VLESS | XHTTP | `ORIGIN_ENGINE_REQUIRED` | Origin | Emitted only if origin host + XHTTP allowlist |
| VLESS | gRPC | `ORIGIN_ENGINE_REQUIRED` | Origin | Emitted only if origin host + gRPC allowlist; ALPN h2 |
| VLESS | HTTPUpgrade | `ORIGIN_ENGINE_REQUIRED` | Origin | Emitted only if origin host + HTTPUpgrade allowlist |
| Trojan | XHTTP | `ORIGIN_ENGINE_REQUIRED` | Origin | Emitted only if origin host + XHTTP allowlist |
| VMess | WebSocket | `ORIGIN_ENGINE_REQUIRED` | Origin | Emitted only if origin host + WS allowlist |
| WireGuard | UDP | `UNSUPPORTED` | Origin would be needed | No UDP-capable adapter/profile generator |
| Hysteria2 | UDP | `UNSUPPORTED` | Origin would be needed | No UDP-capable adapter/profile generator |
| Shadowsocks | TCP/UDP | `UNSUPPORTED` | Origin would be needed | No generator in this release |
| Generic HTTP proxy | TCP/HTTP | `UNSUPPORTED` | Origin would be needed | No generator in this release |

Every other protocol/transport pair in the complete matrix is `UNSUPPORTED`. A host alone does not enable a profile. Origin templates are labeled `declared_not_tested` and the generator rejects invalid ports (valid range: 1–65535).

## ALPN and security

Only actual emitted pairs receive security/ALPN metadata. Current generated origin profiles use TLS; gRPC uses `h2`, WebSocket/HTTPUpgrade use `http/1.1`, and XHTTP receives the generator's supported HTTP ALPN set. The generic ALPN catalog is not permission to synthesize a profile; e.g. HTTP/3 has no generator and no ready profile.

## Compatibility

The full matrix is exposed through the existing authenticated `GET /{panelPath}/api/network/capabilities` and `/api/network/policy` routes and the adaptive subscription. No D1 migration or environment-variable rename is required. `ORIGIN_ENGINE_TRANSPORTS` remains the existing allowlist.
