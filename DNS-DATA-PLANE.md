# DNS and transport boundaries — Gozargah 2.11.0

## Authenticated DoH endpoint

Each D1-backed subscription exposes an RFC 8484 endpoint:

```text
https://<worker-host>/<subPath>/<subscription-token>/dns-query
```

It accepts:

- `POST` with `Content-Type: application/dns-message` and a DNS wire-format body;
- `GET` with the standard base64url `dns` query parameter;
- `OPTIONS` for CORS preflight.

The token is the existing per-user subscription bearer token. Each request re-reads current user authorization from D1, enforces a default atomic budget of 120 queries/minute/user, and records request/response bytes in the user's normal usage counters. Disabled, expired, deleted, or over-quota users are rejected. The endpoint is not an anonymous/open resolver.

## Resolver configuration and fallback

`DNS_UPSTREAMS` is an optional comma-separated list of up to four HTTPS RFC 8484 URLs. Invalid/non-HTTPS entries are ignored. Defaults are Cloudflare DoH and Google DoH. Each request uses a 3.5-second abort timeout and sequentially falls through the ordered list on transport, status, content-type, size, or DNS-response validation failure. A bounded isolate-local EWMA latency and smoothed reliability score reorder future attempts; consecutive failures trigger a short exponential quarantine, and health expires after ten minutes without observations. This is operational failover, not an AI or censorship/DPI classifier.

The resolver accepts DNS messages up to 4096 bytes and requires one standard question. Responses must be valid, bounded, and match the query ID and question. It does not log the queried names or retain DNS payloads.

## DNS64 behavior

DNS64 is enabled by default. Set `DNS64_ENABLED=false` to disable it. `DNS64_PREFIX` defaults to `64:ff9b::/96`; supported RFC 6052 prefix lengths are `/32`, `/40`, `/48`, `/56`, `/64`, and `/96`.

For a standard IN AAAA query, the Worker first forwards the original query. If the response is NOERROR with no AAAA answer, it performs a second A query and synthesizes AAAA records from returned IPv4 answer records. It preserves CNAMEs and response metadata, omits the source A answer records, and does not synthesize when the EDNS DNSSEC-OK (DO) bit is set. If the A lookup fails, the original AAAA response is returned unchanged.

DNS64 only embeds an IPv4 address into an IPv6 prefix. It is not a NAT64 gateway or translator. The client-side network, Worker egress, or a separately deployed gateway must actually route those synthesized addresses to a NAT64 translator.

## VLESS UDP DNS adapter

The WebSocket data plane accepts VLESS command `UDP` only when the requested destination port is 53. It reads standard two-byte-length-prefixed datagrams, validates each DNS message, forwards it through the same DoH/DNS64 resolver, and sends a length-prefixed reply. User authorization, D1 rate limits, and byte accounting apply per datagram.

This does **not** open a UDP/53 socket on Cloudflare Workers and is not a generic UDP relay. Generated Clash profiles enable UDP on the VLESS outbound so DNS datagrams can reach the adapter; any non-53 VLESS UDP destination is still rejected by the Worker. Trojan and Shadowsocks profiles disable UDP. Trojan UDP, Shadowsocks UDP, WireGuard, and Hysteria2 remain unsupported.

## Shadowsocks AEAD profile

The third protocol is SIP004 legacy AEAD `aes-256-gcm` over WebSocket/TLS using a SIP003 `v2ray-plugin` client. Standard salt, HKDF-SHA1 subkey derivation, encrypted chunk-length/data framing, and independent direction nonces are implemented. The user's existing UUID is the Shadowsocks password; no extra key is stored in D1. Generated links/configs use the dedicated WebSocket path `/ss/<user-uuid>`; the explicit marker keeps authenticated SIP004 prefix detection separate from VLESS/Trojan protocol headers. The profile is TCP-only; its `ready` capability means the repository generates a matching profile, not that a live client or remote egress path has been tested.

## Network reachability boundary

This Worker relies on an HTTPS/WebSocket route from the client to Cloudflare and on Cloudflare Worker egress to configured DoH endpoints. A complete international disconnect or total block of the Worker/Cloudflare route cannot be bypassed by code running inside that Worker. A separate reachable entry point or independent communication path would be required.
