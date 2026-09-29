# Gozargah 2.11.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository tests, TypeScript checks, and the Wrangler dry-run build pass on the 2.11.0 working tree.

| Command | Result |
|---|---|
| `npm test` | Pass — 36 engine checks, supplemental pure-logic/protocol suites, and 13 Vitest + Miniflare integration tests |
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; 454.31 KiB upload, 121.12 KiB gzip |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live Cloudflare deployment or external-client interoperability session was performed.

## Coverage added or extended

- **Shadowsocks SIP004:** master-key derivation fixture; AES-GCM stream round-trip; authenticated-prefix detection and tamper rejection; multi-chunk framing and maximum chunk splitting.
- **DNS wire/DNS64:** bounded query parsing, RFC 6052 prefix embedding, DNSSEC-DO bypass, synthetic-answer validation and SERVFAIL construction. Synthesized answers do not inherit upstream DNSSEC AD status.
- **DoH resolver and VLESS DNS:** HTTPS URL filtering, upstream fallback, adaptive EWMA/reliability ordering, short quarantine, ten-minute stale-health reset, and length-prefixed multi-datagram stream handling across split reads.
- **Worker/D1 integration (13 tests):** authenticated DoH, DNS64, D1 query budget and usage accounting, Telegram FSM/deduplication/allowlist behavior, authorization and other existing worker paths.
- **Existing adaptive engine:** policy, health, signal fusion, guardrails, capability catalog, user page, and profile-generation checks remain green.

## Capability boundaries

- VLESS UDP is handled only for destination port 53 and is carried over the existing WebSocket session to HTTPS DoH. Cloudflare Workers does not expose a raw UDP/53 listener here; arbitrary UDP is rejected.
- Shadowsocks is `aes-256-gcm` SIP004 over TLS/WebSocket using SIP003 `v2ray-plugin`. It is TCP-only; generic Shadowsocks UDP is unsupported.
- DNS64 synthesizes IPv6 AAAA answers; it does not implement a NAT64 translator.
- DoH failover is local operational resolver telemetry, not an AI DPI classifier.
- This Worker cannot restore access when a user's network has no route to the Worker/Cloudflare edge, and no live DPI-bypass guarantee is claimed.
