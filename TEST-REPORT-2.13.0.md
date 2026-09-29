# Gozargah 2.13.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository tests, TypeScript checks, and the Wrangler dry-run build pass on the 2.13.0 working tree.

| Command | Result |
|---|---|
| `npm test` | Pass — 36 engine checks, 9 supplemental pure-logic suites (regime, path-rotation, fp-rotation, shape, decision, predictive-mesh, protocol-catalog, protocol-controller, network-intelligence), and 14 Vitest + Miniflare integration tests |
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; 501.00 KiB upload, 130.89 KiB gzip |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live Cloudflare deployment or external-client interoperability session was performed.

## Coverage added or extended

- **Fingerprint rotation (`src/sub/fp-rotation.ts` + `src/test/fp-rotation.ts`):** determinism within a 6h window, value confined to the neutral set (chrome/firefox/safari — the intersection supported by Xray + Sing-box + Clash-Meta), at least two distinct values across six windows, `fpFor` seed parity, and explicit-operator-preset precedence (`randomized`/`chrome`/`auto` fall-through).
- **Traffic shaping (`src/utils/shape.ts` + `src/test/shape.ts`):** segment plan bounds (small chunks unshaped, exact min-chunk split, huge-chunk segment-count cap with exact byte sum, invalid-length handling), mode parsing fallback, bounded deterministic jitter, and `sendShaped` send counts/coverage for shaped vs small chunks.
- **Decision view (`src/ai/decision.ts` + `src/test/decision.ts`):** verdict mapping for stable/degraded/watch/critical across network state, condition (`UPSTREAM_UNAVAILABLE`), and regime (`suspected_change`) inputs; score bounds; bilingual honest advice; critical-state "no remote route" statement; probe-mode/shape metadata pass-through.
- **Worker/D1 integration (14 tests):** all 13 existing tests plus the authenticated `/api/network/decision` route (401 without a panel session).
- **Existing suites:** engine (fingerprint assertions updated to the rotation contract), predictive-mesh, protocol-catalog, protocol-controller, network-intelligence, shadowsocks, DNS wire/resolver, VLESS-DNS remain green.

## Platform boundaries (what 2.13 does and does not change)

- TLS is terminated at the Cloudflare edge. The Worker never sees or mutates the ClientHello; fingerprint rotation changes the uTLS identity the generated client configs select (JA3/JA4 input), not the edge TLS stack.
- No FEC, no ClientHello extension/cipher/curve mutation by the Worker, no protocol-framing mutation: the VLESS/Trojan/Shadowsocks wire formats remain standard-compatible so stock Xray/sing-box/Hiddify/Clash clients work unchanged.
- Traffic shaping only alters in-tunnel size/timing statistics (bounded segmentation, inter-frame micro-gaps, handshake jitter) inside the edge-terminated TLS tunnel; it changes no protocol byte and is client-compatible.
- The stealth decoy now serves rotated wording + random padding (byte-hash variance); it still leaks no state and no information.
- The probe state machine and regime detection are aggregate statistics from configured probes/dials only; no payload is inspected, no DPI is identified, and no bypass is guaranteed. A fully cut route remains unrestorable from inside the Worker.
