# Gozargah 2.12.0 — Test and build report

Date: 2026-09-29 (UTC)

## Result

All repository tests, TypeScript checks, and the Wrangler dry-run build pass on the 2.12.0 working tree.

| Command | Result |
|---|---|
| `npm test` | Pass — 36 engine checks, supplemental pure-logic/protocol suites (incl. new `regime` and `path-rotation` suites), and 13 Vitest + Miniflare integration tests |
| `npm run typecheck` | Pass — `tsc --noEmit` |
| `npm run build` | Pass — `wrangler deploy --dry-run --outdir dist`; 481.40 KiB upload, 126.86 KiB gzip |

The dry-run reports D1 binding `GZ_DB` and Workers AI binding `AI`. No live Cloudflare deployment or external-client interoperability session was performed.

## Coverage added or extended

- **Regime intelligence (`src/ai/regime.ts` + `src/test/regime.ts`):** steady stream stays `stable`; a good-baseline/sustained-failure stream is flagged `suspected_change` with positive confidence and bounded CUSUM; the symmetric step-up is `recovering`; low-sample input stays `stable` with `insufficient_evidence`; gradual deterioration is `watch`; empty input returns the empty-regime shape; bilingual advice text must not claim DPI detection.
- **Rotating path (`src/sub/path-rotation.ts` + `src/test/path-rotation.ts`):** determinism within a 6h window, shape `/<uuid>/g/<16 hex>`, path change across the window boundary, per-user uniqueness, and backward compatibility of previous windows.
- **Protocol controller:** a calm healthy network stays `stable`; feeding a `suspected_change` regime upgrades the strategy to `diversify`, adds the `suspected_regime_change` reason code, and carries `regimeState`/`regimeConfidence` in the plan (fingerprint now regime-aware).
- **Backup entry ladder:** `backupEntryHosts` settings round-trip (panel API validation, max 4, hostname format), emergency-ladder entries in the live adaptive bundle with measured/unmeasured status and the honest-limit text, backup outbounds in Clash-Meta/Sing-box/Xray-core/Base64 output, user-page backup section with per-host tokens.
- **Existing suites:** engine, predictive-mesh, protocol-catalog, network-intelligence, shadowsocks, DNS wire/resolver, VLESS-DNS, and the 13 Worker/D1 integration tests remain green.

## Capability boundaries

- The regime detector is bounded aggregate statistics over configured probe/dial outcomes. It never inspects payloads, never identifies a DPI system, and its `suspected_change` label is explicitly not a detection or a proof of censorship.
- Rotating paths age out static path fingerprints but are not a confidentiality or authentication change; authentication remains in-band per protocol.
- The emergency ladder only helps when at least one entry point (primary or backup domain) is still reachable from the client network. If no route to the Worker/Cloudflare edge remains, no software inside the Worker can create a new route remotely — that limit is stated in the bundle, the user page, and the panel.
- No live DPI-bypass guarantee is claimed anywhere in this release.
