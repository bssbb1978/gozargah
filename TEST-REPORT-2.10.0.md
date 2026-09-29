# Test Report — Gozargah 2.10.0

Verification status from this checkout; not a production deployment test.

## Commands

| Command | Status | Observed result |
|---|---|---|
| `npm install` | **PASS** | Dependencies reconciled from package-lock; no runtime dependency was added |
| `npm run typecheck` | **PASS** | TypeScript strict check succeeds |
| `npm test` | **PASS** | 36 engine checks; predictive mesh, protocol catalog/controller and network-intelligence smoke suites; 12 Worker/D1 integration tests |
| `npm run build` | **PASS** | Wrangler dry-run: 408.98 KiB upload / 109.56 KiB gzip; no deployment performed |
| `npm audit` | **PASS** | Zero reported vulnerabilities |
| `git diff --check` | **PASS** | No whitespace errors |
| ESLint / formatter | **NOT RUN** | No ESLint/format script or configuration in this repository |
| Live Cloudflare deployment | **NOT RUN** | Credentials/deployment target were not exercised |
| Live Xray/sing-box verification | **REQUIRES LIVE ORIGIN** | No origin was available; templates remain declared-but-not-tested |
| Real client/ISP/region probe | **REQUIRES CLIENT** | Worker egress measurements are not client-side telemetry |

## New deterministic network-intelligence scenarios

- all configured paths fresh and succeeding → `HEALTHY`;
- mixed successful/failing paths → `PARTIALLY_UNREACHABLE`;
- all three monitored configured paths fail → `UPSTREAM_UNAVAILABLE` scoped to Worker egress, never physical global outage proof;
- one failing path → `SEVERELY_DEGRADED`, not broad outage;
- stale/future/absent samples → `UNKNOWN`;
- opaque errors/timeouts remain `UNKNOWN`;
- explicit DNS/TCP/TLS/HTTP/WebSocket/origin/auth/configuration markers are classified;
- unknown endpoints are filtered and duplicates resolve to the newest sample.

## Not covered by these tests

Actual Iranian ISP behavior, DPI detection/bypass, physical international disconnection, DNS resolver phase under opaque Cloudflare errors, TLS/WebSocket probe handshakes, POP/region correlation, live origin compatibility, client-side capability negotiation, and real-world canary outcomes require external test vantage points and deployed clients/origins.
