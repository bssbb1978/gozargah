# Failure Domains and Network Condition — Gozargah 2.10.0

## Telemetry sources

The existing bounded D1 `health_samples` table now uses its existing `kind` column to separate `path_tcp`, `path_dial`, and `path_https` samples (legacy `path` rows are retained). Each source keeps at most 24 samples per subject. Reads use one bounded window-function query for at most 32 configured endpoint IDs. Path forecasting still consumes a merged bounded path history. No D1 schema migration was added.

- `path_tcp`: scheduled Cloudflare Socket open/close probe; TCP establishment only, not TLS or application health.
- `path_dial`: actual Worker socket dial attempts during proxy sessions.
- `path_https`: manual allowlisted HTTPS HEAD probe; it can observe the HTTP status and runtime DNS/TLS errors when the runtime reports them.

The result labels `source=WORKER` and `scope=WORKER_EGRESS_CONFIGURED_PATHS`. There is no client-side ISP telemetry, POP/region telemetry, raw packet analysis, or live origin handshake probe.

## Failure-classification policy

`classifyFailureDomain` only returns a specific cause for explicit stage-coded or recognizable evidence. Known classes include DNS, TCP, TLS, HTTP/domain, WebSocket, transport, origin, regional, POP, client, configuration, authentication and upstream failures. Generic errors and ambiguous timeouts map to `UNKNOWN`; no inference is made from a failure alone about censorship.

For TCP socket probes, only explicit DNS indicators are classified as DNS; explicit refusal/unreachable/TCP errors are TCP. A generic timeout is intentionally unknown because the runtime may not expose whether resolution or connect timed out. HTTPS fetch exceptions are marked TLS/DNS only when their message provides such evidence; otherwise they are unknown. A non-2xx HEAD result is recorded as an HTTP/domain failure.

## Condition states

The classifier compares only the latest fresh observation per configured endpoint (10-minute TTL, 60-second future timestamp tolerance), and ignores unconfigured IDs.

- `HEALTHY`: every configured path has a fresh success.
- `DEGRADED`: all fresh paths succeeded but at least one measured path latency is at least 2 seconds.
- `PARTIALLY_UNREACHABLE`: fresh observations include both success and failure.
- `SEVERELY_DEGRADED`: all observed paths fail but the configured set is too small to call the monitored set unavailable.
- `UPSTREAM_UNAVAILABLE`: at least three configured endpoints are all fresh and all failed. The wording means monitored Worker-egress endpoints only.
- `UNKNOWN`: no fresh observations, low coverage, no configured paths, or insufficient evidence.

Confidence is bounded (maximum 0.8). Results always state `physicalUpstreamDisconnectionProven=false` and `dpiProven=false`. This is a conservative configured-path estimator, not a regional censorship detector.

## Failure isolation limits

This release can separate some probe stages and healthy-vs-failing configured endpoints. It does not know registrable-domain ownership, ISP, physical IP reachability separate from DNS, origin protocol handshake result, TLS result for raw TCP probes, WebSocket upgrade success by a scheduled probe, or regional correlation. Those domains remain `UNKNOWN` until actual tagged measurements exist.
