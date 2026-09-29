/**
 * Conservative network-condition estimator based on configured-path telemetry.
 *
 * Its scope is deliberately narrow: this Worker can observe configured egress
 * probes and socket outcomes, not a client's ISP, country-wide connectivity, or
 * the cause of an opaque timeout. Unknown evidence remains UNKNOWN.
 */

export type NetworkConditionState =
  | 'HEALTHY'
  | 'DEGRADED'
  | 'SEVERELY_DEGRADED'
  | 'PARTIALLY_UNREACHABLE'
  | 'UPSTREAM_UNAVAILABLE'
  | 'UNKNOWN';

export type FailureDomain =
  | 'DNS_FAILURE'
  | 'DOMAIN_FAILURE'
  | 'IP_FAILURE'
  | 'TCP_FAILURE'
  | 'TLS_FAILURE'
  | 'WEBSOCKET_FAILURE'
  | 'TRANSPORT_FAILURE'
  | 'ORIGIN_FAILURE'
  | 'REGIONAL_FAILURE'
  | 'POP_FAILURE'
  | 'CLIENT_FAILURE'
  | 'CONFIGURATION_FAILURE'
  | 'AUTHENTICATION_FAILURE'
  | 'UPSTREAM_FAILURE'
  | 'UNKNOWN';

export type NetworkObservationSource = 'WORKER_TCP' | 'WORKER_SOCKET_DIAL' | 'WORKER_HTTPS_HEAD' | 'WORKER_LEGACY_UNSPECIFIED';

export interface ConfiguredPathEvidence {
  pathId: string;
  source?: NetworkObservationSource;
  ok: boolean;
  checkedAt: number;
  latencyMs: number | null;
  failures: number;
  successes: number;
  consecutiveFailures?: number;
  lastError?: string;
}

export interface NetworkCondition {
  state: NetworkConditionState;
  confidence: number;
  suspectedDomains: string[];
  evidence: string[];
  recommendedAction: string;
  source: 'WORKER';
  scope: 'WORKER_EGRESS_CONFIGURED_PATHS';
  generatedAt: number;
  configuredPathCount: number;
  freshPathCount: number;
  healthyPathCount: number;
  failedPathCount: number;
  observationSources: NetworkObservationSource[];
  lastKnownGood: { pathId: string; checkedAt: number } | null;
  physicalUpstreamDisconnectionProven: false;
  dpiProven: false;
}

const OBSERVATION_TTL_MS = 10 * 60_000;
const MAX_FUTURE_SKEW_MS = 60_000;
const MAX_ENDPOINTS = 32;

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/** Reduce socket errors to a bounded stage code; never persist an arbitrary exception. */
export function normalizeSocketFailure(error: unknown): string {
  const text = (error instanceof Error ? error.message : String(error)).slice(0, 240).toLowerCase();
  if (/eai_again|enotfound|name_not_resolved|dns|resolve/.test(text)) return 'dns_failure';
  if (/econnrefused|connection refused|ehostunreach|network is unreachable|no route to host|tcp connect/.test(text)) return 'tcp_failure';
  if (/timed? ?out|timeout/.test(text)) return 'unknown_socket_timeout';
  return 'unknown_socket_failure';
}

/** Fetch hides its internal phase; only preserve DNS/TLS when the runtime says so. */
export function normalizeFetchFailure(error: unknown): string {
  const text = (error instanceof Error ? error.message : String(error)).slice(0, 240).toLowerCase();
  if (/eai_again|enotfound|name_not_resolved|dns|resolve/.test(text)) return 'dns_failure';
  if (/tls|ssl|certificate|cert verify/.test(text)) return 'tls_failure';
  return 'unknown_https_probe_failure';
}

/** Only classify causes when the stored error has recognizable stage evidence. */
export function classifyFailureDomain(error?: string): FailureDomain {
  const text = (error ?? '').slice(0, 240).toLowerCase();
  if (!text) return 'UNKNOWN';
  if (/auth(entication)?_failure|auth_failed|unauthori[sz]ed|forbidden/.test(text)) return 'AUTHENTICATION_FAILURE';
  if (/config(uration)?_failure|invalid_config|invalid_port|unsupported_profile/.test(text)) return 'CONFIGURATION_FAILURE';
  if (/dns_failure|eai_again|enotfound|name_not_resolved|dns resolution|resolve[_ ]failed/.test(text)) return 'DNS_FAILURE';
  if (/tls_failure|tls handshake|certificate verify|certificate[_ ]error/.test(text)) return 'TLS_FAILURE';
  if (/websocket_failure|websocket upgrade|upgrade[_ ]failed|ws handshake/.test(text)) return 'WEBSOCKET_FAILURE';
  if (/origin_failure|origin[_ ]unavailable|origin connect/.test(text)) return 'ORIGIN_FAILURE';
  if (/regional_failure|region[_ ]unavailable/.test(text)) return 'REGIONAL_FAILURE';
  if (/pop_failure|colo[_ ]unavailable/.test(text)) return 'POP_FAILURE';
  if (/client_failure|client[_ ]disconnect/.test(text)) return 'CLIENT_FAILURE';
  if (/upstream_failure|upstream[_ ]unavailable/.test(text)) return 'UPSTREAM_FAILURE';
  if (/http_failure|http_status_[45]\d\d|http status [45]\d\d|application[_ ]failure/.test(text)) return 'DOMAIN_FAILURE';
  if (/tcp_failure|tcp_probe_timeout|econnrefused|connection refused|connection timed out|network is unreachable|no route to host/.test(text)) return 'TCP_FAILURE';
  if (/transport_failure|transport[_ ]error/.test(text)) return 'TRANSPORT_FAILURE';
  // Do not guess the phase of generic fetch/socket errors.
  return 'UNKNOWN';
}

function rounded(value: number): number {
  return Math.round(clamp(value, 0, 1) * 1000) / 1000;
}

function sourceRank(source: NetworkObservationSource | undefined): number {
  if (source === 'WORKER_HTTPS_HEAD') return 4;
  if (source === 'WORKER_SOCKET_DIAL') return 3;
  if (source === 'WORKER_TCP') return 2;
  return 1;
}

export function classifyNetworkCondition(
  configuredPathIds: string[],
  observations: ConfiguredPathEvidence[],
  now = Date.now(),
): NetworkCondition {
  const configured = [...new Set(configuredPathIds.map((x) => x.trim()).filter(Boolean))].slice(0, MAX_ENDPOINTS);
  const allowed = new Set(configured);
  const latest = new Map<string, ConfiguredPathEvidence>();
  for (const row of observations) {
    if (!allowed.has(row.pathId) || !Number.isFinite(row.checkedAt) || row.checkedAt <= 0) continue;
    if (row.checkedAt > now + MAX_FUTURE_SKEW_MS || now - row.checkedAt > OBSERVATION_TTL_MS) continue;
    const old = latest.get(row.pathId);
    if (!old || row.checkedAt > old.checkedAt || (row.checkedAt === old.checkedAt && sourceRank(row.source) > sourceRank(old.source))) latest.set(row.pathId, row);
  }

  const fresh = [...latest.values()];
  const healthy = fresh.filter((row) => row.ok);
  const failed = fresh.filter((row) => !row.ok);
  const failureDomains = [...new Set(failed.map((row) => classifyFailureDomain(row.lastError)).filter((x) => x !== 'UNKNOWN'))];
  const evidence: string[] = [];
  const coverage = configured.length ? fresh.length / configured.length : 0;
  const enoughData = fresh.length > 0 && coverage >= 0.5;
  const allFreshFailed = enoughData && healthy.length === 0 && failed.length === configured.length;
  const allFreshHealthy = enoughData && healthy.length === configured.length;

  let state: NetworkConditionState = 'UNKNOWN';
  let confidence = 0;
  let recommendedAction = 'Collect fresh observations; current evidence is insufficient for a network condition claim.';

  if (allFreshHealthy) {
    const highLatency = fresh.filter((row) => row.latencyMs != null && row.latencyMs >= 2000).length;
    if (highLatency > 0) {
      state = 'DEGRADED';
      confidence = clamp(0.45 + coverage * 0.2 + Math.min(0.2, fresh.length * 0.04), 0, 0.8);
      evidence.push('all_recent_configured_tcp_probes_succeeded');
      evidence.push('one_or_more_paths_have_high_measured_tcp_latency');
      recommendedAction = 'Keep working paths; compare fresh measurements before any policy change.';
    } else {
      state = 'HEALTHY';
      confidence = clamp(0.4 + coverage * 0.25 + Math.min(0.2, fresh.length * 0.04), 0, 0.8);
      evidence.push('all_recent_configured_tcp_probes_succeeded');
      recommendedAction = 'Keep the current policy; continue bounded monitoring.';
    }
  } else if (healthy.length > 0 && failed.length > 0) {
    state = 'PARTIALLY_UNREACHABLE';
    confidence = clamp(0.35 + coverage * 0.25 + Math.min(0.2, fresh.length * 0.04), 0, 0.8);
    evidence.push('some_configured_paths_succeeded_while_others_failed');
    recommendedAction = 'Keep measured healthy paths; isolate only the failed endpoints and probe them after cooldown.';
  } else if (allFreshFailed) {
    evidence.push('all_fresh_configured_paths_failed_from_worker_egress');
    if (failureDomains.length) evidence.push('recognized_failure_stages:' + failureDomains.join(','));
    if (failed.length >= 3) {
      state = 'UPSTREAM_UNAVAILABLE';
      confidence = clamp(0.45 + Math.min(0.25, failed.length * 0.05) + Math.min(0.1, coverage * 0.1), 0, 0.8);
      recommendedAction = 'Configured egress paths are unavailable from this Worker vantage. Stop broad profile rotation, preserve last-known-good, and continue bounded recovery probes.';
    } else {
      state = 'SEVERELY_DEGRADED';
      confidence = clamp(0.3 + Math.min(0.25, failed.length * 0.08) + coverage * 0.15, 0, 0.7);
      recommendedAction = 'The monitored path set is failing; use a known-good configured alternative if available and probe with backoff.';
    }
  } else if (!fresh.length) {
    evidence.push(configured.length ? 'no_fresh_configured_path_observations' : 'no_configured_paths');
  } else {
    evidence.push('fresh_observation_coverage_below_half');
    confidence = clamp(coverage * 0.25, 0, 0.25);
  }

  const lastKnownGoodRow = [...observations]
    .filter((row) => allowed.has(row.pathId) && row.ok && Number.isFinite(row.checkedAt) && row.checkedAt <= now && row.checkedAt > 0)
    .sort((a, b) => b.checkedAt - a.checkedAt)[0];
  const lastKnownGood = lastKnownGoodRow ? { pathId: lastKnownGoodRow.pathId, checkedAt: lastKnownGoodRow.checkedAt } : null;
  if (lastKnownGood && state === 'UPSTREAM_UNAVAILABLE') evidence.push('last_known_good_is_historical_not_current_connectivity');

  return {
    state,
    confidence: rounded(confidence),
    suspectedDomains: failureDomains,
    evidence,
    recommendedAction,
    source: 'WORKER',
    scope: 'WORKER_EGRESS_CONFIGURED_PATHS',
    generatedAt: now,
    configuredPathCount: configured.length,
    freshPathCount: fresh.length,
    healthyPathCount: healthy.length,
    failedPathCount: failed.length,
    observationSources: [...new Set(fresh.map((row) => row.source ?? 'WORKER_LEGACY_UNSPECIFIED'))],
    lastKnownGood,
    physicalUpstreamDisconnectionProven: false,
    dpiProven: false,
  };
}
