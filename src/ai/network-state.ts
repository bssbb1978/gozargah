/**
 * Network-state classifier.
 *
 * Purely observational: it classifies the health of configured paths from
 * recent telemetry. It never claims a specific censoring mechanism and never
 * scans arbitrary networks.
 */

import { PathObservation, PathScore, scorePath } from './resilience';

export type NetworkState = 'healthy' | 'degraded' | 'recovery' | 'no_healthy_path' | 'unknown';
export type NetworkSignalClass = 'normal' | 'broad_degradation' | 'selective_degradation' | 'insufficient_evidence';

export interface NetworkStateDecision {
  state: NetworkState;
  quorum: number;
  healthy: number;
  degraded: number;
  quarantined: number;
  unknown: number;
  total: number;
  failureRate: number;
  confidence: number;
  selectedPath: string | null;
  reasonCodes: string[];
  generatedAt: number;
  anomalyScore: number;
  signalClass: NetworkSignalClass;
}

const RECENT_MS = 10 * 60_000;
const MAX_FUTURE_SKEW_MS = 60_000;

export interface StoredNetworkStateSnapshot {
  state: string;
  quorum: number;
  failureRate: number;
  selectedPath: string;
  reasonCodes: string[];
  confidence: number;
  anomalyScore: number;
  signalClass: string;
  updatedAt: number;
}

export function isNetworkStateFresh(updatedAt: number, now = Date.now()): boolean {
  return Number.isFinite(updatedAt) && updatedAt > 0 &&
    updatedAt <= now + MAX_FUTURE_SKEW_MS && now - updatedAt <= RECENT_MS;
}

/** Prevent stale persisted status from masquerading as current connectivity. */
export function normalizeStoredNetworkState(
  snapshot: StoredNetworkStateSnapshot | null | undefined,
  now = Date.now(),
): StoredNetworkStateSnapshot | null {
  if (!snapshot) return null;
  if (isNetworkStateFresh(snapshot.updatedAt, now)) return snapshot;
  return {
    ...snapshot,
    state: 'unknown',
    quorum: 0,
    failureRate: 0.5,
    selectedPath: '',
    reasonCodes: ['stale_network_state'],
    confidence: 0,
    anomalyScore: 0,
    signalClass: 'insufficient_evidence',
  };
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export function classifyNetworkState(observations: PathObservation[], now = Date.now(), configuredPathIds?: string[]): NetworkStateDecision {
  // Keep one fresh observation per path and reject malformed or implausibly
  // future timestamps. A Worker clock correction must not turn a future probe
  // into artificial freshness or confidence.
  const configured = configuredPathIds === undefined
    ? null
    : new Set(configuredPathIds.map((id) => id.trim()).filter(Boolean));
  const latest = new Map<string, PathObservation>();
  for (const observation of observations) {
    if (!observation.id || (configured && !configured.has(observation.id)) || !isNetworkStateFresh(observation.checkedAt, now)) continue;
    const previous = latest.get(observation.id);
    if (!previous || observation.checkedAt > previous.checkedAt) latest.set(observation.id, observation);
  }
  const recent = [...latest.values()];
  const scored: PathScore[] = recent.map((o) => scorePath(o, now));
  const total = configured?.size ?? recent.length;
  const healthy = scored.filter((x) => x.state === 'healthy').length;
  const degraded = scored.filter((x) => x.state === 'degraded').length;
  const quarantined = scored.filter((x) => x.state === 'quarantined').length;
  const unknown = scored.filter((x) => x.state === 'unknown').length + Math.max(0, total - recent.length);
  const samples = recent.reduce((n, o) => n + o.failures + o.successes, 0);
  const failures = recent.reduce((n, o) => n + o.failures, 0);
  const failureRate = samples ? failures / samples : 0.5;
  const usable = healthy + degraded;
  const quorum = total ? usable / total : 0;
  const selected = scored
    .filter((x) => x.state === 'healthy' || x.state === 'degraded')
    .sort((a, b) => b.score - a.score)[0] ?? null;

  let state: NetworkState = 'healthy';
  if (!total || (usable === 0 && unknown > 0) || unknown >= Math.max(1, Math.ceil(total * 0.5))) state = 'unknown';
  else if (usable === 0) state = 'no_healthy_path';
  else if (quorum < 0.5 || failureRate >= 0.5) state = 'recovery';
  else if (quorum < 0.75 || degraded > healthy) state = 'degraded';

  const reasonCodes: string[] = [];
  if (!recent.length) reasonCodes.push('no_recent_probe_data');
  if (unknown > 0) reasonCodes.push('some_path_evidence_unknown');
  if (state === 'no_healthy_path') reasonCodes.push('no_healthy_configured_path');
  if (quarantined >= Math.max(1, Math.ceil(total * 0.5))) reasonCodes.push('quorum_quarantined');
  if (quorum < 0.5 && total > 0) reasonCodes.push('low_usable_quorum');
  if (failureRate >= 0.5) reasonCodes.push('elevated_recent_failure_rate');
  if (unknown >= Math.max(1, Math.ceil(total * 0.5))) reasonCodes.push('insufficient_fresh_data');
  if (!reasonCodes.length) reasonCodes.push('healthy_quorum');

  const confidence = total === 0
    ? 0
    : clamp((Math.min(1, recent.length / 4) * 0.35) + (Math.min(1, samples / 20) * 0.35) + (Math.abs(quorum - 0.5) * 0.6), 0, 1);
  const staleCount = recent.filter((o) => now - o.checkedAt > RECENT_MS / 2).length;
  const anomalyScore = total === 0
    ? 0
    : clamp((failureRate * 0.55) + ((1 - quorum) * 0.35) + ((staleCount / Math.max(1, total)) * 0.10), 0, 1);
  let signalClass: NetworkSignalClass = 'normal';
  if (!total || unknown >= Math.max(1, Math.ceil(total * 0.5))) signalClass = 'insufficient_evidence';
  else if (quorum < 0.35 && failureRate >= 0.65) signalClass = 'broad_degradation';
  else if (healthy > 0 && (degraded + quarantined) > 0) signalClass = 'selective_degradation';

  return {
    state,
    quorum: Math.round(quorum * 1000) / 1000,
    healthy,
    degraded,
    quarantined,
    unknown,
    total,
    failureRate: Math.round(failureRate * 1000) / 1000,
    confidence: Math.round(confidence * 100) / 100,
    selectedPath: selected?.id ?? null,
    reasonCodes,
    generatedAt: now,
    anomalyScore: Math.round(anomalyScore * 100) / 100,
    signalClass,
  };
}
