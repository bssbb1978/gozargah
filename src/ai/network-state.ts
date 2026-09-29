/**
 * Network-state classifier.
 *
 * Purely observational: it classifies the health of configured paths from
 * recent telemetry. It never claims a specific censoring mechanism and never
 * scans arbitrary networks.
 */

import { PathObservation, PathScore, scorePath } from './resilience';

export type NetworkState = 'healthy' | 'degraded' | 'recovery' | 'no_healthy_path';
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

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export function classifyNetworkState(observations: PathObservation[], now = Date.now()): NetworkStateDecision {
  const recent = observations.filter((o) => o.checkedAt > 0 && now - o.checkedAt <= RECENT_MS);
  const scored: PathScore[] = recent.map((o) => scorePath(o, now));
  const total = scored.length;
  const healthy = scored.filter((x) => x.state === 'healthy').length;
  const degraded = scored.filter((x) => x.state === 'degraded').length;
  const quarantined = scored.filter((x) => x.state === 'quarantined').length;
  const unknown = scored.filter((x) => x.state === 'unknown').length;
  const samples = recent.reduce((n, o) => n + o.failures + o.successes, 0);
  const failures = recent.reduce((n, o) => n + o.failures, 0);
  const failureRate = samples ? failures / samples : 0.5;
  const usable = healthy + degraded;
  const quorum = total ? usable / total : 0;
  const best = [...scored].sort((a, b) => b.score - a.score)[0] ?? null;

  let state: NetworkState = 'healthy';
  if (!total || usable === 0) state = 'no_healthy_path';
  else if (quorum < 0.5 || failureRate >= 0.5) state = 'recovery';
  else if (quorum < 0.75 || degraded > healthy) state = 'degraded';

  const reasonCodes: string[] = [];
  if (!total) reasonCodes.push('no_recent_probe_data');
  if (healthy === 0 && total > 0) reasonCodes.push('no_healthy_configured_path');
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
    selectedPath: best?.id ?? null,
    reasonCodes,
    generatedAt: now,
    anomalyScore: Math.round(anomalyScore * 100) / 100,
    signalClass,
  };
}
