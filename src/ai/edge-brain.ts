/**
 * Local Adaptive Policy Brain.
 *
 * This is a bounded, deterministic policy layer. It never rewrites protocol
 * bytes or invents arbitrary network settings. It chooses among explicitly
 * configured client profiles using observed outcomes and conservative guards.
 */

import { EdgeLearnerState, explorationBonus, observationFeatures, predictSuccess } from './edge-learner';

export type AdaptiveProfileId = 'standard' | 'fragmented' | 'alt-port' | 'fragmented-alt';

export interface ProfileObservation {
  profileId: AdaptiveProfileId;
  ok: boolean;
  latencyMs: number | null;
  failures: number;
  successes: number;
  checkedAt: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  quarantineUntil: number;
}

export interface ProfileScore {
  profileId: AdaptiveProfileId;
  score: number;
  state: 'healthy' | 'degraded' | 'quarantined' | 'unknown';
  confidence: number;
  failureRate: number;
  trend: 'improving' | 'stable' | 'declining';
}

export interface PolicyDecision {
  selected: AdaptiveProfileId;
  profiles: ProfileScore[];
  confidence: number;
  mode: 'normal' | 'degraded' | 'recovery';
  policyVersion: '2.0-local-brain-v2';
}

const PROFILES: AdaptiveProfileId[] = ['standard', 'fragmented', 'alt-port', 'fragmented-alt'];
const STALE_MS = 15 * 60_000;
const QUARANTINE_MS = 5 * 60_000;

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function trend(o: ProfileObservation): ProfileScore['trend'] {
  if (o.consecutiveSuccesses >= 2 && o.consecutiveSuccesses > o.consecutiveFailures) return 'improving';
  if (o.consecutiveFailures >= 2 && o.consecutiveFailures > o.consecutiveSuccesses) return 'declining';
  return 'stable';
}

export function scoreProfile(o: ProfileObservation, now = Date.now(), learner?: EdgeLearnerState): ProfileScore {
  const total = o.failures + o.successes;
  const failureRate = total ? o.failures / total : 0.5;
  const age = o.checkedAt ? Math.max(0, now - o.checkedAt) : Number.POSITIVE_INFINITY;
  const freshness = Number.isFinite(age) ? clamp(1 - age / STALE_MS, 0, 1) : 0;
  const latencyPenalty = o.latencyMs == null ? 16 : clamp(Math.log1p(o.latencyMs) * 4.8, 0, 34);
  const failurePenalty = failureRate * 56;
  const stalePenalty = (1 - freshness) * 10;
  const t = trend(o);
  const trendBonus = t === 'improving' ? 7 : t === 'declining' ? -10 : 0;
  const confidence = clamp(total / 8, 0, 1) * freshness;
  const baseScore = clamp(100 - latencyPenalty - failurePenalty - stalePenalty + trendBonus + confidence * 6, 0, 100);
  const features = observationFeatures({
    latencyMs: o.latencyMs, failures: o.failures, successes: o.successes, freshness, trend: t,
    consecutiveSuccesses: o.consecutiveSuccesses,
  });
  const probability = learner ? predictSuccess(learner, features) : baseScore / 100;
  const explore = explorationBonus(total, total);
  const quarantinePenalty = o.quarantineUntil > now ? 100 : 0;
  const score = clamp(baseScore * 0.62 + probability * 100 * 0.28 + explore - quarantinePenalty, 0, 100);
  let state: ProfileScore['state'] = 'unknown';
  if (o.quarantineUntil > now) state = 'quarantined';
  else if (total < 2 || freshness < 0.15) state = 'unknown';
  else if (score >= 72 && probability >= 0.55) state = 'healthy';
  else if (score >= 40) state = 'degraded';
  else state = 'quarantined';
  return {
    profileId: o.profileId, score: Math.round(score * 10) / 10, state, confidence: Math.round(confidence * 100) / 100,
    failureRate: Math.round(failureRate * 1000) / 1000, trend: t,
  };
}

export function decideAdaptiveProfile(observations: ProfileObservation[], stableIndex = 0, now = Date.now(), learner?: EdgeLearnerState): PolicyDecision {
  const byId = new Map(observations.map((x) => [x.profileId, x]));
  const scored = PROFILES.map((profileId) => scoreProfile(byId.get(profileId) ?? {
    profileId,
    ok: false,
    latencyMs: null,
    failures: 0,
    successes: 0,
    checkedAt: 0,
    consecutiveFailures: 0,
    consecutiveSuccesses: 0,
    quarantineUntil: 0,
  }, now, learner));
  scored.sort((a, b) => b.score - a.score || b.confidence - a.confidence || a.profileId.localeCompare(b.profileId));
  const usable = scored.filter((x) => x.state === 'healthy' || x.state === 'degraded');
  const rotated = usable.length
    ? usable[((stableIndex % usable.length) + usable.length) % usable.length]
    : scored[((stableIndex % scored.length) + scored.length) % scored.length];
  const known = observations.some((x) => x.successes + x.failures >= 2);
  const mode = !usable.length ? 'recovery' : rotated.state === 'degraded' ? 'degraded' : known ? 'normal' : 'recovery';
  return {
    selected: rotated.profileId,
    profiles: scored,
    confidence: rotated.confidence,
    mode,
    policyVersion: '2.0-local-brain-v2',
  };
}

export function nextProfileObservation(prev: ProfileObservation | undefined, ok: boolean, latencyMs: number | null, now = Date.now()): ProfileObservation {
  const old = prev ?? {
    profileId: 'standard' as const,
    ok: false,
    latencyMs: null,
    failures: 0,
    successes: 0,
    checkedAt: 0,
    consecutiveFailures: 0,
    consecutiveSuccesses: 0,
    quarantineUntil: 0,
  };
  const failures = old.failures + (ok ? 0 : 1);
  const successes = old.successes + (ok ? 1 : 0);
  const consecutiveFailures = ok ? 0 : old.consecutiveFailures + 1;
  const consecutiveSuccesses = ok ? old.consecutiveSuccesses + 1 : 0;
  const latency = latencyMs == null ? old.latencyMs : old.latencyMs == null ? latencyMs : Math.round(old.latencyMs * 0.7 + latencyMs * 0.3);
  const quarantineUntil = !ok && consecutiveFailures >= 3
    ? now + Math.min(30 * 60_000, QUARANTINE_MS * Math.max(1, consecutiveFailures - 2))
    : ok && consecutiveSuccesses >= 2 ? 0 : old.quarantineUntil;
  return { ...old, ok, latencyMs: latency, failures, successes, checkedAt: now, consecutiveFailures, consecutiveSuccesses, quarantineUntil };
}
