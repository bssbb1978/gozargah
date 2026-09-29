/**
 * Adaptive Censorship-Resilience Engine v2.
 *
 * Bounded, deterministic control plane. It learns from aggregate connection
 * outcomes, uses a tiny local online model, and performs conservative
 * half-open recovery when every configured path is unhealthy.
 * It never rewrites protocol bytes or scans arbitrary networks.
 */

import { EdgeLearnerState, explorationBonus, learnerConfidence, observationFeatures, predictSuccess } from './edge-learner';

export type HealthState = 'healthy' | 'degraded' | 'quarantined' | 'unknown';
export type ResilienceMode = 'normal' | 'degraded' | 'recovery' | 'no_healthy_path';

export interface PathObservation {
  id: string;
  latencyMs: number | null;
  ok: boolean;
  checkedAt: number;
  failures: number;
  successes: number;
  quarantineUntil: number;
  consecutiveFailures?: number;
  consecutiveSuccesses?: number;
  lastError?: string;
}

export interface PathScore {
  id: string;
  score: number;
  state: HealthState;
  latencyMs: number | null;
  failureRate: number;
  quarantineUntil: number;
  freshness: number;
  trend: 'improving' | 'stable' | 'declining';
  modelProbability: number;
  exploration: number;
  sampleCount: number;
}

export interface ResilienceDecision {
  mode: ResilienceMode;
  selectedPath: string | null;
  candidates: PathScore[];
  recoveryCandidates: string[];
  generatedAt: number;
  confidence: number;
  learnerConfidence: number;
  rationale: string[];
  policyVersion: string;
}

const POLICY_VERSION = '2.0-adaptive-ensemble';
const BASE_QUARANTINE_MS = 5 * 60_000;
const FAILURE_THRESHOLD = 3;
const STALE_MS = 10 * 60_000;

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export function updateObservation(prev: PathObservation | undefined, ok: boolean, latencyMs: number | null, now = Date.now(), lastError = ''): PathObservation {
  const old = prev ?? { id: '', latencyMs: null, ok: false, checkedAt: 0, failures: 0, successes: 0, quarantineUntil: 0, consecutiveFailures: 0, consecutiveSuccesses: 0 };
  const failures = ok ? old.failures : old.failures + 1;
  const successes = ok ? old.successes + 1 : old.successes;
  const consecutiveFailures = ok ? 0 : (old.consecutiveFailures ?? 0) + 1;
  const consecutiveSuccesses = ok ? (old.consecutiveSuccesses ?? 0) + 1 : 0;
  const nextLatency = latencyMs == null
    ? old.latencyMs
    : old.latencyMs == null
      ? latencyMs
      : Math.round(old.latencyMs * 0.7 + latencyMs * 0.3);
  const backoff = Math.min(30 * 60_000, BASE_QUARANTINE_MS * Math.max(1, consecutiveFailures - FAILURE_THRESHOLD + 1));
  const quarantineUntil = !ok && consecutiveFailures >= FAILURE_THRESHOLD
    ? now + backoff
    : ok && consecutiveSuccesses >= 2
      ? 0
      : old.quarantineUntil;
  return {
    ...old,
    ok,
    latencyMs: nextLatency,
    checkedAt: now,
    failures,
    successes,
    consecutiveFailures,
    consecutiveSuccesses,
    quarantineUntil,
    lastError: ok ? '' : lastError || old.lastError || 'path_failed',
  };
}

function trendOf(o: PathObservation): PathScore['trend'] {
  const good = o.consecutiveSuccesses ?? 0;
  const bad = o.consecutiveFailures ?? 0;
  if (good >= 2 && good > bad) return 'improving';
  if (bad >= 2 && bad > good) return 'declining';
  return 'stable';
}

export function scorePath(observation: PathObservation, now = Date.now(), learner?: EdgeLearnerState): PathScore {
  const total = observation.failures + observation.successes;
  const failureRate = total ? observation.failures / total : 0.5;
  const age = observation.checkedAt ? Math.max(0, now - observation.checkedAt) : Number.POSITIVE_INFINITY;
  const freshness = Number.isFinite(age) ? clamp(1 - age / STALE_MS, 0, 1) : 0;
  const latencyPenalty = observation.latencyMs == null ? 28 : clamp(Math.log1p(observation.latencyMs) * 5.2, 0, 35);
  const failurePenalty = failureRate * 55;
  const stalePenalty = (1 - freshness) * 12;
  const trend = trendOf(observation);
  const trendAdjustment = trend === 'improving' ? 7 : trend === 'declining' ? -9 : 0;
  const sampleConfidence = clamp(total / 10, 0, 1);
  const confidenceBonus = sampleConfidence * 5;
  const baseScore = clamp(100 - latencyPenalty - failurePenalty - stalePenalty + trendAdjustment + confidenceBonus, 0, 100);

  const features = observationFeatures({
    latencyMs: observation.latencyMs,
    failures: observation.failures,
    successes: observation.successes,
    freshness,
    trend,
    consecutiveSuccesses: observation.consecutiveSuccesses ?? 0,
  });
  const modelProbability = learner ? predictSuccess(learner, features) : baseScore / 100;
  const exploration = explorationBonus(total, total);
  const quarantinePenalty = observation.quarantineUntil > now ? 100 : 0;
  const blended = (baseScore * 0.62) + (modelProbability * 100 * 0.28) + exploration - quarantinePenalty;
  const score = clamp(blended, 0, 100);

  let state: HealthState = 'unknown';
  if (observation.quarantineUntil > now) state = 'quarantined';
  else if (total < 2 || freshness < 0.15) state = 'unknown';
  else if (score >= 72 && modelProbability >= 0.55) state = 'healthy';
  else if (score >= 38) state = 'degraded';
  else state = 'quarantined';
  return {
    id: observation.id,
    score: Math.round(score * 10) / 10,
    state,
    latencyMs: observation.latencyMs,
    failureRate: Math.round(failureRate * 1000) / 1000,
    quarantineUntil: observation.quarantineUntil,
    freshness: Math.round(freshness * 100) / 100,
    trend,
    modelProbability: Math.round(modelProbability * 1000) / 1000,
    exploration: Math.round(exploration * 100) / 100,
    sampleCount: total,
  };
}

export function decideResilience(observations: PathObservation[], now = Date.now(), learner?: EdgeLearnerState, preferredPathId = ''): ResilienceDecision {
  const candidates = observations.map((x) => scorePath(x, now, learner)).sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (b.modelProbability !== a.modelProbability) return b.modelProbability - a.modelProbability;
    if (b.freshness !== a.freshness) return b.freshness - a.freshness;
    return a.id.localeCompare(b.id);
  });
  const usable = candidates.filter((x) => x.state === 'healthy' || x.state === 'degraded');
  let selected = usable[0] ?? null;
  if (preferredPathId) {
    const preferred = usable.find((x) => x.id === preferredPathId);
    if (preferred && (!selected || preferred.score >= selected.score - 8)) selected = preferred;
  }
  const allUnknown = candidates.length > 0 && candidates.every((x) => x.state === 'unknown');
  const mode: ResilienceMode = !selected ? 'no_healthy_path' : allUnknown ? 'recovery' : selected.state === 'degraded' ? 'degraded' : 'normal';

  const recoveryCandidates = !selected
    ? [...candidates]
      .sort((a, b) => (a.quarantineUntil || Number.MAX_SAFE_INTEGER) - (b.quarantineUntil || Number.MAX_SAFE_INTEGER) || b.score - a.score)
      .slice(0, 2)
      .map((x) => x.id)
    : [];

  const next = selected && candidates.find((x) => x.id !== selected!.id);
  const topGap = selected && next ? Math.max(0, selected.score - next.score) : selected ? 25 : 0;
  const confidence = selected
    ? clamp((selected.score / 100) * (0.6 + selected.freshness * 0.4) * (0.72 + Math.min(0.28, topGap / 100)), 0, 1)
    : 0;
  const rationale: string[] = [];
  if (!selected) rationale.push('no_usable_configured_path');
  if (recoveryCandidates.length) rationale.push('half_open_recovery_enabled');
  if (selected) {
    if (preferredPathId && selected.id === preferredPathId) rationale.push('per_user_preference_honored');
    if (selected.failureRate > 0.35) rationale.push('elevated_failure_rate');
    if (selected.latencyMs != null && selected.latencyMs > 500) rationale.push('high_latency');
    if (selected.freshness < 0.5) rationale.push('stale_measurement');
    if (selected.trend === 'declining') rationale.push('declining_recent_trend');
    if (selected.trend === 'improving') rationale.push('improving_recent_trend');
    if (!rationale.length) rationale.push('best_measured_health');
  }
  return {
    mode,
    selectedPath: selected?.id ?? null,
    candidates,
    recoveryCandidates,
    generatedAt: now,
    confidence: Math.round(confidence * 100) / 100,
    learnerConfidence: Math.round(learnerConfidence(learner) * 100) / 100,
    rationale,
    policyVersion: POLICY_VERSION,
  };
}

export function localResilienceAdvice(decision: ResilienceDecision, language: 'fa' | 'en'): string {
  const confidence = Math.round(decision.confidence * 100);
  const learner = Math.round(decision.learnerConfidence * 100);
  if (language === 'fa') {
    if (decision.mode === 'no_healthy_path') return `هیچ مسیر پیکربندی‌شده‌ای در وضعیت عادی قابل‌استفاده نیست؛ موتور recovery می‌تواند حداکثر دو مسیر را به‌صورت half-open دوباره آزمایش کند. این نتیجه به‌تنهایی ثابت نمی‌کند اینترنت بین‌الملل قطع یا DPI فعال است. یادگیری محلی ${learner}٪ اطمینان دارد.`;
    if (decision.mode === 'recovery') return `موتور در حالت بازیابی است و با داده‌های تازه‌تر و تغییرات محدود تصمیم می‌گیرد؛ اطمینان ${confidence}٪؛ یادگیری محلی ${learner}٪.`;
    if (decision.mode === 'degraded') return `مسیر منتخب افت کیفیت دارد و مسیرهای ضعیف‌تر موقتاً اولویت پایین‌تری دارند؛ اطمینان ${confidence}٪.`;
    return `مسیر منتخب بالاترین سلامت اندازه‌گیری‌شده را دارد؛ اطمینان ${confidence}٪؛ یادگیری محلی ${learner}٪.`;
  }
  if (decision.mode === 'no_healthy_path') return `No configured path is healthy; the recovery ladder may half-open up to two candidates. This alone does not prove an international outage or DPI. Local learner confidence ${learner}%.`;
  if (decision.mode === 'recovery') return `The engine is in recovery mode and makes bounded changes while collecting fresh measurements; confidence ${confidence}%.`;
  if (decision.mode === 'degraded') return `The selected path is degraded and weaker paths are temporarily deprioritized; confidence ${confidence}%.`;
  return `The selected path currently has the strongest measured health; confidence ${confidence}%.`;
}

/** Stable per-user rotation while still honoring health. If nothing is healthy,
 * allow a bounded half-open recovery probe instead of permanently deadlocking. */
export function orderPathsForUser(pathIds: string[], decision: ResilienceDecision, stableIndex = 0, preferredPathId = ''): string[] {
  const allowed = new Set(pathIds);
  const ranked = decision.candidates.filter(x => x.state !== 'quarantined' && allowed.has(x.id)).map(x => x.id);
  const recovery = decision.recoveryCandidates.filter(id => allowed.has(id));
  const preferred = preferredPathId && allowed.has(preferredPathId) ? [preferredPathId] : [];
  const merged = [...preferred, ...ranked.filter(x => x !== preferredPathId), ...recovery.filter(x => !ranked.includes(x) && x !== preferredPathId), ...pathIds.filter(x => !ranked.includes(x) && !recovery.includes(x) && x !== preferredPathId)];
  const unique = [...new Set(merged)];
  if (!unique.length) return [];
  if (preferred.length) return unique;
  const offset = Math.abs(stableIndex) % unique.length;
  return unique.slice(offset).concat(unique.slice(0, offset));
}
