/**
 * Gozargah 2.4 — live protocol controller.
 *
 * This layer converts the static capability catalog + recent aggregate health
 * into a bounded, auditable fallback ladder. It does not mutate protocol bytes
 * and it never invents unsupported transports.
 */
import type { AdaptiveProtocolProfile } from '../protocols/policy';
import type { NetworkStateDecision } from './network-state';
import type { EdgeLearnerState } from './edge-learner';
import { explorationBonus, observationFeatures, predictSuccess } from './edge-learner';
import { bayesianReliability, riskAdjustedReliability } from './ensemble';
import type { PredictiveAssessment } from './predictive-mesh';
import { combineForecast } from './predictive-mesh';
import { fusePolicySignals, type FusionResult } from './signal-fusion';
import type { RegimeAssessment, RegimeState } from './regime';

export interface ControllerProfileHealth {
  profileId: string;
  latencyMs: number | null;
  failures: number;
  successes: number;
  quarantineUntil: number;
  checkedAt: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
}

export interface AdaptiveProtocolPlan {
  version: '2.12-regime-mesh-v1';
  selected: string | null;
  fallbackLadder: string[];
  confidence: number;
  mode: 'normal' | 'degraded' | 'recovery' | 'no_healthy_path';
  reasonCodes: string[];
  diversity: { protocols: string[]; transports: string[]; securities: string[] };
  learnerConfidence: number;
  policyFingerprint: string;
  generatedAt: number;
  strategy: 'stable' | 'diversify' | 'safe';
  failureDomains: string[];
  forecastSuccess: number;
  drift: 'improving' | 'stable' | 'degrading';
  volatility: number;
  consensus: number;
  signalAgreement: number;
  switchRisk: number;
  fusionMode: FusionResult['mode'];
  /** 2.12 — aggregate-statistics regime label (never a DPI claim). */
  regimeState: RegimeState;
  regimeConfidence: number;
}


function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function hash32(text: string): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

function healthScore(h: ControllerProfileHealth | undefined, now: number): { score: number; known: boolean; failureRate: number; posterior: ReturnType<typeof bayesianReliability> } {
  if (!h) return { score: 0, known: false, failureRate: 0.5, posterior: bayesianReliability(0, 0) };
  const total = h.failures + h.successes;
  const age = h.checkedAt > 0 ? Math.max(0, now - h.checkedAt) : Number.POSITIVE_INFINITY;
  const freshness = Number.isFinite(age) ? clamp(1 - age / (20 * 60_000), 0, 1) : 0;
  const failureRate = total ? h.failures / total : 0.5;
  const posterior = bayesianReliability(h.successes, h.failures);
  const reliability = riskAdjustedReliability(h.successes, h.failures);
  const latency = h.latencyMs == null ? 0.5 : clamp(1 - h.latencyMs / 1200, 0, 1);
  const continuity = clamp(h.consecutiveSuccesses / 4, 0, 1);
  const penalty = h.quarantineUntil > now ? 100 : 0;
  const score = clamp((reliability * 46) + (latency * 18) + (freshness * 14) + (continuity * 12) + (posterior.certainty * 10) - penalty, 0, 100);
  return { score, known: total > 0 && freshness > 0.1, failureRate, posterior };
}

/**
 * Select a live fallback ladder from capability profiles.
 * Diversity is intentional: the ladder should not contain only one protocol or
 * one transport family when alternatives actually exist.
 */
export function buildAdaptiveProtocolPlan(args: {
  profiles: AdaptiveProtocolProfile[];
  health?: ControllerProfileHealth[];
  networkState?: NetworkStateDecision | null;
  learner?: EdgeLearnerState;
  preferredProfileId?: string;
  /** Opt-in Workers AI hint, applied only to capability-ready candidates. */
  preferredTransport?: string;
  predictive?: Record<string, PredictiveAssessment>;
  /** 2.12 — aggregate regime intelligence from scheduled health + dial outcomes. */
  regime?: RegimeAssessment;
  limit?: number;
  now?: number;
}): AdaptiveProtocolPlan {
  const now = args.now ?? Date.now();
  const limit = Math.max(2, Math.min(args.limit ?? 8, 12));
  const healthMap = new Map((args.health ?? []).map((h) => [h.profileId, h]));
  const net = args.networkState;
  const regime = args.regime;

  const samplesTotal = (args.health ?? []).reduce((n, h) => n + h.failures + h.successes, 0);
  let strategy: AdaptiveProtocolPlan['strategy'] =
    net?.state === 'no_healthy_path' || net?.signalClass === 'broad_degradation' ? 'safe' :
    net?.state === 'recovery' || net?.signalClass === 'selective_degradation' ? 'diversify' : 'stable';
  // 2.12: a suspected aggregate regime change (e.g. a freshly applied filter
  // list) upgrades a calm 'stable' policy to 'diversify' so the emitted
  // fallback ladder spans more transport/protocol families. 'safe' stays.
  if (regime?.state === 'suspected_change' && strategy === 'stable') strategy = 'diversify';

  const familyStats = new Map<string, { samples: number; failures: number; successes: number }>();
  for (const p of args.profiles) {
    const h = healthMap.get(p.id);
    if (!h) continue;
    const family = p.protocol + ':' + p.transport;
    const cur = familyStats.get(family) ?? { samples: 0, failures: 0, successes: 0 };
    cur.samples += h.failures + h.successes;
    cur.failures += h.failures;
    cur.successes += h.successes;
    familyStats.set(family, cur);
  }
  const riskyFamilies = [...familyStats.entries()]
    .filter(([, x]) => x.samples >= 4 && x.failures / x.samples >= 0.65)
    .map(([family]) => family);

  const scored = args.profiles.filter((p) => p.ready).map((p) => {
    const h = healthScore(healthMap.get(p.id), now);
    const predictive = args.predictive?.[p.id];
    const posterior = h.posterior;
    const modelProbability = args.learner
      ? predictSuccess(args.learner, observationFeatures({
          latencyMs: healthMap.get(p.id)?.latencyMs ?? null,
          failures: healthMap.get(p.id)?.failures ?? 0,
          successes: healthMap.get(p.id)?.successes ?? 0,
          freshness: h.known ? 1 : 0.2,
          trend: (healthMap.get(p.id)?.consecutiveSuccesses ?? 0) >= 2 ? 'improving' : ((healthMap.get(p.id)?.consecutiveFailures ?? 0) >= 2 ? 'declining' : 'stable'),
          consecutiveSuccesses: healthMap.get(p.id)?.consecutiveSuccesses ?? 0,
        }))
      : 0.5;
    const exploration = explorationBonus((healthMap.get(p.id)?.failures ?? 0) + (healthMap.get(p.id)?.successes ?? 0), samplesTotal);
    let score = p.score * 0.42;
    if (h.known) score += h.score * 0.32;
    if (predictive) {
      const forecast = combineForecast(h.known ? h.score / 100 : 0.5, predictive);
      score += forecast * 12;
      if (predictive.drift === 'degrading') score -= 16;
      else if (predictive.drift === 'improving') score += 6;
      if (predictive.latencyVolatility > 0.85) score -= 8;
    }
    else score += strategy === 'safe' ? 0 : 4;
    score += modelProbability * 10;
    score += posterior.mean * 6;
    score += strategy === 'diversify' ? exploration * 0.45 : strategy === 'safe' ? -exploration * 0.3 : exploration * 0.25;
    if (args.preferredProfileId && p.id === args.preferredProfileId) score += 6;
    if (args.preferredTransport && p.transport === args.preferredTransport) score += 6;
    if (strategy === 'diversify' && p.transport !== 'ws') score += 6;
    if (strategy === 'safe' && h.known && h.failureRate < 0.25) score += 9;
    const family = p.protocol + ':' + p.transport;
    if (riskyFamilies.includes(family)) score -= 28;
    if (h.known && h.failureRate > 0.45) score -= 18;
    if (h.known && h.failureRate > 0.70) score -= 22;
    if (h.score < 25) score -= 30;
    const candidateSamples = (healthMap.get(p.id)?.failures ?? 0) + (healthMap.get(p.id)?.successes ?? 0);
    const freshness = h.known ? clamp(1 - Math.max(0, now - (healthMap.get(p.id)?.checkedAt ?? 0)) / (20 * 60_000), 0, 1) : 0;
    const fusion = fusePolicySignals({
      measuredHealth: h.score / 100,
      forecastSuccess: predictive?.forecastSuccess ?? (h.known ? h.score / 100 : 0.5),
      learnerProbability: modelProbability,
      networkConfidence: net?.confidence ?? 0.5,
      freshness,
      failureRate: h.failureRate,
      volatility: predictive?.latencyVolatility ?? 1,
      sampleCount: candidateSamples,
      quarantined: h.known && healthMap.get(p.id)!.quarantineUntil > now,
    });
    score += fusion.consensus * 7;
    score -= fusion.switchRisk * 5;
    if (fusion.mode === 'recovery') score -= 8;
    if (fusion.mode === 'cautious') score -= 2;
    return { p, score: clamp(score, 0, 100), known: h.known, failureRate: h.failureRate, quarantined: h.known && healthMap.get(p.id)!.quarantineUntil > now, family, posterior, modelProbability, exploration, predictive, fusion };
  }).sort((a,b) => b.score - a.score || b.p.score - a.p.score || a.p.id.localeCompare(b.p.id));

  const safeMeasured = scored.filter(x => !x.quarantined && x.known && x.failureRate < 0.35);
  const selected = (strategy === 'safe' ? safeMeasured[0] : null) ?? scored.filter(x => !x.quarantined)[0] ?? scored[0] ?? null;
  const ladder: typeof scored = [];
  const seenProtocols = new Set<string>();
  const seenTransports = new Set<string>();

  // First pass: maximize protocol + transport diversity.
  for (const candidate of scored) {
    if (candidate.quarantined) continue;
    const protocol = candidate.p.protocol;
    const transport = candidate.p.transport;
    if (seenProtocols.has(protocol) && seenTransports.has(transport)) continue;
    ladder.push(candidate);
    seenProtocols.add(protocol);
    seenTransports.add(transport);
    if (ladder.length >= limit) break;
  }
  // Second pass: fill remaining slots with highest-scoring healthy candidates.
  for (const candidate of scored) {
    if (candidate.quarantined || ladder.some(x => x.p.id === candidate.p.id)) continue;
    ladder.push(candidate);
    if (ladder.length >= limit) break;
  }

  const selectedId = selected?.p.id ?? null;
  const selectedPredictive = selected?.predictive;
  const forecastSuccess = selectedPredictive?.forecastSuccess ?? (selected?.known ? clamp(selected?.score ?? 50, 0, 100) / 100 : 0.5);
  const drift = selectedPredictive?.drift ?? 'stable';
  const volatility = selectedPredictive?.latencyVolatility ?? 1;
  const consensus = selected?.fusion?.consensus ?? 0.5;
  const signalAgreement = selected?.fusion?.agreement ?? 0.5;
  const switchRisk = selected?.fusion?.switchRisk ?? 0.5;
  const fusionMode = selected?.fusion?.mode ?? 'insufficient_evidence';
  const best = selected?.score ?? 0;
  const second = ladder[1]?.score ?? best;
  const observedCoverage = ladder.length ? ladder.filter(x => x.known).length / ladder.length : 0;
  const confidence = clamp((best / 100) * 0.55 + (Math.max(0, best - second) / 100) * 0.20 + observedCoverage * 0.25, 0, 1);

  const reasonCodes: string[] = [];
  if (args.preferredProfileId && selectedId === args.preferredProfileId) reasonCodes.push('per_user_preference');
  if (args.preferredTransport && selected?.p.transport === args.preferredTransport) reasonCodes.push('ai_advisor_transport_preference');
  if (ladder.length > 1) reasonCodes.push('diverse_fallback_ladder');
  if (net?.state === 'unknown' || net?.signalClass === 'insufficient_evidence') reasonCodes.push('network_evidence_unknown');
  if (net?.state === 'recovery' || net?.state === 'no_healthy_path') reasonCodes.push('network_recovery_bias');
  if (ladder.some(x => x.p.mode === 'origin-engine')) reasonCodes.push('origin_engine_available');
  if (ladder.some(x => x.p.udp)) reasonCodes.push('udp_capability_available');
  if (ladder.some(x => !x.known)) reasonCodes.push('bounded_exploration');
  if (strategy === 'safe') reasonCodes.push('safe_mode');
  if (strategy === 'diversify') reasonCodes.push('diversification_mode');
  if (riskyFamilies.length) reasonCodes.push('failure_domain_penalty');
  if (regime?.state === 'suspected_change') reasonCodes.push('suspected_regime_change');
  else if (regime?.state === 'recovering') reasonCodes.push('regime_recovering');
  else if (regime?.state === 'watch') reasonCodes.push('regime_watch');
  if (drift === 'degrading') reasonCodes.push('predictive_drift_penalty');
  else if (drift === 'improving') reasonCodes.push('predictive_improvement_bonus');
  if (volatility > 0.85) reasonCodes.push('latency_volatility_guard');
  if (consensus >= 0.68) reasonCodes.push('multi_signal_consensus');
  else if (consensus < 0.45) reasonCodes.push('multi_signal_recovery');
  if (signalAgreement < 0.55) reasonCodes.push('signal_disagreement');
  if (switchRisk > 0.52) reasonCodes.push('switch_risk_guard');
  if (!reasonCodes.length) reasonCodes.push('best_measured_capability');

  const diversity = {
    protocols: [...new Set(ladder.map(x => x.p.protocol))],
    transports: [...new Set(ladder.map(x => x.p.transport))],
    securities: [...new Set(ladder.map(x => x.p.security))],
  };
  const fingerprint = hash32(JSON.stringify({ v: '2.12-regime-mesh-v1', strategy, selected: selectedId, ladder: ladder.map(x => x.p.id), diversity, riskyFamilies, net: net?.state ?? 'unknown', regime: regime?.state ?? 'stable' }));

  let mode: AdaptiveProtocolPlan['mode'] = 'normal';
  if (!selected) mode = 'no_healthy_path';
  else if (net?.state === 'recovery' || net?.state === 'no_healthy_path') mode = 'recovery';
  else if (confidence < 0.55 || selected.score < 55) mode = 'degraded';

  return {
    version: '2.12-regime-mesh-v1',
    selected: selectedId,
    fallbackLadder: ladder.map(x => x.p.id),
    confidence: Math.round(confidence * 100) / 100,
    mode,
    reasonCodes,
    diversity,
    learnerConfidence: Math.round(clamp((args.learner?.updates ?? 0) / 40, 0, 1) * 100) / 100,
    policyFingerprint: fingerprint,
    generatedAt: now,
    strategy,
    failureDomains: riskyFamilies,
    forecastSuccess: Math.round(forecastSuccess * 100) / 100,
    drift,
    volatility: Math.round(volatility * 100) / 100,
    consensus: Math.round(consensus * 100) / 100,
    signalAgreement: Math.round(signalAgreement * 100) / 100,
    switchRisk: Math.round(switchRisk * 100) / 100,
    fusionMode,
    regimeState: regime?.state ?? 'stable',
    regimeConfidence: regime ? Math.round(regime.confidence * 100) / 100 : 0,
  };
}
