/**
 * 2.8 signal-fusion layer.
 *
 * Combines independent aggregate signals before a policy switch is allowed.
 * It never inspects payload bytes, scans arbitrary networks, or identifies a
 * censorship mechanism. The output is a bounded confidence/gating signal.
 */

export type FusionMode = 'stable' | 'cautious' | 'recovery' | 'insufficient_evidence';

export interface FusionInput {
  measuredHealth: number;
  forecastSuccess: number;
  learnerProbability: number;
  networkConfidence: number;
  freshness: number;
  failureRate: number;
  volatility: number;
  sampleCount: number;
  quarantined: boolean;
}

export interface FusionResult {
  consensus: number;
  agreement: number;
  uncertainty: number;
  switchRisk: number;
  mode: FusionMode;
  reasonCodes: string[];
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function distance(a: number, b: number): number {
  return Math.abs(a - b);
}

/**
 * Reliability gate using four partly-independent estimates. Confidence is
 * reduced when the signals disagree or data is stale/volatile.
 */
export function fusePolicySignals(input: FusionInput): FusionResult {
  const measured = clamp(input.measuredHealth, 0, 1);
  const forecast = clamp(input.forecastSuccess, 0, 1);
  const learner = clamp(input.learnerProbability, 0, 1);
  const network = clamp(input.networkConfidence, 0, 1);
  const freshness = clamp(input.freshness, 0, 1);
  const failureRate = clamp(input.failureRate, 0, 1);
  const volatility = clamp(input.volatility, 0, 3);
  const uncertainty = clamp(
    1 - (Math.min(1, input.sampleCount / 16) * 0.55 + freshness * 0.25 + network * 0.20),
    0,
    1,
  );

  const values = [measured, forecast, learner];
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const spread = values.reduce((a, b) => a + distance(b, mean), 0) / values.length;
  const agreement = clamp(1 - spread * 2.2, 0, 1);

  const weighted = measured * 0.36 + forecast * 0.28 + learner * 0.20 + network * 0.16;
  const freshnessPenalty = (1 - freshness) * 0.12;
  const volatilityPenalty = clamp(volatility / 2, 0, 0.5) * 0.10;
  const failurePenalty = Math.max(0, failureRate - 0.35) * 0.22;
  const quarantinePenalty = input.quarantined ? 0.75 : 0;
  const consensus = clamp(weighted * 0.72 + agreement * 0.20 + freshness * 0.08 - freshnessPenalty - volatilityPenalty - failurePenalty - quarantinePenalty, 0, 1);

  const switchRisk = clamp(
    (1 - consensus) * 0.60 + (1 - agreement) * 0.20 + volatility * 0.10 + (1 - freshness) * 0.10,
    0,
    1,
  );

  const reasons: string[] = [];
  if (agreement < 0.55) reasons.push('signal_disagreement');
  if (freshness < 0.4) reasons.push('stale_measurement');
  if (volatility > 0.9) reasons.push('high_volatility');
  if (failureRate > 0.55) reasons.push('high_failure_rate');
  if (input.quarantined) reasons.push('quarantined');
  if (input.sampleCount < 3) reasons.push('low_sample_count');
  if (!reasons.length) reasons.push('multi_signal_consensus');

  let mode: FusionMode = 'stable';
  if (input.sampleCount < 2 || freshness < 0.15) mode = 'insufficient_evidence';
  else if (consensus < 0.45 || input.quarantined) mode = 'recovery';
  else if (consensus < 0.68 || switchRisk > 0.52) mode = 'cautious';

  return {
    consensus: Math.round(consensus * 1000) / 1000,
    agreement: Math.round(agreement * 1000) / 1000,
    uncertainty: Math.round(uncertainty * 1000) / 1000,
    switchRisk: Math.round(switchRisk * 1000) / 1000,
    mode,
    reasonCodes: reasons,
  };
}
