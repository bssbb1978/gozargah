/**
 * Lightweight local ensemble used by the adaptive controller.
 * No model runtime or traffic payloads are required.
 */

export interface BayesianReliability {
  mean: number;
  lower: number;
  upper: number;
  certainty: number;
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

/** Jeffreys-smoothed Bernoulli posterior with a bounded credible interval. */
export function bayesianReliability(successes: number, failures: number): BayesianReliability {
  const s = Math.max(0, successes);
  const f = Math.max(0, failures);
  const alpha = s + 0.5;
  const beta = f + 0.5;
  const total = alpha + beta;
  const mean = alpha / total;
  const variance = (alpha * beta) / (total * total * (total + 1));
  const sigma = Math.sqrt(Math.max(0, variance));
  const lower = clamp(mean - 1.64 * sigma, 0, 1);
  const upper = clamp(mean + 1.64 * sigma, 0, 1);
  const certainty = clamp((s + f) / 20, 0, 1);
  return { mean, lower, upper, certainty };
}

/** Conservative score: uncertainty is treated as risk, not as free confidence. */
export function riskAdjustedReliability(successes: number, failures: number): number {
  const posterior = bayesianReliability(successes, failures);
  return clamp((posterior.lower * 0.70) + (posterior.mean * 0.30), 0, 1);
}
