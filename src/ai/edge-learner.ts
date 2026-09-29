/**
 * Tiny on-edge online learner.
 *
 * This is intentionally small enough to run inside a Worker without a model
 * runtime. It learns a bounded logistic model from connection outcomes and
 * feeds a probability signal into the deterministic path/profile policy.
 * No traffic payloads are retained.
 */

export interface EdgeLearnerState {
  version: 1;
  updates: number;
  bias: number;
  weights: number[];
  updatedAt: number;
}

export interface LearnerFeatures {
  latency: number;
  reliability: number;
  freshness: number;
  trend: number;
  confidence: number;
  continuity: number;
}

const INITIAL_WEIGHTS = [1.15, 1.9, 0.85, 0.55, 0.65, 0.4];
const INITIAL_BIAS = -0.95;
const LEARNING_RATE = 0.045;
const WEIGHT_LIMIT = 4;

export function defaultEdgeLearner(now = Date.now()): EdgeLearnerState {
  return { version: 1, updates: 0, bias: INITIAL_BIAS, weights: [...INITIAL_WEIGHTS], updatedAt: now };
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export function featureVector(f: LearnerFeatures): number[] {
  return [
    clamp(f.latency, 0, 1),
    clamp(f.reliability, 0, 1),
    clamp(f.freshness, 0, 1),
    clamp(f.trend, -1, 1),
    clamp(f.confidence, 0, 1),
    clamp(f.continuity, 0, 1),
  ];
}

export function predictSuccess(state: EdgeLearnerState, features: LearnerFeatures): number {
  const xs = featureVector(features);
  let z = state.bias;
  for (let i = 0; i < xs.length; i++) z += (state.weights[i] ?? 0) * xs[i];
  if (z > 30) return 1;
  if (z < -30) return 0;
  return 1 / (1 + Math.exp(-z));
}

export function updateEdgeLearner(
  state: EdgeLearnerState | undefined,
  features: LearnerFeatures,
  ok: boolean,
  now = Date.now(),
): EdgeLearnerState {
  const current = state ?? defaultEdgeLearner(now);
  const xs = featureVector(features);
  const prediction = predictSuccess(current, features);
  const error = (ok ? 1 : 0) - prediction;
  const next: EdgeLearnerState = {
    version: 1,
    updates: current.updates + 1,
    bias: clamp(current.bias + LEARNING_RATE * error, -WEIGHT_LIMIT, WEIGHT_LIMIT),
    weights: current.weights.map((w, i) => clamp(w + LEARNING_RATE * error * xs[i], -WEIGHT_LIMIT, WEIGHT_LIMIT)),
    updatedAt: now,
  };
  return next;
}

export function observationFeatures(args: {
  latencyMs: number | null;
  failures: number;
  successes: number;
  freshness: number;
  trend: 'improving' | 'stable' | 'declining';
  consecutiveSuccesses: number;
}): LearnerFeatures {
  const total = args.failures + args.successes;
  const reliability = total > 0 ? 1 - args.failures / total : 0.5;
  const latency = args.latencyMs == null ? 0.45 : clamp(1 - args.latencyMs / 1200, 0, 1);
  const trend = args.trend === 'improving' ? 1 : args.trend === 'declining' ? -1 : 0;
  const confidence = clamp(total / 12, 0, 1);
  const continuity = clamp(args.consecutiveSuccesses / 4, 0, 1);
  return { latency, reliability, freshness: clamp(args.freshness, 0, 1), trend, confidence, continuity };
}

/** UCB-style exploration bonus. It is bounded so learning never overwhelms health. */
export function explorationBonus(samples: number, totalSamples: number): number {
  const n = Math.max(0, samples) + 1;
  const total = Math.max(1, totalSamples) + 2;
  return clamp(10 * Math.sqrt(Math.log(total) / n), 0, 10);
}

export function learnerConfidence(state: EdgeLearnerState | undefined): number {
  return clamp(((state?.updates ?? 0) / 40), 0, 1);
}
