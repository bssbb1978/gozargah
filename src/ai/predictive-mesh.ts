/**
 * Gozargah 2.7 — predictive mesh layer.
 *
 * Lightweight, deterministic forecasting from aggregate health samples.
 * It does not inspect payloads or attempt to identify a censor by name; it
 * estimates whether a path/profile is improving, stable, or deteriorating.
 */

export interface HealthSample {
  ok: boolean;
  latencyMs: number | null;
  ts: number;
}

export interface PredictiveAssessment {
  sampleCount: number;
  reliability: number;
  latencyEwma: number | null;
  latencyVolatility: number;
  successSlope: number;
  latencySlope: number;
  drift: 'improving' | 'stable' | 'degrading';
  forecastSuccess: number;
  confidence: number;
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function slope(values: number[]): number {
  if (values.length < 2) return 0;
  const n = values.length;
  const xMean = (n - 1) / 2;
  const yMean = values.reduce((a, b) => a + b, 0) / n;
  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    const dx = i - xMean;
    num += dx * (values[i] - yMean);
    den += dx * dx;
  }
  return den ? num / den : 0;
}

export function assessHealth(samples: HealthSample[], now = Date.now()): PredictiveAssessment {
  const ordered = samples.filter((x) => Number.isFinite(x.ts)).sort((a, b) => a.ts - b.ts).slice(-24);
  if (!ordered.length) {
    return {
      sampleCount: 0, reliability: 0.5, latencyEwma: null, latencyVolatility: 1,
      successSlope: 0, latencySlope: 0, drift: 'stable', forecastSuccess: 0.5, confidence: 0,
    };
  }

  const success = ordered.map((x) => x.ok ? 1 : 0);
  const latencies = ordered.filter((x) => x.latencyMs != null).map((x) => Math.max(1, x.latencyMs as number));
  const reliability = success.reduce((a: number, b) => a + b, 0) / success.length;

  let ewma: number | null = null;
  const alpha = 0.35;
  for (const value of latencies) ewma = ewma == null ? value : ewma * (1 - alpha) + value * alpha;

  const successSlope = slope(success);
  const latencySlope = latencies.length > 1 ? slope(latencies) : 0;
  const meanLat = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
  const variance = latencies.length > 1
    ? latencies.reduce((acc, value) => acc + Math.pow(value - meanLat, 2), 0) / latencies.length
    : 0;
  const latencyVolatility = meanLat > 0 ? clamp(Math.sqrt(variance) / meanLat, 0, 3) : 1;

  const recentWindow = ordered.filter((x) => now - x.ts <= 15 * 60_000);
  const freshness = clamp(recentWindow.length / Math.max(4, Math.min(12, ordered.length)), 0, 1);
  const slopeSignal = clamp(successSlope * 3.2, -1, 1);
  const latencySignal = latencies.length ? clamp(-latencySlope / 250, -1, 1) : 0;
  const volatilityPenalty = clamp(latencyVolatility / 2, 0, 0.6);
  const forecastSuccess = clamp(reliability + slopeSignal * 0.12 + latencySignal * 0.08 - volatilityPenalty * 0.08, 0, 1);

  const degradation = successSlope < -0.06 || latencySlope > 120 || latencyVolatility > 0.85;
  const improvement = successSlope > 0.06 && latencySlope < -10 && latencyVolatility < 0.80;
  const drift = degradation ? 'degrading' : improvement ? 'improving' : 'stable';
  const confidence = clamp((ordered.length / 12) * 0.65 + freshness * 0.25 + (latencies.length ? 0.1 : 0), 0, 1);

  return {
    sampleCount: ordered.length,
    reliability,
    latencyEwma: ewma,
    latencyVolatility,
    successSlope,
    latencySlope,
    drift,
    forecastSuccess,
    confidence,
  };
}

export function combineForecast(base: number, predictive: PredictiveAssessment): number {
  const weight = clamp(predictive.confidence, 0, 1) * 0.35;
  return clamp(base * (1 - weight) + predictive.forecastSuccess * weight, 0, 1);
}
