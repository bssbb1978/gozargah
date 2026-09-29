/**
 * Gozargah 2.12 — regime intelligence (internal AI, deterministic).
 *
 * Detects *statistical regime changes* in the aggregate outcome stream of
 * configured paths — e.g. the success rate stepping down sharply, which is
 * consistent with a newly applied filtering regime, a network incident, or a
 * degraded upstream. It is the "fast reflex" layer on top of the slower
 * EWMA/slope machinery in predictive-mesh.ts.
 *
 * Honesty rules (same as the rest of the engine):
 *   - bounded aggregate statistics only (ok/fail + latency of configured
 *     probes and dials); no traffic payloads, no packet inspection;
 *   - never identifies a DPI system or attributes a censor; output states
 *     are "suspected"/"watch", not detection;
 *   - a step change has multiple explanations (incident, outage, new rule).
 *
 * Method (deterministic, no model runtime):
 *   1. Dual timescale: recent window (30 min) vs baseline window
 *      (previous 60 min) success rate with minimum sample floors.
 *   2. Step-change rule: baseline >= 0.55 and recent <= 0.20 ->
 *      suspected_change; symmetric rule for confirmed recovery.
 *   3. One-sided CUSUM over the ordered success stream for gradual drift.
 */

import type { HealthSample } from './predictive-mesh';

export type RegimeState = 'stable' | 'watch' | 'suspected_change' | 'recovering';

export interface RegimeAssessment {
  state: RegimeState;
  sampleCount: number;
  baselineSuccess: number;
  recentSuccess: number;
  /** baseline - recent, clamped to 0..1; positive means the recent window is worse. */
  deterioration: number;
  /** bounded one-sided CUSUM statistic over the success stream */
  cusum: number;
  /** 0..1 confidence in the current regime label (evidence volume + strength) */
  confidence: number;
  reasonCodes: string[];
  generatedAt: number;
}

const RECENT_WINDOW_MS = 30 * 60_000;
const BASELINE_WINDOW_MS = 60 * 60_000;
const MIN_RECENT_SAMPLES = 3;
const MIN_BASELINE_SAMPLES = 3;
const MAX_SAMPLES = 60;

const STEP_BASELINE_MIN = 0.55;
const STEP_RECENT_MAX = 0.2;
const RECOVER_BASELINE_MAX = 0.3;
const RECOVER_RECENT_MIN = 0.75;
const DETERIORATION_WATCH = 0.25;

const CUSUM_K = 0.15;
const CUSUM_P0 = 0.5;
const CUSUM_ALARM = 2.5;
const CUSUM_CAP = 6;

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}
function round3(n: number): number {
  return Math.round(clamp(n, 0, 1) * 1000) / 1000;
}

export function emptyRegime(now = Date.now()): RegimeAssessment {
  return {
    state: 'stable',
    sampleCount: 0,
    baselineSuccess: 0.5,
    recentSuccess: 0.5,
    deterioration: 0,
    cusum: 0,
    confidence: 0,
    reasonCodes: ['no_regime_evidence'],
    generatedAt: now,
  };
}

/**
 * Assess the current regime from ordered aggregate outcome samples.
 * `samples` are ok/fail + latency observations of configured probes/dials —
 * never payload-derived.
 */
export function assessRegime(samples: HealthSample[], now = Date.now()): RegimeAssessment {
  const ordered = samples
    .filter((x) => Number.isFinite(x.ts) && x.ts > 0)
    .sort((a, b) => a.ts - b.ts)
    .slice(-MAX_SAMPLES);

  if (ordered.length < MIN_RECENT_SAMPLES + MIN_BASELINE_SAMPLES) {
    const recent = ordered.filter((x) => now - x.ts <= RECENT_WINDOW_MS);
    const recentRate = recent.length ? recent.filter((x) => x.ok).length / recent.length : 0.5;
    return {
      ...emptyRegime(now),
      sampleCount: ordered.length,
      recentSuccess: round3(recentRate),
      reasonCodes: ['insufficient_evidence'],
    };
  }

  const recent = ordered.filter((x) => now - x.ts <= RECENT_WINDOW_MS);
  const baseline = ordered.filter((x) => {
    const age = now - x.ts;
    return age > RECENT_WINDOW_MS && age <= RECENT_WINDOW_MS + BASELINE_WINDOW_MS;
  });
  const recentRate = recent.length ? recent.filter((x) => x.ok).length / recent.length : 0.5;
  const baseRate = baseline.length ? baseline.filter((x) => x.ok).length / baseline.length : 0.5;

  // One-sided CUSUM (lower branch): accumulates evidence of sustained
  // FAILURES relative to a healthy 0.5 success baseline. Each failure adds
  // +0.35, each success adds -0.65; under a healthy stream the expected
  // increment is negative, so a rising statistic means the recent stream is
  // worse than the baseline. Floor at 0 keeps it one-sided; cap keeps it bounded.
  let s = 0;
  for (const x of ordered) {
    s = Math.max(0, s + (CUSUM_P0 - CUSUM_K) - (x.ok ? 1 : 0));
    if (s >= CUSUM_CAP) { s = CUSUM_CAP; break; }
  }

  const deterioration = clamp(baseRate - recentRate, 0, 1);
  const enough = baseline.length >= MIN_BASELINE_SAMPLES && recent.length >= MIN_RECENT_SAMPLES;
  const stepChange = enough && baseRate >= STEP_BASELINE_MIN && recentRate <= STEP_RECENT_MAX;
  const recovering = enough && baseRate <= RECOVER_BASELINE_MAX && recentRate >= RECOVER_RECENT_MIN;

  const reasons: string[] = [];
  let state: RegimeState = 'stable';
  if (stepChange) {
    state = 'suspected_change';
    reasons.push('step_change_down');
  } else if (recovering) {
    state = 'recovering';
    reasons.push('recovery_confirmed');
  } else if (deterioration >= DETERIORATION_WATCH || s >= CUSUM_ALARM) {
    state = 'watch';
    if (deterioration >= DETERIORATION_WATCH) reasons.push('deterioration_above_threshold');
    if (s >= CUSUM_ALARM) reasons.push('cusum_drift');
  }
  if (!enough) reasons.push('insufficient_baseline');
  if (!reasons.length) reasons.push('stable_baseline');

  const evidence = stepChange ? 0.5 : recovering ? 0.45 : deterioration >= DETERIORATION_WATCH ? 0.35 : s >= CUSUM_ALARM ? 0.3 : 0.15;
  const confidence = clamp(
    Math.min(1, recent.length / 6) * 0.45 + Math.min(1, baseline.length / 10) * 0.35 + evidence,
    0,
    1,
  );

  return {
    state,
    sampleCount: ordered.length,
    baselineSuccess: round3(baseRate),
    recentSuccess: round3(recentRate),
    deterioration: round3(deterioration),
    cusum: Math.round(s * 100) / 100,
    confidence: round3(confidence),
    reasonCodes: reasons,
    generatedAt: now,
  };
}

/** Honest, bilingual one-liner for panels/bundles. Never claims DPI detection. */
export function regimeAdvice(regime: RegimeAssessment | null, language: 'fa' | 'en'): string {
  if (!regime || regime.state === 'stable') {
    return language === 'fa'
      ? 'وضعیت رژیم اتصال پایدار است (بر اساس آمار تجمیعی پروب‌ها و اتصال‌ها).'
      : 'Connection regime is stable (aggregate probe/dial statistics).';
  }
  if (language === 'fa') {
    if (regime.state === 'suspected_change') {
      return 'نرخ موفقیت در پنجرهٔ اخیر نسبت به خط پایه افت محسوس دارد. این فقط آمار تجمیعی است (نه تشخیص DPI و نه اثبات فیلتر) و می‌تواند نشانهٔ تغییر رژیم فیلتر، حادثهٔ شبکه یا مشکل اپراتور باشد؛ موتور به‌طور خودکار تنوع ترنسپورت و نقاط ورود را افزایش می‌دهد.';
    }
    if (regime.state === 'recovering') {
      return 'نرخ موفقیت در پنجرهٔ اخیر نسبت به خط پایه بهبود یافته و رژیم به حالت پایدار در حال بازگشت است.';
    }
    return 'نشانه‌های اولیهٔ افت کیفیت دیده می‌شود (آمار تجمیعی؛ نه تشخیص DPI). موتور در حالت پایش است و تغییر سیاست صرفاً با شواهد بیشتر انجام می‌شود.';
  }
  if (regime.state === 'suspected_change') {
    return 'The recent success rate dropped materially versus baseline. This is aggregate statistics only (not DPI detection or proof of filtering) and may indicate a regime change, a network incident, or an operator issue; the engine automatically increases transport/entry diversity.';
  }
  if (regime.state === 'recovering') {
    return 'The recent success rate recovered versus baseline; the regime is returning to stable.';
  }
  return 'Early signs of degradation are visible (aggregate statistics; not DPI detection). The engine is in watch mode and only changes policy with stronger evidence.';
}
