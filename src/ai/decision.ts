/**
 * Gozargah 2.13 — internal decision view ("هوش مصنوعی داخلی" verdict).
 *
 * A pure, deterministic synthesis of the existing engine signals — network
 * state, condition estimator, regime intelligence, probe state machine,
 * traffic shape, protocol plan and the emergency entry ladder — into one
 * bounded verdict with reason codes and honest bilingual advice.
 *
 * Honesty rules: no payload is inspected anywhere upstream of this view;
 * `verdict` and `regime` are aggregate statistics, not DPI detection; the
 * advice never claims a bypass guarantee or that a full international outage
 * is restorable from inside the Worker.
 */

import type { RegimeAssessment } from './regime';
import { regimeAdvice } from './regime';
import { localResilienceAdvice } from './resilience';
import type { ResilienceDecision } from './resilience';
import type { ShapeMode } from '../utils/shape';

export type DecisionVerdict = 'stable' | 'watch' | 'degraded' | 'critical';

export interface DecisionInput {
  networkState?: { state: 'healthy' | 'degraded' | 'recovery' | 'no_healthy_path'; confidence: number; updatedAt: number; reasonCodes?: string[] } | null;
  conditionState?: string | null;
  regime?: RegimeAssessment | null;
  probeMode?: 'normal' | 'aggressive';
  shape?: ShapeMode;
  plan?: {
    selected: string | null;
    strategy: 'stable' | 'diversify' | 'safe';
    confidence: number;
    mode: 'normal' | 'degraded' | 'recovery' | 'no_healthy_path';
    fallbackLadder: string[];
    reasonCodes?: string[];
  } | null;
  ladder?: Array<{ host: string; role: string; status: string; latencyMs: number | null }>;
  resilience?: ResilienceDecision | null;
}

export interface DecisionView {
  ok: true;
  verdict: DecisionVerdict;
  score: number;
  regime: { state: string; confidence: number; recentSuccess: number; baselineSuccess: number } | null;
  strategy: string;
  probeMode: 'normal' | 'aggressive';
  trafficShape: ShapeMode;
  activeProfile: string | null;
  fallbackLadder: string[];
  entries: Array<{ host: string; role: string; status: string; latencyMs: number | null }>;
  reasonCodes: string[];
  adviceFa: string;
  adviceEn: string;
  honestLimits: { fa: string; en: string };
  generatedAt: number;
}

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

export function buildDecisionView(input: DecisionInput, now = Date.now()): DecisionView {
  const net = input.networkState;
  const regime = input.regime ?? null;
  const plan = input.plan ?? null;
  const probeMode: 'normal' | 'aggressive' = input.probeMode ?? 'normal';
  const shape: ShapeMode = input.shape ?? 'conservative';

  const reasons: string[] = [];

  // --- verdict (bounded, evidence-ordered) ---
  let verdict: DecisionVerdict = 'stable';
  if (net?.state === 'no_healthy_path' || input.conditionState === 'UPSTREAM_UNAVAILABLE') {
    verdict = 'critical';
    reasons.push('no_healthy_path_from_worker_vantage');
  } else if (
    net?.state === 'recovery' ||
    input.conditionState === 'SEVERELY_DEGRADED' ||
    regime?.state === 'suspected_change'
  ) {
    verdict = 'degraded';
    if (net?.state === 'recovery') reasons.push('network_recovery_mode');
    if (input.conditionState === 'SEVERELY_DEGRADED') reasons.push('severely_degraded_condition');
    if (regime?.state === 'suspected_change') reasons.push('suspected_regime_change');
  } else if (net?.state === 'degraded' || regime?.state === 'watch') {
    verdict = 'watch';
    if (net?.state === 'degraded') reasons.push('network_degraded');
    if (regime?.state === 'watch') reasons.push('regime_watch');
  }
  if (!reasons.length) reasons.push('all_signals_stable');

  // --- score: 0..100 composite of the bounded signals ---
  const netScore = net ? (net.state === 'healthy' ? 0.95 : net.state === 'degraded' ? 0.6 : net.state === 'recovery' ? 0.4 : 0.15) : 0.5;
  const regimeScore = regime
    ? (regime.state === 'stable' ? 0.9 : regime.state === 'recovering' ? 0.75 : regime.state === 'watch' ? 0.5 : 0.3)
    : 0.5;
  const planScore = plan ? clamp01(plan.confidence) : 0.5;
  const entriesOk = input.ladder?.length
    ? input.ladder.filter((e) => e.status === 'measured_ok' || e.role === 'primary').length / input.ladder.length
    : 1;
  const score = Math.round((netScore * 0.4 + regimeScore * 0.25 + planScore * 0.2 + entriesOk * 0.15) * 100);

  // --- advice: compose the honest local texts (no model required) ---
  const partsFa: string[] = [];
  const partsEn: string[] = [];
  if (input.resilience) {
    partsFa.push(localResilienceAdvice(input.resilience, 'fa'));
    partsEn.push(localResilienceAdvice(input.resilience, 'en'));
  }
  partsFa.push(regimeAdvice(regime, 'fa'));
  partsEn.push(regimeAdvice(regime, 'en'));
  if (probeMode === 'aggressive') {
    partsFa.push('ماشین حالت پروب در حالت تهاجمی است: نقاط ورود جایگزین با پروب HTTPS+TCP فراگیرتر زیر نظرند تا اولین مسیر سالم بلافاصله انتخاب شود.');
    partsEn.push('The probe state machine is in aggressive mode: backup entries are under denser HTTPS+TCP probing so the first healthy route is selected as soon as it appears.');
  } else {
    partsFa.push('ماشین حالت پروب در حالت عادی است (پروب مکرر هر ۵ دقیقه).');
    partsEn.push('The probe state machine is in normal mode (periodic 5-minute probes).');
  }
  if (verdict === 'critical') {
    partsFa.push('اگر از شبکهٔ شما هیچ مسیری تا Worker/کلادفلر باقی نمانده باشد، هیچ نرم‌افزاری نمی‌تواند از راه دور مسیر تازه بسازد؛ فقط نقاط ورودِ از پیش قابل‌رسو یا کانال مستقل می‌توانند کمک کنند.');
    partsEn.push('If no route from your network reaches the Worker/Cloudflare edge, no software can create a new route remotely; only pre-provisioned reachable entry points or an independent channel can help.');
  }

  return {
    ok: true,
    verdict,
    score,
    regime: regime
      ? { state: regime.state, confidence: regime.confidence, recentSuccess: regime.recentSuccess, baselineSuccess: regime.baselineSuccess }
      : null,
    strategy: plan?.strategy ?? 'stable',
    probeMode,
    trafficShape: shape,
    activeProfile: plan?.selected ?? null,
    fallbackLadder: plan?.fallbackLadder ?? [],
    entries: input.ladder ?? [],
    reasonCodes: reasons,
    adviceFa: partsFa.join(' '),
    adviceEn: partsEn.join(' '),
    honestLimits: {
      fa: 'همهٔ برچسب‌ها (verdict، regime، condition) بر پایهٔ آمار تجمیعی پروب‌ها و اتصال‌ها هستند؛ نه تشخیص DPI و نه اثبات فیلتر، و عبور از فیلترینگ تضمین نمی‌شود. کد هیچ payloadی را بازرسی نمی‌کند و در قطع کامل مسیر، از راه دور قابل‌رفع نیست.',
      en: 'All labels (verdict, regime, condition) are aggregate probe/dial statistics — not DPI detection, not censorship proof, and no bypass is guaranteed. No payload is inspected, and a fully cut route cannot be restored remotely.',
    },
    generatedAt: now,
  };
}
