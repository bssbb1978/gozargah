import { buildDecisionView } from '../ai/decision';
import { assessRegime } from '../ai/regime';
import type { RegimeAssessment } from '../ai/regime';

const T0 = 1_700_000_000_000;
const MIN = 60_000;

function regimeFixture(kind: 'change' | 'stable'): RegimeAssessment {
  const baseline = Array.from({ length: 20 }, (_, i) => ({ ok: true, latencyMs: 120, ts: T0 - 89 * MIN + i * 2 * MIN }));
  const recent = kind === 'change'
    ? Array.from({ length: 10 }, (_, i) => ({ ok: false, latencyMs: 3000, ts: T0 - 29 * MIN + i * 2 * MIN }))
    : Array.from({ length: 10 }, (_, i) => ({ ok: true, latencyMs: 120, ts: T0 - 29 * MIN + i * 2 * MIN }));
  const a = assessRegime([...baseline, ...recent], T0);
  if (kind === 'change' && a.state !== 'suspected_change') throw new Error('fixture must be suspected_change');
  if (kind === 'stable' && a.state !== 'stable') throw new Error('fixture must be stable');
  return a;
}

// 1) all-healthy -> stable, bounded score, honest limits present
{
  const v = buildDecisionView({
    networkState: { state: 'healthy', confidence: 0.9, updatedAt: T0 },
    regime: regimeFixture('stable'),
    plan: { selected: 'vless:ws:tls', strategy: 'stable', confidence: 0.8, mode: 'normal', fallbackLadder: ['vless:ws:tls', 'trojan:ws:tls'] },
    ladder: [{ host: 'primary', role: 'primary', status: 'primary', latencyMs: null }],
  }, T0);
  if (v.verdict !== 'stable') throw new Error('healthy inputs must be stable, got ' + v.verdict);
  if (v.score < 0 || v.score > 100) throw new Error('score out of bounds');
  if (!v.adviceFa.length || !v.adviceEn.length) throw new Error('bilingual advice required');
  if (!/تضمین نمی‌شود|not DPI/.test(v.honestLimits.fa + v.honestLimits.en)) throw new Error('honest limits missing');
  if (v.strategy !== 'stable' || v.activeProfile !== 'vless:ws:tls') throw new Error('plan metadata missing');
}

// 2) no healthy path -> critical + the "no remote route" honesty
{
  const v = buildDecisionView({
    networkState: { state: 'no_healthy_path', confidence: 0.6, updatedAt: T0 },
    ladder: [
      { host: 'primary', role: 'primary', status: 'primary', latencyMs: null },
      { host: 'backup.example', role: 'backup', status: 'measured_failed', latencyMs: null },
    ],
  }, T0);
  if (v.verdict !== 'critical') throw new Error('no_healthy_path must be critical, got ' + v.verdict);
  if (!/مسیر تازه|new route/.test(v.adviceFa + v.adviceEn)) throw new Error('critical advice must state the no-remote-route limit');
}

// 3) missing or explicitly unknown network evidence is never reported as stable/online
{
  for (const networkState of [
    undefined,
    { state: 'unknown' as const, confidence: 0, updatedAt: T0, reasonCodes: ['no_recent_probe_data'] },
  ]) {
    const v = buildDecisionView({ networkState }, T0);
    if (v.verdict !== 'watch') throw new Error('unknown network evidence must be watch, got ' + v.verdict);
    if (!v.reasonCodes.includes('network_evidence_unknown')) throw new Error('unknown-evidence reason code missing');
    if (!/unknown|نامشخص/.test(v.adviceEn + v.adviceFa)) throw new Error('unknown-evidence advice missing');
  }
  const stale = buildDecisionView({
    networkState: { state: 'healthy', confidence: 0.9, updatedAt: T0 - 600_001, reasonCodes: ['condition_upstream_unavailable'] },
    conditionState: 'UPSTREAM_UNAVAILABLE',
  }, T0);
  if (stale.verdict !== 'watch' || !stale.reasonCodes.includes('network_evidence_unknown')) {
    throw new Error('stale network/condition data must not remain online or offline evidence');
  }
}

// 4) suspected regime change on a calm network -> degraded
{
  const v = buildDecisionView({
    networkState: { state: 'healthy', confidence: 0.9, updatedAt: T0 },
    regime: regimeFixture('change'),
  }, T0);
  if (v.verdict !== 'degraded') throw new Error('suspected_change must be degraded, got ' + v.verdict);
  if (!v.reasonCodes.includes('suspected_regime_change')) throw new Error('reason code missing');
  if (v.regime?.state !== 'suspected_change') throw new Error('regime metadata missing');
}

// 5) degraded network state -> watch
{
  const v = buildDecisionView({ networkState: { state: 'degraded', confidence: 0.7, updatedAt: T0 } }, T0);
  if (v.verdict !== 'watch') throw new Error('degraded network must be watch, got ' + v.verdict);
}

// 6) aggressive probe mode surfaces in the view
{
  const v = buildDecisionView({
    networkState: { state: 'recovery', confidence: 0.5, updatedAt: T0 },
    probeMode: 'aggressive',
    shape: 'aggressive',
  }, T0);
  if (v.verdict !== 'degraded') throw new Error('recovery must be degraded');
  if (v.probeMode !== 'aggressive' || v.trafficShape !== 'aggressive') throw new Error('probe/shape metadata missing');
}

// 7) condition UPSTREAM_UNAVAILABLE alone is critical
{
  const v = buildDecisionView({ conditionState: 'UPSTREAM_UNAVAILABLE' });
  if (v.verdict !== 'critical') throw new Error('UPSTREAM_UNAVAILABLE must be critical');
}

console.log('decision: ok');
