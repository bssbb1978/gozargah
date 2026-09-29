import { assessRegime, emptyRegime, regimeAdvice } from '../ai/regime';
import type { HealthSample } from '../ai/predictive-mesh';

function stream(start: number, stepMs: number, pattern: Array<0 | 1>): HealthSample[] {
  return pattern.map((ok, i) => ({ ok: ok === 1, latencyMs: ok ? 120 : 3000, ts: start + i * stepMs }));
}

const T0 = 1_700_000_000_000;
const MIN = 60_000;

// 1) steady success -> stable
{
  const samples = stream(T0 - 90 * MIN, 2 * MIN, new Array(45).fill(1) as Array<0 | 1>);
  const a = assessRegime(samples, T0);
  if (a.state !== 'stable') throw new Error('steady stream should be stable, got ' + a.state);
  if (a.reasonCodes.length === 0) throw new Error('stable reason code missing');
}

// 2) good baseline (60..30 min ago) then sustained failures (last 30 min) -> suspected_change
{
  const samples = [
    ...stream(T0 - 89 * MIN, 2 * MIN, new Array(20).fill(1) as Array<0 | 1>), // baseline: all ok
    ...stream(T0 - 29 * MIN, 2 * MIN, new Array(10).fill(0) as Array<0 | 1>), // recent: all fail
  ];
  const a = assessRegime(samples, T0);
  if (a.state !== 'suspected_change') throw new Error('step change should be suspected_change, got ' + a.state);
  if (a.baselineSuccess < 0.55) throw new Error('baseline should be high');
  if (a.recentSuccess > 0.2) throw new Error('recent should be low');
  if (a.confidence <= 0) throw new Error('confidence should be positive');
  if (!/^[0-9.]+$/.test(String(a.cusum))) throw new Error('cusum not numeric');
}

// 3) bad baseline then sustained success -> recovering
{
  const samples = [
    ...stream(T0 - 89 * MIN, 2 * MIN, new Array(20).fill(0) as Array<0 | 1>),
    ...stream(T0 - 29 * MIN, 2 * MIN, new Array(10).fill(1) as Array<0 | 1>),
  ];
  const a = assessRegime(samples, T0);
  if (a.state !== 'recovering') throw new Error('step up should be recovering, got ' + a.state);
}

// 4) too few samples -> stable + insufficient_evidence
{
  const a = assessRegime(stream(T0 - 10 * MIN, 2 * MIN, [1, 0, 1]), T0);
  if (a.state !== 'stable') throw new Error('low sample should stay stable');
  if (!a.reasonCodes.includes('insufficient_evidence')) throw new Error('insufficient_evidence reason missing');
}

// 5) gradual deterioration (baseline ok, recent mixed with more failures) -> watch
{
  const pattern: Array<0 | 1> = [1, 1, 0, 1, 0, 0, 1, 0, 0, 0];
  const samples = [
    ...stream(T0 - 89 * MIN, 2 * MIN, new Array(14).fill(1) as Array<0 | 1>),
    ...stream(T0 - 29 * MIN, 2 * MIN, pattern),
  ];
  const a = assessRegime(samples, T0);
  if (a.state !== 'watch' && a.state !== 'suspected_change') throw new Error('deterioration should be watch/suspected_change, got ' + a.state);
  if (a.deterioration < 0.2) throw new Error('deterioration should be visible');
}

// 6) empty stream -> empty regime shape
{
  const a = emptyRegime(T0);
  if (a.state !== 'stable' || a.sampleCount !== 0 || a.confidence !== 0) throw new Error('empty regime shape broken');
}

// 7) advice text is honest (no DPI-claim words as detection)
{
  const samples = [
    ...stream(T0 - 89 * MIN, 2 * MIN, new Array(20).fill(1) as Array<0 | 1>),
    ...stream(T0 - 29 * MIN, 2 * MIN, new Array(10).fill(0) as Array<0 | 1>),
  ];
  const fa = regimeAdvice(assessRegime(samples, T0), 'fa');
  const en = regimeAdvice(assessRegime(samples, T0), 'en');
  if (!fa.length || !en.length) throw new Error('regime advice empty');
  if (/تشخیص DPI است/.test(fa) || /proven DPI/.test(en)) throw new Error('advice must not claim DPI detection');
}

console.log('regime: ok');
