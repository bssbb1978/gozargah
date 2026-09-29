import { SHAPE_PROFILES, jitterDelay, planSegments, shapeModeFor, sendShaped } from '../utils/shape';

const c = SHAPE_PROFILES.conservative;
const ag = SHAPE_PROFILES.aggressive;

// 1) small chunks pass through unshaped
if (JSON.stringify(planSegments(100, c)) !== JSON.stringify([100])) throw new Error('small chunk must stay single');
if (JSON.stringify(planSegments(c.minChunkBytes - 1, c)) !== JSON.stringify([c.minChunkBytes - 1])) throw new Error('below-min chunk must stay single');

// 2) exact min chunk splits into two max segments
if (JSON.stringify(planSegments(c.minChunkBytes, c)) !== JSON.stringify([c.maxSegmentBytes, c.maxSegmentBytes])) throw new Error('min chunk plan wrong');

// 3) huge chunk: bounded segment count, exact sum, positive sizes
{
  const plan = planSegments(1_000_000, c);
  if (plan.length > c.maxSegments) throw new Error('segment count must be bounded');
  if (plan.reduce((x, y) => x + y, 0) !== 1_000_000) throw new Error('segments must sum to the chunk');
  if (plan.some((x) => x <= 0)) throw new Error('segments must be positive');
}

// 4) invalid lengths
if (planSegments(0, c).length !== 0) throw new Error('zero length must be empty');
if (planSegments(-5, c).length !== 0) throw new Error('negative length must be empty');
if (planSegments(NaN, c).length !== 0) throw new Error('NaN length must be empty');

// 5) aggressive mode shapes smaller chunks
if (JSON.stringify(planSegments(ag.minChunkBytes, ag)) !== JSON.stringify([ag.maxSegmentBytes, ag.maxSegmentBytes])) throw new Error('aggressive min plan wrong');

// 6) mode parsing
if (shapeModeFor('aggressive') !== 'aggressive') throw new Error('parse aggressive');
if (shapeModeFor('off') !== 'off') throw new Error('parse off');
if (shapeModeFor(undefined) !== 'conservative') throw new Error('default must be conservative');
if (shapeModeFor('garbage') !== 'conservative') throw new Error('unknown must fall back to conservative');

// 7) jitter is bounded and deterministic under a fixed rnd
if (jitterDelay(15, () => 0) !== 0) throw new Error('jitter lower bound');
if (jitterDelay(15, () => 0.9999) !== 15) throw new Error('jitter upper bound');

// 8) sendShaped: multiple bounded sends for a shaped chunk, one send otherwise
{
  const calls: number[] = [];
  const data = new Uint8Array(c.minChunkBytes);
  await sendShaped((ch) => { calls.push(ch.byteLength); }, data, c, () => 0.5);
  if (calls.length !== 2) throw new Error('shaped chunk must produce 2 sends, got ' + calls.length);
  if (calls.reduce((x, y) => x + y, 0) !== c.minChunkBytes) throw new Error('shaped sends must cover the chunk');

  const calls2: number[] = [];
  await sendShaped((ch) => { calls2.push(ch.byteLength); }, new Uint8Array(64), c, () => 0.5);
  if (calls2.length !== 1) throw new Error('small chunk must produce 1 send');
}

console.log('shape: ok');
