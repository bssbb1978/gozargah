/**
 * Gozargah 2.13 — bounded traffic-shaping planner (server side, in-tunnel).
 *
 * The WebSocket payload already travels inside the edge-terminated TLS
 * tunnel, so nothing here changes what a DPI box can see at the TLS layer.
 * What this changes is the observable *timing/size statistics* of the
 * encrypted stream: long server→client bursts are segmented into bounded
 * frames with small randomized inter-frame gaps, and the first protocol
 * response gets a bounded timing jitter. Both are fully client-compatible
 * (fragmented WS frames and extra latency are normal network behavior) and
 * both smear burst signatures that statistical flow classifiers key on.
 *
 * The planner is pure (testable without a Worker runtime); the sender
 * applies the plan with real timers.
 */

export type ShapeMode = 'conservative' | 'aggressive' | 'off';

export interface ShapeProfile {
  name: ShapeMode;
  /** only shape writes at/above this size */
  minChunkBytes: number;
  /** each segment is at most this large */
  maxSegmentBytes: number;
  /** bounded random inter-segment gap, ms */
  maxGapMs: number;
  /** max segments per write (bounds total added latency) */
  maxSegments: number;
  /** bounded random delay before the first protocol response, ms */
  firstResponseJitterMs: number;
}

export const SHAPE_PROFILES: Record<Exclude<ShapeMode, 'off'>, ShapeProfile> = {
  conservative: {
    name: 'conservative',
    minChunkBytes: 16_384,
    maxSegmentBytes: 8_192,
    maxGapMs: 15,
    maxSegments: 8,
    firstResponseJitterMs: 120,
  },
  aggressive: {
    name: 'aggressive',
    minChunkBytes: 8_192,
    maxSegmentBytes: 4_096,
    maxGapMs: 40,
    maxSegments: 16,
    firstResponseJitterMs: 300,
  },
};

/** Parse the TRAFFIC_SHAPE env value; anything unrecognized -> conservative. */
export function shapeModeFor(value?: string | null): ShapeMode {
  const v = (value ?? '').trim().toLowerCase();
  if (v === 'aggressive') return 'aggressive';
  if (v === 'off') return 'off';
  return 'conservative';
}

/**
 * Split a chunk of `length` bytes into the segment plan.
 *  - below minChunkBytes  -> single segment (no shaping);
 *  - above                -> bounded number of segments, each ≤ maxSegmentBytes
 *    (the last absorbs the remainder; if the chunk is huge, segments grow so
 *    the count stays ≤ maxSegments and total added latency stays bounded).
 */
export function planSegments(length: number, profile: ShapeProfile): number[] {
  if (!Number.isInteger(length) || length <= 0) return [];
  if (length < profile.minChunkBytes) return [length];
  const ideal = Math.ceil(length / profile.maxSegmentBytes);
  const count = Math.min(ideal, profile.maxSegments);
  const base = Math.floor(length / count);
  const rem = length - base * count;
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(base + (i < rem ? 1 : 0));
  // keep only non-empty segments (base can be 0 only when length < count)
  return out.filter((x) => x > 0);
}

/** Bounded random delay in [0, maxMs] — deterministic override for tests. */
export function jitterDelay(maxMs: number, rnd: () => number = Math.random): number {
  const v = Math.floor(rnd() * (maxMs + 1));
  return Math.max(0, Math.min(maxMs, v));
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Send `data` to the WebSocket using the segment plan; applies bounded random
 * inter-segment gaps. Falls back to a single send for small chunks.
 */
export async function sendShaped(
  send: (chunk: Uint8Array) => void | Promise<void>,
  data: Uint8Array,
  profile: ShapeProfile,
  rnd: () => number = Math.random,
): Promise<void> {
  const plan = planSegments(data.byteLength, profile);
  if (plan.length <= 1) {
    await send(data);
    return;
  }
  let offset = 0;
  for (let i = 0; i < plan.length; i++) {
    const size = plan[i];
    await send(data.subarray(offset, offset + size));
    offset += size;
    if (i < plan.length - 1) await sleep(jitterDelay(profile.maxGapMs, rnd));
  }
}
