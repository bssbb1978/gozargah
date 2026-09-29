/**
 * Gozargah 2.12 — deterministic rotating WebSocket path.
 *
 * The Worker accepts WebSocket upgrades on ANY path (the protocol authenticates
 * the user in-band), so the request path is a free entropy dimension. Every
 * 6 hours the generated links rotate to a new per-user path segment derived
 * from two FNV-1a passes over (uuid | window index).
 *
 * Properties:
 *   - deterministic: same uuid + same window => same path, across every
 *     subscription format and every entry host;
 *   - backward compatible: the Worker keeps accepting previous windows' paths,
 *     so an already-installed client is never stranded by a rotation;
 *   - static path fingerprints in a blocklist go stale every window;
 *   - no state, no D1, no payload impact, no per-request randomness.
 */

export const PATH_ROTATION_WINDOW_MS = 6 * 60 * 60 * 1000; // 6 hours

export function pathRotationWindowIndex(now: number): number {
  return Math.floor(now / PATH_ROTATION_WINDOW_MS);
}

function fnv1aHex(text: string, seed: number): string {
  let h = seed >>> 0;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/** Current rotating WS path base for a user, e.g. `/<uuid>/g/<16 hex>`. */
export function rotatedPathBase(uuid: string, now = Date.now()): string {
  const idx = pathRotationWindowIndex(now);
  const seed = 'gz-rot|' + uuid + '|' + idx;
  return '/' + uuid + '/g/' + fnv1aHex(seed, 2166136261) + fnv1aHex(seed, 2166136262);
}
