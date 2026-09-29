/**
 * Gozargah 2.13 — neutral client-fingerprint rotation.
 *
 * What this is and is not:
 *   - TLS is terminated at the Cloudflare edge; the Worker never sees the
 *     ClientHello and cannot mutate it. What rotates here is the uTLS
 *     fingerprint the GENERATED CONFIGS instruct the client to use — i.e. the
 *     ClientHello extension order / cipher / curve set as selected by the
 *     client's uTLS implementation (JA3/JA4 input).
 *   - The neutral set is the intersection of fingerprints supported by every
 *     emitted format (Xray, Sing-box, Clash-Meta): chrome, firefox, safari.
 *     They differ materially in extension order, ciphers and curves, so a
 *     static JA3/JA4 blocklist entry goes stale across windows.
 *   - Deterministic per (uuid | 6h window) and aligned with the rotating WS
 *     path window: every format of the same user carries the same identity.
 *   - An explicit operator preset always wins (honest branding contract).
 */

import { pathRotationWindowIndex } from './path-rotation';

/** Intersection of uTLS fingerprints supported by Xray + Sing-box + Clash-Meta. */
export const NEUTRAL_FINGERPRINTS = ['chrome', 'firefox', 'safari'] as const;

export type NeutralFingerprint = (typeof NEUTRAL_FINGERPRINTS)[number];

function fnv1a(text: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

/** Deterministic neutral fingerprint for a user in the current window. */
export function rotatedFingerprint(uuid: string, now = Date.now()): NeutralFingerprint {
  const idx = pathRotationWindowIndex(now);
  const h = fnv1a('gz-fp|' + uuid + '|' + idx, 2166136263);
  return NEUTRAL_FINGERPRINTS[h % NEUTRAL_FINGERPRINTS.length];
}

/** Window minutes the fingerprint (and path) rotation uses — 6 hours. */
export function fingerprintRotationMinutes(now = Date.now()): number {
  void now;
  return 6 * 60;
}
