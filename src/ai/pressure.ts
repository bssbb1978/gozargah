/**
 * Gozargah 2.17 — pressure engine (internal AI, deterministic, aggregate-only).
 *
 * Fuses the fleet's canary liveness evidence, clean-IP harvest freshness, and
 * the aggregate regime label into a single 0-3 pressure level. The level
 * drives the *dynamic* parts of the AXR manifest:
 *
 *   level 0 (baseline)   path rotation 360 min, probe 90 s, flow profile "web"
 *   level 1 (watch)      path rotation 180 min, probe 60 s, flow profile "chat"
 *   level 2 (elevated)   path rotation  90 min, probe 30 s, flow profile "video"
 *   level 3 (critical)   path rotation  45 min, probe 15 s, flow profile "video"
 *
 * The logic is the server-side half of the closed loop: clients probe a
 * canary (a plain, always-reachable-by-design host) and report ok/fail via
 * the harvest endpoint (kind="canary"); the harvest runner publishes clean
 * edge IPs. When the fleet's canary starts failing, or the last clean-IP
 * harvest grows stale while the regime is stepping down, the engine raises
 * pressure and the manifest rotates faster, probes more aggressively, and
 * escalates the outflow profile — all without any human touching a setting.
 *
 * Honesty rules (same as regime.ts):
 *   - aggregate statistics only (ok/fail flags + timestamps); no payloads,
 *     no packet inspection, no DPI identification;
 *   - absence of evidence is NOT pressure: a canary that was never probed
 *     and a harvest that never happened contribute no reasons — only a
 *     STALE-but-once-fresh signal or an active failure does;
 *   - canary failure has multiple explanations (incident, upstream outage,
 *     filter change); the output is a pressure LEVEL, not a detection.
 */

export interface PressureInput {
  /** True when the operator configured a canary host (AXR_CANARY_HOST). */
  canaryConfigured: boolean;
  /**
   * Fraction of recent (<= 30 min) fleet canary probes that failed (0..1).
   * null = fewer than the evidence floor (3 samples) — no signal.
   */
  canaryFailFrac: number | null;
  /** Minutes since the newest canary result; null = never probed. */
  canaryAgeMin: number | null;
  /** Minutes since the newest clean-IP harvest write; null = never harvested. */
  harvestAgeMin: number | null;
  /** Current aggregate regime label (regime.ts). */
  regimeState: string;
}

export interface PressureAssessment {
  /** 0 baseline, 1 watch, 2 elevated, 3 critical. */
  level: 0 | 1 | 2 | 3;
  /** Bounded reason codes (for the manifest + audit). */
  reasons: string[];
  /** Dynamic manifest: WS path rotation window in minutes. */
  rotationMinutes: number;
  /** Dynamic manifest: client probe cadence in ms. */
  probeIntervalMs: number;
  /** Dynamic manifest: target outflow flow-profile mode. */
  flowProfile: 'web' | 'chat' | 'video';
}

const ROTATION_MINUTES = [360, 180, 90, 45] as const;
const PROBE_INTERVAL_MS = [90_000, 60_000, 30_000, 15_000] as const;

const CANARY_FAIL_FLOOR = 0.5; // >= 50% of recent canary probes failing
const CANARY_STALE_MIN = 30; // canary configured but silent > 30 min
const HARVEST_STALE_MIN = 360; // once-fresh harvest now > 6 h old

/**
 * Assess fleet pressure from aggregate evidence. Pure + deterministic:
 * same input, same output; no clock, no model runtime.
 */
export function assessPressure(input: PressureInput): PressureAssessment {
  const reasons: string[] = [];
  let level = 0;

  const canaryBad =
    input.canaryFailFrac !== null && input.canaryFailFrac >= CANARY_FAIL_FLOOR;
  const harvestStale =
    input.harvestAgeMin !== null && input.harvestAgeMin > HARVEST_STALE_MIN;
  const canaryStale =
    input.canaryConfigured &&
    input.canaryAgeMin !== null &&
    input.canaryAgeMin > CANARY_STALE_MIN &&
    !canaryBad;
  const regimeBad = input.regimeState === 'suspected_change';
  const regimeWatch = input.regimeState === 'watch';

  if (canaryBad) {
    level = 3;
    reasons.push('canary_fleet_failures');
  }
  if (regimeBad) {
    level = Math.max(level, 2);
    reasons.push('regime_step_change');
  }
  if (harvestStale) {
    level = Math.max(level, 2);
    reasons.push('harvest_stale');
  }
  if (canaryStale) {
    level = Math.max(level, 1);
    reasons.push('canary_stale');
  }
  if (regimeWatch) {
    level = Math.max(level, 1);
    reasons.push('regime_watch');
  }
  if (reasons.length === 0) reasons.push('baseline');

  const flowProfile: PressureAssessment['flowProfile'] =
    level >= 2 ? 'video' : level === 1 ? 'chat' : 'web';

  return {
    level: level as PressureAssessment['level'],
    reasons,
    rotationMinutes: ROTATION_MINUTES[level],
    probeIntervalMs: PROBE_INTERVAL_MS[level],
    flowProfile,
  };
}

/**
 * Reduce a stored canary result list (newest first) to the (failFrac, ageMin)
 * evidence pair: failFrac over the last 30 min with a 3-sample floor, ageMin
 * of the newest result. Returns (null, null) for an empty list.
 */
export function canaryEvidence(
  results: Array<{ ok: boolean; at: number }>,
  now = Date.now(),
): { failFrac: number | null; ageMin: number | null } {
  if (!Array.isArray(results) || results.length === 0) {
    return { failFrac: null, ageMin: null };
  }
  const newest = results[0];
  if (!newest || !Number.isFinite(newest.at)) {
    return { failFrac: null, ageMin: null };
  }
  const recent = results.filter((r) => Number.isFinite(r?.at) && now - r.at <= 30 * 60_000);
  let failFrac: number | null = null;
  if (recent.length >= 3) {
    failFrac = recent.filter((r) => !r.ok).length / recent.length;
  }
  return { failFrac, ageMin: (now - newest.at) / 60_000 };
}
