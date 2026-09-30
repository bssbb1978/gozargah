/**
 * Opt-in application gate for Workers AI advice.
 *
 * Only a capability-checked transport preference is applied to the adaptive
 * protocol scorer. It is a bounded tie-breaker, never a command to the client.
 * AXR's native client transport remains WebSocket-only. Automatic rollback uses
 * fresh aggregate Worker-egress success rates, not per-user or Iran-side data.
 */
import type { StrategyTransport } from './strategy-recommendation';

export type AdvisorApplicationStatus =
  | 'advisory'
  | 'applied'
  | 'rolled_back'
  | 'disabled'
  | 'killed'
  | 'unsupported_transport'
  | 'baseline_missing';

export interface AdvisorApplicationState {
  enabled: boolean;
  killed: boolean;
  activeTransport: StrategyTransport | null;
  previousTransport: StrategyTransport | null;
  baselineSuccessRate: number | null;
  appliedAt: number;
  observedAt: number;
  status: AdvisorApplicationStatus;
  reason: string;
}

export const ADVISOR_ROLLBACK_DROP = 0.15;
export const ADVISOR_ROLLBACK_HOLD_MS = 5 * 60_000;
export const ADVISOR_BASELINE_MAX_AGE_MS = 30 * 60_000;

export function advisorKillSwitchEnabled(value?: string): boolean {
  return /^(1|true|yes|on)$/i.test((value ?? '').trim());
}

export function defaultAdvisorApplication(): AdvisorApplicationState {
  return {
    enabled: false,
    killed: false,
    activeTransport: null,
    previousTransport: null,
    baselineSuccessRate: null,
    appliedAt: 0,
    observedAt: 0,
    status: 'advisory',
    reason: 'default_advisory_only',
  };
}

export function normalizeAdvisorApplication(value: unknown): AdvisorApplicationState {
  const fallback = defaultAdvisorApplication();
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fallback;
  const input = value as Partial<AdvisorApplicationState>;
  const transports = new Set<StrategyTransport>(['ws', 'grpc', 'httpupgrade', 'xhttp']);
  const statuses = new Set<AdvisorApplicationStatus>([
    'advisory', 'applied', 'rolled_back', 'disabled', 'killed',
    'unsupported_transport', 'baseline_missing',
  ]);
  const activeTransport = transports.has(input.activeTransport as StrategyTransport) ? input.activeTransport as StrategyTransport : null;
  const previousTransport = transports.has(input.previousTransport as StrategyTransport) ? input.previousTransport as StrategyTransport : null;
  const baseline = typeof input.baselineSuccessRate === 'number' && Number.isFinite(input.baselineSuccessRate)
    ? Math.max(0, Math.min(1, input.baselineSuccessRate))
    : null;
  return {
    enabled: input.enabled === true,
    killed: input.killed === true,
    activeTransport,
    previousTransport,
    baselineSuccessRate: baseline,
    appliedAt: Number.isFinite(input.appliedAt) ? Math.max(0, Number(input.appliedAt)) : 0,
    observedAt: Number.isFinite(input.observedAt) ? Math.max(0, Number(input.observedAt)) : 0,
    status: statuses.has(input.status as AdvisorApplicationStatus) ? input.status as AdvisorApplicationStatus : 'advisory',
    reason: typeof input.reason === 'string' ? input.reason.slice(0, 64) : fallback.reason,
  };
}

export function setAdvisorApplicationControls(
  current: unknown,
  changes: { enabled?: boolean; killed?: boolean },
  now = Date.now(),
): AdvisorApplicationState {
  const state = normalizeAdvisorApplication(current);
  const enabled = changes.enabled ?? state.enabled;
  const killed = changes.killed ?? state.killed;
  if (killed || !enabled) {
    return {
      ...state,
      enabled,
      killed,
      activeTransport: null,
      previousTransport: null,
      baselineSuccessRate: null,
      appliedAt: 0,
      observedAt: now,
      status: killed ? 'killed' : 'disabled',
      reason: killed ? 'operator_kill_switch' : 'operator_disabled',
    };
  }
  return { ...state, enabled, killed, observedAt: now, status: state.activeTransport ? 'applied' : 'advisory', reason: 'operator_enabled' };
}

export function applyAdvisorTransport(
  current: unknown,
  proposed: string,
  allowedTransports: readonly string[],
  baseline: { successRate: number; updatedAt: number } | null,
  now = Date.now(),
): AdvisorApplicationState {
  const state = normalizeAdvisorApplication(current);
  if (state.killed) return { ...state, activeTransport: null, status: 'killed', reason: 'operator_kill_switch' };
  if (!state.enabled) return { ...state, status: 'advisory', reason: 'opt_in_required' };
  if (!['ws', 'grpc', 'httpupgrade', 'xhttp'].includes(proposed) || !allowedTransports.includes(proposed)) {
    return { ...state, status: 'unsupported_transport', reason: 'transport_not_in_live_capabilities' };
  }
  if (!baseline || !Number.isFinite(baseline.successRate) || baseline.successRate < 0 || baseline.successRate > 1 ||
      !Number.isFinite(baseline.updatedAt) || baseline.updatedAt > now || now - baseline.updatedAt > ADVISOR_BASELINE_MAX_AGE_MS) {
    return { ...state, status: 'baseline_missing', reason: 'fresh_worker_egress_baseline_required' };
  }
  return {
    ...state,
    activeTransport: proposed as StrategyTransport,
    previousTransport: state.activeTransport,
    baselineSuccessRate: baseline.successRate,
    appliedAt: now,
    observedAt: baseline.updatedAt,
    status: 'applied',
    reason: 'bounded_transport_preference',
  };
}

/** Roll the AI preference back when a fresh aggregate success rate drops materially. */
export function observeAdvisorSuccessRate(
  current: unknown,
  observation: { successRate: number; updatedAt: number } | null,
  now = Date.now(),
): AdvisorApplicationState {
  const state = normalizeAdvisorApplication(current);
  if (!state.enabled || state.killed || !state.activeTransport || state.baselineSuccessRate === null || !observation) return state;
  if (!Number.isFinite(observation.successRate) || observation.successRate < 0 || observation.successRate > 1 ||
      !Number.isFinite(observation.updatedAt) || observation.updatedAt <= state.appliedAt || observation.updatedAt > now ||
      now - observation.updatedAt > ADVISOR_BASELINE_MAX_AGE_MS) return state;
  if (observation.updatedAt - state.appliedAt < ADVISOR_ROLLBACK_HOLD_MS) return state;
  if (state.baselineSuccessRate - observation.successRate < ADVISOR_ROLLBACK_DROP) {
    return { ...state, observedAt: observation.updatedAt };
  }
  return {
    ...state,
    activeTransport: state.previousTransport,
    previousTransport: null,
    baselineSuccessRate: null,
    appliedAt: 0,
    observedAt: observation.updatedAt,
    status: 'rolled_back',
    reason: 'aggregate_success_rate_drop',
  };
}
