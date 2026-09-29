/**
 * Adaptive plan guard / canary controller.
 *
 * The controller is deliberately conservative: it can promote a new plan only
 * when the evidence is materially better, or when the current plan is failing.
 * This prevents protocol flapping and gives the system a small rollback window.
 */
import type { AdaptiveProtocolPlan } from './protocol-controller';
import type { ControllerProfileHealth } from './protocol-controller';

export interface AdaptiveGuardState {
  version: 2;
  active: AdaptiveProtocolPlan | null;
  previous: AdaptiveProtocolPlan | null;
  staged: AdaptiveProtocolPlan | null;
  status: 'stable' | 'staged' | 'promoted' | 'rollback';
  holdUntil: number;
  rollbackCount: number;
  updatedAt: number;
  changeWindowStartedAt: number;
  changesInWindow: number;
  maxChangesPerWindow: number;
}

export interface AdaptiveGuardDecision {
  active: AdaptiveProtocolPlan;
  staged: AdaptiveProtocolPlan | null;
  status: AdaptiveGuardState['status'];
  promoted: boolean;
  rolledBack: boolean;
  reasonCodes: string[];
  updatedAt: number;
}

const HOLD_MS = 15 * 60_000;
const CHANGE_WINDOW_MS = 30 * 60_000;
const MAX_CHANGES_PER_WINDOW = 3;
const MATERIAL_GAIN = 0.08;
const FAILURE_RATE_LIMIT = 0.65;
const CONSECUTIVE_FAILURE_LIMIT = 3;
const PREDICTIVE_GAIN = 0.06;
const VOLATILITY_LIMIT = 0.95;
const CONSENSUS_MIN = 0.58;
const SWITCH_RISK_MAX = 0.58;

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function failureSignal(profileId: string | null, health: ControllerProfileHealth[], now: number): { bad: boolean; rate: number; consecutive: number; quarantined: boolean } {
  if (!profileId) return { bad: true, rate: 1, consecutive: CONSECUTIVE_FAILURE_LIMIT, quarantined: true };
  const row = health.find((x) => x.profileId === profileId);
  if (!row) return { bad: false, rate: 0.5, consecutive: 0, quarantined: false };
  const total = row.failures + row.successes;
  const rate = total ? row.failures / total : 0.5;
  const quarantined = row.quarantineUntil > now;
  const bad = quarantined || row.consecutiveFailures >= CONSECUTIVE_FAILURE_LIMIT || rate >= FAILURE_RATE_LIMIT;
  return { bad, rate, consecutive: row.consecutiveFailures, quarantined };
}

export function defaultAdaptiveGuard(now = Date.now()): AdaptiveGuardState {
  return { version: 2, active: null, previous: null, staged: null, status: 'stable', holdUntil: 0, rollbackCount: 0, updatedAt: now, changeWindowStartedAt: now, changesInWindow: 0, maxChangesPerWindow: MAX_CHANGES_PER_WINDOW };
}

export function reconcileAdaptivePlan(
  candidate: AdaptiveProtocolPlan,
  current: AdaptiveGuardState | undefined,
  profileHealth: ControllerProfileHealth[],
  now = Date.now(),
): AdaptiveGuardDecision {
  const state = current ?? defaultAdaptiveGuard(now);
  const windowExpired = !state.changeWindowStartedAt || now - state.changeWindowStartedAt >= CHANGE_WINDOW_MS;
  const changesInWindow = windowExpired ? 0 : (state.changesInWindow ?? 0);
  const maxChanges = state.maxChangesPerWindow ?? MAX_CHANGES_PER_WINDOW;
  const budgetAvailable = changesInWindow < maxChanges;
  if (!state.active) {
    return {
      active: candidate,
      staged: null,
      status: 'promoted',
      promoted: true,
      rolledBack: false,
      reasonCodes: ['bootstrap_promotion'],
      updatedAt: now,
    };
  }

  if (state.active.policyFingerprint === candidate.policyFingerprint) {
    return {
      active: state.active,
      staged: null,
      status: 'stable',
      promoted: false,
      rolledBack: false,
      reasonCodes: ['same_policy_fingerprint'],
      updatedAt: now,
    };
  }

  const activeHealth = failureSignal(state.active.selected, profileHealth, now);
  const candidateHealth = failureSignal(candidate.selected, profileHealth, now);
  const confidenceGain = candidate.confidence - state.active.confidence;
  const forecastGain = candidate.forecastSuccess - state.active.forecastSuccess;
  const candidateTooVolatile = candidate.volatility > VOLATILITY_LIMIT;
  const candidateLowConsensus = candidate.consensus < CONSENSUS_MIN || candidate.fusionMode === 'recovery';
  const candidateHighSwitchRisk = candidate.switchRisk > SWITCH_RISK_MAX;
  const activeUnhealthy = activeHealth.bad || state.active.mode === 'recovery' || state.active.mode === 'no_healthy_path';
  const candidateUsable = !candidateHealth.quarantined && candidate.selected !== null;
  const holdExpired = now >= state.holdUntil;

  if (activeUnhealthy && candidateUsable && !candidateLowConsensus) {
    return {
      active: candidate,
      staged: null,
      status: 'promoted',
      promoted: true,
      rolledBack: true,
      reasonCodes: ['active_plan_unhealthy', candidateHealth.rate < activeHealth.rate ? 'lower_failure_rate' : 'recovery_candidate'],
      updatedAt: now,
    };
  }

  if (holdExpired && candidateUsable && !candidateTooVolatile && !candidateLowConsensus && !candidateHighSwitchRisk && (confidenceGain >= MATERIAL_GAIN || forecastGain >= PREDICTIVE_GAIN) && budgetAvailable) {
    return {
      active: candidate,
      staged: null,
      status: 'promoted',
      promoted: true,
      rolledBack: false,
      reasonCodes: [confidenceGain >= MATERIAL_GAIN ? 'material_confidence_gain' : 'predictive_forecast_gain', forecastGain >= PREDICTIVE_GAIN ? 'forecast_improvement' : 'no_forecast_gain', candidate.diversity.protocols.length > state.active.diversity.protocols.length ? 'more_protocol_diversity' : 'same_protocol_diversity'],
      updatedAt: now,
    };
  }

  const staged: AdaptiveProtocolPlan = {
    ...candidate,
    confidence: Math.round(clamp(candidate.confidence, 0, 1) * 100) / 100,
    reasonCodes: [...candidate.reasonCodes, 'staged_by_guard'],
  };
  return {
    active: state.active,
    staged,
    status: 'staged',
    promoted: false,
    rolledBack: false,
    reasonCodes: ['guard_hold', ...(holdExpired ? ['insufficient_confidence_or_forecast_gain'] : ['hold_window_active']), ...(candidateTooVolatile ? ['candidate_volatility_guard'] : []), ...(candidateLowConsensus ? ['consensus_guard'] : []), ...(candidateHighSwitchRisk ? ['switch_risk_guard'] : []), ...(holdExpired && !budgetAvailable ? ['change_budget_exhausted'] : [])],
    updatedAt: now,
  };
}

export function nextAdaptiveGuardState(
  previous: AdaptiveGuardState | undefined,
  decision: AdaptiveGuardDecision,
  now = Date.now(),
): AdaptiveGuardState {
  const prev = previous ?? defaultAdaptiveGuard(now);
  const promoted = decision.promoted;
  const activeChanged = !!prev.active && prev.active.policyFingerprint !== decision.active.policyFingerprint;
  const windowExpired = !prev.changeWindowStartedAt || now - prev.changeWindowStartedAt >= CHANGE_WINDOW_MS;
  const baseStartedAt = windowExpired ? now : prev.changeWindowStartedAt;
  const baseChanges = windowExpired ? 0 : (prev.changesInWindow ?? 0);
  return {
    version: 2,
    active: decision.active,
    previous: promoted && activeChanged ? prev.active : prev.previous,
    staged: decision.staged,
    status: decision.status,
    holdUntil: promoted ? now + HOLD_MS : prev.holdUntil,
    rollbackCount: prev.rollbackCount + (decision.rolledBack ? 1 : 0),
    updatedAt: now,
    changeWindowStartedAt: baseStartedAt,
    changesInWindow: baseChanges + (promoted ? 1 : 0),
    maxChangesPerWindow: prev.maxChangesPerWindow ?? MAX_CHANGES_PER_WINDOW,
  };
}
