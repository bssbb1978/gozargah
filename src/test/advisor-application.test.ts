import { describe, expect, it } from 'vitest';
import {
  applyAdvisorTransport,
  advisorKillSwitchEnabled,
  defaultAdvisorApplication,
  observeAdvisorSuccessRate,
  setAdvisorApplicationControls,
} from '../ai/advisor-application';

const BASELINE = { successRate: 0.92, updatedAt: 1_800_000_000_000 };

describe('opt-in AI advisor application guard', () => {
  it('defaults to advisory-only and refuses application before explicit opt-in', () => {
    const state = defaultAdvisorApplication();
    expect(state.enabled).toBe(false);
    expect(state.activeTransport).toBeNull();
    expect(applyAdvisorTransport(state, 'grpc', ['ws', 'grpc'], BASELINE, BASELINE.updatedAt + 1)).toMatchObject({
      activeTransport: null,
      status: 'advisory',
      reason: 'opt_in_required',
    });
  });

  it('applies only a capability-allowlisted transport with a fresh baseline', () => {
    const enabled = setAdvisorApplicationControls(defaultAdvisorApplication(), { enabled: true }, BASELINE.updatedAt);
    expect(applyAdvisorTransport(enabled, 'xhttp', ['ws', 'grpc'], BASELINE, BASELINE.updatedAt + 1).status).toBe('unsupported_transport');
    expect(applyAdvisorTransport(enabled, 'grpc', ['ws', 'grpc'], null, BASELINE.updatedAt + 1).status).toBe('baseline_missing');
    expect(applyAdvisorTransport(enabled, 'grpc', ['ws', 'grpc'], BASELINE, BASELINE.updatedAt + 1)).toMatchObject({
      activeTransport: 'grpc',
      baselineSuccessRate: 0.92,
      status: 'applied',
      reason: 'bounded_transport_preference',
    });
  });

  it('automatically rolls back after the hold window when aggregate success drops by the hard threshold', () => {
    const at = BASELINE.updatedAt + 1;
    const enabled = setAdvisorApplicationControls(defaultAdvisorApplication(), { enabled: true }, at);
    const applied = applyAdvisorTransport(enabled, 'grpc', ['grpc'], BASELINE, at);
    const early = observeAdvisorSuccessRate(applied, { successRate: 0.4, updatedAt: at + 60_000 }, at + 60_000);
    expect(early.activeTransport).toBe('grpc');
    const rolledBack = observeAdvisorSuccessRate(applied, { successRate: 0.7, updatedAt: at + 6 * 60_000 }, at + 6 * 60_000);
    expect(rolledBack).toMatchObject({
      activeTransport: null,
      status: 'rolled_back',
      reason: 'aggregate_success_rate_drop',
    });
  });

  it('does not roll back on a small, stale, or non-forward health observation', () => {
    const at = BASELINE.updatedAt + 1;
    const enabled = setAdvisorApplicationControls(defaultAdvisorApplication(), { enabled: true }, at);
    const applied = applyAdvisorTransport(enabled, 'ws', ['ws'], BASELINE, at);
    expect(observeAdvisorSuccessRate(applied, { successRate: 0.85, updatedAt: at + 6 * 60_000 }).activeTransport).toBe('ws');
    expect(observeAdvisorSuccessRate(applied, { successRate: 0.4, updatedAt: at }, at + 6 * 60_000).activeTransport).toBe('ws');
  });

  it('operator and Worker kill switches immediately clear the active preference', () => {
    const at = BASELINE.updatedAt + 1;
    const enabled = setAdvisorApplicationControls(defaultAdvisorApplication(), { enabled: true }, at);
    const applied = applyAdvisorTransport(enabled, 'grpc', ['grpc'], BASELINE, at);
    expect(setAdvisorApplicationControls(applied, { killed: true }, at + 1)).toMatchObject({
      activeTransport: null,
      killed: true,
      status: 'killed',
    });
    expect(advisorKillSwitchEnabled('true')).toBe(true);
    expect(advisorKillSwitchEnabled('0')).toBe(false);
  });
});
