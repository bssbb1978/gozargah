/**
 * Scheduled health loop for configured egress/fallback endpoints only.
 *
 * It never scans arbitrary networks. A probe is a plain TCP open/close using
 * Cloudflare's sockets API against a host already present in D1 settings.
 */

import { connect } from 'cloudflare:sockets';
import { Env } from '../config';
import { addEvent, loadAdaptiveGuardState, loadAdaptiveModel, loadPathHealth, loadProfileHealth, loadSettings, saveAdaptiveGuardState, saveNetworkState, savePathHealth, saveProtocolPolicyState, loadHealthSamples, saveHealthSample, savePredictiveState, savePolicySignalState } from '../db/store';
import { classifyNetworkState } from './network-state';
import { updateObservation } from './resilience';
import { buildAdaptiveProtocolPlan } from './protocol-controller';
import { assessHealth } from './predictive-mesh';
import { nextAdaptiveGuardState, reconcileAdaptivePlan } from './adaptive-guard';
import { buildProtocolMatrix } from '../subscription';

const DEFAULT_PORTS = [443, 2053, 2083, 2087, 8443];
const PROBE_TIMEOUT_MS = 4500;

function parsePorts(value?: string): number[] {
  const nums = (value || DEFAULT_PORTS.join(','))
    .split(',')
    .map((x) => Number.parseInt(x.trim(), 10))
    .filter((x) => Number.isInteger(x) && x >= 1 && x <= 65535);
  const unique = [...new Set(nums)].slice(0, 5);
  return unique.length ? unique : DEFAULT_PORTS;
}

async function probeEndpoint(host: string, port: number): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
  const started = Date.now();
  let socket: Socket | null = null;
  try {
    socket = connect(host + ':' + port);
    await Promise.race([
      socket.opened,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('probe_timeout')), PROBE_TIMEOUT_MS)),
    ]);
    return { ok: true, latencyMs: Date.now() - started };
  } catch (e) {
    return { ok: false, latencyMs: Date.now() - started, error: e instanceof Error ? e.message.slice(0, 160) : String(e).slice(0, 160) };
  } finally {
    try { socket?.close(); } catch { /* ignore */ }
  }
}

export async function runScheduledHealth(env: Env): Promise<void> {
  if (!env.GZ_DB) return;
  const settings = await loadSettings(env.GZ_DB);
  const endpoints = [...new Set(settings?.proxyIPs ?? [])].filter(Boolean).slice(0, 32);
  if (!endpoints.length) return;

  const ports = parsePorts(env.HEALTH_PROBE_PORTS);
  const existing = await loadPathHealth(env.GZ_DB);
  const byId = new Map(existing.map((r) => [r.pathId, r]));

  for (const endpoint of endpoints) {
    // One primary probe plus at most one alternate port per cycle keeps cron
    // bounded while still adapting to port-dependent availability.
    const port = ports[(Math.abs(hash32(endpoint)) % Math.max(1, ports.length))];
    const result = await probeEndpoint(endpoint, port);
    const previous = byId.get(endpoint);
    const next = updateObservation(previous ? {
      id: previous.pathId,
      latencyMs: previous.latencyMs,
      ok: previous.ok,
      checkedAt: previous.checkedAt,
      failures: previous.failures,
      successes: previous.successes,
      quarantineUntil: previous.quarantineUntil,
      consecutiveFailures: previous.consecutiveFailures,
      consecutiveSuccesses: previous.consecutiveSuccesses,
      lastError: previous.lastError,
    } : undefined, result.ok, result.latencyMs, Date.now(), result.error);
    next.id = endpoint;
    await savePathHealth(env.GZ_DB, {
      pathId: endpoint,
      latencyMs: next.latencyMs,
      ok: next.ok,
      failures: next.failures,
      successes: next.successes,
      quarantineUntil: next.quarantineUntil,
      checkedAt: next.checkedAt,
      lastError: next.lastError,
      consecutiveFailures: next.consecutiveFailures,
      consecutiveSuccesses: next.consecutiveSuccesses,
    });
    await saveHealthSample(env.GZ_DB, { kind: 'path', subjectId: endpoint, ts: next.checkedAt, ok: next.ok, latencyMs: next.latencyMs });
    const pathSamples = await loadHealthSamples(env.GZ_DB, 'path', endpoint, 24);
    const pathPredictive = assessHealth(pathSamples, next.checkedAt);
    await savePathHealth(env.GZ_DB, {
      pathId: endpoint, latencyMs: next.latencyMs, ok: next.ok, failures: next.failures, successes: next.successes,
      quarantineUntil: next.quarantineUntil, checkedAt: next.checkedAt, lastError: next.lastError,
      consecutiveFailures: next.consecutiveFailures, consecutiveSuccesses: next.consecutiveSuccesses,
      drift: pathPredictive.drift, forecastSuccess: pathPredictive.forecastSuccess, volatility: pathPredictive.latencyVolatility,
    });
    await savePredictiveState(env.GZ_DB, { kind:'path', subjectId:endpoint, stateJson: JSON.stringify(pathPredictive), updatedAt: next.checkedAt });
    byId.set(endpoint, {
      pathId: endpoint, latencyMs: next.latencyMs, ok: next.ok,
      failures: next.failures, successes: next.successes, quarantineUntil: next.quarantineUntil,
      checkedAt: next.checkedAt, lastError: next.lastError,
      consecutiveFailures: next.consecutiveFailures, consecutiveSuccesses: next.consecutiveSuccesses,
    });
  }

  const state = classifyNetworkState([...byId.values()].map((r) => ({
    id: r.pathId, latencyMs: r.latencyMs, ok: r.ok, checkedAt: r.checkedAt,
    failures: r.failures, successes: r.successes, quarantineUntil: r.quarantineUntil,
    consecutiveFailures: r.consecutiveFailures, consecutiveSuccesses: r.consecutiveSuccesses,
    lastError: r.lastError,
  })));
  await saveNetworkState(env.GZ_DB, {
    state: state.state,
    quorum: state.quorum,
    failureRate: state.failureRate,
    selectedPath: state.selectedPath ?? '',
    reasonCodes: state.reasonCodes,
    confidence: state.confidence,
    anomalyScore: state.anomalyScore,
    signalClass: state.signalClass,
    updatedAt: state.generatedAt,
  });

  // Refresh the live protocol policy at the same cadence. This keeps the D1
  // fallback ladder warm even when no client is actively requesting a manifest.
  try {
    const settings = await loadSettings(env.GZ_DB);
    const matrix = buildProtocolMatrix(env, 'scheduler');
    const profileRows = await loadProfileHealth(env.GZ_DB);
    const predictive: Record<string, ReturnType<typeof assessHealth>> = {};
    for (const row of profileRows) {
      const samples = await loadHealthSamples(env.GZ_DB, 'profile', row.profileId, 24);
      predictive[row.profileId] = assessHealth(samples, state.generatedAt);
      await savePredictiveState(env.GZ_DB, { kind:'profile', subjectId:row.profileId, stateJson: JSON.stringify(predictive[row.profileId]), updatedAt: state.generatedAt });
    }
    let learner: any = undefined;
    try {
      const modelRow = await loadAdaptiveModel(env.GZ_DB);
      if (modelRow) learner = JSON.parse(modelRow.stateJson);
    } catch { /* safe default */ }
    const candidate = buildAdaptiveProtocolPlan({
      profiles: matrix.adaptivePolicy.profiles,
      health: profileRows.map((r) => ({
        profileId: r.profileId, latencyMs: r.latencyMs, failures: r.failures, successes: r.successes,
        quarantineUntil: r.quarantineUntil, checkedAt: r.checkedAt, consecutiveFailures: r.consecutiveFailures, consecutiveSuccesses: r.consecutiveSuccesses,
      })),
      networkState: {
        state: state.state, quorum: state.quorum, healthy: state.healthy, degraded: state.degraded,
        quarantined: state.quarantined, unknown: state.unknown, total: state.total, failureRate: state.failureRate,
        confidence: state.confidence, anomalyScore: state.anomalyScore, signalClass: state.signalClass, selectedPath: state.selectedPath, reasonCodes: state.reasonCodes, generatedAt: state.generatedAt,
      },
      learner,
      predictive,
      limit: 10,
      now: state.generatedAt,
    });
    const guardState = await loadAdaptiveGuardState(env.GZ_DB);
    const decision = reconcileAdaptivePlan(candidate, guardState ?? undefined, profileRows.map((r) => ({
      profileId: r.profileId, latencyMs: r.latencyMs, failures: r.failures, successes: r.successes,
      quarantineUntil: r.quarantineUntil, checkedAt: r.checkedAt, consecutiveFailures: r.consecutiveFailures, consecutiveSuccesses: r.consecutiveSuccesses,
    })), state.generatedAt);
    const nextGuard = nextAdaptiveGuardState(guardState ?? undefined, decision, state.generatedAt);
    await saveAdaptiveGuardState(env.GZ_DB, nextGuard);
    if (decision.promoted || decision.staged) {
      await addEvent(env.GZ_DB, 'adaptive_policy_guard', JSON.stringify({
        status: decision.status, promoted: decision.promoted, rolledBack: decision.rolledBack,
        active: decision.active.policyFingerprint, staged: decision.staged?.policyFingerprint ?? null, reasonCodes: decision.reasonCodes,
      }).slice(0, 1800));
    }
    const plan = decision.active;
    await saveProtocolPolicyState(env.GZ_DB, {
      selectedProfile: plan.selected || '',
      fallbackLadder: plan.fallbackLadder,
      reasonCodes: [...plan.reasonCodes, ...decision.reasonCodes.map((x) => 'guard_' + x)],
      diversity: plan.diversity,
      confidence: plan.confidence,
      mode: plan.mode,
      consensus: plan.consensus,
      signalAgreement: plan.signalAgreement,
      switchRisk: plan.switchRisk,
      fusionMode: plan.fusionMode,
      policyFingerprint: plan.policyFingerprint,
      updatedAt: plan.generatedAt,
    });
    await savePolicySignalState(env.GZ_DB, {
      stateJson: JSON.stringify({
        consensus: plan.consensus,
        signalAgreement: plan.signalAgreement,
        switchRisk: plan.switchRisk,
        fusionMode: plan.fusionMode,
        confidence: plan.confidence,
        strategy: plan.strategy,
        selected: plan.selected,
        reasonCodes: plan.reasonCodes.slice(0, 20),
      }),
      updatedAt: plan.generatedAt,
    });
    void settings;
  } catch { /* policy refresh is best-effort and must never block health */ }
}

function hash32(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
