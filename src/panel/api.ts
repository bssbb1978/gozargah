/**
 * Gozargah — authenticated panel JSON API.
 * All routes live under /{panelPath}/api/* and require an HMAC session
 * cookie except /login (throttled) and /status (used to detect auth state).
 */

import { Env, GzError, VERSION } from '../config';
import { EffectiveSettings } from '../settings';
import {
  addEvent, recentEvents, saveSettings, SettingsBlob, loadSettings, invalidateCache,
  consumeAiDiagnosticQuota, consumeUserControlQuota, loadUserControlAudit, loadPathHealth, savePathHealth, loadProfileHealth, loadAdaptiveModel, loadNetworkState, saveProtocolPolicyState, loadProtocolPolicyState, loadAdaptiveGuardState, loadPolicySignalState, saveHealthSample, loadLatestPathSamples, loadPredictiveStates, loadCleanIPHarvest, saveCleanIPHarvest, appendCanaryResult,
} from '../db/store';
import {
  createUser, deleteUser, getAdminUser, getUserByIdFresh, GzUser, invalidateUsers, listUsersFresh, updateUser, flushUsage,
  type UserAuditMutation, type UserPatch,
} from '../db/users';
import {
  checkLoginGate, clearedCookie, ipHash, isAuthed, makeSessionToken, onLoginResult,
  requireAuth, sessionCookie, verifyPanelPassword,
} from '../auth';
import { buildLinks, subTokenFor, buildProtocolMatrix, findUserByToken } from '../subscription';
import { qrSvg } from '../utils/qr';
import { logRing } from '../utils/log';
import { pbkdf2Hex, randomHex } from '../utils/crypto';
import { createDiagnostics } from '../ai/diagnostics';
import { decideResilience, updateObservation, localResilienceAdvice, PathObservation } from '../ai/resilience';
import { decideAdaptiveProfile } from '../ai/edge-brain';
import { buildAdaptiveProtocolPlan } from '../ai/protocol-controller';
import { assessHealth } from '../ai/predictive-mesh';
import { defaultEdgeLearner, learnerConfidence } from '../ai/edge-learner';
import { classifyFailureDomain, classifyNetworkCondition, normalizeFetchFailure } from '../ai/network-intelligence';
import { buildDecisionView } from '../ai/decision';
import type { RegimeAssessment } from '../ai/regime';
import { shapeModeFor } from '../utils/shape';
import { advisorKillSwitchEnabled, normalizeAdvisorApplication, setAdvisorApplicationControls } from '../ai/advisor-application';

const JSON_CT = 'application/json; charset=utf-8';

function json(data: unknown, status = 200, extraHeaders?: Headers): Response {
  const h = extraHeaders ?? new Headers();
  h.set('content-type', JSON_CT);
  h.set('cache-control', 'no-store');
  return new Response(JSON.stringify(data), { status, headers: h });
}

function publicUser(u: GzUser): Record<string, unknown> {
  return {
    id: u.id, name: u.name, uuid: u.uuid, trojanPass: u.trojanPass,
    quotaBytes: u.quotaBytes, usedUp: u.usedUp, usedDown: u.usedDown,
    expiryAt: u.expiryAt, expiryDays: u.expiryDays, firstUsedAt: u.firstUsedAt,
    enabled: u.enabled, isAdmin: u.isAdmin,
    createdAt: u.createdAt, lastSeen: u.lastSeen,
  };
}

async function adminActorId(db: D1Database): Promise<number> {
  // Panel sessions are signed from the single configured panel-admin password;
  // resolve its stable D1 user id for an attributable audit entry.
  const admin = await getAdminUser(db);
  if (!admin?.isAdmin) throw new GzError('admin account unavailable', 'no_db');
  return admin.id;
}

export async function handlePanelApi(
  request: Request,
  env: Env,
  eff: EffectiveSettings,
  action: string,
): Promise<Response> {
  const method = request.method;
  const db = env.GZ_DB;

  try {
    /* ---------------- public ---------------- */

    if (action === 'status' && method === 'GET') {
      return json({
        version: VERSION,
        dbOk: eff.dbOk,
        isDefaultPassword: eff.isDefaultPassword,
        host: new URL(request.url).hostname,
        logs: logRing.slice(-12),
      });
    }

    if (action === 'login' && method === 'POST') {
      const gate = await checkLoginGate(env, request);
      if (!gate.allowed) {
        await addEvent(db!, 'login_blocked', 'rate limit reached');
        return json({ error: 'too_many_attempts', attemptsLeft: 0 }, 429);
      }
      const body = (await request.json().catch(() => ({}))) as { password?: string };
      const ok = await verifyPanelPassword(eff, String(body.password ?? ''));
      await onLoginResult(env, request, ok);
      if (!ok) {
        if (db) await addEvent(db, 'login_failed', 'bad password');
        return json({ error: 'bad_password', attemptsLeft: gate.attemptsLeft - 1 }, 401);
      }
      if (db) await addEvent(db, 'login_ok', 'panel login');
      const token = await makeSessionToken(eff);
      return json({ ok: true }, 200, new Headers({ 'set-cookie': sessionCookie(token) }));
    }

    /* 2.16 — clean-IP harvest ingest. Public (no session cookie) but
     * authenticated by a valid user subscription token OR the operator's
     * HARVEST_TOKEN env secret. Body: {token, ips: string[], source}.
     * The client `axr scan` runner POSTs its probe survivors here; they are
     * validated, deduped, capped at 32, persisted to D1, and unioned into
     * the AXR manifest clean_ip_hints. The Worker never probes itself —
     * live reachability only the client's own network can measure. */
    if (action === 'network/harvest' && method === 'POST') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const body = (await request.json().catch(() => ({}))) as {
        token?: unknown; ips?: unknown; source?: unknown;
        kind?: unknown; canaryHost?: unknown; canaryOk?: unknown;
      };
      const host = new URL(request.url).hostname;
      const tokenIn = String(body.token ?? request.headers.get('x-harvest-token') ?? '');
      let authorized = false;
      if (tokenIn) {
        if (env.HARVEST_TOKEN && tokenIn === env.HARVEST_TOKEN) {
          authorized = true;
        } else {
          authorized = (await findUserByToken(db, host, tokenIn)) !== null;
        }
      }
      if (!authorized) {
        if (db) await addEvent(db, 'harvest_rejected', 'bad token');
        return json({ error: 'unauthorized' }, 401);
      }
      // 2.17 — canary liveness reports: a client's periodic probe of the
      // operator's canary host (ok/fail). Stored newest-first (capped) and
      // reduced to fleet evidence by the pressure engine. No IP semantics.
      if (String(body.kind ?? '') === 'canary') {
        const canaryHost = String(body.canaryHost ?? '').trim().toLowerCase();
        if (!canaryHost || canaryHost.length > 253 || !/^[a-z0-9][a-z0-9.-]*$/.test(canaryHost)) {
          return json({ error: 'bad canary host' }, 400);
        }
        const row = await appendCanaryResult(db, { host: canaryHost, ok: Boolean(body.canaryOk), at: Date.now() });
        await addEvent(db, 'harvest_canary', `${canaryHost}: ${row.results[0]?.ok ? 'ok' : 'fail'}`);
        return json({ ok: true, kind: 'canary', stored: row.results.length });
      }
      const rawIps = Array.isArray(body.ips) ? body.ips : [];
      const seen = new Set<string>();
      const fresh: string[] = [];
      for (const raw of rawIps) {
        const ip = String(raw ?? '').trim();
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) continue;
        if (!ip.split('.').every((o) => Number(o) <= 255)) continue;
        if (seen.has(ip)) continue;
        seen.add(ip);
        fresh.push(ip);
        if (fresh.length >= 32) break;
      }
      const source = String(body.source ?? 'client-scan').slice(0, 48) || 'client-scan';
      const existing = await loadCleanIPHarvest(db);
      const merged = [...fresh, ...(existing?.ips ?? []).filter((ip) => !seen.has(ip))].slice(0, 32);
      const sources = { ...(existing?.sources ?? {}) };
      sources[source] = (sources[source] ?? 0) + fresh.length;
      await saveCleanIPHarvest(db, { ips: merged, updatedAt: Date.now(), sources });
      await addEvent(db, 'harvest_ok', `${source}: +${fresh.length} (total ${merged.length})`);
      return json({ ok: true, accepted: fresh.length, stored: merged.length, total: merged.length, source });
    }

    /* ---------------- authenticated ---------------- */

    if (action === 'logout' && method === 'POST') {
      return json({ ok: true }, 200, new Headers({ 'set-cookie': clearedCookie() }));
    }

    await requireAuth(request, eff);

    const userControlRoute = action === 'users' || action.startsWith('users/') || action === 'user-audit';
    if (userControlRoute && ['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      if (!(await consumeUserControlQuota(db, await ipHash(request)))) {
        return json({ error: 'admin_rate_limited' }, 429, new Headers({ 'retry-after': '60' }));
      }
    }

    if (action === 'me' && method === 'GET') {
      return json({ ok: true, version: VERSION, dbOk: eff.dbOk, isDefaultPassword: eff.isDefaultPassword });
    }

    if (action === 'network/resilience' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const rows = await loadPathHealth(db);
      let learner = defaultEdgeLearner();
      const modelRow = await loadAdaptiveModel(db);
      if (modelRow) { try { learner = JSON.parse(modelRow.stateJson); } catch { /* safe default */ } }
      const decision = decideResilience(rows.map(r => ({ id:r.pathId, latencyMs:r.latencyMs, ok:r.ok, checkedAt:r.checkedAt, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantineUntil, consecutiveFailures:r.consecutiveFailures, consecutiveSuccesses:r.consecutiveSuccesses, lastError:r.lastError })), Date.now(), learner);
      return json({ ok:true, decision, advice: localResilienceAdvice(decision, 'fa'), policy: { mode: decision.mode, selectedPath: decision.selectedPath, dynamicOrdering: true, aiOptional: true, localLearner: true } });
    }

    if (action === 'network/state' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const [state, paths, settings] = await Promise.all([loadNetworkState(db), loadPathHealth(db), loadSettings(db)]);
      const configuredPaths = settings?.proxyIPs ?? eff.proxyIPs;
      const samples = await loadLatestPathSamples(db, configuredPaths);
      const pathById = new Map(paths.map((row) => [row.pathId, row]));
      const sourceByKind = {
        path_tcp: 'WORKER_TCP',
        path_dial: 'WORKER_SOCKET_DIAL',
        path_https: 'WORKER_HTTPS_HEAD',
        path: 'WORKER_LEGACY_UNSPECIFIED',
      } as const;
      const observations = samples.map((sample) => {
        const row = pathById.get(sample.subjectId);
        return {
          pathId: sample.subjectId,
          source: sourceByKind[sample.kind],
          ok: sample.ok,
          checkedAt: sample.ts,
          latencyMs: sample.latencyMs,
          failures: row?.failures ?? 0,
          successes: row?.successes ?? 0,
          consecutiveFailures: row?.consecutiveFailures ?? 0,
          lastError: row?.checkedAt === sample.ts ? row.lastError : '',
        };
      });
      const sampledPaths = new Set(observations.map((row) => row.pathId));
      for (const row of paths) {
        if (configuredPaths.includes(row.pathId) && !sampledPaths.has(row.pathId) && row.checkedAt > 0) {
          observations.push({
            pathId: row.pathId,
            source: 'WORKER_LEGACY_UNSPECIFIED',
            ok: row.ok,
            checkedAt: row.checkedAt,
            latencyMs: row.latencyMs,
            failures: row.failures,
            successes: row.successes,
            consecutiveFailures: row.consecutiveFailures ?? 0,
            lastError: row.lastError ?? '',
          });
        }
      }
      const condition = classifyNetworkCondition(configuredPaths, observations);
      // 2.12 — aggregate regime label (internal AI, deterministic).
      let regime: { state: string; confidence: number; baselineSuccess: number; recentSuccess: number; reasonCodes: string[] } | null = null;
      try {
        const rows = await loadPredictiveStates(db, 'regime');
        const row = rows.find((r) => r.subjectId === 'global');
        if (row) regime = JSON.parse(row.stateJson) as typeof regime;
      } catch { /* optional */ }
      return json({
        ok: true,
        state,
        condition,
        regime,
        backupEntryHosts: settings?.backupEntryHosts ?? [],
        source: 'configured Worker-egress path telemetry only',
        physicalUpstreamDisconnectionProven: false,
        dpiProven: false,
        interpretation: 'observational-signal-only',
      });
    }

    if (action === 'network/brain' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const row = await loadAdaptiveModel(db);
      let learner = defaultEdgeLearner();
      if (row) { try { learner = JSON.parse(row.stateJson); } catch { /* safe default */ } }
      return json({
        ok: true, version: learner.version, updates: learner.updates, updatedAt: learner.updatedAt,
        learnerConfidence: Math.round(learnerConfidence(learner) * 100) / 100,
        weights: learner.weights, bias: learner.bias,
        source: 'aggregate connection telemetry only',
      });
    }

    if (action === 'network/capabilities' && method === 'GET') {
      const matrix = buildProtocolMatrix(env, new URL(request.url).hostname);
      return json({ ok: true, matrix, generatedAt: Date.now() });
    }

    if (action === 'network/policy' && method === 'GET') {
      const matrix = buildProtocolMatrix(env, new URL(request.url).hostname);
      return json({ ok: true, policy: matrix.adaptivePolicy, origin: matrix.origin, limitations: {
        worker_native_tcp_inbound: false,
        worker_native_udp_inbound: false,
        vless_websocket_udp_dns_port53: true,
        generic_udp_relay: false,
        udp_protocols_require_origin_engine: true,
      } });
    }

    if (action === 'network/autoplan' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const host = new URL(request.url).hostname;
      const matrix = buildProtocolMatrix(env, host);
      const [pathRows, profileRows, state] = await Promise.all([loadPathHealth(db), loadProfileHealth(db), loadNetworkState(db)]);
      let learner = defaultEdgeLearner();
      const modelRow = await loadAdaptiveModel(db);
      if (modelRow) { try { learner = JSON.parse(modelRow.stateJson); } catch { /* safe default */ } }
      const predictive = Object.fromEntries(profileRows.map((r) => [r.profileId, {
        sampleCount: r.successes + r.failures, reliability: (r.successes + r.failures) ? r.successes / (r.successes + r.failures) : 0.5,
        latencyEwma: r.latencyMs, latencyVolatility: r.volatility ?? 1, successSlope: 0, latencySlope: 0,
        drift: (r.drift ?? 'stable') as 'improving'|'stable'|'degrading', forecastSuccess: r.forecastSuccess ?? 0.5,
        confidence: Math.min(1, (r.successes + r.failures) / 12),
      }]));
      const plan = buildAdaptiveProtocolPlan({ profiles: matrix.adaptivePolicy.profiles, health: profileRows, predictive, networkState: state ? { state: state.state as 'healthy'|'degraded'|'recovery'|'no_healthy_path', quorum: state.quorum, healthy: 0, degraded: 0, quarantined: 0, unknown: 0, total: pathRows.length, failureRate: state.failureRate, confidence: state.confidence, anomalyScore: state.anomalyScore, signalClass: state.signalClass as import('../ai/network-state').NetworkSignalClass, selectedPath: state.selectedPath || null, reasonCodes: state.reasonCodes, generatedAt: state.updatedAt } : null, learner, limit: 10 });
      await saveProtocolPolicyState(db, { selectedProfile: plan.selected || '', fallbackLadder: plan.fallbackLadder, reasonCodes: plan.reasonCodes, diversity: plan.diversity, confidence: plan.confidence, mode: plan.mode, consensus: plan.consensus, signalAgreement: plan.signalAgreement, switchRisk: plan.switchRisk, fusionMode: plan.fusionMode, policyFingerprint: plan.policyFingerprint, updatedAt: plan.generatedAt });
      return json({ ok: true, plan, persisted: true, origin: matrix.origin, generatedAt: Date.now() });
    }

    if (action === 'network/policy-state' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      return json({ ok: true, state: await loadProtocolPolicyState(db) });
    }

    if (action === 'network/fusion' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const state = await loadPolicySignalState(db);
      let parsed: Record<string, unknown> | null = null;
      if (state) { try { parsed = JSON.parse(state.stateJson) as Record<string, unknown>; } catch { parsed = null; } }
      return json({ ok: true, state: state ? { ...(parsed || {}), updatedAt: state.updatedAt } : null, semantics: {
        payloadInspection: false,
        censorshipIdentityProven: false,
        purpose: 'multi-signal policy gating',
      } });
    }

    if (action === 'network/guard' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const state = await loadAdaptiveGuardState(db);
      return json({
        ok: true,
        state,
        semantics: {
          autonomous_promotion: true,
          canary_hold_ms: 900000,
          change_window_ms: 1800000,
          max_changes_per_window: 3,
          rollback_on_active_failure: true,
          packet_mutation: false,
          dpi_mechanism_claimed: false,
        },
      });
    }

    if (action === 'network/profiles' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const rows = await loadProfileHealth(db);
      const observations = rows.map(r => ({
        profileId: r.profileId as 'standard' | 'fragmented' | 'alt-port' | 'fragmented-alt',
        ok: r.ok, latencyMs: r.latencyMs, failures: r.failures, successes: r.successes,
        checkedAt: r.checkedAt, consecutiveFailures: r.consecutiveFailures,
        consecutiveSuccesses: r.consecutiveSuccesses, quarantineUntil: r.quarantineUntil,
      }));
      const decision = decideAdaptiveProfile(observations);
      return json({ ok: true, decision, learning: { persistent: true, source: 'connection-telemetry', deterministicFallback: true } });
    }

    if (action === 'network/forecast' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const rows = await loadProfileHealth(db);
      const forecast = rows.map((r) => ({
        profileId: r.profileId, drift: r.drift ?? 'stable', forecastSuccess: r.forecastSuccess ?? 0.5,
        volatility: r.volatility ?? 1, samples: r.successes + r.failures, checkedAt: r.checkedAt,
      })).sort((a,b) => b.forecastSuccess - a.forecastSuccess);
      return json({ ok: true, forecast, semantics: { predictive: true, payloadInspection: false, censorshipIdentityProven: false } });
    }

    if (action === 'network/probe' && method === 'POST') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const body = (await request.json().catch(() => ({}))) as { url?: unknown };
      const target = String(body.url ?? '').trim();
      if (!/^https:\/\//i.test(target) || target.length > 2048) throw new GzError('invalid probe url', 'validation');
      const parsed = new URL(target);
      const settings = await loadSettings(db);
      const allowed = new Set(settings?.proxyIPs ?? eff.proxyIPs);
      if (!allowed.has(parsed.hostname)) throw new GzError('probe target is not configured', 'validation');
      const started = Date.now();
      let ok = false;
      let lastError = '';
      let httpStatus: number | null = null;
      try {
        const response = await fetch(parsed.toString(), { method:'HEAD', redirect:'error', signal:AbortSignal.timeout(5000) });
        ok = response.ok;
        httpStatus = response.status;
        if (!ok) lastError = 'http_failure:' + response.status;
      } catch (error) {
        lastError = normalizeFetchFailure(error);
      }
      const latencyMs = Date.now() - started;
      const previous = (await loadPathHealth(db)).find(r => r.pathId === parsed.hostname);
      const next = updateObservation(previous ? { id:previous.pathId, latencyMs:previous.latencyMs, ok:previous.ok, checkedAt:previous.checkedAt, failures:previous.failures, successes:previous.successes, quarantineUntil:previous.quarantineUntil, consecutiveFailures:previous.consecutiveFailures, consecutiveSuccesses:previous.consecutiveSuccesses, lastError:previous.lastError } : undefined, ok, latencyMs, Date.now(), lastError);
      next.id = parsed.hostname;
      await saveHealthSample(db, { kind: 'path_https', subjectId: next.id, ts: next.checkedAt, ok, latencyMs });
      await savePathHealth(db, { pathId:next.id, latencyMs:next.latencyMs, ok:next.ok, failures:next.failures, successes:next.successes, quarantineUntil:next.quarantineUntil, checkedAt:next.checkedAt, consecutiveFailures:next.consecutiveFailures, consecutiveSuccesses:next.consecutiveSuccesses, lastError: ok ? '' : lastError });
      const decision = decideResilience(await loadPathHealth(db).then(rows => rows.map(r => ({ id:r.pathId, latencyMs:r.latencyMs, ok:r.ok, checkedAt:r.checkedAt, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantineUntil, consecutiveFailures:r.consecutiveFailures, consecutiveSuccesses:r.consecutiveSuccesses, lastError:r.lastError }))));
      const failureDomain = ok ? null : classifyFailureDomain(lastError);
      await addEvent(db, 'network_probe', JSON.stringify({ host: parsed.hostname, ok, latencyMs, httpStatus, failureDomain }).slice(0, 1000));
      return json({ ok, latencyMs, httpStatus, failureDomain, decision, probeScope: 'HTTPS_HEAD_FROM_WORKER_EGRESS' });
    }

    if (action === 'ai/diagnostics' && method === 'POST') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const allowed = await consumeAiDiagnosticQuota(db, await ipHash(request));
      if (!allowed) return json({ error: 'ai_rate_limited' }, 429);
      const body = (await request.json().catch(() => ({}))) as { language?: unknown };
      const language = body.language === 'en' ? 'en' : 'fa';
      return json(await createDiagnostics(env, language));
    }

    if (action === 'settings' && method === 'GET') {
      const s = db ? await loadSettings(db) : null;
      const advisor = normalizeAdvisorApplication(s?.aiAdvisorApplication);
      const workerKillSwitch = advisorKillSwitchEnabled(env.AI_ADVISOR_KILL_SWITCH);
      return json({
        panelPath: s?.panelPath ?? eff.panelPath,
        subPath: s?.subPath ?? eff.subPath,
        proxyIPs: s?.proxyIPs ?? eff.proxyIPs,
        backupEntryHosts: s?.backupEntryHosts ?? eff.backupEntryHosts ?? [],
        resetCycle: s?.resetCycle ?? eff.resetCycle ?? 'none',
        isDefaultPassword: s?.isDefaultPassword ?? eff.isDefaultPassword,
        aiAdvisorEnabled: advisor.enabled,
        aiAdvisorKilled: advisor.killed,
        aiAdvisorKillSwitch: workerKillSwitch,
        aiAdvisorStatus: workerKillSwitch ? 'killed' : advisor.status,
        aiAdvisorActiveTransport: workerKillSwitch ? null : advisor.activeTransport,
        dbOk: eff.dbOk,
      });
    }

    if (action === 'settings' && method === 'POST') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;

      const next = await saveSettings(db, (prev) => {
        const cur: SettingsBlob = prev ?? {
          schemaVersion: 1, panelPath: eff.panelPath, subPath: eff.subPath,
          proxyIPs: eff.proxyIPs, resetCycle: 'none', passwordSalt: eff.passwordSalt, passwordHash: eff.passwordHash,
          pwIterations: eff.pwIterations, isDefaultPassword: eff.isDefaultPassword, createdAt: Date.now(),
        };
        const out: SettingsBlob = { ...cur };

        if (typeof body.aiAdvisorEnabled === 'boolean' || typeof body.aiAdvisorKilled === 'boolean') {
          out.aiAdvisorApplication = setAdvisorApplicationControls(out.aiAdvisorApplication, {
            enabled: typeof body.aiAdvisorEnabled === 'boolean' ? body.aiAdvisorEnabled : undefined,
            killed: typeof body.aiAdvisorKilled === 'boolean' ? body.aiAdvisorKilled : undefined,
          });
        }

        if (typeof body.panelPath === 'string') {
          const v = body.panelPath.trim().toLowerCase();
          if (!/^[a-z0-9][a-z0-9-]{2,31}$/.test(v)) throw new GzError('invalid panelPath', 'validation');
          out.panelPath = v;
        }
        if (typeof body.subPath === 'string') {
          const v = body.subPath.trim().toLowerCase();
          if (!/^[a-z0-9][a-z0-9-]{2,31}$/.test(v)) throw new GzError('invalid subPath', 'validation');
          out.subPath = v;
        }
        if (typeof body.resetCycle === 'string') {
          const v = body.resetCycle;
          if (v !== 'none' && v !== 'daily' && v !== 'weekly' && v !== 'monthly') {
            throw new GzError('invalid resetCycle', 'validation');
          }
          out.resetCycle = v;
        }
        if (Array.isArray(body.proxyIPs)) {
          const ips = (body.proxyIPs as unknown[])
            .map((x) => String(x).trim())
            .filter((x) => /^[a-z0-9.\-:]+$/i.test(x) && x.length <= 253);
          if (ips.length > 32) throw new GzError('too many proxyIPs', 'validation');
          out.proxyIPs = ips.length ? ips : ['proxyip.cmliussss.net'];
        }
        if (Array.isArray(body.backupEntryHosts)) {
          const hosts = (body.backupEntryHosts as unknown[])
            .map((x) => String(x).trim().toLowerCase())
            .filter((x) => /^[a-z0-9][a-z0-9.-]{2,252}$/.test(x) && x.includes('.'));
          if (hosts.length > 4) throw new GzError('too many backupEntryHosts (max 4)', 'validation');
          out.backupEntryHosts = hosts;
        }
        if (typeof body.newPassword === 'string' && body.newPassword.length > 0) {
          const pw = body.newPassword;
          if (pw.length < 8) throw new GzError('password too short (min 8)', 'validation');
          out.passwordSalt = randomHex(16);
          out.pwIterations = eff.pwIterations;
          // hash computed outside (async) — handled below
          (out as SettingsBlob & { __newPw?: string }).__newPw = pw;
        }
        return out;
      });

      // password hashing needs async — apply post-write if requested
      const marker = next as SettingsBlob & { __newPw?: string };
      if (marker.__newPw) {
        const pw = marker.__newPw;
        delete marker.__newPw;
        const salt = randomHex(16);
        const hash = await pbkdf2Hex(pw, salt, eff.pwIterations);
        marker.passwordSalt = salt;
        marker.passwordHash = hash;
        marker.isDefaultPassword = false;
        await saveSettings(db, () => marker);
        invalidateUsers();
        invalidateCache();
        await addEvent(db, 'password_changed', 'panel password updated');
      }
      invalidateCache();
      if (typeof body.aiAdvisorEnabled === 'boolean' || typeof body.aiAdvisorKilled === 'boolean') {
        const state = normalizeAdvisorApplication(next.aiAdvisorApplication);
        await addEvent(db, 'ai_advisor_control', JSON.stringify({ enabled: state.enabled, killed: state.killed, status: state.status }));
      }
      return json({ ok: true });
    }

    if (action === 'users' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const users = await listUsersFresh(db);
      const withTokens = [] as Array<Record<string, unknown>>;
      const host = new URL(request.url).hostname;
      for (const u of users) {
        withTokens.push({ ...publicUser(u), subToken: await subTokenFor(host, u.uuid) });
      }
      return json({ users: withTokens });
    }

    if (action === 'users' && method === 'POST') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      const name = String(body.name ?? '').trim().slice(0, 32);
      if (!/^[\w\u0600-\u06FF .-]{1,32}$/.test(name)) throw new GzError('invalid name', 'validation');
      const quotaGB = Number(body.quotaGB ?? 0);
      if (!Number.isFinite(quotaGB) || quotaGB < 0 || quotaGB > 1024 * 100) throw new GzError('invalid quotaGB', 'validation');
      const expiryAt = Number(body.expiryAt ?? 0);
      if (!Number.isSafeInteger(expiryAt) || expiryAt < 0) throw new GzError('invalid expiryAt', 'validation');
      const expiryDays = Number(body.expiryDays ?? 0);
      if (!Number.isSafeInteger(expiryDays) || expiryDays < 0 || expiryDays > 3650) throw new GzError('invalid expiryDays', 'validation');
      const quotaBytes = Math.round(quotaGB * 1024 ** 3);
      const actorUserId = await adminActorId(db);
      const audit: UserAuditMutation = {
        actorUserId,
        action: 'user_created',
        details: { name, quotaBytes, expiryAt, expiryDays },
      };
      const u = await createUser(db, { name, quotaBytes, expiryAt, expiryDays }, audit);
      return json({ user: publicUser(u) }, 201);
    }

    const userMatch = action.match(/^users\/(\d+)$/);
    if (userMatch) {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const id = Number(userMatch[1]);
      if (method === 'PATCH') {
        const before = await getUserByIdFresh(db, id);
        if (!before || before.isAdmin) throw new GzError('user not found', 'not_found');
        const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
        const patch: UserPatch = {};
        const details: Record<string, unknown> = {};
        if (body.name !== undefined) {
          if (typeof body.name !== 'string') throw new GzError('invalid name', 'validation');
          const n = body.name.trim().slice(0, 32);
          if (!/^[\w\u0600-\u06FF .-]{1,32}$/.test(n)) throw new GzError('invalid name', 'validation');
          patch.name = n;
          details.name = n;
        }
        if (body.quotaGB !== undefined) {
          const q = Number(body.quotaGB);
          if (!Number.isFinite(q) || q < 0 || q > 1024 * 100) throw new GzError('invalid quotaGB', 'validation');
          patch.quotaBytes = Math.round(q * 1024 ** 3);
          details.quotaBytes = patch.quotaBytes;
        }
        if (body.expiryAt !== undefined) {
          const x = Number(body.expiryAt);
          if (!Number.isSafeInteger(x) || x < 0) throw new GzError('invalid expiryAt', 'validation');
          patch.expiryAt = x;
          details.expiryAt = x;
        }
        if (body.expiryDays !== undefined) {
          const d = Number(body.expiryDays);
          if (!Number.isSafeInteger(d) || d < 0 || d > 3650) throw new GzError('invalid expiryDays', 'validation');
          patch.expiryDays = d;
          details.expiryDays = d;
          if (d > 0) {
            patch.expiryAt = 0; // first-use and absolute expiry modes are mutually exclusive
            details.expiryAt = 0;
          }
        }
        if (body.enabled !== undefined) {
          if (typeof body.enabled !== 'boolean') throw new GzError('enabled must be boolean', 'validation');
          patch.enabled = body.enabled;
          details.enabled = body.enabled;
        }
        if (body.resetUsage === true) {
          patch.resetUsage = true;
          patch.usedUp = 0;
          patch.usedDown = 0;
          details.resetUsage = true;
        }
        if (body.rotateCredentials === true) {
          patch.uuid = crypto.randomUUID();
          patch.trojanPass = randomHex(12);
          // Never write credential values to the audit record.
          details.credentialsRotated = true;
        }
        if (Object.keys(patch).length === 0) return json({ ok: true, unchanged: true });
        const actionName = patch.enabled === true
          ? 'user_enabled'
          : patch.enabled === false ? 'user_disabled' : 'user_updated';
        const audit: UserAuditMutation = {
          actorUserId: await adminActorId(db),
          action: actionName,
          details,
        };
        await updateUser(db, id, patch, audit);
        if (patch.usedUp !== undefined || patch.usedDown !== undefined) await flushUsage(db);
        invalidateUsers();
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        const target = await getUserByIdFresh(db, id);
        if (!target || target.isAdmin) throw new GzError('user not found', 'not_found');
        await deleteUser(db, id, {
          actorUserId: await adminActorId(db),
          action: 'user_deleted',
          details: { deleted: true },
        });
        return json({ ok: true });
      }
    }

    const linksMatch = action.match(/^users\/(\d+)\/links$/);
    if (linksMatch && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const id = Number(linksMatch[1]);
      const u = await getUserByIdFresh(db, id);
      if (!u) throw new GzError('user not found', 'not_found');
      const host = new URL(request.url).hostname;
      const links = buildLinks(host, u, null);
      const tok = await subTokenFor(host, u.uuid);
      return json({
        links,
        subBase: 'https://' + host + '/' + eff.subPath + '/' + tok,
        subClash: 'https://' + host + '/' + eff.subPath + '/' + tok + '/clash',
        subSingbox: 'https://' + host + '/' + eff.subPath + '/' + tok + '/singbox',
        subXray: 'https://' + host + '/' + eff.subPath + '/' + tok + '/xray',
        subAdaptive: 'https://' + host + '/' + eff.subPath + '/' + tok + '/adaptive',
        dnsDoh: 'https://' + host + '/' + eff.subPath + '/' + tok + '/dns-query',
        statusPage: 'https://' + host + '/' + eff.subPath + '/' + tok,
      });
    }

    // on-demand QR (server-side generation — v1.2 removed the client CDN loader)
    if (action === 'qr' && method === 'GET') {
      const raw = new URL(request.url).searchParams.get('t') ?? '';
      let text = '';
      try { text = decodeURIComponent(escape(atob(raw.replace(/-/g, '+').replace(/_/g, '/')))); }
      catch { throw new GzError('invalid qr payload', 'validation'); }
      if (!text || text.length > 512) throw new GzError('invalid qr payload', 'validation');
      return json({ svg: await qrSvg(text, 230) });
    }

    if (action === 'user-audit' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const query = new URL(request.url).searchParams;
      const rawLimit = query.get('limit');
      const rawBefore = query.get('before');
      const limit = rawLimit === null ? 50 : Number(rawLimit);
      const before = rawBefore === null ? 0 : Number(rawBefore);
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
          !Number.isSafeInteger(before) || before < 0) {
        throw new GzError('invalid audit pagination', 'validation');
      }
      return json({ events: await loadUserControlAudit(db, limit, before) });
    }

    if (action === 'events' && method === 'GET') {
      if (!db) return json({ events: [] });
      return json({ events: await recentEvents(db, 10) });
    }

    // 2.13 — internal decision view: the synthesized verdict of the local
    // intelligence engine (network state + condition + regime + probe state
    // machine + traffic shape + protocol plan + emergency ladder).
    if (action === 'network/decision' && method === 'GET') {
      if (!db) throw new GzError('database_not_bound', 'no_db');
      const [state, signal, policy, settings, pathRows] = await Promise.all([
        loadNetworkState(db), loadPolicySignalState(db), loadProtocolPolicyState(db), loadSettings(db), loadPathHealth(db),
      ]);
      let regime: RegimeAssessment | null = null;
      try {
        const rows = await loadPredictiveStates(db, 'regime');
        const row = rows.find((r) => r.subjectId === 'global');
        if (row) regime = JSON.parse(row.stateJson) as RegimeAssessment;
      } catch { /* optional */ }
      let signalJson: Record<string, unknown> | null = null;
      try { signalJson = signal ? (JSON.parse(signal.stateJson) as Record<string, unknown>) : null; } catch { signalJson = null; }
      const host = new URL(request.url).hostname;
      const ladder: Array<{ host: string; role: string; status: string; latencyMs: number | null }> = [
        { host, role: 'primary', status: 'primary', latencyMs: null },
      ];
      for (const bh of (settings?.backupEntryHosts ?? []).slice(0, 4)) {
        const row = pathRows.find((r) => r.pathId === 'entry:' + bh);
        ladder.push({
          host: bh, role: 'backup',
          status: row ? (row.ok ? 'measured_ok' : 'measured_failed') : 'unmeasured',
          latencyMs: row?.latencyMs ?? null,
        });
      }
      const conditionCode = state?.reasonCodes.find((c) => c.startsWith('condition_'));
      const view = buildDecisionView({
        networkState: state ? {
          state: state.state as 'healthy' | 'degraded' | 'recovery' | 'no_healthy_path',
          confidence: state.confidence, updatedAt: state.updatedAt, reasonCodes: state.reasonCodes,
        } : null,
        conditionState: conditionCode ? conditionCode.slice('condition_'.length).toUpperCase() : null,
        regime,
        probeMode: signalJson?.probeMode === 'aggressive' ? 'aggressive' : 'normal',
        shape: shapeModeFor(env.TRAFFIC_SHAPE),
        plan: policy ? {
          selected: policy.selectedProfile || null,
          strategy: (signalJson?.strategy as 'stable' | 'diversify' | 'safe') ?? 'stable',
          confidence: policy.confidence,
          mode: policy.mode as 'normal' | 'degraded' | 'recovery' | 'no_healthy_path',
          fallbackLadder: policy.fallbackLadder,
          reasonCodes: policy.reasonCodes,
        } : null,
        ladder,
      });
      return json(view);
    }

    return json({ error: 'not_found' }, 404);
  } catch (e) {
    if (e instanceof GzError && e.code === 'unauthorized') {
      return json({ error: 'unauthorized' }, 401);
    }
    if (e instanceof GzError && e.code === 'validation') {
      return json({ error: e.message }, 400);
    }
    if (e instanceof GzError && e.code === 'not_found') {
      return json({ error: e.message }, 404);
    }
    if (e instanceof GzError && e.code === 'no_db') {
      return json({ error: 'database_not_bound' }, 503);
    }
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
}

export async function checkIsAuthed(request: Request, eff: EffectiveSettings): Promise<boolean> {
  return isAuthed(request, eff);
}
