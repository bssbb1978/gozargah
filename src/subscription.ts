/**
 * Gozargah — subscription engine. Everything is generated in-worker:
 * no third-party subconverter, no runtime dependency on raw.githubusercontent.
 *
 * Formats: base64 (v2rayNG/NeoR/Streisand) · clash-meta YAML · sing-box JSON
 *          · xray-core JSON (v1.2: observatory + leastPing auto-best + fragment)
 * Client detection: UA sniffing + explicit /{app} override.
 * v1.2 tuning: per-operator presets (?op=) + ECH strictly opt-in (?ech=1).
 * Headers: real Subscription-Userinfo from byte accounting (not fake {usage}).
 */

import { toBase64 } from './utils/crypto';
import { GzUser, listUsers } from './db/users';
import { loadAdaptiveGuardState, loadAdaptiveModel, loadCanaryState, loadCleanIPHarvest, loadNetworkState, loadPathHealth, loadPolicySignalState, loadPredictiveStates, loadProfileHealth, loadSettings, loadUserAdaptiveState, saveAdaptiveGuardState, saveProtocolPolicyState } from './db/store';
import { decideResilience, type PathObservation } from './ai/resilience';
import { assessPressure, canaryEvidence } from './ai/pressure';
import { buildAdaptiveProtocolPlan } from './ai/protocol-controller';
import { nextAdaptiveGuardState, reconcileAdaptivePlan } from './ai/adaptive-guard';
import { EffectiveSettings } from './settings';
import { DEFAULT_FP, FragPreset, adaptiveProfiles, fpFor, opBranding, resolveOp, SubOpts, AdaptiveProfile } from './sub/operators';
import { PATH_ROTATION_WINDOW_MS, rotatedPathBase } from './sub/path-rotation';
import { NEUTRAL_FINGERPRINTS, rotatedFingerprint } from './sub/fp-rotation';
import { shapeModeFor } from './utils/shape';
import type { RegimeAssessment } from './ai/regime';
import { ALPN_PROFILES, protocolCatalog, adaptiveProtocolOrder, parseOriginTransports, type ProtocolCapability } from './protocols/catalog';
import { buildAdaptiveProtocolPolicy, choosePreferredProfiles, policySummary } from './protocols/policy';
import { Env, VERSION } from './config';
import { SHADOWSOCKS_METHOD } from './protocols/shadowsocks';

export interface ClientLinks {
  vless: string;
  trojan: string;
  shadowsocks: string;
  wsPath: string;
}

export interface ProtocolMatrixBundle {
  version: string;
  edge: { host: string; nativeProtocols: Array<{ protocol: string; transport: string; ready: boolean }> };
  origin: { configured: boolean; host?: string; port?: number; validation: 'not_configured' | 'invalid_port' | 'declared_not_tested' };
  capabilities: ReturnType<typeof protocolCatalog>;
  preferredOrder: ReturnType<typeof adaptiveProtocolOrder>;
  alpnProfiles: string[][];
  generatedAt: number;
  adaptivePolicy: { profiles: ReturnType<typeof buildAdaptiveProtocolPolicy>; preferred: ReturnType<typeof choosePreferredProfiles>; summary: ReturnType<typeof policySummary> };
}

function parseOriginEnginePort(value?: string): number | null {
  if (value == null || value.trim() === '') return 443;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

export function buildProtocolMatrix(env: Env | undefined, host: string): ProtocolMatrixBundle {
  const originHost = env?.ORIGIN_ENGINE_HOST?.trim() || '';
  const originPort = parseOriginEnginePort(env?.ORIGIN_ENGINE_PORT);
  const configured = !!originHost && originPort !== null;
  const originTransports = parseOriginTransports(env?.ORIGIN_ENGINE_TRANSPORTS);
  const all = protocolCatalog(configured, originTransports);
  const adaptiveProfiles = buildAdaptiveProtocolPolicy(all);
  return {
    version: VERSION,
    edge: { host, nativeProtocols: all.filter((c) => c.mode === 'native-edge').map((c) => ({ protocol: c.protocol, transport: c.transport, ready: c.ready })) },
    origin: configured
      ? { configured: true, host: originHost, port: originPort!, validation: 'declared_not_tested' }
      : { configured: false, validation: originHost ? 'invalid_port' : 'not_configured' },
    capabilities: all,
    preferredOrder: adaptiveProtocolOrder(configured, originTransports),
    alpnProfiles: ALPN_PROFILES,
    generatedAt: Date.now(),
    adaptivePolicy: { profiles: adaptiveProfiles, preferred: choosePreferredProfiles(adaptiveProfiles, 14), summary: policySummary(adaptiveProfiles) },
  };
}

function originTemplates(capabilities: ProtocolCapability[], transports: readonly string[], host: string, port: number, uuid: string, password: string): Record<string, unknown> {
  const allowed = new Set(transports);
  const canGenerate = (protocol: string, transport: string): boolean =>
    allowed.has(transport) && capabilities.some((cap) => cap.protocol === protocol && cap.transport === transport && cap.generatorAvailable && cap.ready);
  const templates: Record<string, unknown> = {};
  const path = '/' + uuid;
  const tls = { enabled: true, allow_insecure: false };
  if (canGenerate('vmess', 'ws')) templates.vmess_ws = { protocol: 'vmess', transport: 'ws', server: host, port, id: uuid, tls, alpn: ['http/1.1'] };
  // Trojan/WebSocket has a real Worker-native generator and also an existing
  // direct-origin Xray outbound; the capability row gates that shared pair.
  if (canGenerate('trojan', 'ws')) templates.trojan_ws = { protocol: 'trojan', transport: 'ws', server: host, port, password, tls, alpn: ['http/1.1'] };
  if (canGenerate('vless', 'xhttp')) templates.vless_xhttp = { protocol: 'vless', transport: 'xhttp', server: host, port, id: uuid, tls, path };
  if (canGenerate('trojan', 'xhttp')) templates.trojan_xhttp = { protocol: 'trojan', transport: 'xhttp', server: host, port, password, tls, path };
  if (canGenerate('vless', 'grpc')) templates.vless_grpc = { protocol: 'vless', transport: 'grpc', server: host, port, id: uuid, tls, alpn: ['h2'], service_name: 'g' };
  if (canGenerate('vless', 'httpupgrade')) templates.vless_httpupgrade = { protocol: 'vless', transport: 'httpupgrade', server: host, port, id: uuid, tls, alpn: ['http/1.1'], path };
  return templates;
}

/**
 * 2.14 — AXR client manifest: the machine-readable feed the native AXR core
 * bootstraps from. Aggregate server-side intelligence (regime, strategy,
 * probe mode, measured entry health, rotation windows) in one small JSON.
 * Authenticated by the same subscription bearer token; no payload data.
 *
 * 2.16 — v3: integrity + resilience fields
 *   - `manifest_sig`: HMAC-SHA256 over a canonical string of the structural
 *     fields, keyed by the user's subscription token. The client core
 *     recomputes it and rejects a tampered/altered manifest (falling back to
 *     its last-known-good copy). The shared test vector lives in
 *     docs/AXR-V3-HYPER-RESILIENCE.md and in both test suites.
 *   - `clean_ip_hints`: union of the operator's CLEAN_EDGE_IPS env and the
 *     D1-persisted harvest (fed by the client `scan` runner via the
 *     /api/network/harvest endpoint), capped at 16.
 *   - `fronting_hint`: optional domestic-CDN relay host (FRONTING_RELAY_HOST
 *     env) the client merges into its entry ladder.
 *
 * 2.17 — closed-loop pressure (internal AI, fully dynamic):
 *   - `pressure`: the ai/pressure engine fuses the fleet's canary liveness
 *     evidence, clean-IP harvest freshness, and the aggregate regime label
 *     into a 0-3 level. It drives the *dynamic* manifest levers — the client
 *     probe cadence (reconnect.probe_interval_ms), the outflow profile floor
 *     (flow_profile.mode), and exposed backup-entry diversity. `path_rotation
 *     _minutes` stays the real deterministic window (honesty: the manifest
 *     never advertises a rotation faster than the path actually rotates).
 *   - `canary`: when AXR_CANARY_HOST is configured, a canary host rides in
 *     the signed `entries` field (role "canary" — a probe target, never a
 *     tunnel arm) plus a top-level convenience pointer. Clients probe it as
 *     a plain TLS liveness check and report ok/fail via harvest kind="canary",
 *     which feeds the pressure engine. Liveness signal, never a DPI detector.
 */
export async function buildAxrManifest(host: string, user: { uuid: string }, env?: Env, token?: string): Promise<string> {
  const db = env?.GZ_DB;
  const now = Date.now();
  const out: Record<string, unknown> = {
    schema: 'gozargah-axr-manifest/v3',
    version: VERSION,
    generated_at: now,
    host,
    ws_path_base: rotatedPathBase(user.uuid),
    path_rotation_minutes: PATH_ROTATION_WINDOW_MS / 60_000,
    fingerprint: {
      rotation_minutes: 360,
      current: fpFor({}, user.uuid),
      neutral_set: [...NEUTRAL_FINGERPRINTS],
      note: 'Client-side uTLS identity the generated identity window selects; TLS terminates at the edge.',
    },
    traffic_shape: { mode: shapeModeFor(env?.TRAFFIC_SHAPE) },
    // 2.15 — AXR-v2 fields:
    transports: ['ws', 'ws-alt'],
    flow_profile: { mode: 'web', note: 'Target outflow length/IPD profile the client core should match; regime can escalate to "video".' },
    clean_ip_hints: cleanIpHints(env?.CLEAN_EDGE_IPS),
    reconnect: {
      strategy: 'observe_and_failover',
      probe_interval_ms: 90_000,
      // 2.17 — width (ms) of the per-client uniform offset (deterministic
      // per UUID) the client adds to the probe cadence; 0 = fleet-synchronized.
      probe_jitter_ms: 0,
      backoff_ms: [1000, 2000, 5000, 15000, 30000],
      on_route_reopen: 'immediate_resume',
    },
    entries: [{ host, role: 'primary', status: 'primary', latency_ms: null }],
    honest_limit: {
      en: 'Aggregate server-side statistics only. Not DPI detection; no bypass guaranteed; a fully cut route cannot be restored from inside the Worker.',
      fa: 'فقط آمار تجمیعی سمت Worker است؛ تشخیص DPI نیست، عبور تضمین‌شده نیست و در قطع کامل مسیر، از راه دور قابل‌رفع نیست.',
    },
  };
  // 2.17 — canary host (env config; validated hostname, '' when absent).
  const canary = frontingHint(env?.AXR_CANARY_HOST);
  if (db) {
    try {
      const [ns, regimeRows, signal, settings, pathRows, harvest, canaryState] = await Promise.all([
        loadNetworkState(db),
        loadPredictiveStates(db, 'regime'),
        loadPolicySignalState(db),
        loadSettings(db),
        loadPathHealth(db),
        loadCleanIPHarvest(db),
        loadCanaryState(db),
      ]);
      const regimeRow = regimeRows.find((r) => r.subjectId === 'global');
      let regimeState: string | undefined;
      if (regimeRow) {
        const parsed = JSON.parse(regimeRow.stateJson) as RegimeAssessment;
        out.regime = { state: parsed.state, confidence: parsed.confidence, recent_success: parsed.recentSuccess, baseline_success: parsed.baselineSuccess };
        regimeState = parsed.state;
      }
      if (ns) {
        out.network_state = { state: ns.state, updated_at: ns.updatedAt };
      }
      // 2.17 — pressure engine: fleet canary evidence + harvest freshness +
      // regime label -> 0-3 level -> the dynamic manifest levers (probe
      // cadence, outflow-profile floor, entry diversity). Fully automatic —
      // the client's canary probes and scan uploads are the only inputs.
      const { failFrac, ageMin } = canaryEvidence(canaryState?.results ?? []);
      const pressure = assessPressure({
        canaryConfigured: canary !== '',
        canaryFailFrac: failFrac,
        canaryAgeMin: ageMin,
        harvestAgeMin: harvest ? (now - harvest.updatedAt) / 60_000 : null,
        regimeState: regimeState ?? 'stable',
      });
      (out.reconnect as Record<string, unknown>).probe_interval_ms = pressure.probeIntervalMs;
      (out.flow_profile as Record<string, unknown>).mode = pressure.flowProfile;
      out.pressure = { level: pressure.level, reasons: pressure.reasons };
      // The network-state machine still overrides the cadence when it has
      // DIRECTLY measured a dead/recovering route (stronger than inference).
      if (ns?.state === 'recovery' || ns?.state === 'no_healthy_path') {
        (out.reconnect as Record<string, unknown>).probe_interval_ms = Math.min(pressure.probeIntervalMs, 30_000);
        (out.flow_profile as Record<string, unknown>).mode = 'video';
      }
      // 2.17 — probe de-synchronization: fleet-wide phase-locked probing is
      // itself a visible fingerprint, so each client offsets its cadence by
      // a uniform draw (deterministic per UUID) within this width. Kept
      // <= the applied interval (at most one cycle wide).
      const appliedInterval = (out.reconnect as Record<string, unknown>).probe_interval_ms as number;
      (out.reconnect as Record<string, unknown>).probe_jitter_ms = Math.min(pressure.probeJitterMs, appliedInterval);
      if (signal) {
        try {
          const sig = JSON.parse(signal.stateJson) as Record<string, unknown>;
          if (typeof sig.strategy === 'string') out.strategy = sig.strategy;
          if (sig.probeMode === 'aggressive') out.probe_mode = 'aggressive';
        } catch { /* optional */ }
      }
      // 2.17 — under elevated pressure expose more backup diversity (all
      // configured backups are our own domains; more options for the ladder).
      for (const bh of (settings?.backupEntryHosts ?? []).slice(0, pressure.level >= 2 ? 6 : 4)) {
        const row = pathRows.find((r) => r.pathId === 'entry:' + bh);
        out.entries = [
          ...(out.entries as Array<Record<string, unknown>>),
          { host: bh, role: 'backup', status: row ? (row.ok ? 'measured_ok' : 'measured_failed') : 'unmeasured', latency_ms: row?.latencyMs ?? null },
        ];
      }
      // 2.16 — union operator env hints with D1-persisted harvested IPs.
      if (harvest && harvest.ips.length > 0) {
        const merged = [...cleanIpHints(env?.CLEAN_EDGE_IPS), ...harvest.ips.filter((ip) => !(out.clean_ip_hints as string[]).includes(ip))];
        out.clean_ip_hints = merged.slice(0, 16);
      }
    } catch { /* manifest stays minimal when D1 reads fail */ }
  }
  // 2.16 — domestic-CDN fronting hint (validated hostname only).
  const fronting = frontingHint(env?.FRONTING_RELAY_HOST);
  if (fronting) out.fronting_hint = fronting;
  // 2.17 — canary: a probe target, never a tunnel arm. The host rides in the
  // SIGNED entries field (role "canary") so a tampered canary fails the HMAC;
  // the top-level pointer is a convenience mirror for the client core.
  if (canary) {
    out.entries = [
      ...(out.entries as Array<Record<string, unknown>>),
      { host: canary, role: 'canary', status: 'probe_target', latency_ms: null },
    ];
    out.canary = { host: canary, expect: 'ok', interval_ms: 300_000 };
  }
  // 2.16 — manifest integrity: HMAC-SHA256 keyed by the subscription token.
  if (token) {
    try {
      out.manifest_sig = await manifestSign(manifestCanonical(out), token);
    } catch { /* signature is best-effort; the client treats absence as "v2, unverified" */ }
  }
  return JSON.stringify(out, null, 2);
}

/** Parse + validate CLEAN_EDGE_IPS into a bounded list of IPv4 hints. */
export function cleanIpHints(raw: string | undefined): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const part of raw.split(',')) {
    const ip = part.trim();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
      const octets = ip.split('.').map(Number);
      if (octets.every((o) => o >= 0 && o <= 255)) out.push(ip);
    }
    if (out.length >= 8) break;
  }
  return out;
}

/** Validate FRONTING_RELAY_HOST into a bare lowercase hostname (or ''). */
export function frontingHint(raw: string | undefined): string {
  const h = (raw ?? '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  return /^[a-z0-9][a-z0-9.-]{2,252}$/.test(h) && h.includes('.') ? h : '';
}

/**
 * Canonical string of the structural manifest fields, in a FIXED order,
 * joined by '|'. The client core must build the same string from the
 * parsed JSON before recomputing the HMAC. Fields covered: schema,
 * version, host, ws_path_base, path_rotation_minutes, transports,
 * entries (host:role, sorted), clean_ip_hints, fronting_hint,
 * flow_profile.mode, reconnect.probe_interval_ms. Deliberately NOT
 * covered: generated_at (time-dependent), honest_limit (display text),
 * regime/network_state (server intelligence the client only observes),
 * reconnect.probe_jitter_ms (advisory de-sync width — tampering with it
 * is harmless, so it rides outside the signature like backoff_ms).
 */
export function manifestCanonical(out: Record<string, unknown>): string {
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');
  const num = (v: unknown): string => (typeof v === 'number' && Number.isFinite(v) ? String(v) : '');
  const entries = Array.isArray(out.entries) ? (out.entries as Array<Record<string, unknown>>) : [];
  const entryKeys = entries
    .filter((e) => typeof e?.host === 'string' && typeof e?.role === 'string')
    .map((e) => e.host as string + ':' + e.role as string)
    .sort();
  const transports = Array.isArray(out.transports) ? (out.transports as string[]) : [];
  const hints = Array.isArray(out.clean_ip_hints) ? (out.clean_ip_hints as string[]) : [];
  const flow = (typeof out.flow_profile === 'object' && out.flow_profile !== null ? out.flow_profile : {}) as Record<string, unknown>;
  const reconnect = (typeof out.reconnect === 'object' && out.reconnect !== null ? out.reconnect : {}) as Record<string, unknown>;
  return [
    str(out.schema),
    str(out.version),
    str(out.host),
    str(out.ws_path_base),
    num(out.path_rotation_minutes),
    transports.join(','),
    entryKeys.join(','),
    hints.join(','),
    str(out.fronting_hint),
    str(flow.mode),
    num(reconnect.probe_interval_ms),
  ].join('|');
}

/** HMAC-SHA256 hex over a UTF-8 canonical string, keyed by token. */
export async function manifestSign(canonical: string, token: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(token), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonical));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function buildAdaptiveClientBundle(host: string, user: { uuid: string; trojanPass: string; name: string }, opts: BuildOpts | null | undefined, env?: Env, dnsUrl?: string): string {
  const matrix = buildProtocolMatrix(env, host);
  const originTransports = parseOriginTransports(env?.ORIGIN_ENGINE_TRANSPORTS);
  const out: Record<string, unknown> = {
    schema: 'gozargah-adaptive-profiles/v4',
    generated_at: matrix.generatedAt,
    selection: { strategy: 'health-weighted', native_first: true, fallback: 'next-healthy' },
    native: {
      vless_ws: buildLinks(host, user, opts).vless,
      trojan_ws: buildLinks(host, user, opts).trojan,
      shadowsocks_ws: buildLinks(host, user, opts).shadowsocks,
    },
    dynamic_path: {
      rotationMinutes: PATH_ROTATION_WINDOW_MS / 60_000,
      currentBase: rotatedPathBase(user.uuid),
      note: 'The WebSocket path rotates deterministically per window; older windows remain valid, so installed clients are never stranded.',
    },
    fingerprint: {
      rotation: '6h-window',
      current: fpFor(opts, user.uuid),
      neutralSet: [...NEUTRAL_FINGERPRINTS],
      operatorWins: true,
      note: 'Client-side uTLS/JA4 diversity: the generated configs rotate the ClientHello identity (extension order/ciphers/curves) per window. TLS is terminated at the Cloudflare edge; the Worker never sees or mutates the ClientHello.',
    },
    traffic_shape: {
      mode: shapeModeFor(env?.TRAFFIC_SHAPE),
      note: 'Server-side, in-tunnel size/timing entropy (bounded downlink segmentation + handshake jitter). The payload stays inside the edge TLS tunnel; no protocol bytes change.',
    },
    dns_forwarding: {
      doh_url: dnsUrl || null,
      client_udp: 'VLESS UDP DNS only (destination port 53)',
      upstream: 'HTTPS RFC 8484 with bounded adaptive failover',
      dns64: 'AAAA synthesis for RFC 6052 NAT64 when enabled; requires a reachable NAT64 translator',
    },
    capability_matrix: matrix.capabilities,
    preferred_order: matrix.preferredOrder,
    adaptive_policy: matrix.adaptivePolicy,
  };
  if (matrix.origin.configured) {
    const oh = matrix.origin.host!;
    const op = matrix.origin.port!;
    out.origin = {
      host: oh,
      port: op,
      note: 'Origin-engine profiles require a compatible Xray/sing-box listener. The Worker does not terminate native UDP protocols.',
      engine_validation: 'declared_not_tested',
      protocol_templates: originTemplates(matrix.capabilities, originTransports, oh, op, user.uuid, user.trojanPass),
    };
  }
  return JSON.stringify(out, null, 2);
}


export async function buildLiveAdaptiveClientBundle(
  host: string,
  user: { id?: number; uuid: string; trojanPass: string; name: string },
  opts: BuildOpts | null | undefined,
  env?: Env,
  dnsUrl?: string,
): Promise<string> {
  const base = JSON.parse(buildAdaptiveClientBundle(host, user, opts, env, dnsUrl)) as Record<string, unknown>;
  const now = Date.now();
  const matrix = buildProtocolMatrix(env, host);
  const db = env?.GZ_DB;
  let networkState = null as Awaited<ReturnType<typeof loadNetworkState>>;
  let profileHealth = [] as Awaited<ReturnType<typeof loadProfileHealth>>;
  let userState = null as Awaited<ReturnType<typeof loadUserAdaptiveState>>;
  let learner: ReturnType<typeof JSON.parse> | undefined;
  let pathRows: Awaited<ReturnType<typeof loadPathHealth>> = [];
  let regime: RegimeAssessment | null = null;
  let backupHosts: string[] = [];
  if (db) {
    try { networkState = await loadNetworkState(db); } catch { /* optional */ }
    try { profileHealth = await loadProfileHealth(db); } catch { /* optional */ }
    try { pathRows = await loadPathHealth(db); } catch { /* optional */ }
    try {
      const s = await loadSettings(db);
      backupHosts = (s?.backupEntryHosts ?? []).slice(0, 4);
    } catch { /* optional */ }
    if (user.id && user.id > 0) {
      try { userState = await loadUserAdaptiveState(db, user.id); } catch { /* optional */ }
    }
    try {
      const row = await loadAdaptiveModel(db);
      if (row) learner = JSON.parse(row.stateJson);
    } catch { /* optional */ }
    try {
      const rows = await loadPredictiveStates(db, 'regime');
      const row = rows.find((r) => r.subjectId === 'global');
      if (row) {
        const parsed = JSON.parse(row.stateJson) as RegimeAssessment;
        if (parsed && typeof parsed.state === 'string' && Number.isFinite(parsed.confidence)) regime = parsed;
      }
    } catch { /* optional */ }
  }
  const observations: PathObservation[] = pathRows.map(r => ({
    id: r.pathId, latencyMs: r.latencyMs, ok: r.ok, checkedAt: r.checkedAt,
    failures: r.failures, successes: r.successes, quarantineUntil: r.quarantineUntil,
    consecutiveFailures: r.consecutiveFailures, consecutiveSuccesses: r.consecutiveSuccesses,
    lastError: r.lastError,
  }));
  const resilience = observations.length ? decideResilience(observations, now, learner, userState?.preferredPathId ?? '') : null;
  const networkDecision = networkState ? {
    state: networkState.state as 'healthy'|'degraded'|'recovery'|'no_healthy_path',
    quorum: networkState.quorum, healthy: 0, degraded: 0, quarantined: 0, unknown: 0,
    total: observations.length, failureRate: networkState.failureRate, confidence: networkState.confidence, anomalyScore: networkState.anomalyScore, signalClass: networkState.signalClass as import('./ai/network-state').NetworkSignalClass,
    selectedPath: networkState.selectedPath || null, reasonCodes: networkState.reasonCodes, generatedAt: networkState.updatedAt,
  } : null;
  const predictive = Object.fromEntries(profileHealth.map((row) => [row.profileId, {
    sampleCount: row.successes + row.failures,
    reliability: (row.successes + row.failures) ? row.successes / (row.successes + row.failures) : 0.5,
    latencyEwma: row.latencyMs, latencyVolatility: row.volatility ?? 1,
    successSlope: 0, latencySlope: 0, drift: (row.drift ?? 'stable') as 'improving'|'stable'|'degrading',
    forecastSuccess: row.forecastSuccess ?? 0.5, confidence: Math.min(1, (row.successes + row.failures) / 12),
  }]));
  const controllerPlan = buildAdaptiveProtocolPlan({
    profiles: matrix.adaptivePolicy.profiles,
    health: profileHealth,
    predictive,
    networkState: networkDecision,
    learner,
    regime: regime ?? undefined,
    preferredProfileId: userState?.preferredProfileId ?? '',
    limit: 10,
    now,
  });

  let activePlan = controllerPlan;
  let guardMeta: Record<string, unknown> | null = null;
  if (db) {
    try {
      const guardState = await loadAdaptiveGuardState(db);
      const decision = reconcileAdaptivePlan(controllerPlan, guardState ?? undefined, profileHealth.map((r) => ({
        profileId: r.profileId, latencyMs: r.latencyMs, failures: r.failures, successes: r.successes,
        quarantineUntil: r.quarantineUntil, checkedAt: r.checkedAt, consecutiveFailures: r.consecutiveFailures, consecutiveSuccesses: r.consecutiveSuccesses,
      })), now);
      activePlan = decision.active;
      const nextGuard = nextAdaptiveGuardState(guardState ?? undefined, decision, now);
      await saveAdaptiveGuardState(db, nextGuard);
      await saveProtocolPolicyState(db, {
        selectedProfile: activePlan.selected || '', fallbackLadder: activePlan.fallbackLadder, reasonCodes: activePlan.reasonCodes,
        diversity: activePlan.diversity, confidence: activePlan.confidence, mode: activePlan.mode,
        consensus: activePlan.consensus, signalAgreement: activePlan.signalAgreement, switchRisk: activePlan.switchRisk, fusionMode: activePlan.fusionMode,
        policyFingerprint: activePlan.policyFingerprint, updatedAt: activePlan.generatedAt,
      });
      guardMeta = { status: decision.status, promoted: decision.promoted, rolledBack: decision.rolledBack, staged: decision.staged?.policyFingerprint ?? null, reasonCodes: decision.reasonCodes };
    } catch { /* guard is best-effort; candidate remains safe */ }
  }

  // 2.12 — emergency ladder: the primary entry plus configured backup entry
  // hosts, each with last measured health. Honest by construction: this only
  // helps when at least one entry point is still reachable from the client.
  const pathBase = rotatedPathBase(user.uuid);
  const entries: Array<Record<string, unknown>> = [{
    host, role: 'primary', url: 'wss://' + host + pathBase,
    status: 'primary', latencyMs: null,
  }];
  for (const bh of backupHosts) {
    const row = pathRows.find((r) => r.pathId === 'entry:' + bh);
    entries.push({
      host: bh, role: 'backup', url: 'wss://' + bh + pathBase,
      status: row ? (row.ok ? 'measured_ok' : 'measured_failed') : 'unmeasured',
      latencyMs: row?.latencyMs ?? null,
      checkedAt: row?.checkedAt ?? null,
    });
  }
  base.emergency_ladder = {
    schema: 'gozargah-emergency-ladder/v1',
    network_state: networkDecision?.state ?? (networkState ? networkState.state : 'unknown'),
    entries,
    honest_limit: {
      fa: 'اگر از شبکهٔ شما هیچ مسیری تا این Worker/کلادفلر باقی نمانده باشد، هیچ نرم‌افزاری نمی‌تواند از راه دور مسیر تازه‌ای بسازد؛ این پله فقط وقتی کمک می‌کند که دست‌کم یکی از نقاط ورود هنوز قابل‌رسو باشد.',
      en: 'If no route from your network reaches this Worker/Cloudflare edge, no software can create a new route remotely; this ladder only helps when at least one entry point is still reachable.',
    },
  };
  base.schema = 'gozargah-live-adaptive-profiles/v8';
  base.generated_at = now;
  base.live_policy = {
    ...activePlan,
    guard: guardMeta,
    path_selection: resilience ? {
      selected: resilience.selectedPath,
      mode: resilience.mode,
      confidence: resilience.confidence,
      candidates: resilience.candidates.slice(0, 12).map(x => ({ id: x.id, score: x.score, state: x.state, failureRate: x.failureRate, latencyMs: x.latencyMs })),
    } : null,
    network_state: networkState,
    client_behavior: {
      sticky_preference: userState?.preferredProfileId || null,
      switch_only_on_degrade_or_failure: true,
      bounded_recovery_candidates: resilience?.recoveryCandidates?.slice(0, 2) ?? [],
      no_random_protocol_generation: true,
      // 2.13 — smart reconnection loop: probe harder while the engine reports
      // recovery, back off calmly otherwise; failover follows the ladder.
      reconnect: {
        strategy: 'observe_and_failover',
        probeIntervalMs: activePlan.mode === 'recovery' || activePlan.mode === 'no_healthy_path' ? 30_000 : 90_000,
        backoffMs: [1000, 2000, 5000, 15000, 30000],
        failoverOrder: entries.map((e) => e.host as string),
        on_route_reopen: 'immediate_resume',
      },
    },
  };
  return JSON.stringify(base, null, 2);
}

export interface BuildOpts extends SubOpts {
  /** alt TLS port (Workers HTTPS ports) — default 443 */
  port?: number;
  /** override remark label (default: auto) */
  remark?: string;
}

function remarkFor(user: { name: string }, opts: BuildOpts | null | undefined): string {
  const brand = opBranding(opts);
  const proto = ' Gozargah';
  if (brand) return proto + ' · ' + brand.fa + ' · ' + user.name;
  return proto + ' · ' + user.name;
}

export function buildLinks(
  host: string,
  user: { uuid: string; trojanPass: string; name: string },
  opts: BuildOpts | null | undefined,
): ClientLinks {
  const port = opts?.port && opts.port !== 443 ? opts.port : 443;
  // 2.12 — deterministic 6h-rotating path; the Worker accepts any path.
  const wsPath = rotatedPathBase(user.uuid) + '?ed=2048&gz_profile=standard';
  // 2.13 — neutral uTLS/JA4 fingerprint rotates per (uuid | 6h window).
  const fp = fpFor(opts, user.uuid);
  const ech = opts?.ech ? '&ech=' : '';
  const tag = encodeURIComponent(remarkFor(user, opts));
  const params =
    'security=tls&sni=' + host + '&fp=' + fp + '&type=ws&host=' + host +
    '&path=' + encodeURIComponent(wsPath) + ech;
  const vless =
    'vless://' + user.uuid + '@' + host + ':' + port + '?encryption=none&' + params +
    '#' + tag;
  const trojan =
    'trojan://' + user.trojanPass + '@' + host + ':' + port + '?' + params +
    '#' + tag;
  const ssUserInfo = toBase64(SHADOWSOCKS_METHOD + ':' + user.uuid)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  const plugin = encodeURIComponent('v2ray-plugin;mode=websocket;tls;host=' + host + ';path=/ss/' + user.uuid);
  const shadowsocks = 'ss://' + ssUserInfo + '@' + host + ':' + port + '/?plugin=' + plugin + '#' + tag;
  return { vless, trojan, shadowsocks, wsPath };
}

export async function subTokenFor(host: string, uuid: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('gz-sub:' + host + ':' + uuid));
  const hex = [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 20);
}

/** Resolve a subscription token to its user (admin included). */
export async function findUserByToken(db: D1Database, host: string, token: string): Promise<GzUser | null> {
  const users = await listUsers(db);
  for (const u of users) {
    if ((await subTokenFor(host, u.uuid)) === token) return u;
  }
  return null;
}

/* ------------------------------ formatters ------------------------------ */

export function buildBase64(links: ClientLinks[]): string {
  return toBase64(links.map((l) => [l.vless, l.trojan, l.shadowsocks].join('\n')).join('\n'));
}

export function buildClashYaml(
  host: string,
  user: { uuid: string; trojanPass: string; name: string },
  opts: BuildOpts | null | undefined,
  dnsUrl?: string,
  backupHosts?: string[],
): string {
  const port = opts?.port && opts.port !== 443 ? opts.port : 443;
  const wsPath = rotatedPathBase(user.uuid) + '?ed=2048&gz_profile=standard';
  const fp = fpFor(opts, user.uuid);
  const brand = opBranding(opts);
  const vName = 'Gozargah-VLESS-' + (brand ? brand.en.split(' ')[0] + '-' : '') + user.name;
  const tName = 'Gozargah-Trojan-' + (brand ? brand.en.split(' ')[0] + '-' : '') + user.name;
  const ech = opts?.ech
    ? '    ech-opts:\n      enabled: true\n'
    : '';
  // 2.12 — backup entry hosts: same credentials, different domain/edge.
  const backupNames: string[] = [];
  const backupBlocks: string[] = (backupHosts ?? []).slice(0, 2).map((bh, i) => {
    const bName = 'Gozargah-VLESS-BK' + (i + 1) + '-' + user.name;
    backupNames.push(bName);
    return [
      '  - name: "' + bName + '"',
      '    type: vless',
      '    server: ' + bh,
      '    port: ' + port,
      '    uuid: ' + user.uuid,
      '    tls: true',
      '    servername: ' + bh,
      '    client-fingerprint: ' + fp,
      '    network: ws',
      '    udp: true',
      '    ws-opts:',
      '      path: "' + wsPath + '"',
      '      headers:',
      '        Host: ' + bh,
      '      max-early-data: 2048',
      '      early-data-header-name: Sec-WebSocket-Protocol',
    ].join('\n');
  });
  const ssName = 'Gozargah-Shadowsocks-' + (brand ? brand.en.split(' ')[0] + '-' : '') + user.name;
  const proxy = (name: string, kind: 'vless' | 'trojan'): string[] => [
    '  - name: "' + name + '"',
    '    type: ' + kind,
    '    server: ' + host,
    '    port: ' + port,
    kind === 'vless' ? '    uuid: ' + user.uuid : '    password: ' + user.trojanPass,
    '    tls: true',
    '    servername: ' + host,
    '    client-fingerprint: ' + fp,
    '    network: ws',
    kind === 'vless' ? '    udp: true' : '    udp: false',
    '    ws-opts:',
    '      path: "' + wsPath + '"',
    '      headers:',
    '        Host: ' + host,
    '      max-early-data: 2048',
    '      early-data-header-name: Sec-WebSocket-Protocol',
  ];
  const shadowsocksProxy = [
    '  - name: "' + ssName + '"',
    '    type: ss',
    '    server: ' + host,
    '    port: ' + port,
    '    cipher: ' + SHADOWSOCKS_METHOD,
    '    password: "' + user.uuid + '"',
    '    udp: false',
    '    plugin: v2ray-plugin',
    '    plugin-opts:',
    '      mode: websocket',
    '      tls: true',
    '      host: ' + host,
    '      path: "/ss/' + user.uuid + '"',
  ];
  return [
    '# gozargah clash-meta profile',
    'mixed-port: 7890',
    'allow-lan: false',
    'mode: rule',
    'log-level: info',
    'ipv6: true',
    'dns:',
    '  enable: true',
    '  enhanced-mode: fake-ip',
    '  nameserver:',
    ...(dnsUrl ? ['    - ' + JSON.stringify(dnsUrl)] : ['    - https://cloudflare-dns.com/dns-query', '    - https://dns.google/dns-query']),
    'proxies:',
    ...proxy(vName, 'vless'),
    ech,
    ...proxy(tName, 'trojan'),
    ech,
    ...shadowsocksProxy,
    ...backupBlocks,
    'proxy-groups:',
    '  - name: Gozargah',
    '    type: select',
    '    proxies:',
    '      - ' + vName,
    '      - ' + tName,
    '      - ' + ssName,
    ...backupNames.map((n) => '      - ' + n),
    'rules:',
    '  - MATCH,Gozargah',
    '',
  ].join('\n');
}

export function buildSingBoxJson(
  host: string,
  user: { uuid: string; trojanPass: string; name: string },
  opts: BuildOpts | null | undefined,
  dnsUrl?: string,
  backupHosts?: string[],
): string {
  const port = opts?.port && opts.port !== 443 ? opts.port : 443;
  const wsPath = rotatedPathBase(user.uuid) + '?ed=2048&gz_profile=standard';
  const fp = fpFor(opts, user.uuid);
  const tls: Record<string, unknown> = {
    enabled: true,
    server_name: host,
    utls: { enabled: true, fingerprint: fp },
  };
  if (opts?.ech) tls.ech = { enabled: true };
  const transport = {
    type: 'ws',
    path: wsPath,
    headers: { Host: host },
    max_early_data: 2048,
    early_data_header_name: 'Sec-WebSocket-Protocol',
  };
  const brand = opBranding(opts);
  const vName = 'Gozargah-VLESS-' + (brand ? brand.en.split(' ')[0] + '-' : '') + user.name;
  const tName = 'Gozargah-Trojan-' + (brand ? brand.en.split(' ')[0] + '-' : '') + user.name;
  const ssName = 'Gozargah-Shadowsocks-' + (brand ? brand.en.split(' ')[0] + '-' : '') + user.name;
  const cfg = {
    log: { level: 'info' },
    dns: { servers: dnsUrl ? [dnsUrl] : ['1.1.1.1', '8.8.8.8'], strategy: 'prefer_ipv6' },
    inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
    outbounds: [
      {
        type: 'vless',
        tag: vName,
        server: host,
        server_port: port,
        uuid: user.uuid,
        tls,
        transport,
      },
      {
        type: 'trojan',
        tag: tName,
        server: host,
        server_port: port,
        password: user.trojanPass,
        tls,
        transport,
      },
      {
        type: 'shadowsocks',
        tag: ssName,
        server: host,
        server_port: port,
        method: SHADOWSOCKS_METHOD,
        password: user.uuid,
        plugin: 'v2ray-plugin',
        plugin_opts: 'mode=websocket;tls;host=' + host + ';path=/ss/' + user.uuid,
        network: 'tcp',
      },
      // 2.12 — backup entry outbounds: same credentials on alternate domains.
      ...(backupHosts ?? []).slice(0, 2).map((bh, i) => ({
        type: 'vless',
        tag: vName + '-bk' + (i + 1),
        server: bh,
        server_port: port,
        uuid: user.uuid,
        tls: { ...tls, server_name: bh },
        transport: { ...transport, headers: { Host: bh } },
      })),
      { type: 'selector', tag: 'gozargah-select', outbounds: [vName, tName, ssName, ...(backupHosts ?? []).slice(0, 2).map((_, i) => vName + '-bk' + (i + 1))], default: vName },
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'gozargah-select' },
  };
  return JSON.stringify(cfg, null, 2);
}

/* --------------------------- xray-core JSON --------------------------- */

/**
 * Xray-core profile (v1.2) — the "always-connected" shape ported from the
 * production panel: burst probes across every gz-* outbound via the
 * observatory, and a leastPing balancer ("auto-best") routes the catch-all
 * through whichever outbound currently answers fastest. A throttled or
 * DPI-starved path is demoted automatically — no user action needed.
 *
 * Fragment (per-operator preset) rides as internal gzx-* freedom outbounds
 * that app-level clones dial through with dialerProxy.
 *
 * Naming contract: app outbounds = gz-* (probed + balanced), internal
 * transports = gzx-* (probed, never routed directly).
 */
export function buildXrayJson(
  host: string,
  user: { uuid: string; trojanPass: string; name: string },
  opts: BuildOpts | null | undefined,
  env?: Env,
  backupHosts?: string[],
  observatoryIntervalSec = 90,
): string {
  const profiles = adaptiveProfiles(opts, user.uuid);
  // 2.12 — deterministic 6h-rotating path base (all profiles share it).
  const wsPathBase = rotatedPathBase(user.uuid);
  const wsPath = (profileId: string) => wsPathBase + '?ed=2048&gz_profile=' + profileId;
  const brand = opBranding(opts);
  const suffix = brand ? '-' + brand.key : '';
  const outbounds: Array<Record<string, unknown>> = [];
  const appTags: string[] = [];

  const addProfileOutbounds = (profile: AdaptiveProfile): void => {
    const stream = {
      network: 'ws',
      security: 'tls',
      tlsSettings: {
        serverName: host,
        allowInsecure: false,
        fingerprint: profile.fp,
      },
      wsSettings: {
        path: wsPath(profile.id),
        headers: { Host: host },
      },
    };
    const vTag = 'gz-' + profile.id + '-vless' + suffix;
    const tTag = 'gz-' + profile.id + '-trojan' + suffix;
    outbounds.push({
      tag: vTag,
      protocol: 'vless',
      settings: { vnext: [{ address: host, port: profile.port, users: [{ id: user.uuid, encryption: 'none', level: 0 }] }] },
      streamSettings: stream,
    });
    outbounds.push({
      tag: tTag,
      protocol: 'trojan',
      settings: { servers: [{ address: host, port: profile.port, password: user.trojanPass, level: 0 }] },
      streamSettings: stream,
    });
    appTags.push(vTag, tTag);

    if (profile.frag) {
      const fragTag = 'gzx-' + profile.id + '-frag';
      outbounds.push({
        tag: fragTag,
        protocol: 'freedom',
        settings: {
          domainStrategy: 'AsIs',
          fragment: { packets: profile.frag.packets, length: profile.frag.length, interval: profile.frag.interval },
        },
      });
      const fvTag = 'gz-' + profile.id + '-frag-vless' + suffix;
      outbounds.push({
        tag: fvTag,
        protocol: 'vless',
        settings: { vnext: [{ address: host, port: profile.port, users: [{ id: user.uuid, encryption: 'none', level: 0 }] }] },
        streamSettings: stream,
        dialerProxy: fragTag,
      });
      appTags.push(fvTag);
    }
  };

  for (const profile of profiles) addProfileOutbounds(profile);

  // When an origin engine is configured, emit a second adaptive family using
  // current Xray transport primitives. The Worker itself still terminates only
  // its native HTTP/WebSocket profiles; these outbounds are client->origin.
  const originHost = env?.ORIGIN_ENGINE_HOST?.trim() || '';
  const originPort = parseOriginEnginePort(env?.ORIGIN_ENGINE_PORT);
  if (originHost && originPort !== null) {
    const originSni = (env?.ORIGIN_ENGINE_SNI || originHost).trim();
    const originPath = (env?.ORIGIN_ENGINE_PATH || '/' + user.uuid).trim() || '/';
    const grpcService = (env?.ORIGIN_ENGINE_GRPC_SERVICE || 'g').trim() || 'g';
    const allowed = new Set(parseOriginTransports(env?.ORIGIN_ENGINE_TRANSPORTS));
    const originCapabilities = buildProtocolMatrix(env, host).capabilities;
    const canGenerateOrigin = (protocol: string, transport: ReturnType<typeof parseOriginTransports>[number]): boolean =>
      allowed.has(transport) &&
      originCapabilities.some((capability) => capability.protocol === protocol && capability.transport === transport && capability.generatorAvailable && capability.ready);
    const originTags: string[] = [];
    const addOrigin = (tag: string, protocol: string, transport: string, streamSettings: Record<string, unknown>, settings: Record<string, unknown>): void => {
      outbounds.push({ tag, protocol, settings, streamSettings });
      originTags.push(tag);
    };
    const tlsSettings = {
      serverName: originSni,
      allowInsecure: false,
      fingerprint: 'chrome',
    };
    if (canGenerateOrigin('vless', 'xhttp') && canGenerateOrigin('trojan', 'xhttp')) {
      const stream = { network: 'xhttp', security: 'tls', tlsSettings, xhttpSettings: { path: originPath } };
      addOrigin('origin-vless-xhttp', 'vless', 'xhttp', stream, { vnext: [{ address: originHost, port: originPort, users: [{ id: user.uuid, encryption: 'none', level: 0 }] }] });
      addOrigin('origin-trojan-xhttp', 'trojan', 'xhttp', stream, { servers: [{ address: originHost, port: originPort, password: user.trojanPass, level: 0 }] });
    }
    if (canGenerateOrigin('vless', 'grpc')) {
      const stream = { network: 'grpc', security: 'tls', tlsSettings, grpcSettings: { serviceName: grpcService, multiMode: true } };
      addOrigin('origin-vless-grpc', 'vless', 'grpc', stream, { vnext: [{ address: originHost, port: originPort, users: [{ id: user.uuid, encryption: 'none', level: 0 }] }] });
    }
    if (canGenerateOrigin('vless', 'httpupgrade')) {
      const stream = { network: 'httpupgrade', security: 'tls', tlsSettings, httpupgradeSettings: { path: originPath, host: originSni } };
      addOrigin('origin-vless-httpupgrade', 'vless', 'httpupgrade', stream, { vnext: [{ address: originHost, port: originPort, users: [{ id: user.uuid, encryption: 'none', level: 0 }] }] });
    }
    if (canGenerateOrigin('vmess', 'ws') && canGenerateOrigin('trojan', 'ws')) {
      const stream = { network: 'ws', security: 'tls', tlsSettings, wsSettings: { path: originPath, headers: { Host: originSni } } };
      addOrigin('origin-vmess-ws', 'vmess', 'ws', stream, { vnext: [{ address: originHost, port: originPort, users: [{ id: user.uuid, alterId: 0, security: 'auto' }] }] });
      addOrigin('origin-trojan-ws', 'trojan', 'ws', stream, { servers: [{ address: originHost, port: originPort, password: user.trojanPass, level: 0 }] });
    }
    appTags.push(...originTags);
  }

  // 2.12 — backup entry outbounds (same credentials on alternate domains).
  // They join the auto-best balancer so Xray's observatory probes them and
  // routes to whichever entry is reachable/fastest.
  (backupHosts ?? []).slice(0, 2).forEach((bh, i) => {
    const bTag = 'gz-bk' + (i + 1) + '-vless' + suffix;
    outbounds.push({
      tag: bTag,
      protocol: 'vless',
      settings: { vnext: [{ address: bh, port: 443, users: [{ id: user.uuid, encryption: 'none', level: 0 }] }] },
      streamSettings: {
        network: 'ws',
        security: 'tls',
        tlsSettings: { serverName: bh, allowInsecure: false, fingerprint: 'chrome' },
        wsSettings: { path: wsPath('standard'), headers: { Host: bh } },
      },
    });
    appTags.push(bTag);
  });

  const cfg = {
    log: { loglevel: 'warning' },
    dns: { servers: ['localhost', '1.1.1.1'], queryStrategy: 'UseIPv4' },
    inbounds: [
      { tag: 'socks-in', listen: '127.0.0.1', port: 10808, protocol: 'socks', settings: { udp: true, auth: 'noauth' }, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] } },
      { tag: 'http-in', listen: '127.0.0.1', port: 10809, protocol: 'http', settings: {}, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] } },
    ],
    outbounds,
    // 2.13 — smart reconnection: the observatory probes harder (30s) while
    // the engine is in recovery/no_healthy_path, 90s otherwise.
    observatory: {
      subjectSelector: ['gz-'],
      probeUrl: 'https://connectivitycheck.gstatic.com/generate_204',
      probeInterval: observatoryIntervalSec + 's',
      enableConcurrency: true,
    },
    routing: {
      domainStrategy: 'IPIfNonMatch',
      balancers: [
        { tag: 'auto-best', selector: appTags, strategy: { type: 'leastPing' } },
      ],
      rules: [
        { type: 'field', network: 'tcp,udp', balancerTag: 'auto-best' },
      ],
    },
  };
  return JSON.stringify(cfg, null, 2);
}

/* ------------------------------ UA sniffing ------------------------------ */

export function sniffApp(ua: string): 'clash' | 'singbox' | 'v2ray' {
  const s = ua.toLowerCase();
  if (s.includes('clash') || s.includes('stash') || s.includes('vera') || s.includes('hiddify-clash')) return 'clash';
  if (s.includes('sing-box') || s.includes('singbox') || s.includes('karing') || s.includes('hiddify')) return 'singbox';
  return 'v2ray';
}

/** Browser UAs get the rich status page; proxy clients get raw configs. */
export function isBrowserUa(ua: string): boolean {
  const s = (ua || '').toLowerCase();
  if (!s) return false;
  // known proxy clients never get the page (even if they mention mozilla)
  const clientMarkers = [
    'clash', 'sing-box', 'singbox', 'hiddify', 'v2ray', 'v2box', 'streisand',
    'shadowrocket', 'karing', 'nekobox', 'nekoring', 'happ', 'pharos',
    'stash', 'loon', 'surge', 'quantumult', 'wxvpn', 'foxray', 'sphere',
  ];
  if (clientMarkers.some((m) => s.includes(m))) return false;
  return /mozilla|chrome|safari|firefox|edg\/|edie|opera|samsungbrowser|applewebkit/.test(s);
}

export type SubApp = 'clash' | 'singbox' | 'v2ray' | 'xray' | 'profiles' | 'adaptive' | 'capabilities' | 'page';

/** Resolve the requested app: explicit override > confident UA > browser page > base64. */
export function resolveApp(appOverride: string, ua: string): SubApp {
  const ov = (appOverride || '').toLowerCase();
  if (ov === 'page' || ov === 'status') return 'page';
  if (ov === 'clash') return 'clash';
  if (ov === 'singbox') return 'singbox';
  if (ov === 'xray') return 'xray';
  if (ov === 'profiles') return 'profiles';
  if (ov === 'adaptive' || ov === 'autoadaptive' || ov === 'live') return 'adaptive';
  if (ov === 'capabilities') return 'capabilities';
  if (ov === 'v2ray' || ov === 'base64') return 'v2ray';
  const uaApp = sniffApp(ua);
  if (uaApp === 'clash' || uaApp === 'singbox') return uaApp;
  if (isBrowserUa(ua)) return 'page';
  return 'v2ray';
}

/* ------------------------------ response ------------------------------ */

export function subHeaders(
  eff: EffectiveSettings,
  host: string,
  user: GzUser,
  app: string,
  opts: SubOpts | null | undefined,
  token?: string,
): Headers {
  const h = new Headers();
  if (app === 'clash') h.set('content-type', 'text/yaml; charset=utf-8');
  else if (app === 'singbox' || app === 'xray' || app === 'profiles' || app === 'adaptive' || app === 'capabilities') h.set('content-type', 'application/json; charset=utf-8');
  else h.set('content-type', 'text/plain; charset=utf-8');
  h.set('access-control-allow-origin', '*');
  h.set('cache-control', 'no-store');
  const brand = opBranding(opts);
  // HTTP headers are ByteString-only — Unicode titles ride the standard
  // `base64:` prefix that v2rayNG/Hiddify/Streisand natively decode.
  const title = 'Gozargah · ' + (brand ? brand.fa + ' · ' : '') + user.name;
  h.set('profile-title', 'base64:' + toBase64(title));
  h.set('profile-update-interval', '6');
  // the user's own live status page (v1.2) — falls back to the panel for admins w/o page
  if (token) h.set('profile-web-page-url', 'https://' + host + '/' + eff.subPath + '/' + token);
  else h.set('profile-web-page-url', 'https://' + host + '/' + eff.panelPath);
  if (user.quotaBytes || user.expiryAt) {
    // REAL numbers from byte accounting (0 upload tracked separately in v2)
    const used = Math.max(0, user.usedUp + user.usedDown);
    h.set(
      'subscription-userinfo',
      'upload=' + user.usedUp + '; download=' + user.usedDown + '; total=' +
        (user.quotaBytes || 0) + '; expire=' + (user.expiryAt ? Math.floor(user.expiryAt / 1000) : 0),
    );
    h.set('x-gz-used-bytes', String(used));
  }
  return h;
}

export async function renderSub(app: string, host: string, user: GzUser, opts: SubOpts | null | undefined, env?: Env, dnsUrl?: string): Promise<{ body: string; app: string }> {
  // 2.12 — configured backup entry hosts (cached; best-effort).
  let backupHosts: string[] = [];
  // 2.13 — smart reconnection cadence (30s while the engine is in recovery).
  let observatoryIntervalSec = 90;
  if (env?.GZ_DB) {
    try {
      const s = await loadSettings(env.GZ_DB);
      backupHosts = (s?.backupEntryHosts ?? [])
        .map((x) => String(x).trim().toLowerCase())
        .filter((x) => /^[a-z0-9][a-z0-9.-]{2,252}$/.test(x) && x.includes('.'))
        .slice(0, 4);
    } catch { /* best-effort; ladder simply stays primary-only */ }
    try {
      const ns = await loadNetworkState(env.GZ_DB);
      if (ns && (ns.state === 'recovery' || ns.state === 'no_healthy_path')) observatoryIntervalSec = 30;
    } catch { /* best-effort; keep the calm 90s cadence */ }
  }
  if (app === 'clash') return { body: buildClashYaml(host, user, opts, dnsUrl, backupHosts), app };
  if (app === 'singbox') return { body: buildSingBoxJson(host, user, opts, dnsUrl, backupHosts), app };
  if (app === 'xray') return { body: buildXrayJson(host, user, opts, env, backupHosts, observatoryIntervalSec), app };
  if (app === 'profiles') return { body: buildAdaptiveClientBundle(host, user, opts, env, dnsUrl), app };
  if (app === 'capabilities') return { body: JSON.stringify(buildProtocolMatrix(env, host), null, 2), app };
  const links = buildLinks(host, user, opts);
  const lines = [links.vless, links.trojan, links.shadowsocks];
  for (const bh of backupHosts.slice(0, 2)) lines.push(buildLinks(bh, user, opts).vless);
  return { body: toBase64(lines.join('\n')), app: 'v2ray' };
}

export { DEFAULT_FP };
export type { Env };
