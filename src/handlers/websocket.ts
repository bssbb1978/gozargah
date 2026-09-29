/**
 * Gozargah — WebSocket proxy pipeline.
 *
 *  1. accept upgrade on ANY path (the protocol itself authenticates the user)
 *  2. consume 0-RTT early data from Sec-WebSocket-Protocol
 *     (nahan advertised this header but never read it — we actually use it)
 *  3. buffered header read + VLESS/Trojan/SIP004 AEAD protocol sniff
 *  4. user lookup + enforcement (enabled / expiry / real-byte quota)
 *  5. edgetunnel-style dial: direct first, ProxyIP fallback chain, per-user stable start
 *  6. bidirectional pump with REAL byte accounting, coalesced flush to D1
 */

import { Env, GzError } from '../config';
import { b64UrlDecode, concatBytes, utf8Decode } from '../utils/crypto';
import { sha224Hex } from '../utils/sha224';
import { glog } from '../utils/log';
import { dialWithFallback } from './proxy';
import { parseVless, vlessOkResponse } from '../protocols/vless';
import { parseTrojan } from '../protocols/trojan';
import { hasValidShadowsocksPrefix, ShadowsocksAeadDecoder, ShadowsocksAeadEncoder, SHADOWSOCKS_KEY_LENGTH } from '../protocols/shadowsocks';
import { pumpVlessDns } from './vless-dns';
import {
  findUserByTrojanHash, getUserByIdFresh, getUserByUuid, GzUser, isUserAllowed,
  lazyMaintenance, maybeFlushUsage, queueUsage, recordUsageDelta,
} from '../db/users';
import { envlessSettings } from '../settings';
import { DEFAULTS } from '../config';
import { decideResilience, orderPathsForUser, updateObservation } from '../ai/resilience';
import { loadPathHealth, savePathHealth, loadProfileHealth, saveProfileHealth, loadAdaptiveModel, saveAdaptiveModel, loadUserAdaptiveState, saveUserAdaptiveState, saveHealthSample, loadHealthSamples, savePredictiveState } from '../db/store';
import { nextProfileObservation } from '../ai/edge-brain';
import { defaultEdgeLearner, observationFeatures, updateEdgeLearner } from '../ai/edge-learner';
import { assessHealth } from '../ai/predictive-mesh';

/** Implicit single user in no-database mode. */
// Bounded revocation/quota lag without a database round-trip per traffic chunk.
const SESSION_REVALIDATE_MS = 120_000;

const IMPLICIT_USER: GzUser = {
  id: 0, name: 'admin', uuid: '', trojanPass: '',
  quotaBytes: 0, usedUp: 0, usedDown: 0, expiryAt: 0,
  expiryDays: 0, firstUsedAt: 0, resetAnchor: 0,
  enabled: true, isAdmin: true, createdAt: 0, lastSeen: 0,
};

export function acceptWebSocket(request: Request, env: Env, ctx: ExecutionContext): Response {
  const pair = new WebSocketPair();
  const server = pair[1];
  server.accept();

  let early: Uint8Array | null = null;
  const protoHeader = request.headers.get('sec-websocket-protocol');
  if (protoHeader) {
    // Only consume the repo's base64url early-data form. SIP003 clients may use
    // Sec-WebSocket-Protocol for a normal WebSocket subprotocol such as "binary".
    const token = protoHeader.trim().split(',', 1)[0].trim();
    if (token.length > 0 && token.length <= 2732 && /^[A-Za-z0-9_-]+={0,2}$/.test(token)) {
      try {
        const decoded = b64UrlDecode(token);
        if (decoded.length > 0 && decoded.length <= 2048 && (decoded[0] === 0 || isHexByte(decoded[0]))) early = decoded;
      } catch { early = null; }
    }
  }

  const requestUrl = new URL(request.url);
  const host = requestUrl.host;
  const rawProfile = requestUrl.searchParams.get('gz_profile');
  const profileId = rawProfile === 'standard' || rawProfile === 'fragmented' || rawProfile === 'alt-port' || rawProfile === 'fragmented-alt'
    ? rawProfile : 'standard';

  ctx.waitUntil(pumpProxy(server, early, env, host, requestUrl.pathname, ctx, profileId).catch((e) => {
    glog('proxy pump error: ' + (e instanceof Error ? e.message : String(e)));
    try { server.close(1011); } catch { /* ignore */ }
  }));

  return new Response(null, { status: 101, webSocket: pair[0] });
}

interface HeaderInfo {
  proto: 'vless' | 'trojan' | 'shadowsocks';
  headerLen: number;
  version: number;
  host: string;
  port: number;
  isUDP: boolean;
  user: GzUser | null;
}

function wsReadable(server: WebSocket): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(ctrl) {
      server.addEventListener('message', (ev: MessageEvent) => {
        if (typeof ev.data === 'string') {
          ctrl.enqueue(new TextEncoder().encode(ev.data));
        } else {
          ctrl.enqueue(new Uint8Array(ev.data as ArrayBuffer));
        }
      });
      server.addEventListener('close', () => { try { ctrl.close(); } catch { /* ignore */ } });
      server.addEventListener('error', () => { try { ctrl.error(new Error('ws error')); } catch { /* ignore */ } });
    },
  });
}

async function pumpProxy(server: WebSocket, early: Uint8Array | null, env: Env, host: string, requestPath: string, ctx: ExecutionContext, profileId: 'standard' | 'fragmented' | 'alt-port' | 'fragmented-alt'): Promise<void> {
  const reader = wsReadable(server).getReader();

  // --- buffered header read (early data may carry only a partial header) ---
  let buf = early ?? new Uint8Array(0);
  let info: HeaderInfo | null = null;
  for (let guard = 0; guard < 64 && !info; guard++) {
    info = await tryParseAndResolve(buf, env, host, requestPath);
    if (info) break;
    const { done, value } = await reader.read();
    if (done) throw new GzError('ws closed before full header', 'bad_request');
    if (value && value.length) buf = concatBytes(buf, value);
  }
  if (!info) throw new GzError('could not parse protocol header', 'bad_request');

  let ssDecoder: ShadowsocksAeadDecoder | null = null;
  let ssInitialPayload: Uint8Array | null = null;
  if (info.proto === 'shadowsocks') {
    if (!info.user) throw new GzError('auth failed', 'auth_failed');
    const raw = new BufferedByteReader(reader, buf);
    ssDecoder = await ShadowsocksAeadDecoder.create((length, eof) => raw.readExactly(length, eof), info.user.uuid);
    const target = await readShadowsocksTarget(ssDecoder);
    info = { ...info, host: target.host, port: target.port, headerLen: 0, isUDP: false };
    ssInitialPayload = target.payload;
  }

  if (info.user) {
    // Bypass the short-lived isolate cache at the authorization boundary so a
    // just-disabled or rotated account cannot start a new tunnel from stale data.
    if (info.user.id > 0 && env.GZ_DB) {
      try {
        const fresh = await getUserByIdFresh(env.GZ_DB, info.user.id);
        if (!fresh) {
          try { server.close(1008); } catch { /* ignore */ }
          return;
        }
        info.user = fresh;
      } catch {
        try { server.close(1011); } catch { /* ignore */ }
        return;
      }
    }
    const verdict = isUserAllowed(info.user);
    if (!verdict.ok) {
      glog('user blocked (' + verdict.reason + ') id=' + info.user.id);
      try { server.close(1008); } catch { /* ignore */ }
      return;
    }
    // First-use stamping + rolling reset; live sessions recheck policy below.
    if (info.user.id > 0 && env.GZ_DB) {
      const cycle = ((await getResetCycle(env)) ?? 'none') as 'none' | 'daily' | 'weekly' | 'monthly';
      ctx.waitUntil(
        lazyMaintenance(env.GZ_DB, info.user, cycle)
          .catch(() => { /* ignore */ }),
      );
    }
  } else {
    throw new GzError('auth failed', 'auth_failed');
  }

  if (info.isUDP) {
    if (info.proto === 'vless' && info.port === 53 && info.user) {
      const input = new BufferedByteReader(reader, buf.slice(info.headerLen));
      await pumpVlessDns(server, (length, eof) => input.readExactly(length, eof), env, info.user, info.version);
      return;
    }
    glog('unsupported UDP request; only VLESS DNS on port 53 is accepted');
    try { server.close(1008); } catch { /* ignore */ }
    return;
  }

  // --- dial (direct first, ProxyIP fallback chain, per-user stable start) ---
  const currentUser = info.user;
  if (!currentUser) throw new GzError('auth failed', 'auth_failed');
  const configuredProxyIPs = await getProxyIPs(env);
  const startIdx = currentUser.isAdmin && currentUser.id === 0 ? 0 : stableIndex(currentUser.uuid, configuredProxyIPs.length);
  let proxyIPs = configuredProxyIPs;
  let userAdaptive: Awaited<ReturnType<typeof loadUserAdaptiveState>> = null;
  let activeLearner = defaultEdgeLearner();
  if (env.GZ_DB && configuredProxyIPs.length) {
    try {
      if (currentUser.id > 0) userAdaptive = await loadUserAdaptiveState(env.GZ_DB, currentUser.id);
      const modelRow = await loadAdaptiveModel(env.GZ_DB);
      if (modelRow) {
        try {
          const parsed = JSON.parse(modelRow.stateJson) as ReturnType<typeof defaultEdgeLearner>;
          if (parsed && parsed.version === 1 && Array.isArray(parsed.weights) && parsed.weights.length === 6) activeLearner = parsed;
        } catch { /* corrupted model state: use safe defaults */ }
      }
      const rows = await loadPathHealth(env.GZ_DB);
      const decision = decideResilience(rows.map(r => ({ id:r.pathId, latencyMs:r.latencyMs, ok:r.ok, checkedAt:r.checkedAt, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantineUntil, consecutiveFailures:r.consecutiveFailures, consecutiveSuccesses:r.consecutiveSuccesses, lastError:r.lastError })), Date.now(), activeLearner, userAdaptive?.preferredPathId ?? '');
      const ordered = orderPathsForUser(configuredProxyIPs, decision, startIdx, userAdaptive?.preferredPathId ?? '');
      if (ordered.length) proxyIPs = ordered;
    } catch { /* health intelligence is optional; retain deterministic fallback */ }
  }
  const dial = await dialWithFallback(info.host, info.port, proxyIPs, 0, (attempt) => {
    if (!env.GZ_DB || !attempt.pathId) return;
    ctx.waitUntil((async () => {
      try {
        const rows = await loadPathHealth(env.GZ_DB!);
        const previous = rows.find(r => r.pathId === attempt.pathId);
        const next = updateObservation(previous ? {
          id: previous.pathId, latencyMs: previous.latencyMs, ok: previous.ok,
          checkedAt: previous.checkedAt, failures: previous.failures, successes: previous.successes,
          quarantineUntil: previous.quarantineUntil, consecutiveFailures: previous.consecutiveFailures,
          consecutiveSuccesses: previous.consecutiveSuccesses, lastError: previous.lastError,
        } : undefined, attempt.ok, attempt.latencyMs, Date.now(), attempt.error);
        next.id = attempt.pathId;
        await saveHealthSample(env.GZ_DB!, { kind:'path_dial', subjectId:next.id, ts:next.checkedAt, ok:next.ok, latencyMs:next.latencyMs });
        const pathSamples = await loadHealthSamples(env.GZ_DB!, 'path', next.id, 24);
        const pathPredictive = assessHealth(pathSamples, next.checkedAt);
        await savePredictiveState(env.GZ_DB!, { kind:'path', subjectId:next.id, stateJson:JSON.stringify(pathPredictive), updatedAt:next.checkedAt });
        await savePathHealth(env.GZ_DB!, {
          pathId: next.id, latencyMs: next.latencyMs, ok: next.ok, failures: next.failures,
          successes: next.successes, quarantineUntil: next.quarantineUntil, checkedAt: next.checkedAt,
          lastError: next.lastError, consecutiveFailures: next.consecutiveFailures,
          consecutiveSuccesses: next.consecutiveSuccesses, drift:pathPredictive.drift, forecastSuccess:pathPredictive.forecastSuccess, volatility:pathPredictive.latencyVolatility,
        });

        const profileRows = await loadProfileHealth(env.GZ_DB!);
        const profilePrevious = profileRows.find(r => r.profileId === profileId);
        const profileNext = nextProfileObservation(profilePrevious ? {
          profileId: profileId as 'standard' | 'fragmented' | 'alt-port' | 'fragmented-alt',
          ok: profilePrevious.ok, latencyMs: profilePrevious.latencyMs, failures: profilePrevious.failures,
          successes: profilePrevious.successes, checkedAt: profilePrevious.checkedAt,
          consecutiveFailures: profilePrevious.consecutiveFailures, consecutiveSuccesses: profilePrevious.consecutiveSuccesses,
          quarantineUntil: profilePrevious.quarantineUntil,
        } : undefined, attempt.ok, attempt.latencyMs);
        await saveHealthSample(env.GZ_DB!, { kind: 'profile', subjectId: profileId, ts: profileNext.checkedAt, ok: profileNext.ok, latencyMs: profileNext.latencyMs });
        const profileSamples = await loadHealthSamples(env.GZ_DB!, 'profile', profileId, 24);
        const profilePredictive = assessHealth(profileSamples, profileNext.checkedAt);
        await savePredictiveState(env.GZ_DB!, { kind:'profile', subjectId:profileId, stateJson:JSON.stringify(profilePredictive), updatedAt:profileNext.checkedAt });
        await saveProfileHealth(env.GZ_DB!, {
          profileId, latencyMs: profileNext.latencyMs, ok: profileNext.ok, failures: profileNext.failures,
          successes: profileNext.successes, quarantineUntil: profileNext.quarantineUntil, checkedAt: profileNext.checkedAt,
          consecutiveFailures: profileNext.consecutiveFailures, consecutiveSuccesses: profileNext.consecutiveSuccesses,
          drift: profilePredictive.drift, forecastSuccess: profilePredictive.forecastSuccess, volatility: profilePredictive.latencyVolatility,
        });
        // Online local learner: update only from aggregate outcome + latency.
        const age = next.checkedAt ? Math.max(0, Date.now() - next.checkedAt) : Number.POSITIVE_INFINITY;
        const freshness = Number.isFinite(age) ? Math.max(0, Math.min(1, 1 - age / (10 * 60_000))) : 0;
        const trend = (next.consecutiveSuccesses ?? 0) >= 2 && (next.consecutiveSuccesses ?? 0) > (next.consecutiveFailures ?? 0)
          ? 'improving' as const
          : (next.consecutiveFailures ?? 0) >= 2 && (next.consecutiveFailures ?? 0) > (next.consecutiveSuccesses ?? 0)
            ? 'declining' as const : 'stable' as const;
        const modelState = updateEdgeLearner(activeLearner, observationFeatures({
          latencyMs: next.latencyMs, failures: next.failures, successes: next.successes, freshness, trend,
          consecutiveSuccesses: next.consecutiveSuccesses ?? 0,
        }), attempt.ok);
        activeLearner = modelState;
        // Persist model state best-effort; a model failure never blocks the tunnel.
        await saveAdaptiveModel(env.GZ_DB!, { scope: 'global', stateJson: JSON.stringify(modelState), updatedAt: modelState.updatedAt });

        if (currentUser.id > 0) {
          const ua = await loadUserAdaptiveState(env.GZ_DB!, currentUser.id);
          const successes = (ua?.successes ?? 0) + (attempt.ok ? 1 : 0);
          const failures = (ua?.failures ?? 0) + (attempt.ok ? 0 : 1);
          const preferredPathId = attempt.ok ? attempt.pathId : (ua?.preferredPathId === attempt.pathId ? '' : (ua?.preferredPathId ?? ''));
          const preferredProfileId = attempt.ok ? profileId : (ua?.preferredProfileId === profileId ? '' : (ua?.preferredProfileId ?? ''));
          await saveUserAdaptiveState(env.GZ_DB!, {
            userId: currentUser.id, preferredPathId, preferredProfileId, successes, failures,
            lastOk: attempt.ok, updatedAt: Date.now(),
          });
        }
      } catch { /* telemetry must never break the data plane */ }
    })());
  });

  if (info.proto === 'vless') server.send(vlessOkResponse(info.version));

  // --- client -> remote (decode SIP004 for Shadowsocks, otherwise raw stream) ---
  let up = 0;
  let down = 0;
  let leftover: Uint8Array | null = ssInitialPayload ?? buf.slice(info.headerLen);
  const ssEncoder = info.proto === 'shadowsocks' ? new ShadowsocksAeadEncoder(info.user!.uuid) : null;

  const upPipe = new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      while (true) {
        if (leftover) {
          const c = leftover;
          leftover = null;
          if (c.length) {
            up += c.length;
            ctrl.enqueue(c);
            return;
          }
        }
        if (ssDecoder) {
          const clear = await ssDecoder.readChunk();
          if (!clear) { try { ctrl.close(); } catch { /* ignore */ } return; }
          if (!clear.length) continue;
          up += clear.length;
          ctrl.enqueue(clear);
          return;
        }
        const { done, value } = await reader.read();
        if (done) { try { ctrl.close(); } catch { /* ignore */ } return; }
        if (value && value.length) {
          up += value.length;
          ctrl.enqueue(value);
          return;
        }
      }
    },
    cancel() { try { server.close(); } catch { /* ignore */ } },
  })
    .pipeTo(dial.socket.writable)
    .catch(() => { try { dial.socket.close(); } catch { /* ignore */ } });

  // --- remote -> client (encode SIP004 chunks for Shadowsocks) ---
  const downPipe = dial.socket.readable
    .pipeTo(
      new WritableStream<Uint8Array>({
        async write(chunk) {
          down += chunk.byteLength;
          server.send(ssEncoder ? await ssEncoder.encode(chunk) : chunk);
        },
        close() { try { server.close(); } catch { /* ignore */ } },
        abort() { try { server.close(1011); } catch { /* ignore */ } },
      }),
    )
    .catch(() => { try { server.close(); } catch { /* ignore */ } });

  const trackedUser = info.user && env.GZ_DB && info.user.id > 0 ? info.user : null;
  const trackedDb = trackedUser ? env.GZ_DB! : null;
  let committedUp = 0;
  let committedDown = 0;
  const commitUsage = async (): Promise<void> => {
    if (!trackedUser || !trackedDb) return;
    const snapshotUp = up;
    const snapshotDown = down;
    await recordUsageDelta(trackedDb, trackedUser.id, snapshotUp - committedUp, snapshotDown - committedDown);
    committedUp = snapshotUp;
    committedDown = snapshotDown;
  };

  const stopMonitor = new AbortController();
  const monitor = trackedUser && trackedDb
    ? superviseSession(trackedUser.id, stopMonitor.signal, async () => {
        await commitUsage();
        const current = await getUserByIdFresh(trackedDb, trackedUser.id);
        return current ? isUserAllowed(current) : { ok: false, reason: 'deleted' };
      }, () => {
        try { server.close(1008); } catch { /* ignore */ }
        try { dial.socket.close(); } catch { /* ignore */ }
      })
    : Promise.resolve();

  await Promise.allSettled([upPipe, downPipe]);
  stopMonitor.abort();
  await monitor;
  try { dial.socket.close(); } catch { /* ignore */ }
  try { server.close(); } catch { /* ignore */ }

  if (trackedUser && trackedDb) {
    try {
      await commitUsage();
    } catch {
      // Preserve counters if D1 is briefly unavailable; the coalescer retries later.
      queueUsage(trackedUser.id, up - committedUp, down - committedDown);
      await maybeFlushUsage(trackedDb);
    }
    glog('conn closed user=' + trackedUser.id + ' up=' + up + ' down=' + down + ' via=' + dial.via);
  }
}

interface ShadowsocksTarget {
  host: string;
  port: number;
  headerLen: number;
  payload: Uint8Array;
}

/** Small bounded byte queue joining WebSocket message boundaries into a stream. */
class BufferedByteReader {
  private chunks: Uint8Array[] = [];
  private available = 0;

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>, initial: Uint8Array = new Uint8Array(0)) {
    if (initial.length) {
      if (initial.length > 1_048_576) throw new GzError('websocket message too large', 'bad_request');
      this.chunks.push(initial);
      this.available = initial.length;
    }
  }

  async readExactly(length: number, allowCleanEof = false): Promise<Uint8Array | null> {
    if (!Number.isInteger(length) || length < 1 || length > 65_535) throw new GzError('invalid stream read length', 'bad_request');
    while (this.available < length) {
      const { done, value } = await this.reader.read();
      if (done) {
        if (allowCleanEof && this.available === 0) return null;
        throw new GzError('truncated websocket stream', 'bad_request');
      }
      if (!value?.length) continue;
      if (value.length > 1_048_576 || this.available + value.length > 2_097_152) {
        throw new GzError('websocket buffer too large', 'bad_request');
      }
      this.chunks.push(value);
      this.available += value.length;
    }

    const out = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      const first = this.chunks[0];
      const size = Math.min(first.length, length - offset);
      out.set(first.subarray(0, size), offset);
      offset += size;
      this.available -= size;
      if (size === first.length) this.chunks.shift();
      else this.chunks[0] = first.subarray(size);
    }
    return out;
  }
}

async function readShadowsocksTarget(decoder: ShadowsocksAeadDecoder): Promise<ShadowsocksTarget> {
  let clear: Uint8Array = new Uint8Array(0);
  for (let i = 0; i < 32 && clear.length <= 512; i++) {
    const chunk = await decoder.readChunk();
    if (!chunk) throw new GzError('shadowsocks closed before destination header', 'bad_request');
    clear = concatBytes(clear, chunk);
    const target = parseShadowsocksTarget(clear);
    if (target) return { ...target, payload: clear.slice(target.headerLen) };
  }
  throw new GzError('invalid shadowsocks destination header', 'bad_request');
}

function parseShadowsocksTarget(data: Uint8Array): { host: string; port: number; headerLen: number } | null {
  if (!data.length) return null;
  const atyp = data[0];
  let cursor = 1;
  let host: string;
  if (atyp === 1) {
    if (data.length < cursor + 4) return null;
    host = [...data.slice(cursor, cursor + 4)].join('.');
    cursor += 4;
  } else if (atyp === 3) {
    if (data.length < cursor + 1) return null;
    const size = data[cursor++];
    if (size === 0) throw new GzError('empty shadowsocks domain', 'bad_request');
    if (data.length < cursor + size) return null;
    try { host = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(data.slice(cursor, cursor + size)); }
    catch { throw new GzError('invalid shadowsocks domain', 'bad_request'); }
    if (!host || /[\u0000-\u0020]/.test(host)) throw new GzError('invalid shadowsocks domain', 'bad_request');
    cursor += size;
  } else if (atyp === 4) {
    if (data.length < cursor + 16) return null;
    const parts: string[] = [];
    for (let i = 0; i < 8; i++) parts.push(((data[cursor + i * 2] << 8) | data[cursor + i * 2 + 1]).toString(16));
    host = '[' + parts.join(':') + ']';
    cursor += 16;
  } else {
    throw new GzError('unsupported shadowsocks address type', 'bad_request');
  }
  if (data.length < cursor + 2) return null;
  const port = (data[cursor] << 8) | data[cursor + 1];
  if (port < 1 || port > 65535) throw new GzError('invalid shadowsocks port', 'bad_request');
  return { host, port, headerLen: cursor + 2 };
}

/* ------------------------------------------------------------------ */

async function superviseSession(
  userId: number,
  signal: AbortSignal,
  check: () => Promise<{ ok: boolean; reason: string }>,
  revoke: () => void,
): Promise<void> {
  while (!signal.aborted) {
    if (await waitOrAbort(SESSION_REVALIDATE_MS, signal)) return;
    if (signal.aborted) return;
    try {
      const verdict = await check();
      if (!verdict.ok) {
        glog('live session revoked (' + verdict.reason + ') id=' + userId);
        revoke();
        return;
      }
    } catch {
      // Fail closed when D1 cannot prove that a long-lived session is still authorized.
      glog('live session check failed; closing id=' + userId);
      revoke();
      return;
    }
  }
}

function waitOrAbort(ms: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(true);
  return new Promise((resolve) => {
    const finish = (aborted: boolean) => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      resolve(aborted);
    };
    const onAbort = () => finish(true);
    const timer = setTimeout(() => finish(false), ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

function isHexByte(b: number): boolean {
  return (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66);
}

function isShortError(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.includes('short');
}

/** Parse VLESS/Trojan headers or authenticate a SIP004 stream on its dedicated path. */
async function tryParseAndResolve(buf: Uint8Array, env: Env, host: string, requestPath: string): Promise<HeaderInfo | null> {
  if (buf.length === 0) return null;

  if (isShadowsocksPath(requestPath)) {
    if (buf.length < SHADOWSOCKS_KEY_LENGTH + 2 + 16) return null;
    const ss = await shadowsocksHeader(env, host, requestPath);
    if (!ss.user) return ss;
    if (await hasValidShadowsocksPrefix(buf, ss.user.uuid)) return ss;
    throw new GzError('invalid Shadowsocks AEAD prefix', 'bad_request');
  }

  const b0 = buf[0];
  if (b0 === 0) {
    if (buf.length < 24) return null;
    try {
      const req = parseVless(buf);
      const user = await resolveVlessUser(env, host, req.uuid);
      return { proto: 'vless', headerLen: req.headerLen, version: req.version, host: req.host, port: req.port, isUDP: req.isUDP, user };
    } catch (error) {
      if (isShortError(error)) return null;
      throw error;
    }
  }

  if (isTrojanPrefix(buf)) {
    if (buf.length < 58) return null;
    try {
      const req = parseTrojan(buf);
      const user = await resolveTrojanUser(env, host, utf8Decode(buf.slice(0, 56)));
      return { proto: 'trojan', headerLen: req.headerLen, version: 0, host: req.host, port: req.port, isUDP: req.isUDP, user };
    } catch (error) {
      if (isShortError(error)) return null;
      throw error;
    }
  }

  throw new GzError('unsupported protocol header', 'bad_request');
}

function isShadowsocksPath(requestPath: string): boolean {
  const parts = requestPath.split('/').filter(Boolean);
  return parts.length === 2 && parts[0] === 'ss';
}

async function shadowsocksHeader(env: Env, host: string, requestPath: string): Promise<HeaderInfo> {
  const parts = requestPath.split('/').filter(Boolean);
  const uuid = parts.length === 2 && parts[0] === 'ss' ? parts[1] : '';
  if (!uuid) return { proto: 'shadowsocks', headerLen: 0, version: 0, host: '', port: 0, isUDP: false, user: null };
  const user = await resolveVlessUser(env, host, uuid);
  return { proto: 'shadowsocks', headerLen: 0, version: 0, host: '', port: 0, isUDP: false, user };
}

function isTrojanPrefix(buf: Uint8Array): boolean {
  const hashBytes = Math.min(buf.length, 56);
  for (let i = 0; i < hashBytes; i++) if (!isHexByte(buf[i])) return false;
  if (buf.length > 56 && buf[56] !== 0x0d) return false;
  if (buf.length > 57 && buf[57] !== 0x0a) return false;
  return true;
}

async function resolveVlessUser(env: Env, host: string, uuid: string): Promise<GzUser | null> {
  if (env.GZ_DB) return getUserByUuid(env.GZ_DB, uuid);
  const eff = await envlessSettings(host);
  return uuid === eff.uuid ? IMPLICIT_USER : null;
}

async function resolveTrojanUser(env: Env, host: string, wireHash: string): Promise<GzUser | null> {
  if (env.GZ_DB) return findUserByTrojanHash(env.GZ_DB, wireHash);
  const eff = await envlessSettings(host);
  return (await sha224Hex(eff.trojanPass)) === wireHash ? IMPLICIT_USER : null;
}

async function getProxyIPs(env: Env): Promise<string[]> {
  if (env.GZ_DB) {
    try {
      const { loadSettings } = await import('../db/store');
      const s = await loadSettings(env.GZ_DB);
      if (s && s.proxyIPs.length) return s.proxyIPs;
    } catch { /* fall through */ }
  }
  return [...DEFAULTS.proxyIPs];
}

async function getResetCycle(env: Env): Promise<string | null> {
  if (env.GZ_DB) {
    try {
      const { loadSettings } = await import('../db/store');
      const s = await loadSettings(env.GZ_DB);
      if (s) return s.resetCycle || 'none';
    } catch { /* fall through */ }
  }
  return null;
}

function stableIndex(seed: string, mod: number): number {
  if (mod <= 1) return 0;
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  return h % mod;
}
