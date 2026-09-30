/**
 * Gozargah — D1 storage layer.
 *
 * Design decisions (borrowed from the 5-panel benchmark study):
 *  - relational tables (users / events / auth_throttle) instead of one JSON blob
 *  - settings kept as a versioned JSON row with OPTIMISTIC locking (rev counter)
 *    -> fixes the JSON-blob write race found in nahan/BPB
 *  - schema auto-created on first use, memoized per isolate with promise dedup
 *  - every read cached for DEFAULTS.cacheTtlMs with in-flight promise dedup
 */

import { DEFAULTS, SCHEMA_VERSION, ResetCycle } from '../config';
import type { AdaptiveGuardState } from '../ai/adaptive-guard';
import type { AdvisorApplicationState } from '../ai/advisor-application';

export interface SettingsBlob {
  schemaVersion: number;
  panelPath: string;
  subPath: string;
  proxyIPs: string[];
  /** 2.12 — alternate domains pointing at the same Worker (emergency entry ladder). */
  backupEntryHosts?: string[];
  /** Workers AI transport preference controller; advisory by default. */
  aiAdvisorApplication?: AdvisorApplicationState;
  /** rolling quota-reset window for every non-admin user */
  resetCycle: ResetCycle;
  passwordSalt: string;
  passwordHash: string;
  pwIterations: number;
  isDefaultPassword: boolean;
  /** Emergency/operator recovery marker; cleared after a successful password update. */
  forcePasswordChange?: boolean;
  createdAt: number;
}

const DDL = [
  `CREATE TABLE IF NOT EXISTS kv_store (
     key TEXT PRIMARY KEY,
     value TEXT NOT NULL,
     rev INTEGER NOT NULL DEFAULT 0,
     updated_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS users (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     name TEXT NOT NULL,
     uuid TEXT NOT NULL UNIQUE,
     trojan_pass TEXT NOT NULL,
     quota_bytes INTEGER NOT NULL DEFAULT 0,
     used_up INTEGER NOT NULL DEFAULT 0,
     used_down INTEGER NOT NULL DEFAULT 0,
     expiry_at INTEGER NOT NULL DEFAULT 0,
     enabled INTEGER NOT NULL DEFAULT 1,
     is_admin INTEGER NOT NULL DEFAULT 0,
     created_at INTEGER NOT NULL,
     last_seen INTEGER NOT NULL DEFAULT 0,
     first_used_at INTEGER NOT NULL DEFAULT 0,
     expiry_days INTEGER NOT NULL DEFAULT 0,
     reset_anchor INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS events (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     ts INTEGER NOT NULL,
     type TEXT NOT NULL,
     detail TEXT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS auth_throttle (
     ip_hash TEXT PRIMARY KEY,
     count INTEGER NOT NULL,
     window_start INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS path_health (
     path_id TEXT PRIMARY KEY,
     latency_ms INTEGER,
     ok INTEGER NOT NULL DEFAULT 0,
     failures INTEGER NOT NULL DEFAULT 0,
     successes INTEGER NOT NULL DEFAULT 0,
     quarantine_until INTEGER NOT NULL DEFAULT 0,
     checked_at INTEGER NOT NULL DEFAULT 0,
     last_error TEXT NOT NULL DEFAULT '',
     consecutive_failures INTEGER NOT NULL DEFAULT 0,
     consecutive_successes INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS ai_throttle (
     ip_hash TEXT PRIMARY KEY,
     count INTEGER NOT NULL,
     window_start INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS dns_throttle (
     user_id INTEGER PRIMARY KEY,
     count INTEGER NOT NULL,
     window_start INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS user_control_throttle (
     ip_hash TEXT PRIMARY KEY,
     count INTEGER NOT NULL CHECK (count >= 0),
     window_start INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS user_control_audit (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     actor_user_id INTEGER NOT NULL CHECK (actor_user_id > 0),
     target_user_id INTEGER NOT NULL CHECK (target_user_id > 0),
     action TEXT NOT NULL CHECK (action IN ('user_created', 'user_updated', 'user_enabled', 'user_disabled', 'user_deleted')),
     details_json TEXT NOT NULL CHECK (json_valid(details_json)),
     created_at INTEGER NOT NULL CHECK (created_at > 0)
   )`,
  'CREATE INDEX IF NOT EXISTS idx_user_control_audit_target ON user_control_audit(target_user_id, id DESC)',
  `CREATE TRIGGER IF NOT EXISTS user_control_audit_no_update
   BEFORE UPDATE ON user_control_audit
   BEGIN
     SELECT RAISE(ABORT, 'user control audit is append-only');
   END`,
  `CREATE TRIGGER IF NOT EXISTS user_control_audit_no_delete
   BEFORE DELETE ON user_control_audit
   BEGIN
     SELECT RAISE(ABORT, 'user control audit is append-only');
   END`,
  `CREATE TABLE IF NOT EXISTS profile_health (
     profile_id TEXT PRIMARY KEY,
     latency_ms INTEGER,
     ok INTEGER NOT NULL DEFAULT 0,
     failures INTEGER NOT NULL DEFAULT 0,
     successes INTEGER NOT NULL DEFAULT 0,
     quarantine_until INTEGER NOT NULL DEFAULT 0,
     checked_at INTEGER NOT NULL DEFAULT 0,
     consecutive_failures INTEGER NOT NULL DEFAULT 0,
     consecutive_successes INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS health_samples (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     kind TEXT NOT NULL,
     subject_id TEXT NOT NULL,
     ts INTEGER NOT NULL,
     ok INTEGER NOT NULL DEFAULT 0,
     latency_ms INTEGER
   )`,
  `CREATE INDEX IF NOT EXISTS idx_health_samples_subject ON health_samples(kind, subject_id, ts DESC)`,
  `CREATE TABLE IF NOT EXISTS predictive_state (
     kind TEXT NOT NULL,
     subject_id TEXT NOT NULL,
     state_json TEXT NOT NULL,
     updated_at INTEGER NOT NULL,
     PRIMARY KEY(kind, subject_id)
   )`,
  `CREATE TABLE IF NOT EXISTS adaptive_model (
     scope TEXT PRIMARY KEY,
     state_json TEXT NOT NULL,
     updated_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS user_adaptive_state (
     user_id INTEGER PRIMARY KEY,
     preferred_path_id TEXT NOT NULL DEFAULT '',
     preferred_profile_id TEXT NOT NULL DEFAULT '',
     successes INTEGER NOT NULL DEFAULT 0,
     failures INTEGER NOT NULL DEFAULT 0,
     last_ok INTEGER NOT NULL DEFAULT 0,
     updated_at INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS ai_model_health (
     model_id TEXT PRIMARY KEY,
     failures INTEGER NOT NULL DEFAULT 0,
     successes INTEGER NOT NULL DEFAULT 0,
     quarantine_until INTEGER NOT NULL DEFAULT 0,
     updated_at INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS network_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     state TEXT NOT NULL,
     quorum REAL NOT NULL DEFAULT 0,
     failure_rate REAL NOT NULL DEFAULT 0,
     selected_path TEXT NOT NULL DEFAULT '',
     reason_codes TEXT NOT NULL DEFAULT '[]',
     confidence REAL NOT NULL DEFAULT 0,
     anomaly_score REAL NOT NULL DEFAULT 0,
     signal_class TEXT NOT NULL DEFAULT 'normal',
     updated_at INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS protocol_policy_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     selected_profile TEXT NOT NULL DEFAULT '',
     fallback_ladder TEXT NOT NULL DEFAULT '[]',
     reason_codes TEXT NOT NULL DEFAULT '[]',
     diversity TEXT NOT NULL DEFAULT '{}',
     confidence REAL NOT NULL DEFAULT 0,
     mode TEXT NOT NULL DEFAULT 'normal',
     policy_fingerprint TEXT NOT NULL DEFAULT '',
     consensus REAL NOT NULL DEFAULT 0.5,
     signal_agreement REAL NOT NULL DEFAULT 0.5,
     switch_risk REAL NOT NULL DEFAULT 0.5,
     fusion_mode TEXT NOT NULL DEFAULT 'insufficient_evidence',
     updated_at INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS adaptive_guard_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     state_json TEXT NOT NULL DEFAULT '{}',
     updated_at INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS policy_signal_state (
     id INTEGER PRIMARY KEY CHECK (id = 1),
     state_json TEXT NOT NULL DEFAULT '{}',
     updated_at INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS telegram_fsm (
     chat_id TEXT PRIMARY KEY,
     state TEXT NOT NULL CHECK (state IN ('awaiting_disable_id', 'awaiting_enable_id')),
     updated_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS telegram_updates (
     update_id INTEGER PRIMARY KEY,
     processed_at INTEGER NOT NULL
   )`,
];

/** v1.2 additions for databases created with v1.x (guarded ALTERs). */
const MIGRATIONS = [
  "ALTER TABLE path_health ADD COLUMN last_error TEXT NOT NULL DEFAULT ''",
  'ALTER TABLE path_health ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE path_health ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN first_used_at INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN expiry_days INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN reset_anchor INTEGER NOT NULL DEFAULT 0',
  "ALTER TABLE network_state ADD COLUMN anomaly_score REAL NOT NULL DEFAULT 0",
  "ALTER TABLE network_state ADD COLUMN signal_class TEXT NOT NULL DEFAULT 'normal'",
  "ALTER TABLE path_health ADD COLUMN drift TEXT NOT NULL DEFAULT 'stable'",
  "ALTER TABLE path_health ADD COLUMN forecast_success REAL NOT NULL DEFAULT 0.5",
  "ALTER TABLE path_health ADD COLUMN volatility REAL NOT NULL DEFAULT 1",
  "ALTER TABLE profile_health ADD COLUMN drift TEXT NOT NULL DEFAULT 'stable'",
  "ALTER TABLE profile_health ADD COLUMN forecast_success REAL NOT NULL DEFAULT 0.5",
  "ALTER TABLE profile_health ADD COLUMN volatility REAL NOT NULL DEFAULT 1",
  "ALTER TABLE protocol_policy_state ADD COLUMN consensus REAL NOT NULL DEFAULT 0.5",
  "ALTER TABLE protocol_policy_state ADD COLUMN signal_agreement REAL NOT NULL DEFAULT 0.5",
  "ALTER TABLE protocol_policy_state ADD COLUMN switch_risk REAL NOT NULL DEFAULT 0.5",
  "ALTER TABLE protocol_policy_state ADD COLUMN fusion_mode TEXT NOT NULL DEFAULT 'insufficient_evidence'",
];

let schemaPromise: Promise<void> | null = null;

/** Create tables once per isolate (promise-deduped) + guarded v1->v2 migrations. */
export function ensureSchema(db: D1Database): Promise<void> {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await db.batch(DDL.map((sql) => db.prepare(sql)));
      for (const sql of MIGRATIONS) {
        try { await db.prepare(sql).run(); } catch { /* column already exists */ }
      }
    })().catch((e) => {
      schemaPromise = null; // allow retry on next request
      throw e;
    });
  }
  return schemaPromise;
}

/* ------------------------------ settings ------------------------------ */

interface CacheEntry { at: number; value: unknown; }
const cache = new Map<string, CacheEntry>();

function cached<T>(key: string): T | null {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < DEFAULTS.cacheTtlMs) return hit.value as T;
  return null;
}
function putCache(key: string, value: unknown): void {
  cache.set(key, { at: Date.now(), value });
}
export function invalidateCache(prefix?: string): void {
  if (!prefix) { cache.clear(); return; }
  for (const k of cache.keys()) if (k.startsWith(prefix)) cache.delete(k);
}

const SETTINGS_KEY = 'settings';

export async function loadSettings(db: D1Database): Promise<SettingsBlob | null> {
  const hit = cached<SettingsBlob>(SETTINGS_KEY);
  if (hit) return hit;
  await ensureSchema(db);
  const row = await db
    .prepare('SELECT value, rev FROM kv_store WHERE key = ?1')
    .bind(SETTINGS_KEY)
    .first<{ value: string; rev: number }>();
  if (!row) return null;
  const value = JSON.parse(row.value) as SettingsBlob;
  // forward-fill fields introduced after v1.1 (schema v2)
  if (!value.resetCycle) value.resetCycle = 'none';
  if (!Array.isArray(value.backupEntryHosts)) value.backupEntryHosts = [];
  if (typeof value.forcePasswordChange !== 'boolean') value.forcePasswordChange = false;
  putCache(SETTINGS_KEY + '#rev', row.rev);
  putCache(SETTINGS_KEY, value);
  return value;
}

/** Read-modify-write with optimistic rev check (3 retries). */
export async function saveSettings(
  db: D1Database,
  mutate: (prev: SettingsBlob | null) => SettingsBlob,
): Promise<SettingsBlob> {
  await ensureSchema(db);
  for (let attempt = 0; attempt < 3; attempt++) {
    const row = await db
      .prepare('SELECT value, rev FROM kv_store WHERE key = ?1')
      .bind(SETTINGS_KEY)
      .first<{ value: string; rev: number }>();
    const prev = row ? (JSON.parse(row.value) as SettingsBlob) : null;
    const rev = row ? row.rev : 0;
    const next = mutate(prev);
    next.schemaVersion = SCHEMA_VERSION;
    const encoded = JSON.stringify(next);
    const res = row
      ? await db
          .prepare('UPDATE kv_store SET value = ?1, rev = rev + 1, updated_at = ?2 WHERE key = ?3 AND rev = ?4')
          .bind(encoded, Date.now(), SETTINGS_KEY, rev)
          .run()
      : await db
          .prepare('INSERT INTO kv_store (key, value, rev, updated_at) VALUES (?1, ?2, 1, ?3)')
          .bind(SETTINGS_KEY, encoded, Date.now())
          .run();
    if (res.meta.changes === 1 || !row) {
      invalidateCache(SETTINGS_KEY);
      return next;
    }
  }
  throw new Error('settings concurrent write conflict — retry');
}

/* ------------------------------ events ------------------------------ */

export async function addEvent(db: D1Database, type: string, detail: string): Promise<void> {
  try {
    await ensureSchema(db);
    await db.prepare('INSERT INTO events (ts, type, detail) VALUES (?1, ?2, ?3)').bind(Date.now(), type, detail).run();
    // keep the ring small
    await db.prepare(
      'DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET 49)',
    ).run();
  } catch {
    /* logging must never break requests */
  }
}

export async function recentEvents(db: D1Database, limit = 10): Promise<Array<{ ts: number; type: string; detail: string }>> {
  await ensureSchema(db);
  const res = await db
    .prepare('SELECT ts, type, detail FROM events ORDER BY id DESC LIMIT ?1')
    .bind(limit)
    .all<{ ts: number; type: string; detail: string }>();
  return res.results ?? [];
}

/* ------------------------------ login throttle ------------------------------ */

export async function loginAttemptsLeft(db: D1Database, ipHash: string): Promise<number> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT count, window_start FROM auth_throttle WHERE ip_hash = ?1').bind(ipHash).first<{ count: number; window_start: number }>();
  if (!row || Date.now() - row.window_start > DEFAULTS.loginWindowMs) return DEFAULTS.loginMaxAttempts;
  return Math.max(0, DEFAULTS.loginMaxAttempts - row.count);
}

export async function recordLoginFailure(db: D1Database, ipHash: string): Promise<void> {
  await ensureSchema(db);
  const now = Date.now();
  const row = await db.prepare('SELECT count, window_start FROM auth_throttle WHERE ip_hash = ?1').bind(ipHash).first<{ count: number; window_start: number }>();
  if (!row || now - row.window_start > DEFAULTS.loginWindowMs) {
    await db.prepare(
      'INSERT INTO auth_throttle (ip_hash, count, window_start) VALUES (?1, 1, ?2) ' +
      'ON CONFLICT(ip_hash) DO UPDATE SET count = 1, window_start = ?2',
    ).bind(ipHash, now).run();
  } else {
    await db.prepare('UPDATE auth_throttle SET count = count + 1 WHERE ip_hash = ?1').bind(ipHash).run();
  }
}

/** Atomic D1-backed budget for expensive AI diagnostics (five calls per 10 minutes/IP). */
export async function consumeAiDiagnosticQuota(db: D1Database, ipHash: string, now = Date.now()): Promise<boolean> {
  await ensureSchema(db);
  const windowMs = 10 * 60_000;
  const row = await db.prepare(
    'INSERT INTO ai_throttle (ip_hash, window_start, count) VALUES (?1, ?2, 1) ' +
    'ON CONFLICT(ip_hash) DO UPDATE SET ' +
    'count = CASE WHEN ai_throttle.window_start <= ?3 THEN 1 ELSE ai_throttle.count + 1 END, ' +
    'window_start = CASE WHEN ai_throttle.window_start <= ?3 THEN ?2 ELSE ai_throttle.window_start END ' +
    'WHERE ai_throttle.window_start <= ?3 OR ai_throttle.count < ?4 RETURNING count',
  ).bind(ipHash, now, now - windowMs, 5).first<{ count: number }>();
  return row !== null;
}

/** Atomic per-user DNS request budget (default callers use 120 queries/minute). */
export async function consumeDnsQueryQuota(
  db: D1Database,
  userId: number,
  now = Date.now(),
  limit = 120,
  windowMs = 60_000,
): Promise<boolean> {
  if (!Number.isSafeInteger(userId) || userId <= 0 || !Number.isInteger(limit) || limit < 1 || !Number.isInteger(windowMs) || windowMs < 1) return false;
  await ensureSchema(db);
  const row = await db.prepare(
    'INSERT INTO dns_throttle (user_id, window_start, count) VALUES (?1, ?2, 1) ' +
    'ON CONFLICT(user_id) DO UPDATE SET ' +
    'count = CASE WHEN dns_throttle.window_start <= ?3 THEN 1 ELSE dns_throttle.count + 1 END, ' +
    'window_start = CASE WHEN dns_throttle.window_start <= ?3 THEN ?2 ELSE dns_throttle.window_start END ' +
    'WHERE dns_throttle.window_start <= ?3 OR dns_throttle.count < ?4 RETURNING count',
  ).bind(userId, now, now - windowMs, limit).first<{ count: number }>();
  return row !== null;
}

/** Atomic authenticated-admin request budget (30 user-control calls/minute/IP). */
export async function consumeUserControlQuota(
  db: D1Database,
  ipHash: string,
  now = Date.now(),
  limit = 30,
  windowMs = 60_000,
): Promise<boolean> {
  if (!ipHash || !Number.isSafeInteger(now) || !Number.isInteger(limit) || limit < 1 || !Number.isInteger(windowMs) || windowMs < 1) return false;
  await ensureSchema(db);
  const row = await db.prepare(
    'INSERT INTO user_control_throttle (ip_hash, window_start, count) VALUES (?1, ?2, 1) ' +
    'ON CONFLICT(ip_hash) DO UPDATE SET ' +
    'count = CASE WHEN user_control_throttle.window_start <= ?3 THEN 1 ELSE user_control_throttle.count + 1 END, ' +
    'window_start = CASE WHEN user_control_throttle.window_start <= ?3 THEN ?2 ELSE user_control_throttle.window_start END ' +
    'WHERE user_control_throttle.window_start <= ?3 OR user_control_throttle.count < ?4 RETURNING count',
  ).bind(ipHash, now, now - windowMs, limit).first<{ count: number }>();
  return row !== null;
}

export interface UserControlAuditEntry {
  id: number;
  actorUserId: number;
  targetUserId: number;
  action: 'user_created' | 'user_updated' | 'user_enabled' | 'user_disabled' | 'user_deleted';
  details: Record<string, unknown>;
  createdAt: number;
}

export async function loadUserControlAudit(db: D1Database, limit = 50, beforeId = 0): Promise<UserControlAuditEntry[]> {
  await ensureSchema(db);
  const n = Math.max(1, Math.min(100, Math.floor(limit)));
  const before = Number.isSafeInteger(beforeId) && beforeId > 0 ? beforeId : Number.MAX_SAFE_INTEGER;
  const rows = await db.prepare(
    'SELECT id, actor_user_id, target_user_id, action, details_json, created_at ' +
    'FROM user_control_audit WHERE id < ?1 ORDER BY id DESC LIMIT ?2',
  ).bind(before, n).all<{
    id: number; actor_user_id: number; target_user_id: number;
    action: UserControlAuditEntry['action']; details_json: string; created_at: number;
  }>();
  return (rows.results ?? []).map((row) => ({
    id: row.id,
    actorUserId: row.actor_user_id,
    targetUserId: row.target_user_id,
    action: row.action,
    details: JSON.parse(row.details_json) as Record<string, unknown>,
    createdAt: row.created_at,
  }));
}

export async function clearLoginThrottle(db: D1Database, ipHash: string): Promise<void> {
  await ensureSchema(db);
  await db.prepare('DELETE FROM auth_throttle WHERE ip_hash = ?1').bind(ipHash).run();
}


export interface PathHealthRow {
  pathId: string; latencyMs: number | null; ok: boolean; failures: number; successes: number; quarantineUntil: number; checkedAt: number;
  lastError?: string; consecutiveFailures?: number; consecutiveSuccesses?: number; drift?: string; forecastSuccess?: number; volatility?: number;
}

export async function loadPathHealth(db: D1Database): Promise<PathHealthRow[]> {
  await ensureSchema(db);
  const res = await db.prepare('SELECT path_id, latency_ms, ok, failures, successes, quarantine_until, checked_at, last_error, consecutive_failures, consecutive_successes, drift, forecast_success, volatility FROM path_health ORDER BY checked_at DESC LIMIT 64').all<{path_id:string;latency_ms:number|null;ok:number;failures:number;successes:number;quarantine_until:number;checked_at:number;last_error:string;consecutive_failures:number;consecutive_successes:number;drift:string;forecast_success:number;volatility:number}>();
  return (res.results ?? []).map(r => ({ pathId:r.path_id, latencyMs:r.latency_ms, ok:r.ok === 1, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantine_until, checkedAt:r.checked_at, lastError:r.last_error, consecutiveFailures:r.consecutive_failures, consecutiveSuccesses:r.consecutive_successes, drift:r.drift, forecastSuccess:r.forecast_success, volatility:r.volatility }));
}

export async function savePathHealth(db: D1Database, row: PathHealthRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare('INSERT INTO path_health(path_id,latency_ms,ok,failures,successes,quarantine_until,checked_at,last_error,consecutive_failures,consecutive_successes,drift,forecast_success,volatility) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(path_id) DO UPDATE SET latency_ms=?2, ok=?3, failures=?4, successes=?5, quarantine_until=?6, checked_at=?7, last_error=?8, consecutive_failures=?9, consecutive_successes=?10, drift=?11, forecast_success=?12, volatility=?13').bind(row.pathId,row.latencyMs,row.ok?1:0,row.failures,row.successes,row.quarantineUntil,row.checkedAt,row.lastError ?? '',row.consecutiveFailures ?? 0,row.consecutiveSuccesses ?? 0,row.drift ?? 'stable',row.forecastSuccess ?? 0.5,row.volatility ?? 1).run();
}


export interface ProfileHealthRow {
  profileId: string;
  latencyMs: number | null;
  ok: boolean;
  failures: number;
  successes: number;
  quarantineUntil: number;
  checkedAt: number;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  drift?: string;
  forecastSuccess?: number;
  volatility?: number;
}

export async function loadProfileHealth(db: D1Database): Promise<ProfileHealthRow[]> {
  await ensureSchema(db);
  const res = await db.prepare(
    'SELECT profile_id, latency_ms, ok, failures, successes, quarantine_until, checked_at, consecutive_failures, consecutive_successes, drift, forecast_success, volatility FROM profile_health ORDER BY checked_at DESC LIMIT 16',
  ).all<{
    profile_id: string; latency_ms: number | null; ok: number; failures: number; successes: number;
    quarantine_until: number; checked_at: number; consecutive_failures: number; consecutive_successes: number; drift: string; forecast_success: number; volatility: number;
  }>();
  return (res.results ?? []).map((r) => ({
    profileId: r.profile_id,
    latencyMs: r.latency_ms,
    ok: r.ok === 1,
    failures: r.failures,
    successes: r.successes,
    quarantineUntil: r.quarantine_until,
    checkedAt: r.checked_at,
    consecutiveFailures: r.consecutive_failures,
    consecutiveSuccesses: r.consecutive_successes,
    drift: r.drift, forecastSuccess: r.forecast_success, volatility: r.volatility,
  }));
}

export async function saveProfileHealth(db: D1Database, row: ProfileHealthRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO profile_health(profile_id,latency_ms,ok,failures,successes,quarantine_until,checked_at,consecutive_failures,consecutive_successes,drift,forecast_success,volatility) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ' +
    'ON CONFLICT(profile_id) DO UPDATE SET latency_ms=?2, ok=?3, failures=?4, successes=?5, quarantine_until=?6, checked_at=?7, consecutive_failures=?8, consecutive_successes=?9, drift=?10, forecast_success=?11, volatility=?12',
  ).bind(
    row.profileId, row.latencyMs, row.ok ? 1 : 0, row.failures, row.successes, row.quarantineUntil, row.checkedAt,
    row.consecutiveFailures, row.consecutiveSuccesses, row.drift ?? 'stable', row.forecastSuccess ?? 0.5, row.volatility ?? 1,
  ).run();
}



export type HealthSampleKind = 'path' | 'profile' | 'path_tcp' | 'path_dial' | 'path_https';
export interface HealthSampleRow { kind: HealthSampleKind; subjectId: string; ts: number; ok: boolean; latencyMs: number | null; }

export async function saveHealthSample(db: D1Database, row: HealthSampleRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare('INSERT INTO health_samples(kind,subject_id,ts,ok,latency_ms) VALUES(?1,?2,?3,?4,?5)').bind(row.kind,row.subjectId,row.ts,row.ok?1:0,row.latencyMs).run();
  await db.prepare('DELETE FROM health_samples WHERE kind = ?1 AND subject_id = ?2 AND id NOT IN (SELECT id FROM health_samples WHERE kind = ?1 AND subject_id = ?2 ORDER BY ts DESC LIMIT 24)').bind(row.kind,row.subjectId).run();
}

export async function loadHealthSamples(db: D1Database, kind: 'path' | 'profile', subjectId: string, limit = 24): Promise<Array<{ ts:number; ok:boolean; latencyMs:number|null }>> {
  await ensureSchema(db);
  const n = Math.max(1, Math.min(48, limit));
  const kinds = kind === 'path' ? ['path', 'path_tcp', 'path_dial', 'path_https'] : ['profile'];
  const placeholders = kinds.map((_, index) => '?' + String(index + 1)).join(',');
  const statement = 'SELECT ts, ok, latency_ms FROM health_samples WHERE kind IN (' + placeholders + ') AND subject_id = ?' + String(kinds.length + 1) + ' ORDER BY ts DESC LIMIT ' + String(n);
  const res = await db.prepare(statement).bind(...kinds, subjectId).all<{ts:number;ok:number;latency_ms:number|null}>();
  return (res.results ?? []).reverse().map(r => ({ ts:r.ts, ok:r.ok === 1, latencyMs:r.latency_ms }));
}

/**
 * 2.12 — global aggregate outcome stream for regime intelligence: the most
 * recent path-level observations across all configured subjects, ascending.
 */
export async function loadRecentHealthSamples(db: D1Database, limit = 60): Promise<Array<{ ts: number; ok: boolean; latencyMs: number | null }>> {
  await ensureSchema(db);
  const n = Math.max(8, Math.min(96, limit));
  const res = await db
    .prepare('SELECT ts, ok, latency_ms FROM health_samples WHERE kind IN (\'path\', \'path_tcp\', \'path_dial\', \'path_https\') ORDER BY ts DESC LIMIT ' + String(n))
    .all<{ ts: number; ok: number; latency_ms: number | null }>();
  return (res.results ?? []).reverse().map(r => ({ ts: r.ts, ok: r.ok === 1, latencyMs: r.latency_ms }));
}

export interface LatestPathSample {
  kind: Exclude<HealthSampleKind, 'profile'>;
  subjectId: string;
  ts: number;
  ok: boolean;
  latencyMs: number | null;
}

/** One bounded D1 query: at most one recent observation per source and configured endpoint. */
export async function loadLatestPathSamples(db: D1Database, subjectIds: string[]): Promise<LatestPathSample[]> {
  await ensureSchema(db);
  const ids = [...new Set(subjectIds)].filter(Boolean).slice(0, 32);
  if (!ids.length) return [];
  const placeholders = ids.map((_, index) => '?' + String(index + 1)).join(',');
  const sql = `SELECT kind, subject_id, ts, ok, latency_ms FROM (
    SELECT kind, subject_id, ts, ok, latency_ms,
      ROW_NUMBER() OVER (PARTITION BY kind, subject_id ORDER BY ts DESC) AS rank
    FROM health_samples
    WHERE kind IN ('path', 'path_tcp', 'path_dial', 'path_https') AND subject_id IN (${placeholders})
  ) WHERE rank = 1`;
  const result = await db.prepare(sql).bind(...ids).all<{kind: LatestPathSample['kind'];subject_id:string;ts:number;ok:number;latency_ms:number|null}>();
  return (result.results ?? []).map((row) => ({
    kind: row.kind,
    subjectId: row.subject_id,
    ts: row.ts,
    ok: row.ok === 1,
    latencyMs: row.latency_ms,
  }));
}

export interface PredictiveStateRow { kind:'path'|'profile'|'regime'|'harvest'; subjectId:string; stateJson:string; updatedAt:number; }
export async function savePredictiveState(db:D1Database,row:PredictiveStateRow):Promise<void>{
  await ensureSchema(db);
  await db.prepare('INSERT INTO predictive_state(kind,subject_id,state_json,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(kind,subject_id) DO UPDATE SET state_json=?3, updated_at=?4').bind(row.kind,row.subjectId,row.stateJson,row.updatedAt).run();
}
export async function loadPredictiveStates(db:D1Database, kind:'path'|'profile'|'regime'|'harvest'):Promise<Array<{subjectId:string;stateJson:string;updatedAt:number}>>{
  await ensureSchema(db);
  const res=await db.prepare('SELECT subject_id,state_json,updated_at FROM predictive_state WHERE kind=?1 ORDER BY updated_at DESC LIMIT 64').bind(kind).all<{subject_id:string;state_json:string;updated_at:number}>();
  return (res.results ?? []).map(r=>({subjectId:r.subject_id,stateJson:r.state_json,updatedAt:r.updated_at}));
}

/**
 * 2.16 — clean-IP harvest store. The AXR client `scan` runner probes real
 * Cloudflare edge addresses from the local network and POSTs the survivors
 * to the Worker; they are persisted here (capped) and unioned into the
 * `clean_ip_hints` manifest field. One row: kind='harvest', subject_id
 * ='clean_ips'. The JSON payload is `{ips: string[], updatedAt: number,
 * sources: Record<string, number>}`.
 */
export interface CleanIPHarvestRow { ips: string[]; updatedAt: number; sources: Record<string, number>; }

export async function loadCleanIPHarvest(db: D1Database): Promise<CleanIPHarvestRow | null> {
  const rows = await loadPredictiveStates(db, 'harvest');
  const row = rows.find((r) => r.subjectId === 'clean_ips');
  if (!row) return null;
  try {
    const parsed = JSON.parse(row.stateJson) as CleanIPHarvestRow;
    if (!Array.isArray(parsed.ips)) return null;
    parsed.ips = parsed.ips.filter((x) => typeof x === 'string' && isIPv4ish(x));
    return parsed;
  } catch {
    return null;
  }
}

export async function saveCleanIPHarvest(db: D1Database, row: CleanIPHarvestRow): Promise<void> {
  const ips = row.ips.filter((x) => isIPv4ish(x)).slice(0, 32);
  const sources: Record<string, number> = {};
  for (const [k, v] of Object.entries(row.sources ?? {})) {
    if (typeof k === 'string' && k.length <= 48 && Number.isFinite(v)) sources[k] = v;
  }
  await savePredictiveState(db, {
    kind: 'harvest',
    subjectId: 'clean_ips',
    stateJson: JSON.stringify({ ips, updatedAt: row.updatedAt, sources } satisfies CleanIPHarvestRow),
    updatedAt: row.updatedAt,
  });
}

function isIPv4ish(s: string): boolean {
  if (!/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s)) return false;
  return s.split('.').every((o) => Number(o) <= 255);
}

/**
 * 2.17 — canary liveness store. Clients periodically probe the operator's
 * canary host (a plain host expected to stay reachable) and report ok/fail
 * via the harvest endpoint (kind="canary"). Results are kept here, newest
 * first, capped at 64, in one row: kind='harvest', subject_id='canary'.
 * The pressure engine (ai/pressure.ts) reduces this list to fleet evidence.
 * Honesty: these are liveness flags from client probes — aggregate
 * statistics, never DPI detection.
 */
export interface CanaryResult { host: string; ok: boolean; at: number; }
export interface CanaryStateRow { results: CanaryResult[]; updatedAt: number; }

const CANARY_MAX_RESULTS = 64;
const CANARY_MAX_HOST_LEN = 253;

export async function loadCanaryState(db: D1Database): Promise<CanaryStateRow | null> {
  const rows = await loadPredictiveStates(db, 'harvest');
  const row = rows.find((r) => r.subjectId === 'canary');
  if (!row) return null;
  try {
    const parsed = JSON.parse(row.stateJson) as CanaryStateRow;
    if (!Array.isArray(parsed.results)) return null;
    parsed.results = parsed.results
      .filter((r) => r && typeof r.host === 'string' && typeof r.ok === 'boolean' && Number.isFinite(r.at))
      .map((r) => ({ host: r.host.slice(0, CANARY_MAX_HOST_LEN), ok: r.ok, at: r.at }));
    return parsed;
  } catch {
    return null;
  }
}

/** Append one canary result (newest first, capped). Returns the stored row. */
export async function appendCanaryResult(db: D1Database, r: CanaryResult): Promise<CanaryStateRow> {
  const existing = (await loadCanaryState(db))?.results ?? [];
  const clean: CanaryResult = {
    host: String(r.host ?? '').slice(0, CANARY_MAX_HOST_LEN),
    ok: Boolean(r.ok),
    at: Number.isFinite(r.at) ? r.at : Date.now(),
  };
  const results = [clean, ...existing].slice(0, CANARY_MAX_RESULTS);
  const row: CanaryStateRow = { results, updatedAt: clean.at };
  await savePredictiveState(db, {
    kind: 'harvest',
    subjectId: 'canary',
    stateJson: JSON.stringify(row),
    updatedAt: row.updatedAt,
  });
  return row;
}

export interface NetworkStateRow {
  state: string;
  quorum: number;
  failureRate: number;
  selectedPath: string;
  reasonCodes: string[];
  confidence: number;
  anomalyScore: number;
  signalClass: string;
  updatedAt: number;
}

export async function loadNetworkState(db: D1Database): Promise<NetworkStateRow | null> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT state, quorum, failure_rate, selected_path, reason_codes, confidence, anomaly_score, signal_class, updated_at FROM network_state WHERE id = 1').first<{
    state:string; quorum:number; failure_rate:number; selected_path:string; reason_codes:string; confidence:number; anomaly_score:number; signal_class:string; updated_at:number;
  }>();
  if (!row) return null;
  let reasonCodes: string[] = [];
  try {
    const parsed = JSON.parse(row.reason_codes);
    if (Array.isArray(parsed)) reasonCodes = parsed.filter((x): x is string => typeof x === 'string').slice(0, 12);
  } catch { /* safe default */ }
  return { state: row.state, quorum: row.quorum, failureRate: row.failure_rate, selectedPath: row.selected_path, reasonCodes, confidence: row.confidence, anomalyScore: row.anomaly_score ?? 0, signalClass: row.signal_class || 'normal', updatedAt: row.updated_at };
}

export interface ProtocolPolicyStateRow {
  selectedProfile: string;
  fallbackLadder: string[];
  reasonCodes: string[];
  diversity: { protocols: string[]; transports: string[]; securities: string[] };
  confidence: number;
  mode: string;
  policyFingerprint: string;
  consensus: number;
  signalAgreement: number;
  switchRisk: number;
  fusionMode: string;
  updatedAt: number;
}

export async function loadProtocolPolicyState(db: D1Database): Promise<ProtocolPolicyStateRow | null> {
  await ensureSchema(db);
  const row = await db.prepare(
    'SELECT selected_profile, fallback_ladder, reason_codes, diversity, confidence, mode, policy_fingerprint, consensus, signal_agreement, switch_risk, fusion_mode, updated_at FROM protocol_policy_state WHERE id = 1',
  ).first<{ selected_profile:string; fallback_ladder:string; reason_codes:string; diversity:string; confidence:number; mode:string; policy_fingerprint:string; consensus:number; signal_agreement:number; switch_risk:number; fusion_mode:string; updated_at:number }>();
  if (!row) return null;
  const parse = (value: string, fallback: unknown): any => { try { return JSON.parse(value); } catch { return fallback; } };
  const ladder = parse(row.fallback_ladder, []);
  const reasons = parse(row.reason_codes, []);
  const diversity = parse(row.diversity, { protocols: [], transports: [], securities: [] });
  return {
    selectedProfile: row.selected_profile,
    fallbackLadder: Array.isArray(ladder) ? ladder.filter((x): x is string => typeof x === 'string').slice(0, 12) : [],
    reasonCodes: Array.isArray(reasons) ? reasons.filter((x): x is string => typeof x === 'string').slice(0, 16) : [],
    diversity: {
      protocols: Array.isArray(diversity?.protocols) ? diversity.protocols.filter((x: unknown): x is string => typeof x === 'string').slice(0, 16) : [],
      transports: Array.isArray(diversity?.transports) ? diversity.transports.filter((x: unknown): x is string => typeof x === 'string').slice(0, 16) : [],
      securities: Array.isArray(diversity?.securities) ? diversity.securities.filter((x: unknown): x is string => typeof x === 'string').slice(0, 16) : [],
    },
    confidence: row.confidence,
    mode: row.mode,
    policyFingerprint: row.policy_fingerprint,
    consensus: Number.isFinite(row.consensus) ? row.consensus : 0.5,
    signalAgreement: Number.isFinite(row.signal_agreement) ? row.signal_agreement : 0.5,
    switchRisk: Number.isFinite(row.switch_risk) ? row.switch_risk : 0.5,
    fusionMode: row.fusion_mode || 'insufficient_evidence',
    updatedAt: row.updated_at,
  };
}

export async function saveProtocolPolicyState(db: D1Database, row: ProtocolPolicyStateRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO protocol_policy_state(id,selected_profile,fallback_ladder,reason_codes,diversity,confidence,mode,policy_fingerprint,consensus,signal_agreement,switch_risk,fusion_mode,updated_at) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ' +
    'ON CONFLICT(id) DO UPDATE SET selected_profile=?1, fallback_ladder=?2, reason_codes=?3, diversity=?4, confidence=?5, mode=?6, policy_fingerprint=?7, consensus=?8, signal_agreement=?9, switch_risk=?10, fusion_mode=?11, updated_at=?12',
  ).bind(
    row.selectedProfile,
    JSON.stringify(row.fallbackLadder),
    JSON.stringify(row.reasonCodes),
    JSON.stringify(row.diversity),
    row.confidence,
    row.mode,
    row.policyFingerprint,
    row.consensus,
    row.signalAgreement,
    row.switchRisk,
    row.fusionMode,
    row.updatedAt,
  ).run();
}


export async function saveNetworkState(db: D1Database, row: NetworkStateRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO network_state(id,state,quorum,failure_rate,selected_path,reason_codes,confidence,anomaly_score,signal_class,updated_at) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9) ' +
    'ON CONFLICT(id) DO UPDATE SET state=?1, quorum=?2, failure_rate=?3, selected_path=?4, reason_codes=?5, confidence=?6, anomaly_score=?7, signal_class=?8, updated_at=?9',
  ).bind(row.state, row.quorum, row.failureRate, row.selectedPath, JSON.stringify(row.reasonCodes.slice(0, 12)), row.confidence, row.anomalyScore, row.signalClass, row.updatedAt).run();
}

export interface AdaptiveModelRow {
  scope: string;
  stateJson: string;
  updatedAt: number;
}

export async function loadAdaptiveModel(db: D1Database, scope = 'global'): Promise<AdaptiveModelRow | null> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT scope, state_json, updated_at FROM adaptive_model WHERE scope = ?1').bind(scope).first<{scope:string;state_json:string;updated_at:number}>();
  return row ? { scope: row.scope, stateJson: row.state_json, updatedAt: row.updated_at } : null;
}

export async function saveAdaptiveModel(db: D1Database, row: AdaptiveModelRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO adaptive_model(scope,state_json,updated_at) VALUES(?1,?2,?3) ON CONFLICT(scope) DO UPDATE SET state_json=?2, updated_at=?3',
  ).bind(row.scope, row.stateJson, row.updatedAt).run();
}

export interface UserAdaptiveRow {
  userId: number;
  preferredPathId: string;
  preferredProfileId: string;
  successes: number;
  failures: number;
  lastOk: boolean;
  updatedAt: number;
}

export async function loadUserAdaptiveState(db: D1Database, userId: number): Promise<UserAdaptiveRow | null> {
  await ensureSchema(db);
  const row = await db.prepare(
    'SELECT user_id, preferred_path_id, preferred_profile_id, successes, failures, last_ok, updated_at FROM user_adaptive_state WHERE user_id = ?1',
  ).bind(userId).first<{user_id:number;preferred_path_id:string;preferred_profile_id:string;successes:number;failures:number;last_ok:number;updated_at:number}>();
  return row ? {
    userId: row.user_id, preferredPathId: row.preferred_path_id, preferredProfileId: row.preferred_profile_id,
    successes: row.successes, failures: row.failures, lastOk: row.last_ok === 1, updatedAt: row.updated_at,
  } : null;
}

export async function saveUserAdaptiveState(db: D1Database, row: UserAdaptiveRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO user_adaptive_state(user_id,preferred_path_id,preferred_profile_id,successes,failures,last_ok,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7) ' +
    'ON CONFLICT(user_id) DO UPDATE SET preferred_path_id=?2, preferred_profile_id=?3, successes=?4, failures=?5, last_ok=?6, updated_at=?7',
  ).bind(row.userId,row.preferredPathId,row.preferredProfileId,row.successes,row.failures,row.lastOk?1:0,row.updatedAt).run();
}


export async function loadAdaptiveGuardState(db: D1Database): Promise<AdaptiveGuardState | null> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT state_json FROM adaptive_guard_state WHERE id = 1').first<{ state_json: string }>();
  if (!row) return null;
  try {
    const parsed = JSON.parse(row.state_json) as any;
    const normalizePlan = (plan: any) => plan ? {
      ...plan,
      version: '2.8-consensus-mesh-v1',
      consensus: Number.isFinite(Number(plan.consensus)) ? Number(plan.consensus) : 0.5,
      signalAgreement: Number.isFinite(Number(plan.signalAgreement)) ? Number(plan.signalAgreement) : 0.5,
      switchRisk: Number.isFinite(Number(plan.switchRisk)) ? Number(plan.switchRisk) : 0.5,
      fusionMode: plan.fusionMode === 'stable' || plan.fusionMode === 'cautious' || plan.fusionMode === 'recovery' ? plan.fusionMode : 'insufficient_evidence',
      forecastSuccess: Number.isFinite(Number(plan.forecastSuccess)) ? Number(plan.forecastSuccess) : 0.5,
      drift: plan.drift === 'improving' || plan.drift === 'degrading' ? plan.drift : 'stable',
      volatility: Number.isFinite(Number(plan.volatility)) ? Number(plan.volatility) : 1,
    } : null;
    if (parsed && parsed.version === 2) return { ...parsed, active: normalizePlan(parsed.active), previous: normalizePlan(parsed.previous), staged: normalizePlan(parsed.staged) } as AdaptiveGuardState;
    if (parsed && parsed.version === 1) {
      return {
        version: 2,
        active: normalizePlan(parsed.active),
        previous: normalizePlan(parsed.previous),
        staged: normalizePlan(parsed.staged),
        status: parsed.status ?? 'stable',
        holdUntil: Number(parsed.holdUntil) || 0,
        rollbackCount: Number(parsed.rollbackCount) || 0,
        updatedAt: Number(parsed.updatedAt) || Date.now(),
        changeWindowStartedAt: Number(parsed.updatedAt) || Date.now(),
        changesInWindow: 0,
        maxChangesPerWindow: 3,
      };
    }
  } catch { /* safe default */ }
  return null;
}

export async function saveAdaptiveGuardState(db: D1Database, state: AdaptiveGuardState): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO adaptive_guard_state(id,state_json,updated_at) VALUES(1,?1,?2) ' +
    'ON CONFLICT(id) DO UPDATE SET state_json=?1, updated_at=?2',
  ).bind(JSON.stringify(state), state.updatedAt).run();
}


export interface AiModelHealthRow {
  modelId: string; failures: number; successes: number; quarantineUntil: number; updatedAt: number;
}

export async function loadAiModelHealth(db: D1Database): Promise<AiModelHealthRow[]> {
  await ensureSchema(db);
  const res = await db.prepare('SELECT model_id, failures, successes, quarantine_until, updated_at FROM ai_model_health ORDER BY updated_at DESC LIMIT 64').all<{model_id:string;failures:number;successes:number;quarantine_until:number;updated_at:number}>();
  return (res.results ?? []).map(r => ({ modelId:r.model_id, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantine_until, updatedAt:r.updated_at }));
}

export async function saveAiModelHealth(db: D1Database, row: AiModelHealthRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO ai_model_health(model_id,failures,successes,quarantine_until,updated_at) VALUES(?1,?2,?3,?4,?5) ' +
    'ON CONFLICT(model_id) DO UPDATE SET failures=?2, successes=?3, quarantine_until=?4, updated_at=?5',
  ).bind(row.modelId,row.failures,row.successes,row.quarantineUntil,row.updatedAt).run();
}


export interface PolicySignalStateRow {
  stateJson: string;
  updatedAt: number;
}

export async function loadPolicySignalState(db: D1Database): Promise<PolicySignalStateRow | null> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT state_json, updated_at FROM policy_signal_state WHERE id = 1').first<{state_json:string;updated_at:number}>();
  return row ? { stateJson: row.state_json, updatedAt: row.updated_at } : null;
}

export async function savePolicySignalState(db: D1Database, row: PolicySignalStateRow): Promise<void> {
  await ensureSchema(db);
  await db.prepare(
    'INSERT INTO policy_signal_state(id,state_json,updated_at) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET state_json=?1, updated_at=?2',
  ).bind(row.stateJson, row.updatedAt).run();
}
