/**
 * Gozargah — user model, CRUD, cache and REAL byte accounting.
 *
 * Traffic accounting: every proxied chunk length is counted (up/down) per user,
 * accumulated in-isolate and coalesced into D1 (ZEUS-style write coalescing) —
 * unlike nahan whose "GB" is actually connections/6000.
 */

import { DEFAULTS, ResetCycle, resetCycleMs } from '../config';
import { ensureSchema, invalidateCache } from './store';
import { sha224Hex } from '../utils/sha224';
import { randomHex } from '../utils/crypto';

export interface GzUser {
  id: number;
  name: string;
  uuid: string;
  trojanPass: string;
  quotaBytes: number; // 0 = unlimited
  usedUp: number;
  usedDown: number;
  expiryAt: number; // epoch ms, 0 = never (absolute mode)
  expiryDays: number; // > 0 = days from FIRST connection (first-use mode)
  firstUsedAt: number; // epoch ms of the first allowed proxy connection (0 = not started)
  resetAnchor: number; // rolling quota-reset window anchor (0 = starts with first use)
  enabled: boolean;
  isAdmin: boolean;
  createdAt: number;
  lastSeen: number;
}

interface UserRow {
  id: number; name: string; uuid: string; trojan_pass: string;
  quota_bytes: number; used_up: number; used_down: number;
  expiry_at: number; enabled: number; is_admin: number;
  created_at: number; last_seen: number;
  first_used_at: number; expiry_days: number; reset_anchor: number;
}

function toUser(r: UserRow): GzUser {
  return {
    id: r.id, name: r.name, uuid: r.uuid, trojanPass: r.trojan_pass,
    quotaBytes: r.quota_bytes, usedUp: r.used_up, usedDown: r.used_down,
    expiryAt: r.expiry_at, enabled: r.enabled === 1, isAdmin: r.is_admin === 1,
    createdAt: r.created_at, lastSeen: r.last_seen,
    firstUsedAt: r.first_used_at || 0, expiryDays: r.expiry_days || 0, resetAnchor: r.reset_anchor || 0,
  };
}

/* ------------------------------ cache ------------------------------ */

let listCache: { at: number; promise: Promise<GzUser[]> } | null = null;

export function invalidateUsers(): void {
  listCache = null;
}

export async function listUsersFresh(db: D1Database): Promise<GzUser[]> {
  await ensureSchema(db);
  const res = await db.prepare('SELECT * FROM users ORDER BY is_admin DESC, id ASC').all<UserRow>();
  return (res.results ?? []).map(toUser);
}

export function listUsers(db: D1Database): Promise<GzUser[]> {
  if (listCache && Date.now() - listCache.at < DEFAULTS.cacheTtlMs) return listCache.promise;
  const p = listUsersFresh(db);
  listCache = { at: Date.now(), promise: p };
  p.catch(() => { listCache = null; });
  return p;
}

export async function getUserByUuid(db: D1Database, uuid: string): Promise<GzUser | null> {
  const users = await listUsers(db);
  return users.find((u) => u.uuid === uuid) ?? null;
}

/** Uncached lookup for live-session revocation and quota supervision. */
export async function getUserByIdFresh(db: D1Database, id: number): Promise<GzUser | null> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT * FROM users WHERE id = ?1').bind(id).first<UserRow>();
  return row ? toUser(row) : null;
}

export interface SubscriptionRouteKey {
  userId: number;
  dynamicPrefix: string;
  routeKey: string;
  createdAt: number;
}

const ROUTE_AUTH_TTL_MS = 30_000;
const ROUTE_AUTH_CACHE_MAX = 2048;
interface RouteAuthCacheEntry { user: GzUser; expiresAt: number; }
const routeAuthCache = new Map<string, RouteAuthCacheEntry>();

function routeAuthCacheRequest(key: string): Request {
  return new Request('https://route-cache.gozargah.invalid/' + key, { method: 'GET' });
}

async function routeAuthCacheKey(dynamicPrefix: string, routeKey: string): Promise<string> {
  const input = new TextEncoder().encode(dynamicPrefix + ':' + routeKey);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Get or lazily provision a user's random opaque route. The D1 row is the
 * source of truth; raw route keys are bearer credentials and are never logged.
 */
export async function getOrCreateSubscriptionRoute(db: D1Database, userId: number): Promise<SubscriptionRouteKey> {
  await ensureSchema(db);
  const existing = await db.prepare(
    'SELECT user_id,dynamic_prefix,route_key,created_at FROM subscription_route_keys WHERE user_id=?1',
  ).bind(userId).first<{ user_id: number; dynamic_prefix: string; route_key: string; created_at: number }>();
  if (existing) return { userId: existing.user_id, dynamicPrefix: existing.dynamic_prefix, routeKey: existing.route_key, createdAt: existing.created_at };

  for (let attempt = 0; attempt < 3; attempt++) {
    const candidate = { dynamicPrefix: 'p-' + randomHex(12), routeKey: randomHex(32), createdAt: Date.now() };
    try {
      await db.prepare(
        'INSERT INTO subscription_route_keys(user_id,dynamic_prefix,route_key,created_at) VALUES(?1,?2,?3,?4)',
      ).bind(userId, candidate.dynamicPrefix, candidate.routeKey, candidate.createdAt).run();
    } catch {
      // Concurrent first access or an extraordinarily unlikely collision; re-read below.
    }
    const row = await db.prepare(
      'SELECT user_id,dynamic_prefix,route_key,created_at FROM subscription_route_keys WHERE user_id=?1',
    ).bind(userId).first<{ user_id: number; dynamic_prefix: string; route_key: string; created_at: number }>();
    if (row) return { userId: row.user_id, dynamicPrefix: row.dynamic_prefix, routeKey: row.route_key, createdAt: row.created_at };
  }
  throw new Error('unable to provision subscription route');
}

/**
 * Resolve a per-user route using isolate RAM -> per-data-center Cache API -> D1.
 * Positive auth results are cached for at most 30 seconds by explicit policy;
 * a disable, expiry, quota change, or key revocation may take that long to
 * reach a warm cache. Unknown routes are never cached.
 */
export async function findUserBySubscriptionRoute(db: D1Database, dynamicPrefix: string, routeKey: string): Promise<GzUser | null> {
  if (!/^p-[0-9a-f]{24}$/.test(dynamicPrefix) || !/^[0-9a-f]{64}$/.test(routeKey)) return null;
  const key = await routeAuthCacheKey(dynamicPrefix, routeKey);
  const now = Date.now();
  const local = routeAuthCache.get(key);
  if (local && local.expiresAt > now) {
    routeAuthCache.delete(key);
    routeAuthCache.set(key, local);
    return local.user;
  }
  if (local) routeAuthCache.delete(key);

  const cacheRequest = routeAuthCacheRequest(key);
  try {
    if (typeof caches !== 'undefined' && caches.default) {
      const cached = await caches.default.match(cacheRequest);
      if (cached) {
        const body = await cached.json() as { user?: GzUser; expiresAt?: number };
        if (body.user && Number(body.expiresAt) > now) {
          rememberRouteUser(key, body.user, Number(body.expiresAt));
          return body.user;
        }
        await caches.default.delete(cacheRequest);
      }
    }
  } catch { /* Cache API is an optimization; D1 remains authoritative on misses. */ }

  await ensureSchema(db);
  const row = await db.prepare(
    'SELECT u.* FROM subscription_route_keys r JOIN users u ON u.id=r.user_id ' +
    'WHERE r.dynamic_prefix=?1 AND r.route_key=?2 LIMIT 1',
  ).bind(dynamicPrefix, routeKey).first<UserRow>();
  if (!row) return null;
  const user = toUser(row);
  const expiresAt = now + ROUTE_AUTH_TTL_MS;
  rememberRouteUser(key, user, expiresAt);
  try {
    if (typeof caches !== 'undefined' && caches.default) {
      await caches.default.put(cacheRequest, new Response(JSON.stringify({ user, expiresAt }), {
        headers: { 'content-type': 'application/json', 'cache-control': 'max-age=30' },
      }));
    }
  } catch { /* Cache API limits/evictions must never break subscription delivery. */ }
  return user;
}

function rememberRouteUser(key: string, user: GzUser, expiresAt: number): void {
  routeAuthCache.delete(key);
  routeAuthCache.set(key, { user, expiresAt });
  while (routeAuthCache.size > ROUTE_AUTH_CACHE_MAX) {
    const oldest = routeAuthCache.keys().next().value;
    if (oldest === undefined) break;
    routeAuthCache.delete(oldest);
  }
}

/** Test helper: clear only this isolate's RAM cache. */
export function clearSubscriptionRouteCacheForTests(): void {
  routeAuthCache.clear();
}

/** Persist one session's usage delta atomically so live quota checks see it. */
export async function recordUsageDelta(db: D1Database, id: number, up: number, down: number): Promise<void> {
  const sent = Math.max(0, Math.floor(up));
  const received = Math.max(0, Math.floor(down));
  if (sent === 0 && received === 0) return;
  await ensureSchema(db);
  await db.prepare('UPDATE users SET used_up = used_up + ?1, used_down = used_down + ?2 WHERE id = ?3')
    .bind(sent, received, id).run();
  invalidateUsers();
}

export async function getAdminUser(db: D1Database): Promise<GzUser | null> {
  await ensureSchema(db);
  const row = await db.prepare('SELECT * FROM users WHERE is_admin = 1 ORDER BY id ASC LIMIT 1').first<UserRow>();
  return row ? toUser(row) : null;
}

/** Trojan clients send sha224(password) on the wire — match against users. */
export async function findUserByTrojanHash(db: D1Database, hashHex: string): Promise<GzUser | null> {
  const users = await listUsers(db);
  for (const u of users) {
    if ((await sha224Hex(u.trojanPass)) === hashHex) return u;
  }
  return null;
}

/**
 * Effective expiry (epoch ms, 0 = none):
 *  - expiryDays > 0 (first-use mode): clock starts at the FIRST allowed connection
 *    — a user who never connected has no expiry yet ("not started")
 *  - otherwise: absolute expiryAt
 */
export function effectiveExpiry(u: Pick<GzUser, 'expiryAt' | 'expiryDays' | 'firstUsedAt'>, now = Date.now()): number {
  if (u.expiryDays > 0) {
    if (!u.firstUsedAt) return 0; // not started — nothing expired
    return u.firstUsedAt + u.expiryDays * 86_400_000;
  }
  return u.expiryAt || 0;
}

/** True when the rolling quota-reset window has elapsed since the anchor. */
export function resetDue(u: Pick<GzUser, 'resetAnchor' | 'firstUsedAt' | 'createdAt'>, cycle: ResetCycle, now = Date.now()): boolean {
  const win = resetCycleMs(cycle);
  if (!win) return false;
  const anchor = u.resetAnchor || u.firstUsedAt || u.createdAt || 0;
  if (!anchor) return false;
  return now >= anchor + win;
}

export function isUserAllowed(u: GzUser, now = Date.now()): { ok: boolean; reason: string } {
  if (!u.enabled) return { ok: false, reason: 'disabled' };
  const exp = effectiveExpiry(u, now);
  if (exp && now > exp) return { ok: false, reason: 'expired' };
  if (u.quotaBytes && u.usedUp + u.usedDown >= u.quotaBytes) return { ok: false, reason: 'quota' };
  return { ok: true, reason: '' };
}

/**
 * Lazy per-user maintenance (fire-and-forget from data/sub/status paths):
 *  1. stamp first_used_at on the very first allowed connection
 *  2. roll the quota-reset window when due (zero counters, move the anchor)
 * Cheap by design: one conditional UPDATE, no cron worker needed.
 */
export async function lazyMaintenance(db: D1Database, u: GzUser, cycle: ResetCycle): Promise<void> {
  if (!db || u.id <= 0) return;
  const now = Date.now();
  const sets: string[] = ['last_seen = ?1'];
  const vals: Array<string | number> = [now];
  let n = 2;
  if (!u.firstUsedAt) {
    sets.push('first_used_at = ?' + n);
    vals.push(now);
    n++;
    if (!u.resetAnchor && cycle !== 'none') {
      sets.push('reset_anchor = ?' + n);
      vals.push(now);
      n++;
    }
  }
  if (resetDue(u, cycle, now)) {
    sets.push('used_up = 0', 'used_down = 0');
    sets.push('reset_anchor = ?' + n);
    vals.push(now);
    n++;
  }
  try {
    await db.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?' + n + ' AND is_admin = 0').bind(...vals, u.id).run();
    invalidateUsers();
  } catch { /* maintenance must never break the data path */ }
}

/* ------------------------------ CRUD ------------------------------ */

export interface UserAuditMutation {
  actorUserId: number;
  action: 'user_created' | 'user_updated' | 'user_enabled' | 'user_disabled' | 'user_deleted';
  details: Record<string, unknown>;
  at?: number;
}

function auditDetailsJson(audit: UserAuditMutation): string {
  const encoded = JSON.stringify(audit.details);
  if (encoded.length > 4096) throw new Error('user audit details exceed the size limit');
  return encoded;
}

function auditForExistingUser(db: D1Database, id: number, audit: UserAuditMutation): D1PreparedStatement {
  return db.prepare(
    'INSERT INTO user_control_audit(actor_user_id,target_user_id,action,details_json,created_at) ' +
    'SELECT ?1,id,?3,?4,?5 FROM users WHERE id=?2 AND is_admin=0',
  ).bind(audit.actorUserId, id, audit.action, auditDetailsJson(audit), audit.at ?? Date.now());
}

export interface NewUser { name: string; quotaBytes: number; expiryAt: number; expiryDays?: number; isAdmin?: boolean; uuid?: string; trojanPass?: string; }

export async function createUser(db: D1Database, data: NewUser, audit?: UserAuditMutation): Promise<GzUser> {
  await ensureSchema(db);
  const now = Date.now();
  const uuid = data.uuid ?? crypto.randomUUID();
  const trojanPass = data.trojanPass ?? randomPass();
  const insert = db
    .prepare(
      'INSERT INTO users (name, uuid, trojan_pass, quota_bytes, expiry_at, expiry_days, enabled, is_admin, created_at) ' +
      'VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)',
    )
    .bind(
      data.name,
      uuid,
      trojanPass,
      Math.max(0, Math.floor(data.quotaBytes)),
      Math.max(0, Math.floor(data.expiryAt)),
      Math.max(0, Math.floor(data.expiryDays ?? 0)),
      data.isAdmin ? 1 : 0,
      now,
    );
  const res = audit
    ? (await db.batch([
        insert,
        db.prepare(
          'INSERT INTO user_control_audit(actor_user_id,target_user_id,action,details_json,created_at) ' +
          'SELECT ?1,id,?3,?4,?5 FROM users WHERE uuid=?2 AND is_admin=0',
        ).bind(audit.actorUserId, uuid, audit.action, auditDetailsJson(audit), audit.at ?? now),
      ]))[0]
    : await insert.run();
  invalidateUsers();
  const id = res.meta.last_row_id as number;
  await getOrCreateSubscriptionRoute(db, id);
  return {
    id, name: data.name, uuid, trojanPass,
    quotaBytes: data.quotaBytes, usedUp: 0, usedDown: 0, expiryAt: data.expiryAt,
    expiryDays: Math.max(0, Math.floor(data.expiryDays ?? 0)),
    firstUsedAt: 0, resetAnchor: 0,
    enabled: true, isAdmin: !!data.isAdmin, createdAt: now, lastSeen: 0,
  };
}

export interface UserPatch {
  name?: string; quotaBytes?: number; expiryAt?: number; expiryDays?: number; enabled?: boolean;
  usedUp?: number; usedDown?: number; uuid?: string; trojanPass?: string; resetUsage?: boolean;
}

export async function updateUser(db: D1Database, id: number, patch: UserPatch, audit?: UserAuditMutation): Promise<void> {
  await ensureSchema(db);
  const sets: string[] = [];
  const vals: Array<string | number> = [];
  if (patch.name !== undefined) { sets.push('name = ?' + (sets.length + 1)); vals.push(patch.name); }
  if (patch.quotaBytes !== undefined) { sets.push('quota_bytes = ?' + (sets.length + 1)); vals.push(Math.max(0, Math.floor(patch.quotaBytes))); }
  if (patch.expiryAt !== undefined) { sets.push('expiry_at = ?' + (sets.length + 1)); vals.push(Math.max(0, Math.floor(patch.expiryAt))); }
  if (patch.enabled !== undefined) { sets.push('enabled = ?' + (sets.length + 1)); vals.push(patch.enabled ? 1 : 0); }
  if (patch.usedUp !== undefined) { sets.push('used_up = ?' + (sets.length + 1)); vals.push(Math.max(0, Math.floor(patch.usedUp))); }
  if (patch.usedDown !== undefined) { sets.push('used_down = ?' + (sets.length + 1)); vals.push(Math.max(0, Math.floor(patch.usedDown))); }
  if (patch.expiryDays !== undefined) { sets.push('expiry_days = ?' + (sets.length + 1)); vals.push(Math.max(0, Math.floor(patch.expiryDays))); }
  if (patch.resetUsage) {
    // manual reset also re-anchors the rolling reset window
    sets.push('used_up = 0', 'used_down = 0');
    sets.push('reset_anchor = ?' + (sets.length + 1));
    vals.push(Date.now());
  }
  if (patch.uuid !== undefined) { sets.push('uuid = ?' + (sets.length + 1)); vals.push(patch.uuid); }
  if (patch.trojanPass !== undefined) { sets.push('trojan_pass = ?' + (sets.length + 1)); vals.push(patch.trojanPass); }
  if (!sets.length) return;
  vals.push(id);
  const update = db.prepare('UPDATE users SET ' + sets.join(', ') + ' WHERE id = ?' + (sets.length + 1) + ' AND is_admin = 0').bind(...vals);
  if (audit) {
    const results = await db.batch([auditForExistingUser(db, id, audit), update]);
    if (results[1].meta.changes === 0) return;
  } else {
    await update.run();
  }
  invalidateUsers();
}

export async function deleteUser(db: D1Database, id: number, audit?: UserAuditMutation): Promise<void> {
  await ensureSchema(db);
  const deletion = db.prepare('DELETE FROM users WHERE id = ?1 AND is_admin = 0').bind(id);
  if (audit) await db.batch([auditForExistingUser(db, id, audit), deletion]);
  else await deletion.run();
  invalidateUsers();
}

function randomPass(): string {
  const b = crypto.getRandomValues(new Uint8Array(12));
  let s = '';
  for (const v of b) s += v.toString(16).padStart(2, '0');
  return s;
}

/* ------------------------------ usage coalescing ------------------------------ */

const pendingUsage = new Map<number, { up: number; down: number; lastSeen: number }>();
let lastFlush = Date.now();

export function queueUsage(userId: number, up: number, down: number): void {
  const cur = pendingUsage.get(userId) ?? { up: 0, down: 0, lastSeen: 0 };
  cur.up += up;
  cur.down += down;
  cur.lastSeen = Date.now();
  pendingUsage.set(userId, cur);
}

function pendingTotals(): { bytes: number; users: number } {
  let bytes = 0;
  for (const v of pendingUsage.values()) bytes += v.up + v.down;
  return { bytes, users: pendingUsage.size };
}

/** Flush coalesced counters to D1 when thresholds are crossed (called at WS close). */
export async function maybeFlushUsage(db: D1Database): Promise<void> {
  const t = pendingTotals();
  const due = t.users > 0 && (
    t.bytes >= DEFAULTS.usageFlushBytes ||
    t.users >= DEFAULTS.usageFlushUsers ||
    Date.now() - lastFlush >= DEFAULTS.usageFlushIntervalMs
  );
  if (!due) return;
  await flushUsage(db);
}

export async function flushUsage(db: D1Database): Promise<void> {
  if (pendingUsage.size === 0) return;
  const batch: D1PreparedStatement[] = [];
  const now = Date.now();
  for (const [id, v] of pendingUsage) {
    batch.push(
      db.prepare(
        'UPDATE users SET used_up = used_up + ?1, used_down = used_down + ?2, last_seen = ?3 WHERE id = ?4',
      ).bind(v.up, v.down, now, id),
    );
  }
  pendingUsage.clear();
  lastFlush = now;
  try {
    await db.batch(batch);
    invalidateUsers();
  } catch {
    /* counters stay in memory; next flush retries */
  }
}
