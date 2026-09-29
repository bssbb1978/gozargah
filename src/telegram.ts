/** Optional, allowlisted Telegram administration with D1-backed conversation state. */
import type { Env } from './config';
import { addEvent, consumeUserControlQuota, ensureSchema } from './db/store';
import { getAdminUser, updateUser } from './db/users';
import { sha256Hex } from './utils/crypto';

interface TelegramMessage {
  message_id?: number;
  text?: string;
  from?: { id?: number };
  chat?: { id?: number; type?: string };
}
interface TelegramUpdate { update_id?: number; message?: TelegramMessage; }
interface TelegramState { state: 'awaiting_disable_id' | 'awaiting_enable_id'; updated_at: number; }

const MAX_UPDATE_BYTES = 64 * 1024;
const FSM_TTL_MS = 15 * 60_000;

/** Webhook endpoint. The secret header is the primary gate; sender IDs are a second gate. */
export async function handleTelegramWebhook(request: Request, env: Env): Promise<Response> {
  const secret = env.TELEGRAM_WEBHOOK_SECRET;
  const token = env.TELEGRAM_BOT_TOKEN;
  const db = env.GZ_DB;
  if (!secret || !token || !db) return json({ error: 'telegram_not_configured' }, 503);
  if (!safeEqual(request.headers.get('x-telegram-bot-api-secret-token') ?? '', secret)) {
    return json({ error: 'not_found' }, 404);
  }
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  if ((request.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    return json({ error: 'unsupported_media_type' }, 415);
  }
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > MAX_UPDATE_BYTES) return json({ error: 'payload_too_large' }, 413);
  const bytes = await readLimitedBody(request, MAX_UPDATE_BYTES);
  if (!bytes) return json({ error: 'payload_too_large' }, 413);
  let update: TelegramUpdate;
  try { update = JSON.parse(new TextDecoder().decode(bytes)) as TelegramUpdate; }
  catch { return json({ error: 'invalid_json' }, 400); }
  const message = update.message;
  const senderId = message?.from?.id;
  const chatId = message?.chat?.id;
  const adminIds = parseAdminIds(env.TELEGRAM_ADMIN_IDS);
  // Bot controls only operate in a private chat with an explicitly allowlisted sender.
  if (!Number.isSafeInteger(senderId) || !Number.isSafeInteger(chatId) || senderId !== chatId || message?.chat?.type !== 'private' || !adminIds.has(senderId!)) {
    return json({ ok: true });
  }
  if (!Number.isSafeInteger(update.update_id) || update.update_id! < 0) return json({ error: 'invalid_update' }, 400);

  try {
    await ensureSchema(db);
    const inserted = await db.prepare('INSERT OR IGNORE INTO telegram_updates (update_id, processed_at) VALUES (?1, ?2)')
      .bind(update.update_id!, Date.now()).run();
    if (inserted.meta.changes !== 1) return json({ ok: true, duplicate: true });
    const actorKey = await sha256Hex('telegram-admin:' + senderId);
    if (!(await consumeUserControlQuota(db, actorKey))) {
      // Keep the dedupe marker: retries of a throttled update must not apply later.
      await db.prepare('DELETE FROM telegram_updates WHERE processed_at < ?1').bind(Date.now() - 7 * 86_400_000).run();
      return json({ ok: true, rateLimited: true });
    }
    await processMessage(db, env, token, chatId!, message?.text ?? '');
    // Telegram retries should not make the update execute a second time.
    await db.prepare('DELETE FROM telegram_updates WHERE processed_at < ?1').bind(Date.now() - 7 * 86_400_000).run();
    return json({ ok: true });
  } catch {
    // Remove the dedupe marker so Telegram's retry can recover from transient D1 errors.
    await db.prepare('DELETE FROM telegram_updates WHERE update_id = ?1').bind(update.update_id!).run().catch(() => undefined);
    return json({ error: 'telegram_processing_failed' }, 500);
  }
}

async function processMessage(db: D1Database, env: Env, token: string, chatId: number, rawText: string): Promise<void> {
  const text = rawText.trim().slice(0, 256);
  if (!text) return;
  const cmd = text.match(/^\/(start|help|status|users|disable|enable|cancel)(?:@[a-z0-9_]+)?(?:\s+.*)?$/i);
  const now = Date.now();
  const state = await db.prepare('SELECT state, updated_at FROM telegram_fsm WHERE chat_id = ?1').bind(String(chatId)).first<TelegramState>();
  if (state && now - state.updated_at > FSM_TTL_MS) {
    await db.prepare('DELETE FROM telegram_fsm WHERE chat_id = ?1').bind(String(chatId)).run();
  }
  if (!cmd) {
    if (state && now - state.updated_at <= FSM_TTL_MS) {
      const id = Number(text);
      if (!Number.isSafeInteger(id) || id <= 0) {
        await sendTelegram(env, token, chatId, 'شناسه باید یک عدد صحیح مثبت باشد. /cancel برای لغو.');
        return;
      }
      const row = await db.prepare('SELECT id, name, is_admin FROM users WHERE id = ?1').bind(id)
        .first<{ id: number; name: string; is_admin: number }>();
      if (!row || row.is_admin === 1) {
        await sendTelegram(env, token, chatId, 'کاربر پیدا نشد یا این حساب مدیریتی است.');
        return;
      }
      const enabled = state.state === 'awaiting_enable_id';
      const admin = await getAdminUser(db);
      if (!admin?.isAdmin) throw new Error('admin account unavailable');
      await updateUser(db, id, { enabled }, {
        actorUserId: admin.id,
        action: enabled ? 'user_enabled' : 'user_disabled',
        details: { enabled, actorChannel: 'telegram', actorTelegramId: chatId },
      });
      await db.prepare('DELETE FROM telegram_fsm WHERE chat_id = ?1').bind(String(chatId)).run();
      await addEvent(db, enabled ? 'telegram_user_enabled' : 'telegram_user_disabled', 'id=' + id);
      await sendTelegram(env, token, chatId, `کاربر ${row.name} (#${id}) ${enabled ? 'فعال' : 'غیرفعال'} شد.`);
    }
    return;
  }

  const command = cmd[1].toLowerCase();
  if (command === 'cancel') {
    await db.prepare('DELETE FROM telegram_fsm WHERE chat_id = ?1').bind(String(chatId)).run();
    await sendTelegram(env, token, chatId, 'عملیات لغو شد.');
    return;
  }
  if (command === 'start' || command === 'help') {
    await sendTelegram(env, token, chatId, 'مدیریت گذرگاه\n/status وضعیت کاربران\n/users فهرست کاربران\n/disable غیرفعال‌سازی با شناسه\n/enable فعال‌سازی با شناسه\n/cancel لغو عملیات');
    return;
  }
  if (command === 'status') {
    const counts = await db.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN enabled = 1 AND is_admin = 0 THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN enabled = 0 AND is_admin = 0 THEN 1 ELSE 0 END) AS disabled FROM users').first<{ total: number; active: number; disabled: number }>();
    await sendTelegram(env, token, chatId, `وضعیت\nکل حساب‌ها: ${counts?.total ?? 0}\nکاربران فعال: ${counts?.active ?? 0}\nکاربران غیرفعال: ${counts?.disabled ?? 0}`);
    return;
  }
  if (command === 'users') {
    const rows = await db.prepare('SELECT id, name, enabled FROM users WHERE is_admin = 0 ORDER BY id DESC LIMIT 20').all<{ id: number; name: string; enabled: number }>();
    const lines = (rows.results ?? []).map((u) => `#${u.id} ${u.name} — ${u.enabled ? 'فعال' : 'غیرفعال'}`);
    await sendTelegram(env, token, chatId, lines.length ? lines.join('\n') : 'کاربری ثبت نشده است.');
    return;
  }
  if (command === 'enable' || command === 'disable') {
    const stateName = command === 'enable' ? 'awaiting_enable_id' : 'awaiting_disable_id';
    await db.prepare('INSERT INTO telegram_fsm (chat_id, state, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(chat_id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at')
      .bind(String(chatId), stateName, now).run();
    await sendTelegram(env, token, chatId, `شناسهٔ کاربر برای ${command === 'enable' ? 'فعال‌سازی' : 'غیرفعال‌سازی'} را بفرستید. /cancel برای لغو.`);
  }
}

async function sendTelegram(env: Env, token: string, chatId: number, text: string): Promise<void> {
  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const init: RequestInit = {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text }),
  };
  const response = env.TELEGRAM_API ? await env.TELEGRAM_API.fetch(url, init) : await fetch(url, init);
  if (!response.ok) throw new Error('telegram_send_failed');
  const result = await response.json() as { ok?: boolean };
  if (result.ok !== true) throw new Error('telegram_send_failed');
}

async function readLimitedBody(request: Request, limit: number): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}

function parseAdminIds(value?: string): Set<number> {
  return new Set((value ?? '').split(',').map((part) => Number(part.trim())).filter((n) => Number.isSafeInteger(n) && n > 0));
}
function safeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const x = enc.encode(a), y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
}
