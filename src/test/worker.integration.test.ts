import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import type { D1Database } from '@cloudflare/workers-types';
import { VERSION } from '../config';
import { getUserByIdFresh, recordUsageDelta } from '../db/users';
import { consumeAiDiagnosticQuota, loadHealthSamples, loadLatestPathSamples, saveHealthSample } from '../db/store';
import { createDiagnostics, getAiModelCandidates, rankCatalogModels } from '../ai/diagnostics';

let mf: Miniflare;
let db: D1Database;
const SECRET = 'test-webhook-secret-should-not-be-used-in-production';
beforeAll(async () => {
  const bundled = await build({
    entryPoints: ['src/index.ts'], bundle: true, format: 'esm', platform: 'browser',
    target: 'es2022', write: false, logLevel: 'silent', external: ['cloudflare:sockets'],
  });
  mf = new Miniflare({
    workers: [
      {
        name: 'gozargah-test', script: bundled.outputFiles[0].text, modules: true,
        compatibilityDate: '2025-01-15', compatibilityFlags: ['nodejs_compat'],
        d1Databases: ['GZ_DB'],
        bindings: {
          TELEGRAM_BOT_TOKEN: '123456:test-token', TELEGRAM_WEBHOOK_SECRET: SECRET,
          TELEGRAM_ADMIN_IDS: '42',
        },
        serviceBindings: { TELEGRAM_API: 'telegram-mock' },
      },
      {
        name: 'telegram-mock', script: `export default { async fetch(request) { await request.json(); return Response.json({ ok: true, result: { message_id: 1 } }); } }`,
        modules: true,
      },
    ],
  });
  db = await mf.getD1Database('GZ_DB', 'gozargah-test');
});

afterAll(async () => { await mf?.dispose(); });

describe('Cloudflare Worker + D1 integration', () => {
  it('serves health without initializing admin state', async () => {
    const response = await mf.dispatchFetch('https://gozargah.test/healthz');
    expect(response.status).toBe(200);
    // Compare with the shared constant, not a literal, so version bumps can't leave this test stale.
    expect(await response.json()).toMatchObject({ ok: true, version: VERSION });
  });

  it('rejects webhook requests without Telegram secret', async () => {
    const response = await mf.dispatchFetch('https://gozargah.test/_telegram/webhook', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    expect(response.status).toBe(404);
  });

  it('persists FSM state and applies allowlisted per-user disable in D1', async () => {
    const send = async (update_id: number, text: string) => mf.dispatchFetch('https://gozargah.test/_telegram/webhook', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-telegram-bot-api-secret-token': SECRET },
      body: JSON.stringify({ update_id, message: { from: { id: 42 }, chat: { id: 42, type: 'private' }, text } }),
    });

    expect((await send(100, '/disable')).status).toBe(200);
    const pending = await db.prepare('SELECT state FROM telegram_fsm WHERE chat_id = ?1').bind('42').first<{ state: string }>();
    expect(pending?.state).toBe('awaiting_disable_id');
    await db.prepare("INSERT INTO users (id, name, uuid, trojan_pass, created_at) VALUES (2, 'Test user', 'test-uuid', 'test-pass', ?1)")
      .bind(Date.now()).run();

    expect((await send(101, '2')).status).toBe(200);
    const user = await db.prepare('SELECT enabled FROM users WHERE id = 2').first<{ enabled: number }>();
    expect(user?.enabled).toBe(0);
    const cleared = await db.prepare('SELECT chat_id FROM telegram_fsm WHERE chat_id = ?1').bind('42').first();
    expect(cleared).toBeNull();

    // Telegram retries are deduplicated and do not repeat messages or actions.
    const replay = await send(101, '2');
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ duplicate: true });
  });

  it('reads fresh authorization state and atomically records live-session usage', async () => {
    const before = await getUserByIdFresh(db, 2);
    expect(before?.enabled).toBe(false);
    await recordUsageDelta(db, 2, 17, 23);
    const after = await getUserByIdFresh(db, 2);
    expect(after?.usedUp).toBe((before?.usedUp ?? 0) + 17);
    expect(after?.usedDown).toBe((before?.usedDown ?? 0) + 23);
  });

  it('ignores non-allowlisted senders and group chats', async () => {
    const post = (update: unknown) => mf.dispatchFetch('https://gozargah.test/_telegram/webhook', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-telegram-bot-api-secret-token': SECRET },
      body: JSON.stringify(update),
    });
    expect((await post({ update_id: 200, message: { from: { id: 99 }, chat: { id: 99, type: 'private' }, text: '/disable' } })).status).toBe(200);
    expect((await post({ update_id: 201, message: { from: { id: 42 }, chat: { id: -10042, type: 'group' }, text: '/disable' } })).status).toBe(200);
    const rows = await db.prepare('SELECT COUNT(*) AS n FROM telegram_fsm').first<{ n: number }>();
    expect(rows?.n).toBe(0);
  });

  it('never permits the FSM to disable the admin account', async () => {
    await db.prepare("INSERT INTO users (id, name, uuid, trojan_pass, is_admin, created_at) VALUES (1, 'admin', 'admin-uuid', 'admin-pass', 1, ?1)")
      .bind(Date.now()).run();
    const post = (update_id: number, text: string) => mf.dispatchFetch('https://gozargah.test/_telegram/webhook', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-telegram-bot-api-secret-token': SECRET },
      body: JSON.stringify({ update_id, message: { from: { id: 42 }, chat: { id: 42, type: 'private' }, text } }),
    });
    await post(300, '/disable');
    await post(301, '1');
    const admin = await db.prepare('SELECT enabled FROM users WHERE id = 1').first<{ enabled: number }>();
    expect(admin?.enabled).toBe(1);
  });

  it('keeps probe-source telemetry bounded and loads latest samples per source without schema migration', async () => {
    const subjectId = 'telemetry-test.example';
    await saveHealthSample(db, { kind: 'path_tcp', subjectId, ts: 1_800_000_000_001, ok: false, latencyMs: 900 });
    await saveHealthSample(db, { kind: 'path_tcp', subjectId, ts: 1_800_000_000_002, ok: true, latencyMs: 80 });
    await saveHealthSample(db, { kind: 'path_https', subjectId, ts: 1_800_000_000_003, ok: false, latencyMs: 120 });
    const latest = await loadLatestPathSamples(db, [subjectId]);
    expect(latest).toHaveLength(2);
    expect(latest.find((row) => row.kind === 'path_tcp')).toMatchObject({ ts: 1_800_000_000_002, ok: true, latencyMs: 80 });
    expect(latest.find((row) => row.kind === 'path_https')).toMatchObject({ ts: 1_800_000_000_003, ok: false });
    const history = await loadHealthSamples(db, 'path', subjectId, 10);
    expect(history).toHaveLength(3);
    expect(history.map((row) => row.ts)).toEqual([1_800_000_000_001, 1_800_000_000_002, 1_800_000_000_003]);
    expect(await loadLatestPathSamples(db, [])).toEqual([]);
  });

  it('falls back to an on-Worker deterministic advisor when AI is not bound', async () => {
    const result = await createDiagnostics({ GZ_DB: db }, 'fa');
    expect(result.ai).toBe(false);
    expect(result.text).toContain('عیب‌یابی محلیِ قاعده‌محور');
    expect(result.text).toContain('بدون فراخوانی بیرونی');
  });

  it('enforces an atomic D1-backed budget for AI analysis', async () => {
    const now = 1_800_000_000_000;
    for (let i = 0; i < 5; i++) expect(await consumeAiDiagnosticQuota(db, 'test-ip-hash', now)).toBe(true);
    expect(await consumeAiDiagnosticQuota(db, 'test-ip-hash', now)).toBe(false);
    expect(await consumeAiDiagnosticQuota(db, 'test-ip-hash', now + 10 * 60_000)).toBe(true);
  });

  it('tries configured Workers AI models in priority order and sends aggregate data only', async () => {
    expect(getAiModelCandidates(' @cf/example/new , invalid url, @cf/example/backup ')).toEqual([
      '@cf/example/new', '@cf/example/backup',
    ]);
    expect(rankCatalogModels({ result: [
      { id: '@cf/example/older', task: 'Text Generation', updated_at: '2025-01-01' },
      { id: '@cf/example/newer', task: 'Text Generation', updated_at: '2026-08-01' },
      { id: '@cf/example/image', task: 'Image Classification', updated_at: '2026-09-01' },
      { id: '@other/vendor/model', task: 'Text Generation', updated_at: '2026-09-02' },
    ] })).toEqual(['@cf/example/newer', '@cf/example/older']);
    const captured: string[] = [];
    const result = await createDiagnostics({
      GZ_DB: db,
      AI_MODELS: '@cf/example/unavailable,@cf/example/working',
      AI: { run: async (model, input) => {
        captured.push(JSON.stringify(input));
        if (model.endsWith('unavailable')) throw new Error('model disabled');
        return { response: 'پیشنهاد: وضعیت سهمیه‌ها را بازبینی کنید.' };
      } },
    }, 'fa');
    expect(result).toMatchObject({ ai: true, model: '@cf/example/working' });
    expect(captured).toHaveLength(2);
    expect(captured.join('')).not.toContain('Test user');
    expect(captured.join('')).not.toContain('admin-uuid');
    expect(captured.join('')).not.toContain('test-pass');
  });

  it('discovers fresh Cloudflare text models without exposing the catalog token', async () => {
    const requests: Array<{ url: string; authorization: string }> = [];
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push({ url: String(input), authorization: new Headers(init?.headers).get('authorization') || '' });
      return Response.json({ success: true, result: [
        { id: '@cf/test/older', task: 'Text Generation', updated_at: '2025-01-01' },
        { id: '@cf/test/newest', task: 'Text Generation', updated_at: '2026-08-01' },
      ] });
    });
    try {
      const result = await createDiagnostics({
        GZ_DB: db,
        AI_CATALOG_ACCOUNT_ID: '11111111111111111111111111111111',
        AI_CATALOG_API_TOKEN: 'test-catalog-token-value',
        AI: { run: async (model) => ({ response: model }) },
      }, 'en');
      expect(result.model).toBe('@cf/test/newest');
      expect(requests).toHaveLength(1);
      expect(requests[0].url).toContain('https://api.cloudflare.com/client/v4/accounts/');
      expect(requests[0].authorization).toBe('Bearer test-catalog-token-value');
      expect(JSON.stringify(result)).not.toContain('test-catalog-token-value');
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('protects the AI diagnostic endpoint behind panel authentication', async () => {
    const response = await mf.dispatchFetch('https://gozargah.test/gozargah/api/ai/diagnostics', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ language: 'fa' }),
    });
    expect(response.status).toBe(401);
  });
});
