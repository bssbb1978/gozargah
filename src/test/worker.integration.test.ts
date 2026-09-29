import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import type { D1Database } from '@cloudflare/workers-types';
import { VERSION } from '../config';
import { createUser, getUserByIdFresh, recordUsageDelta } from '../db/users';
import { consumeAiDiagnosticQuota, consumeDnsQueryQuota, loadHealthSamples, loadLatestPathSamples, saveHealthSample } from '../db/store';
import { subTokenFor } from '../subscription';
import { createDiagnostics, getAiModelCandidates, rankCatalogModels } from '../ai/diagnostics';

let mf: Miniflare;
let db: D1Database;
const SECRET = 'test-webhook-secret-should-not-be-used-in-production';
function makeDnsAaaaQuery(): Uint8Array {
  const name = [7, ...new TextEncoder().encode('example'), 3, ...new TextEncoder().encode('com'), 0];
  const out = new Uint8Array(12 + name.length + 4);
  out[0] = 0x12; out[1] = 0x34; out[2] = 1; out[5] = 1;
  out.set(name, 12);
  const qtype = 12 + name.length;
  out[qtype] = 0; out[qtype + 1] = 28; out[qtype + 3] = 1;
  return out;
}
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
          DNS_UPSTREAMS: 'https://doh.test/dns-query',
          DNS64_ENABLED: 'true',
        },
        serviceBindings: { TELEGRAM_API: 'telegram-mock', DNS_UPSTREAM: 'dns-mock' },
      },
      {
        name: 'telegram-mock', script: `export default { async fetch(request) { await request.json(); return Response.json({ ok: true, result: { message_id: 1 } }); } }`,
        modules: true,
      },
      {
        name: 'dns-mock', script: `export default { async fetch(request) {
          const query = new Uint8Array(await request.arrayBuffer());
          const qtype = (query[query.length - 4] << 8) | query[query.length - 3];
          let answer;
          if (qtype === 1) {
            answer = new Uint8Array(query.length + 16);
            answer.set(query);
            answer[6] = 0; answer[7] = 1;
            answer.set([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 203, 0, 113, 7], query.length);
          } else {
            answer = query.slice(); answer[6] = 0; answer[7] = 0;
          }
          answer[2] = 0x81; answer[3] = 0x80;
          return new Response(answer, { headers: { 'content-type': 'application/dns-message' } });
        } }`,
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

  it('forwards authenticated DoH requests and synthesizes RFC 6052 DNS64 records', async () => {
    const user = await createUser(db, { name: 'DNS integration', quotaBytes: 0, expiryAt: 0 });
    const token = await subTokenFor('gozargah.test', user.uuid);
    const endpoint = `https://gozargah.test/sub/${token}/dns-query`;
    const query = makeDnsAaaaQuery();
    const response = await mf.dispatchFetch(endpoint, {
      method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: query,
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/dns-message');
    const answer = new Uint8Array(await response.arrayBuffer());
    expect((answer[6] << 8) | answer[7]).toBe(1);
    expect([...answer.slice(-16)]).toEqual([0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7]);
    const fresh = await getUserByIdFresh(db, user.id);
    expect(fresh?.usedUp).toBe(query.length);
    expect(fresh?.usedDown).toBe(answer.length);

    const encodedQuery = Buffer.from(query).toString('base64url');
    const getResponse = await mf.dispatchFetch(endpoint + '?dns=' + encodedQuery);
    expect(getResponse.status).toBe(200);
    expect(getResponse.headers.get('content-type')).toBe('application/dns-message');
    expect(new Uint8Array(await getResponse.arrayBuffer()).length).toBe(answer.length);

    const options = await mf.dispatchFetch(endpoint, { method: 'OPTIONS' });
    expect(options.status).toBe(204);

    const budgetNow = Date.now() + 10_000;
    expect(await consumeDnsQueryQuota(db, user.id, budgetNow, 2, 1_000)).toBe(true);
    expect(await consumeDnsQueryQuota(db, user.id, budgetNow, 2, 1_000)).toBe(true);
    expect(await consumeDnsQueryQuota(db, user.id, budgetNow, 2, 1_000)).toBe(false);
    expect(await consumeDnsQueryQuota(db, user.id, budgetNow + 1_000, 2, 1_000)).toBe(true);
  });

  it('rejects webhook requests without Telegram secret', async () => {
    const response = await mf.dispatchFetch('https://gozargah.test/_telegram/webhook', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    expect(response.status).toBe(404);
  });

  it('exposes the internal decision view behind panel auth (2.13)', async () => {
    const response = await mf.dispatchFetch('https://gozargah.test/gozargah/api/network/decision');
    expect(response.status).toBe(401);
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
    await db.prepare("INSERT INTO users (id, name, uuid, trojan_pass, created_at) VALUES (99, 'Test user', 'test-uuid', 'test-pass', ?1)")
      .bind(Date.now()).run();

    expect((await send(101, '99')).status).toBe(200);
    const user = await db.prepare('SELECT enabled FROM users WHERE id = 99').first<{ enabled: number }>();
    expect(user?.enabled).toBe(0);
    const cleared = await db.prepare('SELECT chat_id FROM telegram_fsm WHERE chat_id = ?1').bind('42').first();
    expect(cleared).toBeNull();

    // Telegram retries are deduplicated and do not repeat messages or actions.
    const replay = await send(101, '2');
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ duplicate: true });
  });

  it('reads fresh authorization state and atomically records live-session usage', async () => {
    const before = await getUserByIdFresh(db, 99);
    expect(before?.enabled).toBe(false);
    await recordUsageDelta(db, 99, 17, 23);
    const after = await getUserByIdFresh(db, 99);
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
    const admin = await db.prepare('SELECT id, enabled FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1').first<{ id: number; enabled: number }>();
    expect(admin).not.toBeNull();
    const post = (update_id: number, text: string) => mf.dispatchFetch('https://gozargah.test/_telegram/webhook', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-telegram-bot-api-secret-token': SECRET },
      body: JSON.stringify({ update_id, message: { from: { id: 42 }, chat: { id: 42, type: 'private' }, text } }),
    });
    await post(300, '/disable');
    await post(301, String(admin!.id));
    const unchanged = await db.prepare('SELECT enabled FROM users WHERE id = ?1').bind(admin!.id).first<{ enabled: number }>();
    expect(unchanged?.enabled).toBe(1);
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
