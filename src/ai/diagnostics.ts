/**
 * Privacy-conscious, read-only operations advisor powered by the optional
 * Cloudflare Workers AI binding. It receives aggregate counters only: never
 * user names, credentials, subscription URLs, IPs, or proxy traffic.
 */
import { Env, VERSION } from '../config';
import { listUsers } from '../db/users';
import { loadSettings } from '../db/store';

export interface AiBinding {
  run(model: string, input: {
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    max_tokens?: number;
    temperature?: number;
  }): Promise<unknown>;
}

const DEFAULT_MODELS = [
  // Safe fallback list for deployments that do not configure catalog discovery.
  '@cf/deepseek-ai/deepseek-v4-pro-0813',
  '@cf/deepseek-ai/deepseek-v4-flash-0731',
  '@cf/zai-org/glm-5.3-flash',
  '@cf/qwen/qwen3.8-27b',
  '@cf/google/gemma-4-26b-a4b-it',
  '@cf/meta/llama-3.1-8b-instruct',
] as const;

const MODEL_ID = /^@[a-z0-9][a-z0-9._/-]{2,120}$/i;
const CATALOG_TTL_MS = 6 * 60 * 60 * 1000;
let catalogCache: { account: string; expiresAt: number; models: string[] } | null = null;
let catalogPromise: Promise<string[]> | null = null;

export function getAiModelCandidates(configured?: string): string[] {
  const clean = (configured || '').split(',').map((x) => x.trim()).filter((x) => MODEL_ID.test(x));
  return [...new Set(clean.length ? clean : DEFAULT_MODELS)].slice(0, 8);
}

/** Extract only Cloudflare-hosted text models; newest catalog entries go first when dated. */
export function rankCatalogModels(payload: unknown): string[] {
  if (!payload || typeof payload !== 'object') return [];
  const root = payload as Record<string, unknown>;
  const rows = Array.isArray(root.result) ? root.result : Array.isArray(payload) ? payload : [];
  const found: Array<{ id: string; date: number; index: number }> = [];
  rows.forEach((row, index) => {
    if (!row || typeof row !== 'object') return;
    const item = row as Record<string, unknown>;
    const id = [item.id, item.model_id, item.name].find((value) => typeof value === 'string' && MODEL_ID.test(value)) as string | undefined;
    if (!id || !id.startsWith('@cf/')) return;
    const task = String(item.task ?? item.task_name ?? '').toLowerCase();
    if (task && !/(text|generation|language|chat)/.test(task)) return;
    const dateValue = item.updated_at ?? item.created_at ?? item.created_on ?? item.release_date;
    const parsed = typeof dateValue === 'number' ? dateValue : Date.parse(String(dateValue ?? ''));
    found.push({ id, date: Number.isFinite(parsed) ? parsed : 0, index });
  });
  found.sort((a, b) => (a.date && b.date ? b.date - a.date : a.index - b.index));
  return [...new Set(found.map((item) => item.id))].slice(0, 8);
}

async function discoverModels(env: Env): Promise<string[]> {
  const account = env.AI_CATALOG_ACCOUNT_ID || '';
  const token = env.AI_CATALOG_API_TOKEN || '';
  if (!/^[a-f0-9]{32}$/i.test(account) || token.length < 12) return [];
  if (catalogCache?.account === account && catalogCache.expiresAt > Date.now()) return catalogCache.models;
  if (catalogPromise) return catalogPromise;
  catalogPromise = (async () => {
    try {
      const url = new URL('https://api.cloudflare.com/client/v4/accounts/' + account + '/ai/models/search');
      url.searchParams.set('task', 'text-generation');
      url.searchParams.set('hide_experimental', 'true');
      url.searchParams.set('include_deprecated', 'false');
      url.searchParams.set('per_page', '100');
      const response = await fetch(url, {
        method: 'GET',
        headers: { authorization: 'Bearer ' + token, accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) return [];
      const payload = await response.json() as unknown;
      const models = rankCatalogModels(payload);
      if (models.length) catalogCache = { account, expiresAt: Date.now() + CATALOG_TTL_MS, models };
      return models;
    } catch {
      return [];
    } finally {
      catalogPromise = null;
    }
  })();
  return catalogPromise;
}

async function selectModels(env: Env): Promise<string[]> {
  const configured = (env.AI_MODELS || '').split(',').map((x) => x.trim()).filter((x) => MODEL_ID.test(x));
  if (configured.length) return [...new Set(configured)].slice(0, 8);
  const discovered = await discoverModels(env);
  return discovered.length ? discovered : [...DEFAULT_MODELS];
}

function outputText(result: unknown): string {
  if (typeof result === 'string') return result;
  if (!result || typeof result !== 'object') return '';
  const obj = result as Record<string, unknown>;
  for (const key of ['response', 'output_text', 'text']) {
    if (typeof obj[key] === 'string') return obj[key] as string;
  }
  return '';
}

export async function createDiagnostics(env: Env, language: 'fa' | 'en'): Promise<{
  text: string;
  model: string | null;
  ai: boolean;
  summary: Record<string, number | string>;
}> {
  const users = env.GZ_DB ? await listUsers(env.GZ_DB) : [];
  const enabled = users.filter((u) => u.enabled).length;
  const summary = {
    version: VERSION,
    database: env.GZ_DB ? 'connected' : 'not_bound',
    totalUsers: users.length,
    enabledUsers: enabled,
    disabledUsers: users.length - enabled,
    recentlySeen24h: users.filter((u) => u.lastSeen >= Date.now() - 86_400_000).length,
    quotaLimitedUsers: users.filter((u) => u.quotaBytes > 0).length,
    // Aggregate only; no domain names, IPs, user identifiers, or traffic content.
    configuredFallbackCount: env.GZ_DB ? (await loadSettings(env.GZ_DB))?.proxyIPs.length ?? 0 : 0,
  };

  if (!env.AI) {
    return {
      ai: false,
      model: null,
      summary,
      text: language === 'fa'
        ? 'اتصال Workers AI تنظیم نشده است. برای فعال‌سازی، binding با نام AI را در تنظیمات Worker اضافه کنید. دادهٔ عملیاتی بالا بدون AI هم قابل مشاهده است.'
        : 'Workers AI is not configured. Add a binding named AI to enable the advisor. The operational summary above is available without AI.',
    };
  }

  const models = await selectModels(env);
  const system = language === 'fa'
    ? 'شما مشاور عملیات فقط-خواندنی برای پنل Cloudflare Worker هستید. بر اساس فقط شمارنده‌های تجمیعی، حداکثر سه پیشنهاد عملی و کوتاه به فارسی بده. هیچ‌گاه ادعای تضمین عبور از فیلترینگ/DPI نکن، روش پنهان‌سازی یا دورزدن محدودیت شبکه ارائه نده، تنظیمات را تغییر نده و اگر داده کافی نیست صریح بگو. موارد قابل پیشنهاد: امنیت حساب، سهمیه/انقضا، بازبینی سلامت Worker/D1، بررسی دستی و مجاز دامنه یا مسیر. پاسخ را با محدودیت‌ها و عدم قطعیت همراه کن.'
    : 'You are a read-only operations advisor for a Cloudflare Worker panel. Give at most three concise, practical recommendations based only on aggregate counters. Never claim guaranteed censorship/DPI bypass, provide stealth/evasion instructions, or change settings. If evidence is insufficient, say so. You may suggest account security, quota/expiry review, Worker/D1 health checks, and authorized manual domain/path checks. State uncertainty and platform limitations.';
  const prompt = JSON.stringify(summary);
  let lastError: unknown;
  for (const model of models) {
    try {
      const result = await (env.AI as AiBinding).run(model, {
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: prompt },
        ],
        max_tokens: 350,
        temperature: 0.2,
      });
      const text = outputText(result).trim().slice(0, 5000);
      if (!text) throw new Error('empty model response');
      return { ai: true, model, text, summary };
    } catch (error) {
      lastError = error;
    }
  }

  // Do not disclose provider errors/credentials to the browser. This deterministic
  // fallback is honest and still useful when a model is unavailable or disabled.
  void lastError;
  return {
    ai: false,
    model: null,
    summary,
    text: language === 'fa'
      ? 'مدل‌های Workers AI در دسترس نبودند یا اجرای آن‌ها ناموفق شد. اتصال AI، شناسهٔ مدل و سهمیهٔ حساب را بررسی کنید؛ هیچ تغییری در تنظیمات شبکه انجام نشده است.'
      : 'Workers AI models were unavailable or failed. Check the AI binding, model IDs, and account limits. No network settings were changed.',
  };
}
