/**
 * Privacy-conscious, read-only operations advisor powered by the optional
 * Cloudflare Workers AI binding. It receives aggregate counters only: never
 * user names, credentials, subscription URLs, IPs, or proxy traffic.
 */
import { Env, VERSION } from '../config';
import { listUsers } from '../db/users';
import { loadSettings, loadPathHealth, loadProfileHealth, loadAiModelHealth, saveAiModelHealth, loadNetworkState } from '../db/store';
import { decideResilience, localResilienceAdvice, PathObservation } from './resilience';

export interface AiBinding {
  run(model: string, input: {
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    max_tokens?: number;
    temperature?: number;
  }): Promise<unknown>;
}

const DEFAULT_MODELS = [
  '@cf/deepseek-ai/deepseek-v4-pro-0813',
  '@cf/deepseek-ai/deepseek-v4-flash-0731',
  '@cf/qwen/qwen3.8-27b',
  '@cf/zai-org/glm-5.3-flash',
  '@cf/openai/gpt-oss-120b',
  '@cf/openai/gpt-oss-20b',
] as const;

const MODEL_ID = /^@[a-z0-9][a-z0-9._/-]{2,120}$/i;
const CATALOG_TTL_MS = 6 * 60 * 60 * 1000;
const MODEL_FAILURE_COOLDOWN_MS = 10 * 60 * 1000;
const MODEL_QUARANTINE_MS = 30 * 60 * 1000;
const KNOWN_PAID_ONLY = new Set([
  '@cf/moonshotai/kimi-k2.6',
  '@cf/moonshotai/kimi-k2.7-code',
  '@cf/zai-org/glm-5.2',
]);
const modelFailures = new Map<string, number>();
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
  const found: Array<{ id: string; date: number; index: number; score: number }> = [];
  rows.forEach((row, index) => {
    if (!row || typeof row !== 'object') return;
    const item = row as Record<string, unknown>;
    const id = [item.id, item.model_id, item.name].find((value) => typeof value === 'string' && MODEL_ID.test(value)) as string | undefined;
    if (!id || !id.startsWith('@cf/')) return;
    if (KNOWN_PAID_ONLY.has(id)) return;
    const task = String(item.task ?? item.task_name ?? '').toLowerCase();
    if (task && !/(text|generation|language|chat|reason)/.test(task)) return;
    const description = String(item.description ?? '').toLowerCase();
    const caps = JSON.stringify(item.capabilities ?? item.capability ?? '').toLowerCase();
    const meta = task + ' ' + description + ' ' + caps + ' ' + id.toLowerCase();
    const dateValue = item.updated_at ?? item.created_at ?? item.created_on ?? item.release_date;
    const parsed = typeof dateValue === 'number' ? dateValue : Date.parse(String(dateValue ?? ''));
    const recent = Number.isFinite(parsed) && parsed > 0 ? Math.min(24, Math.max(0, (parsed - Date.UTC(2024, 0, 1)) / 86_400_000 / 180)) : 0;
    const contextRaw = item.context_window ?? item.context_length ?? item.max_context_length;
    const context = typeof contextRaw === 'number' ? Math.min(12, Math.log10(Math.max(1, contextRaw)) * 3) : 0;
    let capability = 0;
    if (/reason|thinking/.test(meta)) capability += 24;
    if (/function.?call|tool.?call/.test(meta)) capability += 18;
    if (/vision|multimodal/.test(meta)) capability += 8;
    if (/agentic|long.?context|1.?m|million/.test(meta)) capability += 10;
    if (/fast|flash|turbo/.test(meta)) capability += 4;
    const score = capability + context + recent;
    found.push({ id, date: Number.isFinite(parsed) ? parsed : 0, index, score });
  });
  found.sort((a, b) => b.score - a.score || (a.date && b.date ? b.date - a.date : a.index - b.index));
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
  const base = configured.length ? [...new Set(configured)] : (await discoverModels(env)).concat(DEFAULT_MODELS);
  const unique = [...new Set(base)].slice(0, 24);
  if (!env.GZ_DB) return unique.slice(0, 8);
  try {
    const health = await loadAiModelHealth(env.GZ_DB);
    const byId = new Map(health.map(h => [h.modelId, h]));
    const now = Date.now();
    return unique
      .filter(id => { const h = byId.get(id); return !h || h.quarantineUntil <= now; })
      .sort((a,b) => {
        const ha = byId.get(a); const hb = byId.get(b);
        const sa = ha ? (ha.successes - ha.failures * 2) : 0;
        const sb = hb ? (hb.successes - hb.failures * 2) : 0;
        return sb - sa;
      })
      .slice(0, 8);
  } catch {
    return unique.slice(0, 8);
  }
}

function localAdvice(summary: Record<string, number | string>, language: 'fa' | 'en', aiUnavailable: boolean): string {
  const notes: string[] = [];
  const total = Number(summary.totalUsers) || 0;
  const enabled = Number(summary.enabledUsers) || 0;
  const disabled = Number(summary.disabledUsers) || 0;
  const seen = Number(summary.recentlySeen24h) || 0;
  const fallbacks = Number(summary.configuredFallbackCount) || 0;
  if (summary.database !== 'connected') {
    notes.push(language === 'fa'
      ? 'D1 متصل نیست؛ کاربران، تنظیمات و محدودیت درخواست‌ها پایدار نخواهند بود.'
      : 'D1 is not connected; users, settings, and request limits are not persistent.');
  } else if (total === 0) {
    notes.push(language === 'fa' ? 'هنوز کاربری در D1 ثبت نشده است.' : 'No users are registered in D1 yet.');
  }
  if (total > 0 && enabled === 0) {
    notes.push(language === 'fa' ? 'هیچ کاربر فعالی وجود ندارد؛ وضعیت دسترسی کاربران را بررسی کنید.' : 'No users are enabled; review account access states.');
  } else if (disabled > 0) {
    notes.push(language === 'fa' ? 'برای تعدادی از کاربران دسترسی غیرفعال است؛ وضعیت هر کارت را بررسی کنید.' : 'Some accounts are disabled; review their status in the user cards.');
  }
  if (enabled > 0 && seen === 0) {
    notes.push(language === 'fa'
      ? 'در ۲۴ ساعت اخیر فعالیتی ثبت نشده؛ این به‌تنهایی نشانهٔ فیلتر نیست. دامنهٔ متصل به Worker، وضعیت کلاینت و اتصال شبکه را جداگانه بررسی کنید.'
      : 'No activity was recorded in the last 24 hours. This alone does not indicate filtering; check the Worker domain, client status, and network separately.');
  }
  if (fallbacks === 0) {
    notes.push(language === 'fa'
      ? 'هیچ ProxyIP جایگزینی تنظیم نشده؛ فقط برای مقصدهای پشت Cloudflare کاربرد دارد و راهکار عمومی قطعی فیلترینگ نیست.'
      : 'No ProxyIP fallback is configured. It only applies to Cloudflare-fronted destinations and is not a general censorship workaround.');
  }
  if (!notes.length) {
    notes.push(language === 'fa'
      ? 'از شمارنده‌های موجود مشکل قطعی مشخص نیست. وضعیت شبکهٔ کاربر و سلامت دامنه را از همان شبکه به‌صورت جداگانه بررسی کنید.'
      : 'The available counters show no definite issue. Check the user network and domain health independently from the affected network.');
  }
  const heading = language === 'fa' ? 'عیب‌یابی محلیِ قاعده‌محور (بدون مدل AI):' : 'Local rule-based diagnostics (no AI model):';
  const status = aiUnavailable
    ? (language === 'fa' ? '\nسرویس مدل AI در دسترس نبود؛ binding، شناسه/مجوز مدل و محدودیت حساب را بررسی کنید. این تحلیل روی Worker و بدون فراخوانی مدل تولید شد.' : '\nThe AI model service was unavailable; check its binding, model ID/permission, and account limits. This analysis ran on the Worker without a model call.')
    : (language === 'fa' ? '\nمدل AI تنظیم نشده؛ این تحلیل روی Worker و بدون فراخوانی بیرونی تولید شد.' : '\nNo AI model is configured; this analysis ran locally on the Worker without an inference call.');
  return heading + '\n• ' + notes.slice(0, 3).join('\n• ') + status;
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
    pathHealthCount: env.GZ_DB ? (await loadPathHealth(env.GZ_DB)).length : 0,
    profileHealthCount: env.GZ_DB ? (await loadProfileHealth(env.GZ_DB)).length : 0,
    networkState: env.GZ_DB ? ((await loadNetworkState(env.GZ_DB))?.state ?? 'unknown') : 'unknown',
  };

  if (env.GZ_DB) {
    const rows = await loadPathHealth(env.GZ_DB);
    const observations: PathObservation[] = rows.map(r => ({ id:r.pathId, latencyMs:r.latencyMs, ok:r.ok, checkedAt:r.checkedAt, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantineUntil }));
    const decision = decideResilience(observations);
    if (!env.AI) {
      return { ai:false, model:null, summary, text: localResilienceAdvice(decision, language) + '\n\n' + localAdvice(summary, language, false) };
    }
  }

  if (!env.AI) {
    return {
      ai: false,
      model: null,
      summary,
      text: localAdvice(summary, language, false),
    };
  }

  const models = await selectModels(env);
  const system = language === 'fa'
    ? 'شما مشاور عملیات فقط-خواندنی برای پنل Cloudflare Worker هستید. بر اساس فقط شمارنده‌های تجمیعی، حداکثر سه پیشنهاد عملی و کوتاه به فارسی بده. هیچ‌گاه ادعای تضمین عبور از فیلترینگ/DPI نکن، روش پنهان‌سازی یا دورزدن محدودیت شبکه ارائه نده، تنظیمات را تغییر نده و اگر داده کافی نیست صریح بگو. موارد قابل پیشنهاد: امنیت حساب، سهمیه/انقضا، بازبینی سلامت Worker/D1، بررسی دستی و مجاز دامنه یا مسیر. پاسخ را با محدودیت‌ها و عدم قطعیت همراه کن.'
    : 'You are a read-only operations advisor for a Cloudflare Worker panel. Give at most three concise, practical recommendations based only on aggregate counters. Never claim guaranteed censorship/DPI bypass, provide stealth/evasion instructions, or change settings. If evidence is insufficient, say so. You may suggest account security, quota/expiry review, Worker/D1 health checks, and authorized manual domain/path checks. State uncertainty and platform limitations.';
  const prompt = JSON.stringify(summary);
  let lastError: unknown;
  for (const model of models) {
    const failedAt = modelFailures.get(model) || 0;
    if (failedAt && Date.now() - failedAt < MODEL_FAILURE_COOLDOWN_MS) continue;
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
      modelFailures.delete(model);
      if (env.GZ_DB) {
        try {
          const h = (await loadAiModelHealth(env.GZ_DB)).find(x => x.modelId === model);
          await saveAiModelHealth(env.GZ_DB, { modelId: model, failures: h?.failures ?? 0, successes: (h?.successes ?? 0) + 1, quarantineUntil: 0, updatedAt: Date.now() });
        } catch { /* health telemetry is optional */ }
      }
      return { ai: true, model, text, summary };
    } catch (error) {
      const now = Date.now();
      modelFailures.set(model, now);
      if (env.GZ_DB) {
        try {
          const h = (await loadAiModelHealth(env.GZ_DB)).find(x => x.modelId === model);
          const failures = (h?.failures ?? 0) + 1;
          await saveAiModelHealth(env.GZ_DB, { modelId: model, failures, successes: h?.successes ?? 0, quarantineUntil: now + MODEL_QUARANTINE_MS, updatedAt: now });
        } catch { /* health telemetry is optional */ }
      }
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
    text: localAdvice(summary, language, true),
  };
}
