/**
 * Privacy-conscious, read-only operations advisor powered by the optional
 * Cloudflare Workers AI binding. It receives aggregate counters only: never
 * user names, credentials, subscription URLs, IPs, or proxy traffic.
 */
import { Env, VERSION } from '../config';
import { listUsers } from '../db/users';
import { loadSettings, saveSettings, loadPathHealth, loadProfileHealth, loadAiModelHealth, saveAiModelHealth, loadNetworkState, loadPredictiveStates } from '../db/store';
import { decideResilience, localResilienceAdvice, PathObservation } from './resilience';
import { normalizeStoredNetworkState } from './network-state';
import { parseOriginTransports, protocolCatalog } from '../protocols/catalog';
import { applyAdvisorTransport, advisorKillSwitchEnabled, defaultAdvisorApplication, normalizeAdvisorApplication, type AdvisorApplicationStatus } from './advisor-application';
import { parseStrategyRecommendation, StrategyConstraints, StrategyRecommendation } from './strategy-recommendation';
import type { RegimeAssessment } from './regime';

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
  const stale = catalogCache?.account === account ? catalogCache.models : [];
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
      if (!response.ok) return stale;
      const payload = await response.json() as unknown;
      const models = rankCatalogModels(payload);
      if (models.length) {
        catalogCache = { account, expiresAt: Date.now() + CATALOG_TTL_MS, models };
        return models;
      }
      return stale;
    } catch {
      return stale;
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
  // 2.12 — regime intelligence note (aggregate statistics, never DPI proof).
  const regimeState = String(summary.regimeState ?? 'unknown');
  if (regimeState === 'suspected_change') {
    notes.push(language === 'fa'
      ? 'هوش مصنوعی داخلی افت محسوس نرخ موفقیت در پنجرهٔ اخیر نسبت به خط پایه دیده است (فقط آمار تجمیعی، نه تشخیص DPI و نه اثبات فیلتر). موتور به‌طور خودکار تنوع ترنسپورت و نقاط ورود را افزایش داده است؛ تنظیمات را تغییر ندهید تا شواهد تازه‌تر جمع شود.'
      : 'The internal AI detected a material drop in the recent success rate versus baseline (aggregate statistics only — not DPI detection or proof of filtering). The engine has automatically increased transport/entry diversity; avoid changing settings until fresher evidence arrives.');
  } else if (regimeState === 'recovering') {
    notes.push(language === 'fa'
      ? 'نرخ موفقیت در پنجرهٔ اخیر نسبت به خط پایه بهبود یافته و رژیم به سمت پایدار در حال بازگشت است (آمار تجمیعی).'
      : 'The recent success rate recovered versus baseline; the regime is returning to stable (aggregate statistics).');
  }
  const netState = String(summary.networkState ?? 'unknown');
  if (Number(summary.backupEntryCount) === 0 && (netState === 'recovery' || netState === 'no_healthy_path')) {
    notes.push(language === 'fa'
      ? 'هیچ نقطهٔ ورود جایگزینی تنظیم نشده است؛ اضافه کردن دومینِ دوم متصل به همین Worker (از بخش تنظیمات) احتمال بقای مسیر در قطع‌ها و فیلترهای موضعی را بالا می‌برد — اما نمی‌تواند قطع کامل مسیر را از راه دور رفع کند.'
      : 'No backup entry point is configured; adding a second domain pointing at this same Worker (Settings) raises the odds of a surviving route during partial outages — it cannot remotely restore a fully cut path.');
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

function strategyAdvice(recommendation: StrategyRecommendation, language: 'fa' | 'en', status: AdvisorApplicationStatus): string {
  const fragment = recommendation.fragment.enabled
    ? `${recommendation.fragment.minBytes}-${recommendation.fragment.maxBytes}B/${recommendation.fragment.gapMs}ms`
    : 'off';
  const fields = [
    `transport=${recommendation.transport}`,
    `profile=${recommendation.profile}`,
    `entry=${recommendation.entry}`,
    `sni=${recommendation.sniChoice}`,
    `fragment=${fragment}`,
    `retry=${recommendation.retry.maxAttempts}x/${recommendation.retry.baseDelayMs}-${recommendation.retry.maxDelayMs}ms`,
  ];
  const note = status === 'applied'
    ? (language === 'fa'
      ? 'اولویت ترنسپورت به‌صورت محدود در سیاست تطبیقی اعمال شد؛ امتیازدهی محلی و بازگشت خودکار همچنان حاکم‌اند. سایر فیلدها فقط راهنما هستند.'
      : 'The transport preference was applied as a bounded adaptive-policy hint; local scoring and automatic rollback remain authoritative. Other fields are advisory only.')
    : status === 'rolled_back'
      ? (language === 'fa'
        ? 'اولویت ترنسپورت قبلی پس از افت نرخ موفقیت تجمیعی بازگردانده شد؛ پیشنهادهای دیگر فقط راهنما هستند.'
        : 'The transport preference was rolled back after an aggregate success-rate drop; other fields remain advisory only.')
      : status === 'killed'
        ? (language === 'fa' ? 'کلید توقف فعال است؛ هیچ پیشنهاد AI اعمال نمی‌شود.' : 'The kill switch is active; no AI advice is applied.')
        : status === 'baseline_missing'
          ? (language === 'fa' ? 'خط پایهٔ تازهٔ سلامت Worker موجود نیست؛ این پیشنهاد اعمال نشد.' : 'No fresh Worker-health baseline is available; this suggestion was not applied.')
          : status === 'unsupported_transport'
            ? (language === 'fa' ? 'ترنسپورت پیشنهادی در قابلیت‌های فعال مجاز نیست؛ اعمال نشد.' : 'The suggested transport is not an enabled capability; it was not applied.')
            : status === 'disabled'
              ? (language === 'fa' ? 'اعمال خودکار خاموش است؛ پیشنهاد فقط راهنماست.' : 'Auto-application is off; this remains advisory only.')
              : (language === 'fa' ? 'پیشنهاد فقط راهنماست؛ خودکار اعمال نشده است.' : 'This remains advisory only; it was not auto-applied.');
  return (language === 'fa' ? '\n\nپیشنهاد پارامتریِ اعتبارسنجی‌شده: ' : '\n\nValidated parameter suggestion: ') + fields.join(language === 'fa' ? '، ' : ', ') + '\n' + note;
}

export async function createDiagnostics(env: Env, language: 'fa' | 'en'): Promise<{
  text: string;
  model: string | null;
  ai: boolean;
  summary: Record<string, number | string>;
  strategyRecommendation: StrategyRecommendation | null;
  advisorApplicationStatus: AdvisorApplicationStatus;
}> {
  const users = env.GZ_DB ? await listUsers(env.GZ_DB) : [];
  const enabled = users.filter((u) => u.enabled).length;
  // 2.12 — aggregate regime label + configured backup entry count (never
  // hostnames or per-user data).
  let regime: RegimeAssessment | null = null;
  let backupEntryCount = 0;
  let settingsSnapshot: Awaited<ReturnType<typeof loadSettings>> = null;
  if (env.GZ_DB) {
    try {
      settingsSnapshot = await loadSettings(env.GZ_DB);
      backupEntryCount = settingsSnapshot?.backupEntryHosts?.length ?? 0;
    } catch { /* optional */ }
    try {
      const rows = await loadPredictiveStates(env.GZ_DB, 'regime');
      const row = rows.find((r) => r.subjectId === 'global');
      if (row) regime = JSON.parse(row.stateJson) as RegimeAssessment;
    } catch { /* optional */ }
  }
  const networkSnapshot = normalizeStoredNetworkState(env.GZ_DB ? await loadNetworkState(env.GZ_DB) : null);
  const networkState = networkSnapshot?.state ?? 'unknown';
  const killSwitch = advisorKillSwitchEnabled(env.AI_ADVISOR_KILL_SWITCH);
  let advisorApplication = normalizeAdvisorApplication(settingsSnapshot?.aiAdvisorApplication ?? defaultAdvisorApplication());
  if (killSwitch && advisorApplication.activeTransport) {
    advisorApplication = { ...advisorApplication, activeTransport: null, status: 'killed', reason: 'worker_kill_switch' };
  }
  const profileRows = env.GZ_DB ? await loadProfileHealth(env.GZ_DB) : [];
  const now = Date.now();
  const profileObservations = profileRows
    .filter((row) => ['standard', 'fragmented', 'alt-port', 'fragmented-alt'].includes(row.profileId))
    .map((row) => {
      const failures = Number.isFinite(row.failures) ? Math.max(0, Math.min(100, Math.floor(row.failures))) : 0;
      const successes = Number.isFinite(row.successes) ? Math.max(0, Math.min(100, Math.floor(row.successes))) : 0;
      const samples = Math.min(100, failures + successes);
      const latency = row.latencyMs != null && Number.isFinite(row.latencyMs) ? Math.max(0, Math.min(120_000, row.latencyMs)) : null;
      return {
        profile: row.profileId,
        samples,
        successRate: samples ? Math.round((successes / (successes + failures)) * 100) / 100 : 0.5,
        latencyBucketMs: latency == null ? null : Math.round(latency / 100) * 100,
        recent: Number.isFinite(row.checkedAt) && row.checkedAt > now - 60 * 60_000,
      };
    });
  const entryChoices = ['primary', ...Array.from({ length: Math.max(0, Math.min(4, Math.floor(backupEntryCount))) }, (_, i) => `backup_${i + 1}`)];
  const readyTransports = new Set(protocolCatalog(
    Boolean(env.ORIGIN_ENGINE_HOST?.trim()),
    env.ORIGIN_ENGINE_HOST ? parseOriginTransports(env.ORIGIN_ENGINE_TRANSPORTS) : [],
  ).filter((capability) => capability.ready && capability.generatorAvailable).map((capability) => capability.transport));
  const constraints: StrategyConstraints = {
    transports: [...readyTransports].filter((transport) => ['ws', 'grpc', 'httpupgrade', 'xhttp'].includes(transport)),
    entries: entryChoices,
    sniChoices: entryChoices,
  };
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
    profileHealthCount: profileRows.length,
    networkState,
    regimeState: regime?.state ?? 'unknown',
    regimeConfidence: regime ? regime.confidence : 0,
    backupEntryCount,
  };

  if (env.GZ_DB) {
    const rows = await loadPathHealth(env.GZ_DB);
    const observations: PathObservation[] = rows.map(r => ({ id:r.pathId, latencyMs:r.latencyMs, ok:r.ok, checkedAt:r.checkedAt, failures:r.failures, successes:r.successes, quarantineUntil:r.quarantineUntil }));
    const decision = decideResilience(observations);
    if (!env.AI) {
      return { ai:false, model:null, summary, strategyRecommendation: null, advisorApplicationStatus: advisorApplication.status, text: localResilienceAdvice(decision, language) + '\n\n' + localAdvice(summary, language, false) };
    }
  }

  if (!env.AI) {
    return {
      ai: false,
      model: null,
      summary,
      strategyRecommendation: null,
      advisorApplicationStatus: advisorApplication.status,
      text: localAdvice(summary, language, false),
    };
  }

  const models = await selectModels(env);
  const system = [
    'Return exactly one JSON object matching schema axr-strategy-advice/v1; no prose, Markdown, or extra keys.',
    'You are read-only. Recommend parameters only; never claim DPI detection, guaranteed bypass, or an international-cut diagnosis. The application controller may use only the allow-listed transport as a bounded preference when the operator opted in; you cannot execute tools or change settings.',
    'Use only the anonymized aggregate counters and profile observations in the user message. Never request or invent user IDs, hostnames, IPs, credentials, traffic content, or secrets.',
    'transport must be one of allowed.transports; entry and sniChoice must be aliases from allowed.entries and allowed.sniChoices. Choose only listed profiles and bounded numbers.',
    'Exact object: {schema:"axr-strategy-advice/v1",transport,profile,entry,sniChoice,fragment:{enabled,minBytes,maxBytes,gapMs},retry:{maxAttempts,baseDelayMs,maxDelayMs}}.',
    'Only the transport field can ever become a soft adaptive-policy preference, and only after capability checks, opt-in, a fresh measured baseline, and local guard checks. Profile, entry, SNI, fragment, and retry fields always remain advisory. If evidence is weak, choose conservative settings.',
  ].join(' ');
  const prompt = JSON.stringify({
    language,
    aggregate: summary,
    profileObservations,
    allowed: constraints,
  });
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
      const raw = outputText(result).trim();
      const recommendation = parseStrategyRecommendation(raw, constraints);
      if (!recommendation) throw new Error('invalid strategy recommendation schema');
      modelFailures.delete(model);
      if (env.GZ_DB) {
        try {
          const h = (await loadAiModelHealth(env.GZ_DB)).find(x => x.modelId === model);
          await saveAiModelHealth(env.GZ_DB, { modelId: model, failures: h?.failures ?? 0, successes: (h?.successes ?? 0) + 1, quarantineUntil: 0, updatedAt: Date.now() });
        } catch { /* health telemetry is optional */ }
      }
      let applicationStatus = advisorApplication.status;
      if (killSwitch) {
        applicationStatus = 'killed';
      } else if (env.GZ_DB && settingsSnapshot) {
        try {
          await saveSettings(env.GZ_DB, (prev) => {
            const state = normalizeAdvisorApplication(prev?.aiAdvisorApplication ?? settingsSnapshot?.aiAdvisorApplication ?? defaultAdvisorApplication());
            const baseline = networkSnapshot && Number.isFinite(networkSnapshot.failureRate)
              ? { successRate: Math.max(0, Math.min(1, 1 - networkSnapshot.failureRate)), updatedAt: networkSnapshot.updatedAt }
              : null;
            const next = applyAdvisorTransport(state, recommendation.transport, constraints.transports, baseline);
            applicationStatus = next.status;
            return { ...(prev ?? settingsSnapshot!), aiAdvisorApplication: next };
          });
        } catch { /* advisor application is best-effort and never blocks diagnostics */ }
      }
      return {
        ai: true,
        model,
        summary,
        strategyRecommendation: recommendation,
        advisorApplicationStatus: applicationStatus,
        // Never return raw model output. Render only the validated enum/numeric fields.
        text: localAdvice(summary, language, false) + strategyAdvice(recommendation, language, applicationStatus),
      };
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
    strategyRecommendation: null,
    advisorApplicationStatus: advisorApplication.status,
    text: localAdvice(summary, language, true),
  };
}
