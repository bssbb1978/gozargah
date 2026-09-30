/**
 * Gozargah — global config, types and shared errors.
 */

export const VERSION = '2.17.0';
export const SCHEMA_VERSION = 17;

/** D1 binding name (see wrangler.toml) */
export const DB_BINDING = 'GZ_DB';

export interface Env {
  /** D1 database — optional at runtime; without it the worker runs in
   *  deterministic "no-database" mode and the panel shows a setup guide. */
  GZ_DB?: D1Database;
  /** Optional Telegram bot integration. Store these as Worker secrets/vars. */
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_WEBHOOK_SECRET?: string;
  TELEGRAM_ADMIN_IDS?: string;
  /** Optional native Cloudflare Workers AI binding for aggregate diagnostics. */
  AI?: { run: (model: string, input: unknown) => Promise<unknown> };
  /** Explicit prioritized model IDs; if absent, optional live model discovery is used. */
  AI_MODELS?: string;
  /** Staging override that keeps the initial-password-change gate enabled. */
  FORCE_INITIAL_PASSWORD_CHANGE?: string;
  /** Emergency rollback only: allow the built-in initial password in production. */
  ALLOW_DEFAULT_PASSWORD?: string;
  /** Emergency Worker-level kill switch for all AI-advice application. */
  AI_ADVISOR_KILL_SWITCH?: string;
  /** Optional Workers AI Read-scoped token for the fixed Cloudflare model-search API. */
  AI_CATALOG_API_TOKEN?: string;
  /** Cloudflare account ID for model discovery; not a secret. */
  AI_CATALOG_ACCOUNT_ID?: string;
  /** Optional service binding for controlled egress/tests; normally omitted. */
  TELEGRAM_API?: Fetcher;
  /** Optional DoH upstream proxy binding for controlled egress/tests; normally omitted. */
  DNS_UPSTREAM?: Fetcher;
  /** Comma-separated HTTPS RFC 8484 resolver URLs, maximum four. */
  DNS_UPSTREAMS?: string;
  /** Enable DNS64 synthesis unless explicitly set to "false". */
  DNS64_ENABLED?: string;
  /** RFC 6052 NAT64 prefix used for synthesized AAAA records. */
  DNS64_PREFIX?: string;
  /** Comma-separated ports for scheduled health probes of configured endpoints. */
  HEALTH_PROBE_PORTS?: string;
  /** 2.13 — in-tunnel traffic shaping: 'conservative' (default), 'aggressive' or 'off'. */
  TRAFFIC_SHAPE?: string;
  /** 2.15 — comma-separated clean Cloudflare edge IPv4 hints re-broadcast in the AXR manifest. */
  CLEAN_EDGE_IPS?: string;
  /** 2.16 — operator-level token accepted by POST /{panelPath}/api/network/harvest
   *  (a valid user subscription token is always accepted too). */
  HARVEST_TOKEN?: string;
  /** 2.16 — domestic-CDN fronting relay host. When set (and validated), it is
   *  published as `fronting_hint` in the AXR manifest: deploy this same Worker
   *  script to a domestic CDN domain and point this var at that domain. The
   *  client core merges it into the entry ladder as a high-priority backup. */
  FRONTING_RELAY_HOST?: string;
  /** 2.17 — canary liveness host for the closed-loop pressure engine. When set
   *  (and validated) it is published in the AXR manifest (entries role
   *  "canary" + a `canary` pointer, both inside the HMAC coverage); client
   *  cores probe it as a plain TLS liveness check and report ok/fail via the
   *  harvest endpoint (kind="canary"). The fleet's canary evidence then
   *  drives the dynamic manifest (rotation/probe/flow-profile). A canary is
   *  a liveness signal, never a DPI detector. */
  AXR_CANARY_HOST?: string;
  /** Optional Xray/sing-box origin engine for protocols not terminated natively by the Worker. */
  ORIGIN_ENGINE_HOST?: string;
  /** Optional origin engine port; defaults to 443. */
  ORIGIN_ENGINE_PORT?: string;
  /** Optional SNI override for origin-engine TLS/REALITY profiles. */
  ORIGIN_ENGINE_SNI?: string;
  /** Optional URI path used by XHTTP/WebSocket/HTTPUpgrade origin profiles. */
  ORIGIN_ENGINE_PATH?: string;
  /** Optional gRPC service name used by origin-engine gRPC profiles. */
  ORIGIN_ENGINE_GRPC_SERVICE?: string;
  /** Comma-separated origin transports to emit; defaults to xhttp,grpc,httpupgrade,ws. */
  ORIGIN_ENGINE_TRANSPORTS?: string;
}

/** Error type carrying a short machine code for the panel API. */
export class GzError extends Error {
  code: string;
  constructor(message: string, code = 'gz_error') {
    super(message);
    this.name = 'GzError';
    this.code = code;
  }
}

/** Shared default values (used before the admin saves settings). */
export const DEFAULTS = {
  panelPath: 'gozargah',
  subPath: 'sub',
  /** community round-robin proxyIP endpoint — replace with your own for production */
  proxyIPs: ['proxyip.cmliussss.net'] as string[],
  defaultPassword: 'admin',
  pwIterations: 100_000,
  sessionTtlMs: 7 * 24 * 3600 * 1000,
  loginWindowMs: 15 * 60 * 1000,
  loginMaxAttempts: 5,
  /** settings/users cache TTL inside an isolate */
  cacheTtlMs: 10_000,
  /** flush accumulated per-user byte counters to D1 when above these */
  usageFlushBytes: 512 * 1024,
  usageFlushUsers: 8,
  usageFlushIntervalMs: 30_000,
  /** rolling quota-reset windows (ms) — user.resetAnchor + window */
  resetCycleMs: { daily: 86_400_000, weekly: 7 * 86_400_000, monthly: 30 * 86_400_000 },
} as const;

export type ResetCycle = 'none' | 'daily' | 'weekly' | 'monthly';

export function resetCycleMs(cycle: ResetCycle): number {
  if (cycle === 'daily') return DEFAULTS.resetCycleMs.daily;
  if (cycle === 'weekly') return DEFAULTS.resetCycleMs.weekly;
  if (cycle === 'monthly') return DEFAULTS.resetCycleMs.monthly;
  return 0;
}
