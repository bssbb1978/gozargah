/** Authenticated DNS-over-HTTPS, bounded DoH failover, and optional DNS64. */

import type { Env } from '../config';
import type { GzUser } from '../db/users';
import { getUserByIdFresh, isUserAllowed, recordUsageDelta } from '../db/users';
import { consumeDnsQueryQuota } from '../db/store';
import {
  dnsResponseHasAaaa,
  isDns64Candidate,
  makeAQuery,
  MAX_DNS_MESSAGE_BYTES,
  parseDnsQuery,
  synthesizeDns64,
  validateDnsResponse,
} from '../dns/wire';

const DEFAULT_UPSTREAMS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
];
const MAX_UPSTREAMS = 4;
const UPSTREAM_TIMEOUT_MS = 3_500;
const DNS64_DEFAULT_PREFIX = '64:ff9b::/96';
const DNS_RATE_WINDOW_MS = 60_000;
const DNS_RATE_LIMIT = 120;
const UPSTREAM_HEALTH_MAX_AGE_MS = 10 * 60_000;

interface UpstreamHealth {
  successes: number;
  failures: number;
  consecutiveFailures: number;
  latencyEwma: number;
  quarantineUntil: number;
  updatedAt: number;
}

const upstreamHealth = new Map<string, UpstreamHealth>();

function getHealth(url: string, now = Date.now()): UpstreamHealth {
  const previous = upstreamHealth.get(url);
  if (previous && now >= previous.updatedAt && now - previous.updatedAt <= UPSTREAM_HEALTH_MAX_AGE_MS) return previous;
  return {
    successes: 0, failures: 0, consecutiveFailures: 0,
    latencyEwma: 1_000, quarantineUntil: 0, updatedAt: 0,
  };
}

/** Return at most four HTTPS resolvers, retaining configured order as a tie-break. */
export function parseDnsUpstreams(value?: string): string[] {
  const values = value == null || value.trim() === '' ? DEFAULT_UPSTREAMS : value.split(',');
  const out: string[] = [];
  for (const item of values) {
    if (out.length >= MAX_UPSTREAMS) break;
    try {
      const url = new URL(item.trim());
      if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.hash) continue;
      const normalized = url.toString();
      if (!out.includes(normalized)) out.push(normalized);
    } catch { /* ignore invalid operator entries */ }
  }
  return out;
}

/** Stable, bounded local health ranking; avoids relying on AI or payload inspection. */
export function rankDnsUpstreams(urls: readonly string[], now = Date.now()): string[] {
  return urls.map((url, index) => ({ url, index, health: getHealth(url, now) }))
    .sort((a, b) => {
      const aQuarantined = a.health.quarantineUntil > now;
      const bQuarantined = b.health.quarantineUntil > now;
      if (aQuarantined !== bQuarantined) return aQuarantined ? 1 : -1;
      const aN = a.health.successes + a.health.failures;
      const bN = b.health.successes + b.health.failures;
      const aReliability = (a.health.successes + 1) / (aN + 2);
      const bReliability = (b.health.successes + 1) / (bN + 2);
      const aScore = aReliability / (1 + Math.max(0, a.health.latencyEwma) / 1_000);
      const bScore = bReliability / (1 + Math.max(0, b.health.latencyEwma) / 1_000);
      return bScore - aScore || a.health.failures - b.health.failures || a.index - b.index;
    })
    .map((item) => item.url);
}

function recordUpstreamResult(url: string, ok: boolean, latencyMs: number, now = Date.now()): void {
  const previous = getHealth(url, now);
  const next: UpstreamHealth = {
    successes: previous.successes + (ok ? 1 : 0),
    failures: previous.failures + (ok ? 0 : 1),
    consecutiveFailures: ok ? 0 : previous.consecutiveFailures + 1,
    latencyEwma: ok ? previous.latencyEwma * 0.75 + latencyMs * 0.25 : previous.latencyEwma,
    quarantineUntil: ok ? 0 : now + Math.min(60_000, 5_000 * (2 ** Math.min(previous.consecutiveFailures, 3))),
    updatedAt: now,
  };
  upstreamHealth.set(url, next);
  // A Worker isolate is short-lived; keep this best-effort cache strictly bounded.
  if (upstreamHealth.size > 32) {
    const oldest = [...upstreamHealth.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt)[0];
    if (oldest) upstreamHealth.delete(oldest[0]);
  }
}

/** Exposed for deterministic tests; production callers should use resolveDnsMessage. */
export function resetDnsUpstreamHealthForTests(): void {
  upstreamHealth.clear();
}

async function readLimited(response: Response, limit: number): Promise<Uint8Array> {
  const declared = Number(response.headers.get('content-length') ?? 0);
  if (declared > limit) throw new Error('dns_response_too_large');
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > limit) throw new Error('dns_response_too_large');
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new Error('dns_response_too_large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

async function fetchOneUpstream(url: string, query: Uint8Array, env: Env): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  const init: RequestInit = {
    method: 'POST',
    headers: { accept: 'application/dns-message', 'content-type': 'application/dns-message' },
    body: query,
    signal: controller.signal,
    redirect: 'manual',
  };
  try {
    const response = env.DNS_UPSTREAM
      ? await env.DNS_UPSTREAM.fetch(url, init)
      : await fetch(url, init);
    if (!response.ok) throw new Error('dns_upstream_status_' + response.status);
    const contentType = (response.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/dns-message') throw new Error('dns_upstream_content_type');
    const bytes = await readLimited(response, MAX_DNS_MESSAGE_BYTES);
    if (!validateDnsResponse(bytes, query)) throw new Error('dns_upstream_invalid_response');
    return bytes;
  } finally {
    clearTimeout(timer);
  }
}

async function queryUpstreams(query: Uint8Array, env: Env): Promise<Uint8Array> {
  const configured = parseDnsUpstreams(env.DNS_UPSTREAMS);
  if (!configured.length) throw new Error('dns_no_valid_upstream');
  const ordered = rankDnsUpstreams(configured).slice(0, configured.length);
  let lastError: unknown;
  for (const url of ordered) {
    const started = Date.now();
    try {
      const response = await fetchOneUpstream(url, query, env);
      recordUpstreamResult(url, true, Math.max(1, Date.now() - started));
      return response;
    } catch (error) {
      lastError = error;
      recordUpstreamResult(url, false, Math.max(1, Date.now() - started));
    }
  }
  throw lastError instanceof Error ? lastError : new Error('dns_all_upstreams_failed');
}

/** Resolve one DNS wire query using HTTPS; optionally synthesize DNS64 AAAA. */
export async function resolveDnsMessage(query: Uint8Array, env: Env): Promise<Uint8Array> {
  parseDnsQuery(query);
  const aaaaResponse = await queryUpstreams(query, env);
  if (env.DNS64_ENABLED?.trim().toLowerCase() === 'false' || !isDns64Candidate(query)) return aaaaResponse;

  // DNS64 applies only to NOERROR/NODATA. Existing AAAA or DNSSEC-aware clients
  // keep the upstream answer intact. A CNAME-only NODATA response is still
  // eligible and is preserved from the separate A lookup.
  const flags = (aaaaResponse[2] << 8) | aaaaResponse[3];
  if ((flags & 0x000f) !== 0 || dnsResponseHasAaaa(aaaaResponse)) return aaaaResponse;
  try {
    const aResponse = await queryUpstreams(makeAQuery(query), env);
    const synthesized = synthesizeDns64(query, aResponse, env.DNS64_PREFIX?.trim() || DNS64_DEFAULT_PREFIX);
    return synthesized ?? aaaaResponse;
  } catch {
    // A DNS64 fallback failure must not discard a valid AAAA NODATA response.
    return aaaaResponse;
  }
}

function b64UrlDecodeDns(value: string): Uint8Array {
  if (!value || value.length > 5500 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value) || value.length % 4 === 1) {
    throw new Error('dns_bad_base64');
  }
  let normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  while (normalized.length % 4) normalized += '=';
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (out.length > MAX_DNS_MESSAGE_BYTES) throw new Error('dns_bad_size');
  return out;
}

async function readRequestBody(request: Request): Promise<Uint8Array> {
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > MAX_DNS_MESSAGE_BYTES) throw new Error('dns_bad_size');
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_DNS_MESSAGE_BYTES) {
        await reader.cancel();
        throw new Error('dns_bad_size');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return out;
}

function dnsHttpHeaders(): Headers {
  return new Headers({
    'content-type': 'application/dns-message',
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'x-content-type-options': 'nosniff',
  });
}

function jsonError(code: string, status: number): Response {
  const headers = dnsHttpHeaders();
  headers.set('content-type', 'application/json; charset=utf-8');
  if (status === 405) headers.set('allow', 'GET, POST, OPTIONS');
  return new Response(JSON.stringify({ error: code }), { status, headers });
}

/** Per-user subscription route /dns-query RFC 8484 handler. */
export async function handleUserDnsRequest(request: Request, env: Env, user: GzUser): Promise<Response> {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: dnsHttpHeaders() });
  if (request.method !== 'GET' && request.method !== 'POST') return jsonError('method_not_allowed', 405);
  if (!env.GZ_DB || user.id <= 0) return jsonError('database_not_bound', 503);

  let fresh: GzUser | null;
  try { fresh = await getUserByIdFresh(env.GZ_DB, user.id); }
  catch { return jsonError('database_unavailable', 503); }
  if (!fresh || !isUserAllowed(fresh).ok) return jsonError('user_not_allowed', 403);

  let query: Uint8Array;
  try {
    if (request.method === 'GET') {
      const encoded = new URL(request.url).searchParams.get('dns') ?? '';
      query = b64UrlDecodeDns(encoded);
    } else {
      const contentType = (request.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/dns-message') return jsonError('unsupported_media_type', 415);
      query = await readRequestBody(request);
    }
    parseDnsQuery(query);
  } catch {
    return jsonError('invalid_dns_message', 400);
  }

  try {
    if (!await consumeDnsQueryQuota(env.GZ_DB, user.id, Date.now(), DNS_RATE_LIMIT, DNS_RATE_WINDOW_MS)) {
      return jsonError('dns_rate_limited', 429);
    }
  } catch {
    return jsonError('database_unavailable', 503);
  }

  let answer: Uint8Array;
  try { answer = await resolveDnsMessage(query, env); }
  catch { return jsonError('dns_upstream_unavailable', 502); }
  try { await recordUsageDelta(env.GZ_DB, user.id, query.length, answer.length); }
  catch { return jsonError('database_unavailable', 503); }
  return new Response(answer, { status: 200, headers: dnsHttpHeaders() });
}

/**
 * DNS-over-VLESS-UDP adapter. VLESS UDP datagrams are length-prefixed; only
 * port 53 is accepted and each packet is forwarded through the same DoH/DNS64
 * resolver. No raw UDP socket or general-purpose UDP relay is claimed.
 */
export async function resolveVlessDnsDatagram(query: Uint8Array, env: Env): Promise<Uint8Array> {
  parseDnsQuery(query);
  return resolveDnsMessage(query, env);
}

export async function consumeUserDnsBudget(env: Env, user: GzUser): Promise<boolean> {
  if (!env.GZ_DB || user.id <= 0) return true;
  return consumeDnsQueryQuota(env.GZ_DB, user.id, Date.now(), DNS_RATE_LIMIT, DNS_RATE_WINDOW_MS);
}
