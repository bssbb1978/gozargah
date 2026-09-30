/**
 * Gozargah — worker entry point & router.
 *
 * Route map:
 *   ANY  (websocket upgrade)  -> VLESS/Trojan/SS over WS; DNS-only VLESS UDP on port 53
 *   GET  /                    -> stealth landing page
 *   GET  /robots.txt          -> disallow all
 *   GET  /favicon.png         -> embedded logo
 *   GET  /{panelPath}         -> panel UI (SPA)
 *   POST /{panelPath}/api/*   -> panel JSON API
 *   GET  /{subPath}/{token}       -> legacy subscription compatibility
 *   GET  /{dynamicPrefix}/{routeKey} -> per-user status/subscription route
 *   GET|POST /{prefix}/{key}/dns-query -> authenticated DNS-over-HTTPS
 *   GET  /{prefix}/{key}/{app} -> explicit format (clash | singbox | v2ray | xray | profiles | adaptive | capabilities | page)
 *   GET  anything else        -> stealth landing (no info leak, nahan-style)
 */

import { Env, VERSION } from './config';
import { getEffectiveSettings, type EffectiveSettings } from './settings';
import { acceptWebSocket } from './handlers/websocket';
import { buildAxrManifest, buildLiveAdaptiveClientBundle, findUserByToken, renderSub, resolveApp, subHeaders } from './subscription';
import { resolveOpts } from './sub/operators';
import { findUserBySubscriptionRoute, isUserAllowed, lazyMaintenance, type GzUser } from './db/users';
import { loadNetworkState } from './db/store';
import { normalizeStoredNetworkState } from './ai/network-state';
import { handlePanelApi } from './panel/api';
import { panelHtml } from './panel/ui';
import { decoyResponse } from './panel/decoy';
import { landingHtml } from './panel/landing';
import { userPageHtml } from './panel/userpage';
import { LOGO_FAV_B64 } from './assets/logo';
import { glog, logRing } from './utils/log';
import { requestWorkerHostname } from './utils/request-host';
import { handleTelegramWebhook } from './telegram';
import { handleUserDnsRequest } from './handlers/dns';
import { runScheduledHealth } from './ai/scheduled-health';

export default {
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runScheduledHealth(env).catch(() => { /* scheduled health is best-effort */ }));
  },
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      glog('router error: ' + (e instanceof Error ? e.message : String(e)));
      return new Response(landingHtml('fa'), {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
  },
};

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);

  // 1) proxy data plane — websocket upgrades on any path
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    return acceptWebSocket(request, env, ctx);
  }

  const rawPath = decodeURIComponent(url.pathname).replace(/^\/+|\/+$/g, '');
  const host = requestWorkerHostname(request, url);

  // 2) static/stealth endpoints
  if (rawPath === 'favicon.ico' || rawPath === 'favicon.png') {
    const bytes = atob(LOGO_FAV_B64.split(',')[1]);
    const buf = new Uint8Array(bytes.length);
    for (let i = 0; i < buf.length; i++) buf[i] = bytes.charCodeAt(i);
    return new Response(buf, { headers: { 'content-type': 'image/png', 'cache-control': 'public, max-age=86400' } });
  }
  if (rawPath === 'robots.txt') {
    return new Response('User-agent: *\nDisallow: /\n', { headers: { 'content-type': 'text/plain' } });
  }
  if (rawPath === 'healthz') {
    return new Response(JSON.stringify({ ok: true, version: VERSION }), {
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  }
  if (rawPath === '_telegram/webhook') return handleTelegramWebhook(request, env);

  // 3) panel
  const eff = await getEffectiveSettings(env, host);
  if (rawPath === eff.panelPath) {
    const html = panelHtml({
      panelPath: eff.panelPath,
      dbOk: eff.dbOk,
      isDefaultPassword: eff.isDefaultPassword,
      version: VERSION,
      lang: 'fa',
    });
    return new Response(html, {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }
  if (rawPath.startsWith(eff.panelPath + '/api/')) {
    const action = rawPath.slice(eff.panelPath.length + 5); // strip "{panelPath}/api/"
    return handlePanelApi(request, env, eff, action);
  }

  // 4) legacy subscription route — retained so existing imports keep working.
  if (rawPath.startsWith(eff.subPath + '/') && env.GZ_DB) {
    const segs = rawPath.slice(eff.subPath.length + 1).split('/').filter(Boolean);
    const token = segs[0] ?? '';
    const user = await findUserByToken(env.GZ_DB, host, token);
    if (user && isUserAllowed(user).ok) {
      const base = 'https://' + host + '/' + eff.subPath + '/' + token;
      return serveSubscriptionRoute(request, env, ctx, url, host, eff, user, token, base, segs.slice(1));
    }
    // unknown token: fall through to stealth landing (no user enumeration)
  }

  // 4b) per-user opaque route — /{dynamicPrefix}/{routeKey}[/{app}].
  // The route key is independent of the VLESS UUID; old /sub links remain valid.
  if (env.GZ_DB) {
    const segs = rawPath.split('/').filter(Boolean);
    if (segs.length >= 2 && segs[0].startsWith('p-')) {
      const [dynamicPrefix, routeKey, ...tail] = segs;
      const user = await findUserBySubscriptionRoute(env.GZ_DB, dynamicPrefix, routeKey);
      if (user && isUserAllowed(user).ok) {
        const base = 'https://' + host + '/' + dynamicPrefix + '/' + routeKey;
        return serveSubscriptionRoute(request, env, ctx, url, host, eff, user, routeKey, base, tail, dynamicPrefix, routeKey);
      }
    }
  }

  // 5) scanner decoy (2.15) → stealth landing for everything else
  const decoy = decoyResponse(request, url);
  if (decoy) return decoy;
  return new Response(landingHtml('fa'), {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

async function serveSubscriptionRoute(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL,
  host: string,
  eff: EffectiveSettings,
  user: GzUser,
  token: string,
  base: string,
  tail: string[],
  dynamicPrefix?: string,
  routeKey?: string,
): Promise<Response> {
  if (tail.length === 1 && tail[0] === 'dns-query') return handleUserDnsRequest(request, env, user);
  const opts = resolveOpts(url.searchParams.get('op'), url.searchParams.get('ech'));
  const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'fa';
  if (tail.length === 1 && tail[0] === 'axr-manifest') {
    const body = await buildAxrManifest(host, user, env, token);
    return new Response(body, { headers: subHeaders(eff, host, user, 'adaptive', opts, token, base) });
  }
  const dnsUrl = base + '/dns-query';
  const app = resolveApp(tail[0] ?? url.searchParams.get('app') ?? '', request.headers.get('user-agent') ?? '');
  if (env.GZ_DB && user.id > 0) {
    ctx.waitUntil(lazyMaintenance(env.GZ_DB, user, eff.resetCycle || 'none').catch(() => { /* ignore */ }));
  }
  if (app === 'page') {
    let netState: { state: string; updatedAt: number } = { state: 'unknown', updatedAt: 0 };
    if (env.GZ_DB) {
      try {
        const ns = normalizeStoredNetworkState(await loadNetworkState(env.GZ_DB));
        if (ns) netState = { state: ns.state, updatedAt: ns.updatedAt };
      } catch { /* optional */ }
    }
    const html = await userPageHtml({
      host: host,
      user,
      token,
      subPath: eff.subPath,
      dynamicPrefix,
      routeKey,
      panelPath: eff.panelPath,
      lang,
      opts,
      echOn: !!opts.ech,
      backupEntryHosts: eff.backupEntryHosts ?? [],
      networkState: netState,
    });
    return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  }
  if (app === 'adaptive') {
    const body = await buildLiveAdaptiveClientBundle(host, user, opts, env, dnsUrl);
    return new Response(body, { headers: subHeaders(eff, host, user, app, opts, token, base) });
  }
  const { body } = await renderSub(app, host, user, opts, env, dnsUrl);
  return new Response(body, { headers: subHeaders(eff, host, user, app, opts, token, base) });
}

// keep logRing referenced (debug endpoint reads it)
void logRing;
