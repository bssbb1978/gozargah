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
 *   GET  /{subPath}/{token}       -> browser: rich status page · client: sub (UA-sniffed)
 *   GET|POST /{subPath}/{token}/dns-query -> authenticated DNS-over-HTTPS
 *   GET  /{subPath}/{token}/{app} -> explicit format (clash | singbox | v2ray | xray | profiles | adaptive | capabilities | page)
 *   GET  anything else        -> stealth landing (no info leak, nahan-style)
 */

import { Env, VERSION } from './config';
import { getEffectiveSettings } from './settings';
import { acceptWebSocket } from './handlers/websocket';
import { buildAxrManifest, buildLiveAdaptiveClientBundle, findUserByToken, renderSub, resolveApp, subHeaders } from './subscription';
import { resolveOpts } from './sub/operators';
import { isUserAllowed, lazyMaintenance } from './db/users';
import { loadNetworkState } from './db/store';
import { handlePanelApi } from './panel/api';
import { panelHtml } from './panel/ui';
import { decoyResponse } from './panel/decoy';
import { landingHtml } from './panel/landing';
import { userPageHtml } from './panel/userpage';
import { LOGO_FAV_B64 } from './assets/logo';
import { glog, logRing } from './utils/log';
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
  const host = url.host;

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

  // 4) subscription — /{subPath}/{token}[/{app}]
  if (rawPath.startsWith(eff.subPath + '/') && env.GZ_DB) {
    const segs = rawPath.slice(eff.subPath.length + 1).split('/').filter(Boolean);
    const token = segs[0] ?? '';
    const appOverride = (segs[1] ?? url.searchParams.get('app') ?? '');
    const user = await findUserByToken(env.GZ_DB, url.hostname, token);
    // Subscription tokens are authorization credentials too: a disable, expiry,
    // or exhausted quota must stop new config issuance from this fresh D1 read.
    if (user && isUserAllowed(user).ok) {
      if (segs.length === 2 && segs[1] === 'dns-query') return handleUserDnsRequest(request, env, user);
      const opts = resolveOpts(url.searchParams.get('op'), url.searchParams.get('ech'));
      const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'fa';
      // 2.14 — AXR machine feed: bootstrap JSON for the native AXR core (no UA sniffing).
      if (segs.length === 2 && segs[1] === 'axr-manifest') {
        // 2.16 — the token keys the manifest HMAC (manifest_sig).
        const body = await buildAxrManifest(url.hostname, user, env, token);
        return new Response(body, { headers: subHeaders(eff, url.hostname, user, 'adaptive', opts, token) });
      }
      const dnsUrl = url.origin + '/' + eff.subPath + '/' + token + '/dns-query';
      const app = resolveApp(appOverride, request.headers.get('user-agent') ?? '');

      // v1.2: lazy maintenance (first-use stamp + rolling reset) on any sub/status read
      if (user.id > 0) {
        ctx.waitUntil(lazyMaintenance(env.GZ_DB, user, eff.resetCycle || 'none').catch(() => { /* ignore */ }));
      }

      if (app === 'page') {
        // 2.12 — best-effort network state for the honest emergency alert.
        let netState: { state: string; updatedAt: number } | null = null;
        if (env.GZ_DB) {
          try {
            const ns = await loadNetworkState(env.GZ_DB);
            if (ns) netState = { state: ns.state, updatedAt: ns.updatedAt };
          } catch { /* optional */ }
        }
        const html = await userPageHtml({
          host: url.hostname,
          user,
          token,
          subPath: eff.subPath,
          panelPath: eff.panelPath,
          lang,
          opts,
          echOn: !!opts.ech,
          backupEntryHosts: eff.backupEntryHosts ?? [],
          networkState: netState,
        });
        return new Response(html, {
          headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
        });
      }

      if (app === 'adaptive') {
        const body = await buildLiveAdaptiveClientBundle(url.hostname, user, opts, env, dnsUrl);
        return new Response(body, { headers: subHeaders(eff, url.hostname, user, app, opts, token) });
      }
      const { body } = await renderSub(app, url.hostname, user, opts, env, dnsUrl);
      return new Response(body, { headers: subHeaders(eff, url.hostname, user, app, opts, token) });
    }
    // unknown token: fall through to stealth landing (no user enumeration)
  }

  // 5) scanner decoy (2.15) → stealth landing for everything else
  const decoy = decoyResponse(request, url);
  if (decoy) return decoy;
  return new Response(landingHtml('fa'), {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

// keep logRing referenced (debug endpoint reads it)
void logRing;
