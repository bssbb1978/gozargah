/**
 * Gozargah — scanner decoy layer (AXR-v2, 2.15).
 *
 * Active/passive scanners probe for known shapes: API endpoints, CMS paths,
 * VCS/dotfiles, admin panels, JSON APIs, and (for this repo) AXR machine
 * paths. Anything that does not match a real authenticated route receives
 * an authentic-looking benign web application response instead of the
 * default landing, so enumeration never sees a constant signature.
 *
 * Honesty: this is content-variant decoy — 3 HTML product-page variants +
 * 2 JSON API shapes + random padding. It does not leak state, does not
 * interact with scanners, and changes no real route.
 */

const PADDING_CHARS = 32;

function randomHex(len: number): string {
  const b = crypto.getRandomValues(new Uint8Array(Math.ceil(len / 2)));
  let s = '';
  for (const v of b) s += v.toString(16).padStart(2, '0');
  return s.slice(0, len);
}

const PAD = () => '<!-- x:' + randomHex(PADDING_CHARS) + '-->';

// Benign JSON API shapes (for JSON-typed probes).
const JSON_DECOYS: Array<() => string> = [
  () =>
    JSON.stringify({
      status: 'ok',
      service: 'edge-cache',
      version: '1.4.2',
      region: 'eu-central',
      time: new Date().toISOString(),
      cache: { hits: 184213, misses: 2041, hit_rate: 0.989 },
    }),
  () =>
    JSON.stringify({
      api: 'v2',
      healthy: true,
      uptime_s: 1842231,
      nodes: 4,
      load: 0.31,
      checks: { dns: 'ok', tls: 'ok', http: 'ok' },
    }),
];

// Benign HTML product-page shapes (for path-shape probes).
const HTML_DECOYS: Array<() => string> = [
  () => {
    const name = 'Nordwind Logistics';
    return (
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<meta name="robots" content="noindex, nofollow">' +
      '<title>' + name + ' — Freight &amp; Customs</title>' +
      '<style>body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1c2430}' +
      '.h{background:#123a63;color:#fff;padding:18px 40px;font-size:18px;font-weight:600}' +
      '.w{max-width:860px;margin:34px auto;padding:0 24px;line-height:1.6}' +
      'h1{font-size:26px}p{color:#41506a}footer{padding:24px;color:#8593a8;font-size:12px;text-align:center}</style></head>' +
      '<body><div class="h">' + name + '</div><div class="w">' +
      '<h1>International freight, customs clearance and warehousing</h1>' +
      '<p>We operate consolidated sea and air lanes across 40 corridors, with bonded warehousing, insurance and door-to-door tracking included in every booking.</p>' +
      '<p>Request a quote through your regional desk. Average customs turnaround: 1.8 business days.</p>' +
      '</div><footer>© ' + new Date().getFullYear() + ' ' + name + '. All rights reserved.</footer>' +
      PAD() + '</body></html>'
    );
  },
  () => {
    const name = 'Helioform Studio';
    return (
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<meta name="robots" content="noindex, nofollow">' +
      '<title>' + name + ' — Architecture &amp; Urban Design</title>' +
      '<style>body{font-family:Georgia,serif;margin:0;background:#fbfaf7;color:#26221c}' +
      '.h{background:#26221c;color:#f5efe2;padding:16px 40px;font-size:17px;letter-spacing:.4px}' +
      '.w{max-width:780px;margin:40px auto;padding:0 24px;line-height:1.7}' +
      'h1{font-size:28px}p{color:#4d463b}footer{padding:28px;color:#9a917f;font-size:12px;text-align:center}</style></head>' +
      '<body><div class="h">' + name + '</div><div class="w">' +
      '<h1>Architecture, interior and urban design practice</h1>' +
      '<p>Founded in 2009, we work on cultural, residential and adaptive-reuse projects in nine countries. Current studio: 24 people, 3 partners.</p>' +
      '<p>Enquiries and press materials are handled by the studio office. Visits by appointment only.</p>' +
      '</div><footer>© ' + new Date().getFullYear() + ' ' + name + ' Studio.</footer>' +
      PAD() + '</body></html>'
    );
  },
  () => {
    const name = 'Cobalt Bay Consulting';
    return (
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<meta name="robots" content="noindex, nofollow">' +
      '<title>' + name + ' — Advisory &amp; Operations</title>' +
      '<style>body{font-family:Helvetica,Arial,sans-serif;margin:0;background:#fff;color:#222}' +
      '.h{background:#0f4c81;color:#fff;padding:18px 40px;font-size:18px;font-weight:700}' +
      '.w{max-width:820px;margin:36px auto;padding:0 24px;line-height:1.65}' +
      'h1{font-size:25px}p{color:#3c4653}footer{padding:24px;color:#8b95a1;font-size:12px;text-align:center}</style></head>' +
      '<body><div class="h">' + name + '</div><div class="w">' +
      '<h1>Management consulting for mid-market operations</h1>' +
      '<p>Our teams help manufacturing, logistics and retail groups with process redesign, cost engineering and digital transformation. Typical engagement: 12–20 weeks, fixed fee.</p>' +
      '<p>References available under NDA. Contact the client desk for introductions.</p>' +
      '</div><footer>© ' + new Date().getFullYear() + ' ' + name + ' Ltd.</footer>' +
      PAD() + '</body></html>'
    );
  },
];

// Path shapes that indicate active scanning (never a real gozargah route).
const SCANNER_PATH =
  /(^|\/)(api|wp-admin|wp-login|wp-content|wp-json|admin|administrator|login|signin|dashboard|config|configuration|debug|status|server-status|health|phpmyadmin|actuator|solr|manager|console|shell|xmlrpc\.php|\.env|\.git|\.svn|\.htaccess|\.well-known|swagger|openapi|robots|sitemap\.xml|crossdomain\.xml|\.axr|axr|vless|trojan|shadowsocks|sub)(\/|\.php|\.json|\.txt|$)/i;

function wantsJson(request: Request, path: string): boolean {
  if (path.endsWith('.json')) return true;
  const accept = request.headers.get('accept') ?? '';
  return accept.includes('application/json') || accept.includes('text/json');
}

/**
 * Returns a benign decoy Response for scanner-shaped requests, or null when
 * the request should follow normal routing (real routes, or the plain
 * stealth landing).
 */
export function decoyResponse(request: Request, url: URL): Response | null {
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  const path = decodeURIComponent(url.pathname).replace(/\/+$/g, '') || '/';

  const scannerish =
    SCANNER_PATH.test(path) || /(^|\/)(axr|axr-manifest|axr-stream|axr-health)$/.test(path);

  // JSON-typed probes (API-ish shapes or the machine feed) → benign JSON API.
  if (wantsJson(request, path) && scannerish) {
    const body = JSON_DECOYS[crypto.getRandomValues(new Uint32Array(1))[0] % JSON_DECOYS.length]();
    return new Response(body, {
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  // Classic scanner path shapes → benign product pages.
  if (path !== '/' && scannerish) {
    const body = HTML_DECOYS[crypto.getRandomValues(new Uint32Array(1))[0] % HTML_DECOYS.length]();
    return new Response(body, {
      headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
    });
  }

  return null;
}
