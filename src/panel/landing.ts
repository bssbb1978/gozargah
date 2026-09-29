/**
 * Gozargah — stealth landing page.
 * Any unknown GET shows this innocuous page: zero information leak
 * (nahan-style), just the brand poem about passages.
 */

import { emblemSvg } from './page';
import { LOGO_FAV_B64 } from '../assets/logo';
import { PANEL_CSS } from './styles';
import { VERSION } from '../config';

/**
 * 2.13 — benign-traffic hardening for the stealth decoy:
 *  - 3 subtly different poetic variants per language (content-variant rotation);
 *  - a random padding comment so the byte hash/length of the response is not
 *    constant across requests (defeats static page-hash fingerprinting).
 * The page still leaks nothing; variants only change wording/padding.
 */
const VARIANTS: Record<'fa' | 'en', Array<{ line1: string; line2: string }>> = {
  fa: [
    { line1: 'هر مسیری، از یک گذرگاه می‌گذرد.', line2: 'سدی، پیش از آبِ روان نایستد.' },
    { line1: 'گذرگاه‌ها همیشه باز هستند.', line2: 'آبِ روان، راه می‌یابد.' },
    { line1: 'برای رسیدن، لازم است گذر کرد.', line2: 'مسیرهای بسته، دیر می‌مانند.' },
  ],
  en: [
    { line1: 'Every road passes through a gateway.', line2: 'A dam cannot hold flowing water forever.' },
    { line1: 'Gateways stay open.', line2: 'Flowing water finds a way.' },
    { line1: 'To arrive, you pass through.', line2: 'Closed routes do not last.' },
  ],
};

function randomHex(len: number): string {
  const b = crypto.getRandomValues(new Uint8Array(Math.ceil(len / 2)));
  let s = '';
  for (const v of b) s += v.toString(16).padStart(2, '0');
  return s.slice(0, len);
}

export function landingHtml(lang: string): string {
  const fa = lang !== 'en';
  const title = fa ? 'گذرگاه' : 'Gozargah';
  const pool = VARIANTS[fa ? 'fa' : 'en'];
  const variant = pool[crypto.getRandomValues(new Uint32Array(1))[0] % pool.length];
  const line1 = variant.line1;
  const line2 = variant.line2;
  const pad = '<!-- gz:' + randomHex(16) + '-->';
  return (
    '<!DOCTYPE html><html lang="' + (fa ? 'fa' : 'en') + '" dir="' + (fa ? 'rtl' : 'ltr') + '"><head>' +
    '<meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="robots" content="noindex, nofollow">' +
    '<title>' + title + '</title>' +
    '<link rel="icon" href="' + LOGO_FAV_B64 + '">' +
    '<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css">' +
    '<style>' + PANEL_CSS +
    '.land{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:30px;gap:6px;position:relative}' +
    '.land::before{content:"";position:absolute;top:calc(50% - 210px);left:50%;transform:translateX(-50%);width:420px;height:260px;' +
    'background:radial-gradient(ellipse,rgba(0,217,255,0.10),rgba(124,58,237,0.06) 55%,transparent 75%);pointer-events:none}' +
    '.land .emblem{width:130px;margin-bottom:10px;position:relative}' +
    '.land h1{font-size:36px;font-weight:800;letter-spacing:.3px}' +
    '.land p{color:var(--gz-text-muted);font-size:15px;max-width:420px}' +
    '.land .p2{font-size:13px;color:var(--gz-text-disabled);font-style:italic}' +
    '.land footer{position:absolute;bottom:18px;font-size:11px;color:var(--gz-text-disabled)}' +
    '</style></head><body>' +
    '<div class="gz-bg"></div>' +
    '<div class="land">' +
    emblemSvg('', 'land') +
    '<h1 class="gradtext">' + title + '</h1>' +
    '<p>' + line1 + '</p>' +
    '<p class="p2">«' + line2 + '»</p>' +
    '<footer>Gozargah · v' + VERSION + '</footer>' +
    '</div>' + pad + '</body></html>'
  );
}
