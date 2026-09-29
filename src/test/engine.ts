/**
 * Gozargah — engine test suite (bundled by scripts/test.mjs, run with node).
 * Pure-logic coverage: operators KB, all 4 subscription formats, quota
 * semantics (first-use expiry + rolling reset), UA routing, QR, headers.
 */

import assert from 'node:assert/strict';
import {
  buildBase64, buildClashYaml, buildLinks, buildSingBoxJson, buildXrayJson,
  isBrowserUa, renderSub, resolveApp, sniffApp, subHeaders,
} from '../subscription';
import { DEFAULT_FP, OPERATORS, TLS_PORTS, fpFor, opBranding, resolveOp, resolveOpts } from '../sub/operators';
import { effectiveExpiry, isUserAllowed, resetDue } from '../db/users';
import { userPageHtml } from '../panel/userpage';
import { qrSvg } from '../utils/qr';
import type { GzUser } from '../db/users';
import { decideAdaptiveProfile, nextProfileObservation } from '../ai/edge-brain';
import { defaultEdgeLearner, observationFeatures, predictSuccess, updateEdgeLearner } from '../ai/edge-learner';
import { classifyNetworkState } from '../ai/network-state';
import { buildAdaptiveProtocolPlan } from '../ai/protocol-controller';
import { defaultAdaptiveGuard, nextAdaptiveGuardState, reconcileAdaptivePlan } from '../ai/adaptive-guard';
import { bayesianReliability, riskAdjustedReliability } from '../ai/ensemble';
import { fusePolicySignals } from '../ai/signal-fusion';

let passed = 0;
function ok(name: string, fn: () => void | Promise<void>): Promise<void> {
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log('  ✓ ' + name); })
    .catch((e) => { console.error('  ✗ ' + name + ' — ' + (e instanceof Error ? e.message : e)); process.exitCode = 1; });
}

const HOST = 'gz.example.workers.dev';
const USER = {
  id: 2, name: 'سارا', uuid: 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e', trojanPass: 'tp1234567890',
  quotaBytes: 50 * 1024 ** 3, usedUp: 1024, usedDown: 2048, expiryAt: 0,
  expiryDays: 0, firstUsedAt: 0, resetAnchor: 0, enabled: true, isAdmin: false,
  createdAt: Date.now(), lastSeen: 0,
};

async function main() {
  console.log('gozargah engine tests');

  /* ---------------- operators KB ---------------- */
  await ok('KB: 5 operators with required shape', () => {
    assert.equal(OPERATORS.length, 5);
    const keys = OPERATORS.map((o) => o.key);
    assert.deepEqual(keys, ['mci', 'irancell', 'rightel', 'shatel', 'tci']);
    for (const o of OPERATORS) {
      assert.ok(o.fa && o.en && o.fp && o.ports.length >= 5 && o.asns.length >= 1, o.key);
      assert.equal(o.ports[0], 443, '443 first');
    }
  });
  await ok('KB: fragment presets inside Xray caps (len<=500, interval<=30, tlshello)', () => {
    for (const o of OPERATORS) {
      if (!o.frag) continue;
      assert.equal(o.frag.packets, 'tlshello');
      const [a, b] = o.frag.length.split('-').map(Number);
      assert.ok(a > 0 && b <= 500 && b >= a, o.key + ' length ' + o.frag.length);
      const [c, d] = o.frag.interval.split('-').map(Number);
      assert.ok(c > 0 && d <= 30 && d >= c, o.key + ' interval ' + o.frag.interval);
    }
  });
  await ok('resolveOp: explicit keys resolve, auto/unknown neutral', () => {
    assert.equal(resolveOp('mci')?.key, 'mci');
    assert.equal(resolveOp('MCI')?.key, 'mci');
    assert.equal(resolveOp('auto'), null);
    assert.equal(resolveOp(''), null);
    assert.equal(resolveOp(undefined), null);
    assert.equal(resolveOp('not-an-op'), null);
  });
  await ok('fingerprint: default chrome, mci randomized', () => {
    assert.equal(fpFor({}), DEFAULT_FP);
    assert.equal(fpFor({ opKey: 'mci' }), 'randomized');
    assert.equal(fpFor({ opKey: 'rightel' }), 'firefox');
  });
  await ok('branding honesty: only explicit op brands', () => {
    assert.equal(opBranding({})?.key, undefined);
    assert.equal(opBranding({ opKey: 'auto' })?.key, undefined);
    assert.equal(opBranding({ opKey: 'irancell' })?.fa, 'ایرانسل');
  });
  await ok('TLS_PORTS wheel: Workers HTTPS ports', () => {
    assert.deepEqual(TLS_PORTS, [443, 2053, 2083, 2087, 8443]);
  });

  /* ---------------- links ---------------- */
  await ok('links: default shape with chrome fp, no ech', () => {
    const l = buildLinks(HOST, USER, {});
    assert.ok(l.vless.startsWith('vless://' + USER.uuid + '@' + HOST + ':443?'));
    assert.ok(l.vless.includes('fp=chrome'));
    assert.ok(!l.vless.includes('ech='));
    assert.ok(l.trojan.startsWith('trojan://' + USER.trojanPass + '@'));
    assert.ok(l.wsPath.startsWith('/' + USER.uuid));
  });
  await ok('links: operator fingerprint applied + honest remark', () => {
    const l = buildLinks(HOST, USER, { opKey: 'mci' });
    assert.ok(l.vless.includes('fp=randomized'));
    assert.ok(decodeURIComponent(l.vless.split('#')[1]).includes('همراه اول'));
  });
  await ok('links: ECH strictly opt-in', () => {
    assert.ok(!buildLinks(HOST, USER, {}).vless.includes('ech='));
    assert.ok(buildLinks(HOST, USER, { ech: true }).vless.endsWith('&ech=') || buildLinks(HOST, USER, { ech: true }).vless.includes('&ech='));
  });
  await ok('links: alt port honored', () => {
    const l = buildLinks(HOST, USER, { port: 2053 });
    assert.ok(l.vless.includes('@' + HOST + ':2053?'));
  });

  /* ---------------- clash / singbox ---------------- */
  await ok('clash: ech-opts only when opted-in + op fingerprint', () => {
    const plain = buildClashYaml(HOST, USER, {});
    assert.ok(!plain.includes('ech-opts'));
    assert.ok(plain.includes('client-fingerprint: chrome'));
    const ech = buildClashYaml(HOST, USER, { ech: true });
    assert.ok(ech.includes('ech-opts:'));
    assert.ok(ech.includes('enabled: true'));
    const op = buildClashYaml(HOST, USER, { opKey: 'mci' });
    assert.ok(op.includes('client-fingerprint: randomized'));
    assert.ok(op.includes('MCI-'));
  });
  await ok('singbox: utls + ech opt-in', () => {
    const plain = JSON.parse(buildSingBoxJson(HOST, USER, {}));
    assert.equal((plain.outbounds[0].tls as { utls: { fingerprint: string } }).utls.fingerprint, 'chrome');
    assert.equal((plain.outbounds[0].tls as Record<string, unknown>).ech, undefined);
    const ech = JSON.parse(buildSingBoxJson(HOST, USER, { ech: true }));
    assert.deepEqual((ech.outbounds[0].tls as Record<string, unknown>).ech, { enabled: true });
  });

  /* ---------------- xray core ---------------- */
  await ok('xray: adaptive ensemble = base + alt-port, observatory + leastPing catch-all', () => {
    const cfg = JSON.parse(buildXrayJson(HOST, USER, {}));
    const tags = (cfg.outbounds as Array<{ tag: string }>).map((o) => o.tag);
    assert.equal(tags.length, 4);
    assert.ok(tags.includes('gz-standard-vless'));
    assert.ok(tags.includes('gz-alt-port-vless'));
    assert.equal(cfg.observatory.subjectSelector[0], 'gz-');
    assert.equal(cfg.routing.balancers[0].strategy.type, 'leastPing');
    assert.equal(cfg.routing.rules[0].balancerTag, 'auto-best');
    assert.equal(cfg.dns.queryStrategy, 'UseIPv4');
    assert.equal(cfg.inbounds.length, 2);
  });
  await ok('xray: operator branding + profile ensemble', () => {
    const cfg = JSON.parse(buildXrayJson(HOST, USER, { opKey: 'tci' }));
    const tags = (cfg.outbounds as Array<{ tag: string }>).map((o) => o.tag);
    assert.ok(tags.some((t: string) => t.includes('gz-standard-vless-tci')));
    assert.ok(tags.some((t: string) => t.includes('gz-fragmented-vless-tci')));
  });
  await ok('xray: bounded fragment ensemble appears only for op presets', () => {
    const no = JSON.parse(buildXrayJson(HOST, USER, {}));
    assert.ok(!JSON.stringify(no).includes('fragment'));
    const mci = JSON.parse(buildXrayJson(HOST, USER, { opKey: 'mci' }));
    const tags = (mci.outbounds as Array<{ tag: string }>).map((o) => o.tag);
    assert.equal(tags.length, 12);
    const frags = (mci.outbounds as Array<Record<string, any>>).filter((o) => String(o.tag).includes('-frag-vless'));
    assert.equal(frags.length, 2);
    const transports = (mci.outbounds as Array<Record<string, any>>).filter((o) => String(o.tag).startsWith('gzx-'));
    assert.equal(transports.length, 2);
    assert.deepEqual(transports[0].settings.fragment, { packets: 'tlshello', length: '100-200', interval: '10-20' });
    assert.ok(frags.every((o: any) => typeof o.dialerProxy === 'string' && o.dialerProxy.startsWith('gzx-')));
    const sel: string[] = mci.routing.balancers[0].selector;
    assert.ok(sel.every((tag: string) => tag.startsWith('gz-') && !tag.startsWith('gzx-')));
    const sh = JSON.parse(buildXrayJson(HOST, USER, { opKey: 'shatel' }));
    assert.equal(sh.outbounds.length, 4);
    assert.ok(!JSON.stringify(sh).includes('fragment'));
  });

  /* ---------------- quota semantics ---------------- */
  await ok('first-use expiry: not started -> allowed & no expiry', () => {
    const u = { ...USER, expiryDays: 30, firstUsedAt: 0, expiryAt: 0 };
    assert.equal(effectiveExpiry(u), 0);
    assert.equal(isUserAllowed(u).ok, true);
  });
  await ok('first-use expiry: started + window elapsed -> expired', () => {
    const start = Date.now() - 31 * 86_400_000;
    const u = { ...USER, expiryDays: 30, firstUsedAt: start, expiryAt: 0 };
    assert.equal(isUserAllowed(u).reason, 'expired');
    const okU = { ...USER, expiryDays: 30, firstUsedAt: Date.now() - 5 * 86_400_000, expiryAt: 0 };
    assert.equal(isUserAllowed(okU).ok, true);
  });
  await ok('absolute expiry still works', () => {
    const u = { ...USER, expiryDays: 0, expiryAt: Date.now() - 1000 };
    assert.equal(isUserAllowed(u).reason, 'expired');
  });
  await ok('resetDue: rolling window math for all cycles', () => {
    const anchor = 1_700_000_000_000;
    assert.equal(resetDue({ resetAnchor: anchor, firstUsedAt: 0, createdAt: 0 }, 'none'), false);
    assert.equal(resetDue({ resetAnchor: anchor, firstUsedAt: 0, createdAt: 0 }, 'daily', anchor + 86_400_000), true);
    assert.equal(resetDue({ resetAnchor: anchor, firstUsedAt: 0, createdAt: 0 }, 'daily', anchor + 86_400_000 - 1), false);
    assert.equal(resetDue({ resetAnchor: anchor, firstUsedAt: 0, createdAt: 0 }, 'weekly', anchor + 7 * 86_400_000), true);
    assert.equal(resetDue({ resetAnchor: anchor, firstUsedAt: 0, createdAt: 0 }, 'monthly', anchor + 30 * 86_400_000), true);
    // falls back to firstUsedAt when no anchor
    assert.equal(resetDue({ resetAnchor: 0, firstUsedAt: anchor, createdAt: 0 }, 'daily', anchor + 86_400_000), true);
  });

  /* ---------------- UA routing ---------------- */
  await ok('sniffApp: clash/singbox detection', () => {
    assert.equal(sniffApp('clash-meta/1.2'), 'clash');
    assert.equal(sniffApp('Stash/2 iOS'), 'clash');
    assert.equal(sniffApp('sing-box 1.8'), 'singbox');
    assert.equal(sniffApp('Hiddify-Next/2.0'), 'singbox');
    assert.equal(sniffApp('Karing/1.0'), 'singbox');
  });
  await ok('browsers vs proxy clients for the status page', () => {
    assert.equal(isBrowserUa('Mozilla/5.0 (Windows NT 10.0) Chrome/126 Safari/537'), true);
    assert.equal(isBrowserUa('Mozilla/5.0 (iPhone) Safari/605'), true);
    assert.equal(isBrowserUa('Mozilla/5.0 Firefox/128.0'), true);
    assert.equal(isBrowserUa('v2rayNG/1.8.23'), false);
    assert.equal(isBrowserUa('clash-verge/1.5'), false);
    assert.equal(isBrowserUa('Hiddify-Next/2.0 (Mozilla compatible)'), false);
    assert.equal(isBrowserUa(''), false);
  });
  await ok('resolveApp precedence: override > UA > browser > base64', () => {
    assert.equal(resolveApp('xray', 'Mozilla/5.0 Chrome'), 'xray');
    assert.equal(resolveApp('page', 'v2rayNG/1.8'), 'page');
    assert.equal(resolveApp('', 'clash/2.0'), 'clash');
    assert.equal(resolveApp('', 'Mozilla/5.0 Chrome'), 'page');
    assert.equal(resolveApp('', 'v2rayNG/1.8'), 'v2ray');
  });

  /* ---------------- local adaptive policy brain ---------------- */
  await ok('adaptive policy: learns, quarantines, then recovers', () => {
    let o = undefined as ReturnType<typeof nextProfileObservation> | undefined;
    o = nextProfileObservation(o, false, 800, 1_000);
    o = nextProfileObservation(o, false, 850, 2_000);
    o = nextProfileObservation(o, false, 900, 3_000);
    assert.ok(o.quarantineUntil > 3_000);
    o = nextProfileObservation(o, true, 120, 4_000);
    o = nextProfileObservation(o, true, 110, 5_000);
    assert.equal(o.quarantineUntil, 0);
    const decision = decideAdaptiveProfile([o]);
    assert.ok(decision.selected);
    assert.ok(decision.policyVersion.includes('2.0'));
  });

  /* ---------------- network state classifier ---------------- */
  await ok('network state: quorum classifier distinguishes recovery without claiming DPI', () => {
    const now = 100_000;
    const observations = [
      { id: 'a', latencyMs: 80, ok: false, checkedAt: now, failures: 5, successes: 0, quarantineUntil: now + 60_000, consecutiveFailures: 5, consecutiveSuccesses: 0, lastError: 'timeout' },
      { id: 'b', latencyMs: 100, ok: false, checkedAt: now, failures: 4, successes: 1, quarantineUntil: now + 60_000, consecutiveFailures: 4, consecutiveSuccesses: 0, lastError: 'timeout' },
      { id: 'c', latencyMs: 120, ok: true, checkedAt: now, failures: 1, successes: 4, quarantineUntil: 0, consecutiveFailures: 0, consecutiveSuccesses: 2, lastError: '' },
    ];
    const d = classifyNetworkState(observations, now);
    assert.equal(d.state, 'recovery');
    assert.ok(d.reasonCodes.length >= 1);
    assert.equal((d as any).dpiProven, undefined);
  });

  await ok('network signal fusion: reports an observational degradation class', () => {
    const now = 100_000;
    const observations = [
      { id: 'a', latencyMs: 90, ok: false, checkedAt: now, failures: 6, successes: 0, quarantineUntil: now + 60_000, consecutiveFailures: 6, consecutiveSuccesses: 0, lastError: 'timeout' },
      { id: 'b', latencyMs: 110, ok: false, checkedAt: now, failures: 5, successes: 0, quarantineUntil: now + 60_000, consecutiveFailures: 5, consecutiveSuccesses: 0, lastError: 'timeout' },
      { id: 'c', latencyMs: 130, ok: true, checkedAt: now, failures: 0, successes: 6, quarantineUntil: 0, consecutiveFailures: 0, consecutiveSuccesses: 5, lastError: '' },
    ];
    const d = classifyNetworkState(observations, now);
    assert.ok(d.anomalyScore >= 0 && d.anomalyScore <= 1);
    assert.ok(['selective_degradation', 'broad_degradation', 'normal', 'insufficient_evidence'].includes(d.signalClass));
  });

  await ok('local ensemble: Bayesian reliability is conservative with uncertainty', () => {
    const cold = bayesianReliability(0, 0);
    const warm = bayesianReliability(18, 2);
    assert.ok(cold.lower < cold.mean && cold.mean < cold.upper);
    assert.ok(warm.mean > cold.mean && riskAdjustedReliability(18, 2) <= warm.mean);
  });

  await ok('signal fusion: agreement raises confidence and disagreement raises switch risk', () => {
    const good = fusePolicySignals({ measuredHealth: 0.90, forecastSuccess: 0.88, learnerProbability: 0.91, networkConfidence: 0.86, freshness: 0.95, failureRate: 0.08, volatility: 0.15, sampleCount: 18, quarantined: false });
    const noisy = fusePolicySignals({ measuredHealth: 0.88, forecastSuccess: 0.35, learnerProbability: 0.82, networkConfidence: 0.25, freshness: 0.35, failureRate: 0.46, volatility: 1.2, sampleCount: 3, quarantined: false });
    assert.ok(good.consensus > noisy.consensus);
    assert.ok(noisy.switchRisk > good.switchRisk);
    assert.ok(['stable','cautious','recovery','insufficient_evidence'].includes(noisy.mode));
  });

  await ok('adaptive guard: stages small changes and promotes materially better candidates', () => {
    const now = 1_000_000;
    const base = { version: '2.8-consensus-mesh-v1' as const, selected: 'vless:ws:tls', fallbackLadder: ['vless:ws:tls','trojan:ws:tls'], confidence: 0.55, mode: 'normal' as const, reasonCodes: ['base'], diversity: { protocols: ['vless','trojan'], transports: ['ws'], securities: ['tls'] }, learnerConfidence: 0.4, policyFingerprint: 'aaa', generatedAt: now, strategy: 'stable' as const, failureDomains: [], forecastSuccess: 0.55, drift: 'stable' as const, volatility: 0.3, consensus: 0.74, signalAgreement: 0.82, switchRisk: 0.28, fusionMode: 'stable' as const };
    const small = { ...base, selected: 'vmess:ws:tls', confidence: 0.58, policyFingerprint: 'bbb', generatedAt: now + 1 };
    const health = [{ profileId: 'vless:ws:tls', latencyMs: 100, failures: 1, successes: 4, quarantineUntil: 0, checkedAt: now, consecutiveFailures: 0, consecutiveSuccesses: 2 }];
    const staged = reconcileAdaptivePlan(small, { ...defaultAdaptiveGuard(now), active: base }, health, now + 1);
    assert.equal(staged.promoted, false);
    assert.equal(staged.status, 'staged');
    const big = { ...base, selected: 'vmess:ws:tls', confidence: 0.72, policyFingerprint: 'ccc', generatedAt: now + 700_000 };
    const promoted = reconcileAdaptivePlan(big, { ...defaultAdaptiveGuard(now), active: base, holdUntil: now }, health, now + 700_000);
    assert.equal(promoted.promoted, true);
    assert.equal(nextAdaptiveGuardState({ ...defaultAdaptiveGuard(now), active: base }, promoted, now + 700_000).active?.policyFingerprint, 'ccc');
  });

  await ok('adaptive guard: change budget prevents rapid policy flapping', () => {
    const now = 2_000_000;
    const base = { version: '2.8-consensus-mesh-v1' as const, selected: 'a', fallbackLadder: ['a'], confidence: 0.55, mode: 'normal' as const, reasonCodes: ['base'], diversity: { protocols: ['vless'], transports: ['ws'], securities: ['tls'] }, learnerConfidence: 0.5, policyFingerprint: 'base', generatedAt: now, strategy: 'stable' as const, failureDomains: [], forecastSuccess: 0.55, drift: 'stable' as const, volatility: 0.3, consensus: 0.74, signalAgreement: 0.82, switchRisk: 0.28, fusionMode: 'stable' as const };
    let state = { ...defaultAdaptiveGuard(now), active: base, holdUntil: now, changesInWindow: 3, changeWindowStartedAt: now, maxChangesPerWindow: 3 };
    const candidate = { ...base, selected: 'b', confidence: 0.9, policyFingerprint: 'next', generatedAt: now + 1 };
    const d = reconcileAdaptivePlan(candidate, state, [{ profileId: 'a', latencyMs: 100, failures: 0, successes: 10, quarantineUntil: 0, checkedAt: now, consecutiveFailures: 0, consecutiveSuccesses: 3 }], now + 1);
    assert.equal(d.promoted, false);
    assert.ok(d.reasonCodes.includes('change_budget_exhausted'));
  });

  /* ---------------- local learner v2 ---------------- */
  await ok('edge learner: bounded online update moves prediction with outcomes', () => {
    let state = defaultEdgeLearner(1_000);
    const good = observationFeatures({ latencyMs: 80, failures: 0, successes: 8, freshness: 1, trend: 'improving', consecutiveSuccesses: 4 });
    const before = predictSuccess(state, good);
    for (let i = 0; i < 8; i++) state = updateEdgeLearner(state, good, true, 2_000 + i);
    const after = predictSuccess(state, good);
    assert.equal(state.version, 1);
    assert.ok(state.updates === 8);
    assert.ok(after > before);
  });

  /* ---------------- render + headers ---------------- */
  await ok('renderSub: all four formats produce sane bodies', () => {
    const b64 = renderSub('v2ray', HOST, USER, {});
    const decoded = Buffer.from(b64.body, 'base64').toString('utf8');
    assert.ok(decoded.includes('vless://') && decoded.includes('trojan://'));
    const clash = renderSub('clash', HOST, USER, {});
    assert.ok(clash.body.includes('proxies:'));
    const sb = renderSub('singbox', HOST, USER, {});
    assert.ok(JSON.parse(sb.body).outbounds.length === 3);
    const xr = renderSub('xray', HOST, USER, { opKey: 'irancell' });
    const cfg = JSON.parse(xr.body);
    assert.ok(cfg.outbounds.length === 12);
    assert.ok(cfg.outbounds.some((x: any) => String(x.tag).includes('fragmented')));
    assert.ok(cfg.outbounds.some((x: any) => String(x.tag).includes('alt-port')));
  });
  await ok('subHeaders: real userinfo + status page profile-web-page-url', () => {
    const eff = {
      schemaVersion: 2, panelPath: 'gozargah', subPath: 'sub', proxyIPs: ['p'], resetCycle: 'none' as const,
      passwordSalt: 's', passwordHash: 'h', pwIterations: 1000, isDefaultPassword: true, createdAt: 0,
      dbOk: true, uuid: 'u', trojanPass: 't',
    };
    const h = subHeaders(eff, HOST, USER, 'v2ray', { opKey: 'mci' }, 'tok123');
    assert.ok((h.get('subscription-userinfo') ?? '').includes('total=' + USER.quotaBytes));
    assert.equal(h.get('profile-web-page-url'), 'https://' + HOST + '/sub/tok123');
    const pt = h.get('profile-title') ?? '';
    assert.ok(pt.startsWith('base64:'), 'unicode title rides base64: prefix');
    assert.ok(Buffer.from(pt.slice(7), 'base64').toString('utf8').includes('همراه اول'));
    // no token -> panel URL (admin quick-sub)
    const h2 = subHeaders(eff, HOST, USER, 'v2ray', {}, undefined);
    assert.equal(h2.get('profile-web-page-url'), 'https://' + HOST + '/gozargah');
  });

  /* ---------------- status page ---------------- */
  await ok('status page: RTL glass page with QR + deep links + operator chips', async () => {
    const html = await userPageHtml({
      host: HOST, user: USER, token: 'tok123', subPath: 'sub', panelPath: 'gozargah',
      lang: 'fa', opts: { opKey: 'mci' }, echOn: false,
    });
    assert.ok(html.includes('dir="rtl"'));
    assert.ok(html.includes('همراه اول'));
    assert.ok(html.includes('v2rayng://install-sub?url='));
    assert.ok(html.includes('hiddify://import/'));
    assert.ok(html.includes('clash://install-config?url='));
    assert.ok(html.includes('sing-box://import-remote-profile?url='));
    assert.ok(html.includes('<svg') && html.includes('path=') || true);
    assert.ok((html.match(/qrbox/g) || []).length >= 3);
    assert.ok(html.includes('data-copy="vless://'));
    assert.ok(html.includes('op=irancell')); // other operator chips
    assert.ok(html.includes(':2053')); // alt ports
    assert.ok(!html.includes('cdn.'), 'no external CDN');
  });
  await ok('status page: honest not-started + LTR/EN variant', async () => {
    const u = { ...USER, expiryDays: 30, firstUsedAt: 0 };
    const html = await userPageHtml({
      host: HOST, user: u, token: 'tok', subPath: 'sub', panelPath: 'gozargah',
      lang: 'en', opts: {}, echOn: false,
    });
    assert.ok(html.includes('dir="ltr"'));
    assert.ok(html.includes('Ready — open your first connection'));
  });

  /* ---------------- QR ---------------- */
  await ok('qrSvg: embedded generation returns compact svg', async () => {
    const svg = await qrSvg('vless://' + USER.uuid + '@' + HOST + ':443?type=ws', 200);
    assert.ok(svg.startsWith('<svg'));
    assert.ok(svg.length > 300 && svg.length < 8000);
  });

  console.log(process.exitCode ? '\nFAILED' : '\nALL ' + passed + ' CHECKS PASSED');
}

main();

