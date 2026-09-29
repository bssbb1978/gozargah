/**
 * 2.17 — pressure engine + canary manifest wiring (pure-logic suite).
 *
 * The pressure engine fuses fleet canary evidence, harvest freshness, and the
 * aggregate regime label into a 0-3 level that drives the dynamic manifest
 * levers. All input is aggregate statistics (ok/fail + timestamps) — no
 * payloads, no DPI detection, no model runtime.
 */

import assert from 'node:assert/strict';
import { assessPressure, canaryEvidence } from '../ai/pressure';
import { buildAxrManifest, manifestCanonical, manifestSign } from '../subscription';

let passed = 0;
function ok(name: string, fn: () => void | Promise<void>): Promise<void> {
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log('  ✓ ' + name); })
    .catch((e) => { console.error('  ✗ ' + name + ' — ' + (e instanceof Error ? e.message : e)); process.exitCode = 1; });
}

const NOW = 1_750_000_000_000;
const USER = { uuid: 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e' };

async function main() {
  console.log('gozargah pressure tests');

  /* ---------------- assessPressure: pure rules ---------------- */
  await ok('baseline: no evidence -> level 0, 360 min, 90 s, web', () => {
    const p = assessPressure({ canaryConfigured: false, canaryFailFrac: null, canaryAgeMin: null, harvestAgeMin: null, regimeState: 'stable' });
    assert.equal(p.level, 0);
    assert.deepEqual(p.reasons, ['baseline']);
    assert.equal(p.rotationMinutes, 360);
    assert.equal(p.probeIntervalMs, 90_000);
    assert.equal(p.flowProfile, 'web');
  });

  await ok('absence of evidence is NOT pressure (never probed / never harvested)', () => {
    // A canary that was configured but never probed, and a harvest that never
    // happened, must not raise pressure (no false alarm on fresh installs).
    const p = assessPressure({ canaryConfigured: true, canaryFailFrac: null, canaryAgeMin: null, harvestAgeMin: null, regimeState: 'stable' });
    assert.equal(p.level, 0);
    assert.deepEqual(p.reasons, ['baseline']);
  });

  await ok('fleet canary failures (>=50% recent) -> level 3, 45 min, 15 s, video', () => {
    const p = assessPressure({ canaryConfigured: true, canaryFailFrac: 0.67, canaryAgeMin: 1, harvestAgeMin: 5, regimeState: 'stable' });
    assert.equal(p.level, 3);
    assert.ok(p.reasons.includes('canary_fleet_failures'));
    assert.equal(p.rotationMinutes, 45);
    assert.equal(p.probeIntervalMs, 15_000);
    assert.equal(p.flowProfile, 'video');
  });

  await ok('regime step change -> level 2, 90 min, 30 s, video', () => {
    const p = assessPressure({ canaryConfigured: false, canaryFailFrac: null, canaryAgeMin: null, harvestAgeMin: 10, regimeState: 'suspected_change' });
    assert.equal(p.level, 2);
    assert.ok(p.reasons.includes('regime_step_change'));
    assert.equal(p.probeIntervalMs, 30_000);
    assert.equal(p.flowProfile, 'video');
  });

  await ok('stale-but-once-fresh harvest (>6h) -> level 2', () => {
    const p = assessPressure({ canaryConfigured: false, canaryFailFrac: null, canaryAgeMin: null, harvestAgeMin: 700, regimeState: 'stable' });
    assert.equal(p.level, 2);
    assert.ok(p.reasons.includes('harvest_stale'));
  });

  await ok('watch regime + stale canary -> level 1, chat profile', () => {
    const p = assessPressure({ canaryConfigured: true, canaryFailFrac: null, canaryAgeMin: 45, harvestAgeMin: 30, regimeState: 'watch' });
    assert.equal(p.level, 1);
    assert.ok(p.reasons.includes('regime_watch'));
    assert.ok(p.reasons.includes('canary_stale'));
    assert.equal(p.probeIntervalMs, 60_000);
    assert.equal(p.flowProfile, 'chat');
  });

  await ok('canary failure dominates a stale harvest (level = max, not sum)', () => {
    // Two independent level-2/3 signals: level is the MAX (3), not a sum.
    const p = assessPressure({ canaryConfigured: true, canaryFailFrac: 0.5, canaryAgeMin: 0, harvestAgeMin: 900, regimeState: 'stable' });
    assert.equal(p.level, 3);
    assert.deepEqual(p.reasons.sort(), ['canary_fleet_failures', 'harvest_stale']);
  });

  /* ---------------- canaryEvidence ---------------- */
  await ok('evidence: <3 recent samples -> null failFrac; age from newest', () => {
    const { failFrac, ageMin } = canaryEvidence(
      [{ ok: false, at: NOW - 5 * 60_000 }, { ok: true, at: NOW - 10 * 60_000 }],
      NOW,
    );
    assert.equal(failFrac, null);
    assert.equal(ageMin, 5);
  });

  await ok('evidence: 1 of 4 recent failed -> 0.25; stale results excluded', () => {
    const { failFrac, ageMin } = canaryEvidence(
      [
        { ok: true, at: NOW - 1 * 60_000 },
        { ok: false, at: NOW - 5 * 60_000 },
        { ok: true, at: NOW - 20 * 60_000 },
        { ok: true, at: NOW - 29 * 60_000 },
        { ok: false, at: NOW - 90 * 60_000 }, // > 30 min: outside the window
      ],
      NOW,
    );
    assert.equal(failFrac, 0.25);
    assert.equal(ageMin, 1);
  });

  await ok('evidence: empty list -> (null, null)', () => {
    const e = canaryEvidence([]);
    assert.equal(e.failFrac, null);
    assert.equal(e.ageMin, null);
  });

  /* ---------------- manifest wiring (no D1: env path) ---------------- */
  await ok('manifest: canary host rides in signed entries + convenience pointer', async () => {
    const manifest = JSON.parse(await buildAxrManifest(
      'host.example.com', USER, { AXR_CANARY_HOST: 'canary.example.com' } as never, 'token-xyz',
    )) as Record<string, any>;
    const canaryEntry = (manifest.entries as Array<Record<string, string>>).find((e) => e.role === 'canary');
    assert.ok(canaryEntry, 'canary entry present');
    assert.equal(canaryEntry.host, 'canary.example.com');
    assert.equal(manifest.canary.host, 'canary.example.com');
    assert.equal(manifest.canary.expect, 'ok');
    // The canary host is inside the HMAC coverage (entries field).
    const canonical = manifestCanonical(manifest);
    assert.ok(canonical.includes('canary.example.com:canary'), 'canary in canonical');
    const sig = await manifestSign(canonical, 'token-xyz');
    assert.equal(sig, manifest.manifest_sig, 'signature verifies with canary inside');
  });

  await ok('manifest: no canary configured -> no canary entry/field', async () => {
    const manifest = JSON.parse(await buildAxrManifest(
      'host.example.com', USER, {} as never, 'token-xyz',
    )) as Record<string, any>;
    assert.equal((manifest.entries as Array<Record<string, string>>).some((e) => e.role === 'canary'), false);
    assert.equal(manifest.canary, undefined);
  });

  await ok('manifest: unvalidated canary host is dropped (junk, no dot, empty)', async () => {
    // (A pasted "https://host/x" is intentionally normalized to "host" — same
    // lenient parse as FRONTING_RELAY_HOST; scheme/path stripping is a feature.)
    for (const bad of ['canary_example.com', 'bad host.com', 'xn--', '']) {
      const manifest = JSON.parse(await buildAxrManifest(
        'host.example.com', USER, { AXR_CANARY_HOST: bad } as never, 'token-xyz',
      )) as Record<string, any>;
      assert.equal((manifest.entries as Array<Record<string, string>>).some((e) => e.role === 'canary'), false, bad);
    }
  });

  await ok('manifest: baseline dynamics without D1 (90 s probes, web profile)', async () => {
    const manifest = JSON.parse(await buildAxrManifest(
      'host.example.com', USER, {} as never, 'token-xyz',
    )) as Record<string, any>;
    assert.equal(manifest.reconnect.probe_interval_ms, 90_000);
    assert.equal(manifest.flow_profile.mode, 'web');
  });

  console.log('pressure: all ' + passed + ' checks passed');
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
