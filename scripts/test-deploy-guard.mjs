#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const guard = path.join(root, 'scripts/guard-deploy-config.mjs');
const dir = mkdtempSync(path.join(os.tmpdir(), 'gozargah-deploy-guard-'));
const config = path.join(dir, 'wrangler.toml');
const zero = '00000000-0000-0000-0000-000000000000';
const real = '12345678-1234-1234-1234-123456789abc';
let count = 0;

function run(toml, ...args) {
  writeFileSync(config, toml);
  return spawnSync(process.execPath, [guard, '--config', config, ...args], { encoding: 'utf8' });
}

try {
  const stagingZero = `[[d1_databases]]\nbinding = "GZ_DB"\ndatabase_id = "${real}"\n\n[[env.staging.d1_databases]]\nbinding = "GZ_DB"\ndatabase_id = "${zero}"\n`;
  let result = run(stagingZero, '--env', 'staging');
  assert.equal(result.status, 1, 'non-dry-run staging deploy must reject the placeholder');
  assert.match(result.stderr, /all-zero placeholder/);
  count++;

  result = run(stagingZero, '--env=staging', '--dry-run');
  assert.equal(result.status, 0, 'dry-run must remain available with the placeholder');
  assert.match(result.stdout, /dry-run detected/);
  count++;

  result = run(stagingZero);
  assert.equal(result.status, 0, 'root deployment checks the real root D1 ID, not staging');
  count++;

  const stagingReal = stagingZero.replace(`database_id = "${zero}"`, `database_id = "${real}"`);
  result = run(stagingReal, '--env', 'staging');
  assert.equal(result.status, 0, 'staging deploy must pass after its own D1 ID is configured');
  count++;

  result = run('name = "missing-binding"\n');
  assert.equal(result.status, 1, 'non-dry-run deploy must fail closed if the target D1 binding is absent');
  assert.match(result.stderr, /no D1 database_id found/);
  count++;

  result = run('[[d1_databases]]\nbinding = "GZ_DB"\ndatabase_id = ""\n');
  assert.equal(result.status, 1, 'non-dry-run deploy must reject an empty D1 ID');
  assert.match(result.stderr, /empty or not a UUID/);
  count++;

  console.log(`Deploy guard tests: ${count}/${count} passed (placeholder blocked; dry-run and configured IDs allowed).`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
