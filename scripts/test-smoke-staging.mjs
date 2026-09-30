#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const smoke = path.join(root, 'scripts/smoke-staging.sh');
const dir = mkdtempSync(path.join(os.tmpdir(), 'gozargah-smoke-'));
const fakeCurl = path.join(dir, 'fake-curl');
const expectedVersion = JSON.parse(execFileSync(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(require(process.argv[1]).version))', path.join(root, 'package.json')], { encoding: 'utf8' }));

writeFileSync(fakeCurl, `#!/usr/bin/env node
const url = process.argv.at(-1);
if (process.env.SMOKE_CURL_FAIL_URL === url) process.exit(7);
if (url.endsWith('/healthz')) {
  process.stdout.write(process.env.SMOKE_HEALTH || JSON.stringify({ ok: true, version: process.env.SMOKE_VERSION }));
} else {
  process.stdout.write(process.env.SMOKE_STATUS || JSON.stringify({ dbOk: true, version: process.env.SMOKE_VERSION }));
}
`);
chmodSync(fakeCurl, 0o755);

function run(extra = {}) {
  return spawnSync('bash', [smoke], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      STAGING_BASE_URL: 'https://gozargah-staging.example.workers.dev',
      CURL_BIN: fakeCurl,
      CURL_TIMEOUT: '3',
      SMOKE_VERSION: expectedVersion,
      ...extra,
    },
  });
}

let count = 0;
try {
  let result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\/healthz reports ok=true/);
  assert.match(result.stdout, /\/gozargah\/api\/status reports dbOk=true/);
  count++;

  result = spawnSync('bash', [smoke], { cwd: root, encoding: 'utf8', env: { ...process.env, STAGING_BASE_URL: '', CURL_BIN: fakeCurl } });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /STAGING_BASE_URL is required/);
  count++;

  result = run({ STAGING_BASE_URL: 'http://staging.example.workers.dev' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must use HTTPS/);
  count++;

  result = run({ SMOKE_HEALTH: JSON.stringify({ ok: true, version: '0.0.0' }) });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /version mismatch/);
  count++;

  result = run({ SMOKE_STATUS: JSON.stringify({ dbOk: false, version: expectedVersion }) });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /dbOk is not true/);
  count++;

  result = run({ SMOKE_CURL_FAIL_URL: 'https://gozargah-staging.example.workers.dev/healthz' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /GET .*\/healthz failed/);
  count++;

  console.log(`Staging smoke-script tests: ${count}/${count} passed (mock HTTP responses; no deployment/network measurement).`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
