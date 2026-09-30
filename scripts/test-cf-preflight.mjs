#!/usr/bin/env node
/**
 * Offline tests for scripts/cf-preflight.mjs.
 *
 * A local HTTP server stands in for api.cloudflare.com (CF_API_BASE), so these
 * tests never touch the network and never need real Cloudflare credentials. They
 * pin down: user-token vs account-owned-token detection, the D1 visibility
 * notice path, D1 ID cross-checking, guard integration, exit codes, and the
 * guarantee that the token value is never echoed.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const preflight = path.join(root, 'scripts/cf-preflight.mjs');
const SECRET = 'cfut_do_not_leak_1234567890abcdef';
const ACCOUNT = '023e105f4ecef8ad9ca31a8372d0c353';
const REAL_D1_A = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const REAL_D1_B = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';

const dir = mkdtempSync(path.join(os.tmpdir(), 'gozargah-cf-preflight-'));

/** Scenario switches for the fake Cloudflare API. */
const scenario = { userToken: true, verifyOk: true, workers: 'list', d1: 'list' };

const server = createServer((request, response) => {
  const send = (status, body) => {
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(JSON.stringify(body));
  };
  const route = request.url || '';
  if (route === '/user/tokens/verify') {
    if (!scenario.verifyOk) return send(403, { success: false, errors: [{ code: 1000, message: 'Invalid API Token' }] });
    if (scenario.userToken) return send(200, { success: true, result: { id: 'tok-1', status: 'active' } });
    return send(403, { success: false, errors: [{ code: 1000, message: 'Invalid API Token' }] });
  }
  if (route === `/accounts/${ACCOUNT}/tokens/verify`) {
    if (!scenario.verifyOk) return send(403, { success: false, errors: [{ code: 1000, message: 'Invalid API Token' }] });
    return send(200, { success: true, result: { id: 'tok-2', status: 'active' } });
  }
  if (route === `/accounts/${ACCOUNT}/workers/scripts`) {
    if (scenario.workers === 'forbidden') return send(403, { success: false, errors: [{ code: 10000, message: 'Authentication error' }] });
    return send(200, { success: true, result: [{ id: 'gozargah' }, { id: 'gozargah-staging' }] });
  }
  if (route === `/accounts/${ACCOUNT}/d1/database`) {
    if (scenario.d1 === 'forbidden') return send(403, { success: false, errors: [{ code: 7403, message: 'Authentication error' }] });
    return send(200, {
      success: true,
      result: [
        { name: 'gozargah', uuid: REAL_D1_A },
        { name: 'gozargah-staging', uuid: REAL_D1_B },
      ],
    });
  }
  return send(404, { success: false, errors: [{ code: 7003, message: 'No route for that URI' }] });
});

/**
 * The mock API runs inside this process, so the child must be started
 * asynchronously: a synchronous spawn would block the event loop and the child
 * would wait forever for an HTTP response that this process can no longer send.
 */
function run(extraEnv = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [preflight], {
      cwd: root,
      env: {
        ...process.env,
        CF_API_BASE: `http://127.0.0.1:${server.address().port}`,
        CLOUDFLARE_API_TOKEN: SECRET,
        CLOUDFLARE_ACCOUNT_ID: ACCOUNT,
        ...extraEnv,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function writeConfig(name, rootId, stagingId, rootName = 'gozargah', stagingName = 'gozargah-staging') {
  const file = path.join(dir, name);
  writeFileSync(
    file,
    [
      'name = "gozargah"',
      'main = "src/index.ts"',
      'compatibility_date = "2025-01-15"',
      '',
      '[[d1_databases]]',
      'binding = "GZ_DB"',
      `database_name = "${rootName}"`,
      `database_id = "${rootId}"`,
      '',
      '[env.staging]',
      'name = "gozargah-staging"',
      '',
      '[[env.staging.d1_databases]]',
      'binding = "GZ_DB"',
      `database_name = "${stagingName}"`,
      `database_id = "${stagingId}"`,
      'migrations_dir = "migrations"',
      '',
    ].join('\n'),
  );
  return file;
}

let count = 0;
try {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  /* 1 — placeholders in the real repository config: verified token, blocked deploy. */
  let result = await run();
  assert.equal(result.status, 1, 'placeholder D1 IDs must produce a blocking preflight');
  assert.match(result.stdout, /verified as a user API token/);
  assert.match(result.stdout, /root \(production\): deploy guard would block/);
  assert.match(result.stdout, /env\.staging: deploy guard would block/);
  assert.match(result.stdout, /all-zero placeholder/);
  count += 1;

  /* 2 — account-owned token (code 1000 on the user endpoint), fully configured target. */
  scenario.userToken = false;
  const goodConfig = writeConfig('good.toml', REAL_D1_A, REAL_D1_B);
  result = await run({ WRANGLER_CONFIG: goodConfig });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /verified as an account-owned API token/);
  assert.match(result.stdout, /Worker "gozargah-staging" exists/);
  assert.match(result.stdout, /root \(production\): deploy guard passes for D1 ID/);
  assert.match(result.stdout, /env\.staging: deploy guard passes/);
  assert.match(result.stdout, /exists in this account as "gozargah-staging"/);
  assert.match(result.stdout, /all checks passed/);
  count += 1;

  /* 3 — a D1 ID that is not in the account must block. */
  const wrongConfig = writeConfig('wrong.toml', 'cccccccc-3333-4333-8333-cccccccccccc', REAL_D1_B);
  result = await run({ WRANGLER_CONFIG: wrongConfig });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /is not one of the databases visible in this account/);
  count += 1;

  /* 4 — missing D1 read scope is a notice, not a blocker; scoped Editor still passes. */
  scenario.d1 = 'forbidden';
  scenario.workers = 'forbidden';
  result = await run({ WRANGLER_CONFIG: goodConfig });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Token cannot list Workers/);
  assert.match(result.stdout, /expected for a token scoped to a single Worker/);
  assert.match(result.stdout, /D1 database list unavailable/);
  assert.match(result.stdout, /does not block a Worker deploy/);
  count += 1;

  /* 5 — a dead token fails closed, with the code that matters. */
  scenario.verifyOk = false;
  scenario.d1 = 'list';
  scenario.workers = 'list';
  result = await run({ WRANGLER_CONFIG: goodConfig });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /neither a valid user token nor a valid account token/);
  assert.match(result.stdout, /code 1000/);
  count += 1;

  /* 6 — missing secrets are reported without a network call. */
  scenario.verifyOk = true;
  result = await run({ CLOUDFLARE_API_TOKEN: '', CLOUDFLARE_ACCOUNT_ID: '' });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /CLOUDFLARE_API_TOKEN is not set/);
  assert.match(result.stdout, /CLOUDFLARE_ACCOUNT_ID is not set/);
  assert.doesNotMatch(result.stdout, /verified as/);
  count += 1;

  /* 7 — the token value must never appear in output. */
  result = await run({ WRANGLER_CONFIG: goodConfig });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(SECRET));
  assert.doesNotMatch(result.stdout + result.stderr, /cfut_/);
  count += 1;

  console.log(`Cloudflare preflight tests: ${count}/${count} passed (local mock API; no real credentials, no network).`);
} finally {
  server.close();
  rmSync(dir, { recursive: true, force: true });
}
