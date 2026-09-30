#!/usr/bin/env node
/**
 * Cloudflare credential preflight — read-only, safe to run before any deploy.
 *
 * It answers three questions without mutating anything:
 *   1. Are CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID present and is the token
 *      active? User tokens verify at `/user/tokens/verify`; account-owned tokens
 *      (`cfat_` prefix) answer error code 1000 there and verify at
 *      `/accounts/{account_id}/tokens/verify` instead. Wrangler 4.x detects the
 *      two the same way, so this script mirrors that behaviour.
 *   2. Can the token see the target Workers and D1 databases? A missing D1 read
 *      scope is reported as a notice, never as a failure: deploying a Worker
 *      that has a D1 binding does not require permissions on the database.
 *   3. Do the D1 IDs configured in wrangler.toml point at databases that
 *      actually exist in this account (root environment and env.staging)?
 *
 * Secrets: the token value is never printed, logged or written anywhere. Only
 * its presence, type and status are reported. Account IDs and database UUIDs are
 * account metadata that `wrangler whoami` also prints.
 *
 * Usage:
 *   CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... npm run preflight:cf
 *   CF_API_BASE=http://127.0.0.1:8080 npm run preflight:cf   # offline tests
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { checkDeployConfig } from './guard-deploy-config.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_BASE = (process.env.CF_API_BASE || 'https://api.cloudflare.com/client/v4').replace(/\/+$/, '');
const CONFIG_PATH = path.resolve(process.env.WRANGLER_CONFIG || path.join(ROOT, 'wrangler.toml'));

const WORKER_TARGETS = ['gozargah', 'gozargah-staging'];
const D1_TARGETS = ['gozargah', 'gozargah-staging'];

let failures = 0;
let warnings = 0;

function line(status, message) {
  const tag = status === 'ok' ? 'OK  ' : status === 'warn' ? 'WARN' : 'FAIL';
  console.log(`${tag} ${message}`);
  if (status === 'fail') failures += 1;
  if (status === 'warn') warnings += 1;
}

async function apiGet(route, token) {
  const response = await fetch(`${API_BASE}${route}`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    /* non-JSON error pages are reported as-is through the status code */
  }
  return { status: response.status, body };
}

function apiErrorCode(result) {
  const first = result.body?.errors?.[0];
  return typeof first?.code === 'number' ? first.code : null;
}

function apiErrorMessage(result) {
  const first = result.body?.errors?.[0];
  if (first?.message) return String(first.message);
  return `HTTP ${result.status}`;
}

/**
 * Read the d1_databases entries (binding / name / id) for one environment.
 * Mirrors the section handling used by the deploy guard.
 */
function d1Entries(toml, environment = '') {
  const target = environment ? `env.${environment}.d1_databases` : 'd1_databases';
  const entries = [];
  let section = '';
  let current = null;
  for (const rawLine of toml.split(/\r?\n/)) {
    const header = rawLine.match(/^\s*\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/);
    if (header) {
      if (current && section === target) entries.push(current);
      section = header[1].trim();
      current = section === target ? {} : null;
      continue;
    }
    if (!current) continue;
    const pair = rawLine.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"/);
    if (pair) current[pair[1]] = pair[2];
  }
  if (current && section === target) entries.push(current);
  return entries;
}

async function main() {
  const token = process.env.CLOUDFLARE_API_TOKEN || '';
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID || '';

  console.log(`Cloudflare preflight against ${API_BASE}`);
  console.log(`Config: ${CONFIG_PATH}`);
  console.log('');

  if (!token) {
    line('fail', 'CLOUDFLARE_API_TOKEN is not set. Create an API token first (Workers Editor for an existing Worker) and export it in this shell only.');
  } else {
    line('ok', 'CLOUDFLARE_API_TOKEN is present (value never printed).');
  }
  if (!accountId) {
    line('fail', 'CLOUDFLARE_ACCOUNT_ID is not set. `npx wrangler whoami` prints the Account ID, or use Workers & Pages → Account details.'); 
  } else {
    line('ok', `CLOUDFLARE_ACCOUNT_ID is present (${accountId}).`);
  }
  if (!token || !accountId) {
    return report();
  }

  /* ---------------- token liveness ---------------- */
  let tokenType = '';
  const userVerify = await apiGet('/user/tokens/verify', token);
  if (userVerify.body?.success) {
    tokenType = 'user API token';
    const status = userVerify.body?.result?.status ?? 'active';
    line(status === 'active' ? 'ok' : 'warn', `Token verified as a ${tokenType} (status: ${status}).`);
  } else if (apiErrorCode(userVerify) === 1000) {
    // Code 1000 on the user endpoint is how wrangler recognises an account-owned token.
    const accountVerify = await apiGet(`/accounts/${accountId}/tokens/verify`, token);
    if (accountVerify.body?.success) {
      tokenType = 'account-owned API token';
      const status = accountVerify.body?.result?.status ?? 'active';
      line(status === 'active' ? 'ok' : 'warn', `Token verified as an ${tokenType} (status: ${status}).`);
    } else {
      line('fail', `Token is neither a valid user token nor a valid account token for account ${accountId}: ${apiErrorMessage(accountVerify)} (code ${apiErrorCode(accountVerify) ?? 'n/a'}).`);
    }
  } else {
    line('fail', `Token verification failed: ${apiErrorMessage(userVerify)} (code ${apiErrorCode(userVerify) ?? 'n/a'}). A 403 usually means a truncated or revoked token; check for stray whitespace or line breaks.`);
  }

  /* ---------------- Workers visibility ---------------- */
  const workers = await apiGet(`/accounts/${accountId}/workers/scripts`, token);
  let workerNames = null;
  if (workers.body?.success && Array.isArray(workers.body.result)) {
    workerNames = workers.body.result.map((script) => script.id ?? script.name).filter(Boolean);
    line('ok', `Token can list Workers (${workerNames.length} in account).`);
  } else if (workers.status === 403 || workers.status === 401) {
    line('warn', `Token cannot list Workers (${apiErrorMessage(workers)}). This is expected for a token scoped to a single Worker; the deploy itself can still succeed.`);
  } else {
    line('warn', `Worker list unavailable: ${apiErrorMessage(workers)}.`);
  }
  for (const name of WORKER_TARGETS) {
    if (!workerNames) break;
    const exists = workerNames.includes(name);
    if (exists) {
      line('ok', `Worker "${name}" exists — a Workers Editor token scoped to it is enough to deploy.`);
    } else if (name === 'gozargah-staging') {
      line('warn', `Worker "${name}" does not exist yet. Its first deploy needs a credential allowed to create Workers (product-level Workers Admin), or create it once from the dashboard.`);
    } else {
      line('warn', `Worker "${name}" does not exist yet.`);
    }
  }

  /* ---------------- D1 visibility ---------------- */
  const d1 = await apiGet(`/accounts/${accountId}/d1/database`, token);
  let databases = null;
  if (d1.body?.success && Array.isArray(d1.body.result)) {
    databases = d1.body.result.map((db) => ({ name: db.name, uuid: db.uuid ?? db.id }));
    line('ok', `Token can list D1 databases (${databases.length} in account).`);
  } else {
    line('warn', `D1 database list unavailable: ${apiErrorMessage(d1)}. This does not block a Worker deploy — a D1 binding needs no database permissions; D1:Read is only needed for this check and D1:Edit only for creating databases and applying migrations to them.`);
  }

  /* ---------------- configuration cross-check ---------------- */
  let toml = '';
  try {
    toml = readFileSync(CONFIG_PATH, 'utf8');
  } catch (error) {
    line('fail', `Cannot read ${CONFIG_PATH}: ${error.message}`);
    return report();
  }

  const environments = [
    { label: 'root (production)', env: '', expectedName: D1_TARGETS[0] },
    { label: 'env.staging', env: 'staging', expectedName: D1_TARGETS[1] },
  ];
  for (const { label, env, expectedName } of environments) {
    const problem = checkDeployConfig(toml, env);
    if (problem) {
      line('fail', `${label}: deploy guard would block a live deploy — ${problem}`);
      continue;
    }
    const entries = d1Entries(toml, env);
    const entry = entries[0];
    line('ok', `${label}: deploy guard passes for D1 ID ${entry.database_id} (binding ${entry.binding}).`);
    if (entry.database_name !== expectedName) {
      line('warn', `${label}: wrangler.toml declares database_name "${entry.database_name}" but this repo expects "${expectedName}".`);
    }
    if (databases) {
      const match = databases.find((db) => db.uuid === entry.database_id);
      if (match) {
        line('ok', `${label}: D1 ID ${entry.database_id} exists in this account as "${match.name}".`);
      } else {
        line('fail', `${label}: D1 ID ${entry.database_id} is not one of the databases visible in this account. Check for a copy/paste mistake or the wrong account.`);
      }
    }
  }

  return report();
}

function report() {
  console.log('');
  if (failures > 0) {
    console.log(`Preflight: ${failures} blocking problem(s), ${warnings} warning(s). Fix the FAIL lines before deploying.`);
    process.exitCode = 1;
    return;
  }
  if (warnings > 0) {
    console.log(`Preflight: no blocking problems, ${warnings} warning(s). Read the WARN lines, then deploy.`);
    return;
  }
  console.log('Preflight: all checks passed.');
}

main().catch((error) => {
  line('fail', `Preflight crashed: ${error?.message ?? String(error)}`);
  return report();
});
