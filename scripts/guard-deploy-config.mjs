#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ZERO_D1_ID = '00000000-0000-0000-0000-000000000000';

function optionValue(args, name, fallback) {
  const inline = args.find((arg) => arg.startsWith(name + '='));
  if (inline) return inline.slice(name.length + 1);
  const index = args.indexOf(name);
  return index >= 0 ? (args[index + 1] || '') : fallback;
}

export function configuredD1Ids(toml, environment = '') {
  const target = environment ? `env.${environment}.d1_databases` : 'd1_databases';
  const ids = [];
  let section = '';
  for (const line of toml.split(/\r?\n/)) {
    const header = line.match(/^\s*\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/);
    if (header) {
      section = header[1].trim();
      continue;
    }
    if (section !== target) continue;
    const match = line.match(/^\s*database_id\s*=\s*"([^"]*)"/);
    if (match) ids.push(match[1].trim());
  }
  return ids;
}

export function checkDeployConfig(toml, environment = '') {
  const ids = configuredD1Ids(toml, environment);
  const target = environment ? `env.${environment}` : 'root (default)';
  if (!ids.length) {
    return `${target}: no D1 database_id found; refusing non-dry-run deploy because the database binding cannot be verified`;
  }
  const malformed = ids.find((id) => !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id));
  if (malformed !== undefined) {
    return `${target}: D1 database_id is empty or not a UUID; refusing non-dry-run deploy until a valid target ID is configured`;
  }
  const placeholder = ids.find((id) => /^0+$/.test(id.replace(/[-{}]/g, '')));
  if (placeholder !== undefined) {
    return `${target}: D1 database_id is the all-zero placeholder ${placeholder || ZERO_D1_ID}; replace it with the target environment's real D1 ID before deploying`;
  }
  return '';
}

function main() {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg === '--dry-run' || arg.startsWith('--dry-run='))) {
    console.log('Deploy config guard: dry-run detected; live D1 ID check not required.');
    return;
  }

  const environment = optionValue(args, '--env', '');
  const configPath = path.resolve(optionValue(args, '--config', 'wrangler.toml'));
  let toml;
  try {
    toml = readFileSync(configPath, 'utf8');
  } catch (error) {
    console.error(`::error title=Unsafe Wrangler deploy::Cannot read ${configPath}: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const problem = checkDeployConfig(toml, environment);
  if (problem) {
    console.error(`::error title=Unsafe Wrangler deploy::${problem}`);
    process.exitCode = 1;
    return;
  }
  console.log(`Deploy config guard: D1 ID is configured for ${environment ? `env.${environment}` : 'the root environment'}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
