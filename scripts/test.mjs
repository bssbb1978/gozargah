/**
 * Bundle and run the repository's pure-logic test entrypoints with esbuild.
 * The Worker/D1 integration suite runs separately through Vitest.
 */

import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const entries = [
  'engine',
  'predictive-mesh',
  'protocol-catalog',
  'protocol-controller',
  'network-intelligence',
  'shadowsocks',
  'dns-wire',
  'dns-resolver',
  'vless-dns',
  'regime',
  'path-rotation',
  'fp-rotation',
  'shape',
  'decision',
];

for (const name of entries) {
  const outfile = join(here, '.test-build.mjs');
  try {
    await build({
      entryPoints: [join(root, 'src', 'test', name + '.ts')],
      bundle: true,
      format: 'esm',
      platform: 'node',
      outfile,
      logLevel: 'warning',
      external: ['qrcode'],
    });
    const result = spawnSync(process.execPath, [outfile], { stdio: 'inherit' });
    if (result.status !== 0) process.exitCode = result.status ?? 1;
  } finally {
    try { rmSync(outfile, { force: true }); } catch { /* cleanup is best effort */ }
  }
  if (process.exitCode) process.exit(process.exitCode);
}
