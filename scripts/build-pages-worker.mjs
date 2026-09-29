import { build } from 'esbuild';
import { mkdir } from 'node:fs/promises';

await mkdir('dist-pages', { recursive: true });
await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist-pages/_worker.js',
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  sourcemap: false,
  minify: true,
});
console.log('Built Pages Advanced Mode worker: dist-pages/_worker.js');
