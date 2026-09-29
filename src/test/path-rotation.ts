import { PATH_ROTATION_WINDOW_MS, pathRotationWindowIndex, rotatedPathBase } from '../sub/path-rotation';

const UUID = '8f1c2a4e-0b3d-4e5f-9a6c-1d2e3f4a5b6c';
const T0 = 1_700_000_000_000;

// 1) deterministic within a window
const a = rotatedPathBase(UUID, T0);
const b = rotatedPathBase(UUID, T0 + 60_000);
if (a !== b) throw new Error('rotation must be deterministic within a window');

// 2) shape: /<uuid>/g/<16 hex>
if (!new RegExp('^/' + UUID + '/g/[0-9a-f]{16}$').test(a)) throw new Error('bad rotated path shape: ' + a);

// 3) window boundary changes the path
const idx = pathRotationWindowIndex(T0);
const nextWindowStart = (idx + 1) * PATH_ROTATION_WINDOW_MS + 1;
const c = rotatedPathBase(UUID, nextWindowStart);
if (c === a) throw new Error('path must change across a window boundary');
if (!new RegExp('^/' + UUID + '/g/[0-9a-f]{16}$').test(c)) throw new Error('bad rotated path shape (next window): ' + c);

// 4) different users get different paths (same window)
const d = rotatedPathBase('11111111-2222-3333-4444-555555555555', T0);
if (d === a) throw new Error('different uuids must not share a path');

// 5) old windows remain structurally valid paths (backward compatible)
const oldIdx = pathRotationWindowIndex(T0) - 1;
const oldPath = rotatedPathBase(UUID, oldIdx * PATH_ROTATION_WINDOW_MS + 1);
if (!oldPath.startsWith('/' + UUID + '/g/')) throw new Error('old window path invalid');

console.log('path-rotation: ok');
