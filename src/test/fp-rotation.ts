import { NEUTRAL_FINGERPRINTS, rotatedFingerprint } from '../sub/fp-rotation';
import { fpFor } from '../sub/operators';
import { PATH_ROTATION_WINDOW_MS } from '../sub/path-rotation';

const UUID = '8f1c2a4e-0b3d-4e5f-9a6c-1d2e3f4a5b6c';
const T0 = 1_700_000_000_000;

// 1) deterministic within a window
const a = rotatedFingerprint(UUID, T0);
const b = rotatedFingerprint(UUID, T0 + 60_000);
if (a !== b) throw new Error('fingerprint must be deterministic within a window');

// 2) value is from the neutral set (intersection of all client formats)
if (!NEUTRAL_FINGERPRINTS.includes(a)) throw new Error('fingerprint outside neutral set: ' + a);

// 3) rotation across windows: 6 consecutive windows must show at least 2 distinct values
const values = new Set<string>();
for (let w = 0; w < 6; w++) values.add(rotatedFingerprint(UUID, w * PATH_ROTATION_WINDOW_MS + 1));
if (values.size < 2) throw new Error('fingerprint must rotate across windows');

// 4) fpFor: neutral rotation applies with a seed (same live window as a);
// default without a seed stays the static neutral default.
if (fpFor({}, UUID) !== rotatedFingerprint(UUID)) throw new Error('fpFor(seed) must match rotatedFingerprint in the same window');
if (fpFor({}) !== 'chrome') throw new Error('fpFor without seed must stay the neutral default');

// 5) explicit operator preset always wins (honest branding contract)
if (fpFor({ opKey: 'mci' }, UUID) !== 'randomized') throw new Error('operator preset must win');
if (fpFor({ opKey: 'irancell' }, UUID) !== 'chrome') throw new Error('operator preset must win (chrome)');
if (fpFor({ opKey: 'auto' }, UUID) !== rotatedFingerprint(UUID)) throw new Error('auto operator must fall through to rotation');

console.log('fp-rotation: ok');
