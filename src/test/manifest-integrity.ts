/**
 * 2.16 — AXR manifest v3 integrity: canonical string + HMAC-SHA256 signature.
 *
 * The pinned test vector below MUST stay byte-identical to the one in the
 * Go client (client/cmd/axr/manifest_sig_test.go) and in
 * docs/AXR-V3-HYPER-RESILIENCE.md. Any change to the canonical field
 * order/format breaks the client<->worker contract.
 */
import { manifestCanonical, manifestSign, frontingHint, cleanIpHints } from '../subscription';

// ---- shared test vector (token, canonical, expected hex) ----
const VECTOR_TOKEN = '0123456789abcdef0123';
const VECTOR_CANONICAL =
  'gozargah-axr-manifest/v3|2.16.0|example.com|/abc123|360|ws,ws-alt|' +
  'backup.example.com:backup,example.com:primary|104.16.13.37,172.67.0.1||web|90000';
const VECTOR_SIG = '996daa7821aa8eae4b89608bff2b61a37cbf590f29826467006d80fbb7e952ac';

async function main(): Promise<void> {
  // 1) canonical builder produces the exact shared vector
  const manifest: Record<string, unknown> = {
    schema: 'gozargah-axr-manifest/v3',
    version: '2.16.0',
    generated_at: 123,
    host: 'example.com',
    ws_path_base: '/abc123',
    path_rotation_minutes: 360,
    transports: ['ws', 'ws-alt'],
    flow_profile: { mode: 'web', note: 'x' },
    clean_ip_hints: ['104.16.13.37', '172.67.0.1'],
    fronting_hint: undefined,
    reconnect: { strategy: 'observe_and_failover', probe_interval_ms: 90_000, backoff_ms: [1] },
    entries: [
      { host: 'example.com', role: 'primary', status: 'primary', latency_ms: null },
      { host: 'backup.example.com', role: 'backup', status: 'unmeasured', latency_ms: null },
    ],
    honest_limit: { en: 'x', fa: 'x' },
    regime: { state: 'stable' }, // not part of the canonical string
  };
  const canonical = manifestCanonical(manifest);
  if (canonical !== VECTOR_CANONICAL) {
    throw new Error(`canonical mismatch:\n got: ${canonical}\n want: ${VECTOR_CANONICAL}`);
  }

  // 2) HMAC matches the pinned vector (WebCrypto path)
  const sig = await manifestSign(VECTOR_CANONICAL, VECTOR_TOKEN);
  if (sig !== VECTOR_SIG) throw new Error(`sig mismatch: ${sig} != ${VECTOR_SIG}`);

  // 3) sig is deterministic and key-sensitive
  const sig2 = await manifestSign(VECTOR_CANONICAL, VECTOR_TOKEN);
  if (sig2 !== sig) throw new Error('sig must be deterministic');
  const otherKey = await manifestSign(VECTOR_CANONICAL, 'ffffffffffffffffffff');
  if (otherKey === sig) throw new Error('different key must change sig');
  const otherMsg = await manifestSign(VECTOR_CANONICAL.replace('web', 'chat'), VECTOR_TOKEN);
  if (otherMsg === sig) throw new Error('different message must change sig');

  // 4) entries are sorted in the canonical string (insertion order irrelevant)
  const shuffled = { ...manifest, entries: [
    { host: 'backup.example.com', role: 'backup' },
    { host: 'example.com', role: 'primary' },
  ] };
  if (manifestCanonical(shuffled) !== VECTOR_CANONICAL) throw new Error('entry order must not matter');

  // 5) fronting_hint participates when present
  {
    const m = { ...manifest, fronting_hint: 'relay.example-iran.net' };
    const c = manifestCanonical(m);
    if (!c.includes('172.67.0.1|relay.example-iran.net|web')) throw new Error('fronting slot wrong: ' + c);
  }

  // 6) missing/odd fields degrade to empty slots, never throw
  const bare = manifestCanonical({});
  if (bare !== '||||||||||') throw new Error('bare canonical must be 11 empty slots: ' + bare);

  // 7) frontingHint validation
  if (frontingHint('Relay.Example-IRAN.Net') !== 'relay.example-iran.net') throw new Error('lowercase/trim');
  if (frontingHint('https://front.cdn.example/') !== 'front.cdn.example') throw new Error('scheme strip');
  if (frontingHint('no_dots.com') !== '') throw new Error('must contain a dot');
  if (frontingHint('-bad.example.com') !== '') throw new Error('must not start with dash');
  if (frontingHint('a b.example.com') !== '') throw new Error('no spaces');
  if (frontingHint(undefined) !== '') throw new Error('undefined -> empty');

  // 8) cleanIpHints validation (pre-existing contract, regression)
  if (JSON.stringify(cleanIpHints('1.2.3.4, 999.1.1.1, 5.6.7.8')) !== JSON.stringify(['1.2.3.4', '5.6.7.8'])) {
    throw new Error('cleanIpHints must filter invalid octets');
  }
  const many = Array.from({ length: 40 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`).join(',');
  if (cleanIpHints(many).length !== 8) throw new Error('cleanIpHints must cap at 8');

  console.log('manifest-integrity: all checks passed (vector ' + VECTOR_SIG.slice(0, 12) + '...)');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
