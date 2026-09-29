import assert from 'node:assert/strict';
import {
  deriveShadowsocksMasterKey, hasValidShadowsocksPrefix, ShadowsocksAeadDecoder, ShadowsocksAeadEncoder,
  SHADOWSOCKS_KEY_LENGTH, SHADOWSOCKS_MAX_CHUNK,
} from '../protocols/shadowsocks';

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

assert.equal(Buffer.from(deriveShadowsocksMasterKey('password')).toString('hex'),
  '5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08');

const password = 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e';
const salt = Uint8Array.from({ length: SHADOWSOCKS_KEY_LENGTH }, (_, i) => i);
const encoder = new ShadowsocksAeadEncoder(password, salt);
const firstPlain = join(
  new Uint8Array([3, 11]), new TextEncoder().encode('example.com'),
  new Uint8Array([1, 187]), new TextEncoder().encode('request payload'),
);
const secondPlain = new TextEncoder().encode('second stream frame');
const firstCipher = await encoder.encode(firstPlain);
assert.equal(Buffer.from(firstCipher).toString('hex'),
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f28cc93765de6075acbf8bda47d7ab00c42110fa8efc12557f3c5cb4abe0f220ac73423b8066bf03c3076a045311f6655bf829369d78d4e897e2c8942b4cffc47');
assert.equal(await hasValidShadowsocksPrefix(firstCipher, password), true);
const badPrefix = firstCipher.slice(); badPrefix[SHADOWSOCKS_KEY_LENGTH + 2] ^= 1;
assert.equal(await hasValidShadowsocksPrefix(badPrefix, password), false);
const secondCipher = await encoder.encode(secondPlain);
const wire = join(firstCipher, secondCipher);
let offset = 0;
const readExact = async (size: number, allowCleanEof = false): Promise<Uint8Array | null> => {
  if (offset === wire.length && allowCleanEof) return null;
  if (offset + size > wire.length) throw new Error('test stream truncated');
  const out = wire.slice(offset, offset + size);
  offset += size;
  return out;
};
const decoder = await ShadowsocksAeadDecoder.create(readExact, password);
assert.deepEqual(await decoder.readChunk(), firstPlain);
assert.deepEqual(await decoder.readChunk(), secondPlain);
assert.equal(await decoder.readChunk(), null);

const large = Uint8Array.from({ length: SHADOWSOCKS_MAX_CHUNK + 11 }, (_, i) => i & 255);
const largeEncoder = new ShadowsocksAeadEncoder(password, new Uint8Array(SHADOWSOCKS_KEY_LENGTH).fill(9));
const largeWire = await largeEncoder.encode(large);
let largeOffset = 0;
const largeDecoder = await ShadowsocksAeadDecoder.create(async (size, eof) => {
  if (largeOffset === largeWire.length && eof) return null;
  if (largeOffset + size > largeWire.length) throw new Error('large fixture truncated');
  const part = largeWire.slice(largeOffset, largeOffset + size);
  largeOffset += size;
  return part;
}, password);
const part1 = await largeDecoder.readChunk();
const part2 = await largeDecoder.readChunk();
assert.equal(part1?.length, SHADOWSOCKS_MAX_CHUNK);
assert.deepEqual(join(part1!, part2!), large);
assert.equal(await largeDecoder.readChunk(), null);

const tampered = wire.slice();
tampered[tampered.length - 1] ^= 1;
let tamperedOffset = 0;
const tamperedDecoder = await ShadowsocksAeadDecoder.create(async (size, eof) => {
  if (tamperedOffset === tampered.length && eof) return null;
  if (tamperedOffset + size > tampered.length) throw new Error('tampered fixture truncated');
  const part = tampered.slice(tamperedOffset, tamperedOffset + size);
  tamperedOffset += size;
  return part;
}, password);
assert.deepEqual(await tamperedDecoder.readChunk(), firstPlain);
await assert.rejects(() => tamperedDecoder.readChunk(), /authentication_failed/);
