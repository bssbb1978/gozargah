/**
 * Shadowsocks SIP004 AEAD stream codec (AES-256-GCM).
 *
 * This handles the standard legacy Shadowsocks AEAD salt + chunk framing used
 * by clients behind v2ray-plugin's WebSocket transport. No payload inspection
 * or packet rewriting is performed after the encrypted stream is decoded.
 */

export const SHADOWSOCKS_KEY_LENGTH = 32;
const KEY_LENGTH = SHADOWSOCKS_KEY_LENGTH;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
export const SHADOWSOCKS_METHOD = 'aes-256-gcm' as const;
export const SHADOWSOCKS_MAX_CHUNK = 0x3fff;

export type ReadExact = (length: number, allowCleanEof?: boolean) => Promise<Uint8Array | null>;

const MD5_SHIFTS = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x1_0000_0000) >>> 0);

/** OpenSSL EVP_BytesToKey-compatible MD5 derivation required by legacy SS AEAD. */
export function deriveShadowsocksMasterKey(password: string, length = KEY_LENGTH): Uint8Array {
  if (!password || !Number.isInteger(length) || length < 1 || length > 64) throw new Error('ss_invalid_key_input');
  const passwordBytes = new TextEncoder().encode(password);
  const blocks: Uint8Array[] = [];
  let previous: Uint8Array = new Uint8Array(0);
  let total = 0;
  while (total < length) {
    previous = md5(concat(previous, passwordBytes));
    blocks.push(previous);
    total += previous.length;
  }
  const joined = concatMany(blocks);
  return joined.slice(0, length);
}

/** SIP004: HKDF-SHA1(master-key, salt, "ss-subkey", key length). */
export async function deriveShadowsocksSubkey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  if (salt.length !== KEY_LENGTH) throw new Error('ss_invalid_salt');
  const master = deriveShadowsocksMasterKey(password, KEY_LENGTH);
  const source = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-1', salt, info: new TextEncoder().encode('ss-subkey') },
    source,
    { name: 'AES-GCM', length: KEY_LENGTH * 8 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Authenticate the SIP004 encrypted length block without consuming the stream. */
export async function hasValidShadowsocksPrefix(buffer: Uint8Array, password: string): Promise<boolean> {
  if (buffer.length < KEY_LENGTH + 2 + TAG_LENGTH) return false;
  try {
    const salt = buffer.slice(0, KEY_LENGTH);
    const key = await deriveShadowsocksSubkey(password, salt);
    const lengthBlock = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(NONCE_LENGTH), tagLength: TAG_LENGTH * 8 },
      key,
      buffer.slice(KEY_LENGTH, KEY_LENGTH + 2 + TAG_LENGTH),
    );
    const bytes = new Uint8Array(lengthBlock);
    const length = (bytes[0] << 8) | bytes[1];
    return length > 0 && length <= SHADOWSOCKS_MAX_CHUNK;
  } catch {
    return false;
  }
}

/** Decrypt successive SIP004 framed chunks from an arbitrary byte stream. */
export class ShadowsocksAeadDecoder {
  private nonce = new Uint8Array(NONCE_LENGTH);
  private constructor(private readonly readExact: ReadExact, private readonly key: CryptoKey) {}

  static async create(readExact: ReadExact, password: string): Promise<ShadowsocksAeadDecoder> {
    const salt = await readExact(KEY_LENGTH);
    if (!salt) throw new Error('ss_missing_salt');
    const key = await deriveShadowsocksSubkey(password, salt);
    return new ShadowsocksAeadDecoder(readExact, key);
  }

  async readChunk(): Promise<Uint8Array | null> {
    const encryptedLength = await this.readExact(2 + TAG_LENGTH, true);
    if (!encryptedLength) return null;
    const lengthPlain = await this.decrypt(encryptedLength);
    const length = (lengthPlain[0] << 8) | lengthPlain[1];
    if (length > SHADOWSOCKS_MAX_CHUNK) throw new Error('ss_chunk_too_large');
    const encryptedPayload = await this.readExact(length + TAG_LENGTH);
    if (!encryptedPayload) throw new Error('ss_truncated_payload');
    return this.decrypt(encryptedPayload);
  }

  private async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    try {
      const clear = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: this.nonce, tagLength: TAG_LENGTH * 8 },
        this.key,
        ciphertext,
      );
      incrementNonce(this.nonce);
      return new Uint8Array(clear);
    } catch {
      throw new Error('ss_authentication_failed');
    }
  }
}

/** Encrypt plaintext chunks and return standard SIP004 salt + ciphertext bytes. */
export class ShadowsocksAeadEncoder {
  private nonce = new Uint8Array(NONCE_LENGTH);
  private initialized = false;
  private keyPromise: Promise<CryptoKey>;

  constructor(private readonly password: string, private readonly salt = randomBytes(KEY_LENGTH)) {
    if (salt.length !== KEY_LENGTH) throw new Error('ss_invalid_salt');
    this.keyPromise = deriveShadowsocksSubkey(password, salt);
  }

  async encode(data: Uint8Array): Promise<Uint8Array> {
    const key = await this.keyPromise;
    const parts: Uint8Array[] = [];
    if (!this.initialized) {
      parts.push(this.salt.slice());
      this.initialized = true;
    }
    for (let offset = 0; offset < data.length;) {
      const size = Math.min(SHADOWSOCKS_MAX_CHUNK, data.length - offset);
      const length = new Uint8Array([(size >>> 8) & 255, size & 255]);
      parts.push(await this.encrypt(key, length));
      parts.push(await this.encrypt(key, data.slice(offset, offset + size)));
      offset += size;
    }
    return concatMany(parts);
  }

  private async encrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: this.nonce, tagLength: TAG_LENGTH * 8 },
      key,
      data,
    );
    incrementNonce(this.nonce);
    return new Uint8Array(encrypted);
  }
}

function incrementNonce(nonce: Uint8Array): void {
  // Shadowsocks uses a 96-bit little-endian unsigned counter, starting at zero.
  for (let i = 0; i < nonce.length; i++) {
    nonce[i] = (nonce[i] + 1) & 255;
    if (nonce[i] !== 0) break;
  }
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function concatMany(chunks: Uint8Array[]): Uint8Array {
  const size = chunks.reduce((n, chunk) => n + chunk.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

function md5(input: Uint8Array): Uint8Array {
  const totalBytes = Math.ceil((input.length + 9) / 64) * 64;
  const padded = new Uint8Array(totalBytes);
  padded.set(input);
  padded[input.length] = 0x80;
  const bitLength = input.length * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(totalBytes - 8, bitLength >>> 0, true);
  view.setUint32(totalBytes - 4, Math.floor(bitLength / 0x1_0000_0000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const words = new Uint32Array(16);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) words[i] = view.getUint32(offset + i * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number, g: number;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const sum = (a + f + MD5_K[i] + words[g]) >>> 0;
      const shift = MD5_SHIFTS[i];
      const rotated = ((sum << shift) | (sum >>> (32 - shift))) >>> 0;
      const nextB = (b + rotated) >>> 0;
      a = d;
      d = c;
      c = b;
      b = nextB;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const digest = new Uint8Array(16);
  const digestView = new DataView(digest.buffer);
  digestView.setUint32(0, a0, true);
  digestView.setUint32(4, b0, true);
  digestView.setUint32(8, c0, true);
  digestView.setUint32(12, d0, true);
  return digest;
}
