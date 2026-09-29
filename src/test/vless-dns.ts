import assert from 'node:assert/strict';
import type { Env } from '../config';
import type { GzUser } from '../db/users';
import type { VlessDnsSocket } from '../handlers/vless-dns';
import { pumpVlessDns } from '../handlers/vless-dns';
import { validateDnsResponse } from '../dns/wire';

function makeQuery(): Uint8Array {
  const name = [7, ...new TextEncoder().encode('example'), 3, ...new TextEncoder().encode('com'), 0];
  const query = new Uint8Array(12 + name.length + 4);
  query.set([0x55, 0x66, 0x01, 0x00, 0, 1], 0);
  query.set(name, 12);
  const qtype = 12 + name.length;
  query[qtype + 1] = 1;
  query[qtype + 3] = 1;
  return query;
}

function makeAnswer(query: Uint8Array): Uint8Array {
  const answer = new Uint8Array(query.length + 16);
  answer.set(query);
  answer[2] = 0x81; answer[3] = 0x80;
  answer[7] = 1;
  answer.set([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 17], query.length);
  return answer;
}

function frameDatagram(query: Uint8Array): Uint8Array {
  const frame = new Uint8Array(query.length + 2);
  frame[0] = (query.length >>> 8) & 255;
  frame[1] = query.length & 255;
  frame.set(query, 2);
  return frame;
}

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

const query = makeQuery();
const answer = makeAnswer(query);
let upstreamCalls = 0;
const service = {
  async fetch(_input: RequestInfo | URL, init?: RequestInit) {
    upstreamCalls++;
    assert.equal(init?.method, 'POST');
    assert.deepEqual(new Uint8Array(init?.body as ArrayBuffer), query);
    return new Response(answer, { headers: { 'content-type': 'application/dns-message' } });
  },
} as unknown as Fetcher;
const env = {
  DNS_UPSTREAMS: 'https://doh.test/dns-query',
  DNS_UPSTREAM: service,
  DNS64_ENABLED: 'false',
} as Env;
const user = { id: 0 } as GzUser;
const datagrams = join(frameDatagram(query), frameDatagram(query));
const chunks = [datagrams.slice(0, 1), datagrams.slice(1, 9), datagrams.slice(9, 22), datagrams.slice(22)];
const source = new ReadableStream<Uint8Array>({
  start(controller) {
    for (const chunk of chunks) controller.enqueue(chunk);
    controller.close();
  },
}).getReader();
let buffered: Uint8Array = new Uint8Array(0);
const readExactly = async (length: number, allowCleanEof = false): Promise<Uint8Array | null> => {
  while (buffered.length < length) {
    const { done, value } = await source.read();
    if (done) {
      if (allowCleanEof && buffered.length === 0) return null;
      throw new Error('test frame truncated');
    }
    if (value?.length) buffered = join(buffered, value);
  }
  const out = buffered.slice(0, length);
  buffered = buffered.slice(length);
  return out;
};
const sent: Uint8Array[] = [];
let closeCode: number | undefined;
const socket = {
  send(data: Uint8Array) { sent.push(data.slice()); },
  close(code?: number) { closeCode = code; },
} as unknown as VlessDnsSocket;
await pumpVlessDns(socket, readExactly, env, user, 0);
assert.deepEqual(sent[0], new Uint8Array([0, 0]));
assert.equal(sent.length, 3, 'VLESS reply plus one framed DNS response per request');
assert.equal(upstreamCalls, 2);
for (const frame of sent.slice(1)) {
  const length = (frame[0] << 8) | frame[1];
  assert.equal(length, frame.length - 2);
  assert.equal(validateDnsResponse(frame.slice(2), query), true);
}
assert.equal(closeCode, undefined, 'clean end closes without an error code');

const invalidSource = new ReadableStream<Uint8Array>({
  start(controller) { controller.enqueue(new Uint8Array([0, 0])); controller.close(); },
}).getReader();
const invalidSocketSent: Uint8Array[] = [];
let invalidCloseCode: number | undefined;
const invalidSocket = {
  send(data: Uint8Array) { invalidSocketSent.push(data.slice()); },
  close(code?: number) { invalidCloseCode = code; },
} as unknown as VlessDnsSocket;
await pumpVlessDns(invalidSocket, async (length, allowCleanEof = false) => {
  const { done, value } = await invalidSource.read();
  if (done) return allowCleanEof ? null : new Uint8Array(0);
  return value?.slice(0, length) ?? null;
}, env, user, 0);
assert.deepEqual(invalidSocketSent, [new Uint8Array([0, 0])]);
assert.equal(invalidCloseCode, 1008, 'malformed DNS datagram is closed as a policy error');
