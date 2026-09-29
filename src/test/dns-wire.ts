import assert from 'node:assert/strict';
import {
  isDns64Candidate, makeAQuery, makeServfailResponse, parseDnsQuery,
  synthesizeDns64, validateDnsResponse,
} from '../dns/wire';

function query(type: number, id = 0x1234, dnssecOk = false): Uint8Array {
  const name = [7, ...new TextEncoder().encode('example'), 3, ...new TextEncoder().encode('com'), 0];
  const extra = dnssecOk ? new Uint8Array([0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]) : new Uint8Array(0);
  const out = new Uint8Array(12 + name.length + 4 + extra.length);
  out[0] = id >>> 8; out[1] = id & 255;
  out[2] = 1; // recursion desired
  out[5] = 1;
  if (dnssecOk) out[11] = 1;
  out.set(name, 12);
  const typeOffset = 12 + name.length;
  out[typeOffset] = type >>> 8; out[typeOffset + 1] = type & 255;
  out[typeOffset + 3] = 1;
  out.set(extra, typeOffset + 4);
  return out;
}

function aResponse(aQuery: Uint8Array, ip = [192, 0, 2, 33]): Uint8Array {
  const out = new Uint8Array(aQuery.length + 16);
  out.set(aQuery);
  out[2] = 0x81; out[3] = 0xa0; // response, recursion available, and upstream AD bit
  out[6] = 0; out[7] = 1;
  // compressed owner pointer to the first question name
  let offset = aQuery.length;
  out[offset++] = 0xc0; out[offset++] = 0x0c;
  out[offset++] = 0; out[offset++] = 1; // A
  out[offset++] = 0; out[offset++] = 1; // IN
  out[offset++] = 0; out[offset++] = 0; out[offset++] = 1; out[offset++] = 44; // TTL 300
  out[offset++] = 0; out[offset++] = 4;
  for (const octet of ip) out[offset++] = octet;
  return out;
}

function aaaaNoData(aaaaQuery: Uint8Array): Uint8Array {
  const out = aaaaQuery.slice();
  out[2] = 0x81; out[3] = 0x80;
  return out;
}

const original = query(28);
assert.equal(parseDnsQuery(original).question.name, 'example.com');
assert.equal(isDns64Candidate(original), true);
assert.equal(isDns64Candidate(query(28, 0x1234, true)), false);
assert.equal((makeAQuery(original)[original.length - 4] << 8) | makeAQuery(original)[original.length - 3], 1);

const answer = synthesizeDns64(original, aResponse(makeAQuery(original)));
assert.ok(answer);
assert.equal(validateDnsResponse(answer!, original), true);
assert.equal((answer![6] << 8) | answer![7], 1);
assert.equal(answer![3] & 0x20, 0, 'synthesized AAAA must not inherit DNSSEC AD');
assert.deepEqual([...answer!.slice(-16)], [
  0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 33,
]);

const prefix64 = synthesizeDns64(original, aResponse(makeAQuery(original)), '2001:db8:1234:5678::/64');
assert.ok(prefix64);
assert.deepEqual([...prefix64!.slice(-16)], [
  0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0, 192, 0, 2, 33, 0, 0, 0,
]);
assert.throws(() => synthesizeDns64(original, aResponse(makeAQuery(original)), '2001:db8::/72'));
assert.equal(synthesizeDns64(original, aaaaNoData(query(1))), null);
assert.equal(synthesizeDns64(query(28, 0x1234, true), aResponse(makeAQuery(query(28, 0x1234, true)))), null);

const servfail = makeServfailResponse(original);
assert.equal((servfail[2] & 0x80) !== 0, true);
assert.equal(servfail[3] & 0x0f, 2);
assert.throws(() => parseDnsQuery(new Uint8Array(5)));
