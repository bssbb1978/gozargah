import assert from 'node:assert/strict';
import type { Env } from '../config';
import {
  parseDnsUpstreams, rankDnsUpstreams, resetDnsUpstreamHealthForTests, resolveDnsMessage,
} from '../handlers/dns';

const label = new TextEncoder().encode('example');
const name = [7, ...label, 3, ...new TextEncoder().encode('com'), 0];
const query = new Uint8Array(12 + name.length + 4);
query[0] = 0xab; query[1] = 0xcd; query[2] = 1; query[5] = 1;
query.set(name, 12);
const qtype = 12 + name.length;
query[qtype + 1] = 1; query[qtype + 3] = 1;

function makeAnswer(q: Uint8Array): Uint8Array {
  const answer = new Uint8Array(q.length + 16);
  answer.set(q);
  answer[2] = 0x81; answer[3] = 0x80;
  answer[7] = 1;
  answer.set([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 9], q.length);
  return answer;
}

resetDnsUpstreamHealthForTests();
assert.deepEqual(parseDnsUpstreams('http://not-https.test, https://one.test/dns, https://two.test/query'), [
  'https://one.test/dns', 'https://two.test/query',
]);
const calls: string[] = [];
const mock = {
  async fetch(input: RequestInfo | URL) {
    const url = String(input);
    calls.push(url);
    if (url.startsWith('https://bad.test/')) return new Response('unavailable', { status: 503 });
    return new Response(makeAnswer(query), { headers: { 'content-type': 'application/dns-message' } });
  },
} as unknown as Fetcher;
const env = {
  DNS_UPSTREAMS: 'https://bad.test/dns-query,https://good.test/dns-query',
  DNS64_ENABLED: 'false',
  DNS_UPSTREAM: mock,
} as Env;
const result = await resolveDnsMessage(query, env);
assert.equal(result[0], 0xab);
assert.equal(result[1], 0xcd);
assert.deepEqual(calls, ['https://bad.test/dns-query', 'https://good.test/dns-query']);
assert.equal(rankDnsUpstreams(['https://bad.test/dns-query', 'https://good.test/dns-query'])[0], 'https://good.test/dns-query');
const staleAt = Date.now() + 11 * 60_000;
assert.equal(rankDnsUpstreams(['https://bad.test/dns-query', 'https://good.test/dns-query'], staleAt)[0], 'https://bad.test/dns-query');

calls.length = 0;
await resolveDnsMessage(query, env);
assert.deepEqual(calls, ['https://good.test/dns-query']);
