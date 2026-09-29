/** Bounded DNS wire-format parsing and RFC 6052 DNS64 synthesis. */

export const MAX_DNS_MESSAGE_BYTES = 4096;

export interface DnsQuestion {
  name: string;
  labels: Uint8Array[];
  type: number;
  klass: number;
  typeOffset: number;
}

export interface ParsedDnsQuery {
  id: number;
  flags: number;
  question: DnsQuestion;
  questionEnd: number;
  dnssecOk: boolean;
}

interface DnsRecord {
  section: 'answer' | 'authority' | 'additional';
  name: string;
  labels: Uint8Array[];
  type: number;
  klass: number;
  ttl: number;
  rdlength: number;
  rdataOffset: number;
  rawStart: number;
  rawEnd: number;
}

interface ParsedDnsMessage {
  id: number;
  flags: number;
  questions: DnsQuestion[];
  questionEnd: number;
  answerCount: number;
  authorityCount: number;
  additionalCount: number;
  records: DnsRecord[];
}

const readU16 = (b: Uint8Array, i: number): number => (b[i] << 8) | b[i + 1];
const readU32 = (b: Uint8Array, i: number): number => (((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0);
const writeU16 = (b: Uint8Array, i: number, n: number): void => { b[i] = (n >>> 8) & 255; b[i + 1] = n & 255; };
const writeU32 = (b: Uint8Array, i: number, n: number): void => { b[i] = (n >>> 24) & 255; b[i + 1] = (n >>> 16) & 255; b[i + 2] = (n >>> 8) & 255; b[i + 3] = n & 255; };

function decodeName(data: Uint8Array, start: number): { labels: Uint8Array[]; name: string; next: number } {
  if (start < 0 || start >= data.length) throw new Error('dns_name_out_of_range');
  const labels: Uint8Array[] = [];
  const visited = new Set<number>();
  let cursor = start;
  let next = -1;
  let wireLength = 1;
  let hops = 0;
  while (true) {
    if (cursor >= data.length || ++hops > 128) throw new Error('dns_bad_name');
    const size = data[cursor];
    if ((size & 0xc0) === 0xc0) {
      if (cursor + 1 >= data.length) throw new Error('dns_bad_pointer');
      const pointer = ((size & 0x3f) << 8) | data[cursor + 1];
      if (pointer >= data.length || visited.has(pointer)) throw new Error('dns_bad_pointer');
      visited.add(pointer);
      if (next < 0) next = cursor + 2;
      cursor = pointer;
      continue;
    }
    if ((size & 0xc0) !== 0 || size > 63) throw new Error('dns_bad_label');
    cursor++;
    if (size === 0) {
      if (next < 0) next = cursor;
      break;
    }
    if (cursor + size > data.length) throw new Error('dns_short_label');
    wireLength += size + 1;
    if (wireLength > 255) throw new Error('dns_name_too_long');
    labels.push(data.slice(cursor, cursor + size));
    cursor += size;
  }
  const name = labels.map((label) => {
    let part = '';
    for (const byte of label) part += String.fromCharCode(byte >= 65 && byte <= 90 ? byte + 32 : byte);
    return part;
  }).join('.');
  return { labels, name, next };
}

function parseQuestion(data: Uint8Array, offset: number): { question: DnsQuestion; next: number } {
  const parsed = decodeName(data, offset);
  if (parsed.next + 4 > data.length) throw new Error('dns_short_question');
  return {
    question: {
      name: parsed.name,
      labels: parsed.labels,
      type: readU16(data, parsed.next),
      klass: readU16(data, parsed.next + 2),
      typeOffset: parsed.next,
    },
    next: parsed.next + 4,
  };
}

/** Validate a standard, single-question DNS query and expose bounded metadata. */
export function parseDnsQuery(data: Uint8Array): ParsedDnsQuery {
  if (data.length < 12 || data.length > MAX_DNS_MESSAGE_BYTES) throw new Error('dns_bad_size');
  const flags = readU16(data, 2);
  if ((flags & 0x8000) !== 0) throw new Error('dns_expected_query');
  if (((flags >>> 11) & 0x0f) !== 0) throw new Error('dns_unsupported_opcode');
  const qd = readU16(data, 4);
  if (qd !== 1) throw new Error('dns_one_question_required');

  const { question, next: questionEnd } = parseQuestion(data, 12);
  let cursor = questionEnd;
  const an = readU16(data, 6);
  const ns = readU16(data, 8);
  const ar = readU16(data, 10);
  // Queries normally contain no answer/authority records, but validate/skip them
  // rather than letting untrusted counts make the OPT scan read out of bounds.
  let dnssecOk = false;
  for (const [section, count] of [['answer', an], ['authority', ns], ['additional', ar]] as const) {
    for (let i = 0; i < count; i++) {
      const owner = decodeName(data, cursor);
      const start = cursor;
      cursor = owner.next;
      if (cursor + 10 > data.length) throw new Error('dns_short_record');
      const type = readU16(data, cursor);
      const ttl = readU32(data, cursor + 4);
      const rdlength = readU16(data, cursor + 8);
      const rdataOffset = cursor + 10;
      if (rdataOffset + rdlength > data.length) throw new Error('dns_short_rdata');
      if (section === 'additional' && type === 41 && (ttl & 0x8000) !== 0) dnssecOk = true;
      cursor = rdataOffset + rdlength;
      void start;
    }
  }
  if (cursor !== data.length) throw new Error('dns_trailing_bytes');
  return { id: readU16(data, 0), flags, question, questionEnd, dnssecOk };
}

function parseDnsMessage(data: Uint8Array): ParsedDnsMessage {
  if (data.length < 12 || data.length > MAX_DNS_MESSAGE_BYTES) throw new Error('dns_bad_response_size');
  const flags = readU16(data, 2);
  if ((flags & 0x8000) === 0) throw new Error('dns_upstream_not_response');
  const qd = readU16(data, 4);
  const answerCount = readU16(data, 6);
  const authorityCount = readU16(data, 8);
  const additionalCount = readU16(data, 10);
  if (qd > 16 || answerCount + authorityCount + additionalCount > 256) throw new Error('dns_upstream_counts_invalid');
  const questions: DnsQuestion[] = [];
  let cursor = 12;
  for (let i = 0; i < qd; i++) {
    const parsed = parseQuestion(data, cursor);
    questions.push(parsed.question);
    cursor = parsed.next;
  }

  const records: DnsRecord[] = [];
  const sections = [
    ['answer', answerCount], ['authority', authorityCount], ['additional', additionalCount],
  ] as const;
  for (const [section, count] of sections) {
    for (let i = 0; i < count; i++) {
      const rawStart = cursor;
      const owner = decodeName(data, cursor);
      cursor = owner.next;
      if (cursor + 10 > data.length) throw new Error('dns_upstream_short_record');
      const type = readU16(data, cursor);
      const klass = readU16(data, cursor + 2);
      const ttl = readU32(data, cursor + 4);
      const rdlength = readU16(data, cursor + 8);
      const rdataOffset = cursor + 10;
      if (rdataOffset + rdlength > data.length) throw new Error('dns_upstream_short_rdata');
      cursor = rdataOffset + rdlength;
      records.push({ section, name: owner.name, labels: owner.labels, type, klass, ttl, rdlength, rdataOffset, rawStart, rawEnd: cursor });
    }
  }
  if (cursor !== data.length) throw new Error('dns_upstream_trailing_bytes');
  return { id: readU16(data, 0), flags, questions, questionEnd: questions.length ? questions[0].typeOffset + 4 : 12, answerCount, authorityCount, additionalCount, records };
}

/** True when the query's question is an IN AAAA lookup and DNSSEC is not requested. */
export function isDns64Candidate(query: Uint8Array): boolean {
  try {
    const parsed = parseDnsQuery(query);
    return parsed.question.type === 28 && parsed.question.klass === 1 && !parsed.dnssecOk;
  } catch {
    return false;
  }
}

/** Fully bounds-check and match a DoH response to the exact wire query. */
export function validateDnsResponse(responseBytes: Uint8Array, queryBytes: Uint8Array): boolean {
  try {
    const query = parseDnsQuery(queryBytes);
    const response = parseDnsMessage(responseBytes);
    if (response.id !== query.id || response.questions.length !== 1) return false;
    if (((response.flags >>> 11) & 0x0f) !== ((query.flags >>> 11) & 0x0f)) return false;
    const question = response.questions[0];
    return question.name === query.question.name && question.type === query.question.type && question.klass === query.question.klass;
  } catch {
    return false;
  }
}

/** True only when a fully valid response includes an IN AAAA answer record. */
export function dnsResponseHasAaaa(responseBytes: Uint8Array): boolean {
  try {
    return parseDnsMessage(responseBytes).records.some((record) => record.section === 'answer' && record.type === 28 && record.klass === 1);
  } catch {
    return false;
  }
}

/**
 * Replace the QTYPE in a copy of an AAAA query with A (DNS64's second lookup).
 * Other bytes, including the query ID and EDNS options, are preserved.
 */
export function makeAQuery(aaaaQuery: Uint8Array): Uint8Array {
  const parsed = parseDnsQuery(aaaaQuery);
  if (parsed.question.type !== 28) throw new Error('dns64_requires_aaaa');
  const out = aaaaQuery.slice();
  writeU16(out, parsed.question.typeOffset, 1);
  return out;
}

/**
 * Synthesize RFC 6052 AAAA answers from an A response. Existing CNAMEs and
 * non-A answers are retained; original A records are omitted from the answer.
 * Returns null when the response is not eligible or no A answers were present.
 */
export function synthesizeDns64(
  originalQuery: Uint8Array,
  aResponse: Uint8Array,
  prefix = '64:ff9b::/96',
): Uint8Array | null {
  const query = parseDnsQuery(originalQuery);
  const response = parseDnsMessage(aResponse);
  if (query.question.type !== 28 || query.question.klass !== 1 || query.dnssecOk) return null;
  if (response.id !== query.id || (response.flags & 0x000f) !== 0 || response.questions.length !== 1) return null;
  const responseQuestion = response.questions[0];
  if (responseQuestion.type !== 1 || responseQuestion.klass !== 1 || responseQuestion.name !== query.question.name) return null;
  if (response.records.some((record) => record.section === 'answer' && record.type === 28 && record.klass === 1)) return null;

  const nat64 = parseNat64Prefix(prefix);
  const answerRecords = response.records.filter((record) => record.section === 'answer');
  const aRecords = answerRecords.filter((record) => record.type === 1 && record.klass === 1 && record.rdlength === 4);
  if (aRecords.length === 0) return null;
  const retainedAnswers = answerRecords.filter((record) => !(record.type === 1 && record.klass === 1 && record.rdlength === 4));
  const synthetic = aRecords.map((record) => {
    const ipv4 = aResponse.slice(record.rdataOffset, record.rdataOffset + 4);
    return encodeRecord(record.labels, 28, record.klass, record.ttl, embedIpv4(nat64.address, nat64.length, ipv4));
  });
  const totalAnswers = retainedAnswers.length + synthetic.length;
  if (totalAnswers > 0xffff) return null;

  const questionWire = originalQuery.slice(12, query.questionEnd);
  const answerWire = retainedAnswers.map((record) => aResponse.slice(record.rawStart, record.rawEnd));
  const authorityWire = response.records.filter((record) => record.section === 'authority').map((record) => aResponse.slice(record.rawStart, record.rawEnd));
  const additionalWire = response.records.filter((record) => record.section === 'additional').map((record) => aResponse.slice(record.rawStart, record.rawEnd));
  const parts = [
    aResponse.slice(0, 12), questionWire, ...answerWire, ...synthetic, ...authorityWire, ...additionalWire,
  ];
  const size = parts.reduce((n, part) => n + part.length, 0);
  if (size > MAX_DNS_MESSAGE_BYTES) return null;
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  // Header + question occupy the same number of bytes for A and AAAA queries.
  writeU16(out, 0, query.id);
  writeU16(out, 2, readU16(out, 2) & ~0x0020); // synthesized data is not DNSSEC-authenticated
  writeU16(out, 4, 1);
  writeU16(out, 6, totalAnswers);
  writeU16(out, 8, response.authorityCount);
  writeU16(out, 10, response.additionalCount);
  return out;
}

export function makeServfailResponse(queryBytes: Uint8Array): Uint8Array {
  const query = parseDnsQuery(queryBytes);
  const out = queryBytes.slice(0, query.questionEnd);
  const flags = (query.flags & 0x7910) | 0x8082; // preserve RD/CD, set QR+RA and SERVFAIL
  writeU16(out, 2, flags);
  writeU16(out, 4, 1);
  writeU16(out, 6, 0);
  writeU16(out, 8, 0);
  writeU16(out, 10, 0);
  return out;
}

interface Nat64Prefix { address: Uint8Array; length: number; }

function parseNat64Prefix(value: string): Nat64Prefix {
  const match = value.trim().match(/^(.+)\/(32|40|48|56|64|96)$/);
  if (!match) throw new Error('dns64_invalid_prefix');
  const length = Number(match[2]);
  const address = parseIpv6(match[1]);
  for (let bit = length; bit < 128; bit++) clearBit(address, bit);
  return { address, length };
}

function parseIpv6(input: string): Uint8Array {
  const value = input.trim();
  if (!value || value.includes('%') || value.includes('.')) throw new Error('dns64_invalid_ipv6');
  const halves = value.split('::');
  if (halves.length > 2) throw new Error('dns64_invalid_ipv6');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const pieces = [...left, ...right];
  if (pieces.some((piece) => !/^[0-9a-fA-F]{1,4}$/.test(piece))) throw new Error('dns64_invalid_ipv6');
  if (halves.length === 1 && pieces.length !== 8) throw new Error('dns64_invalid_ipv6');
  if (halves.length === 2 && pieces.length >= 8) throw new Error('dns64_invalid_ipv6');
  const zeros = halves.length === 2 ? 8 - pieces.length : 0;
  const words = [...left, ...Array(zeros).fill('0'), ...right].map((piece) => Number.parseInt(piece, 16));
  if (words.length !== 8) throw new Error('dns64_invalid_ipv6');
  const out = new Uint8Array(16);
  words.forEach((word, index) => { out[index * 2] = word >>> 8; out[index * 2 + 1] = word & 255; });
  return out;
}

function clearBit(bytes: Uint8Array, bit: number): void {
  bytes[bit >>> 3] &= ~(0x80 >>> (bit & 7));
}

function setBit(bytes: Uint8Array, bit: number, value: number): void {
  if (value) bytes[bit >>> 3] |= 0x80 >>> (bit & 7);
}

function embedIpv4(prefix: Uint8Array, prefixLength: number, ipv4: Uint8Array): Uint8Array {
  const out = prefix.slice();
  for (let i = 0; i < 32; i++) {
    let target = prefixLength + i;
    if (prefixLength <= 64 && target >= 64) target += 8; // RFC 6052's reserved u octet
    const source = (ipv4[i >>> 3] >>> (7 - (i & 7))) & 1;
    setBit(out, target, source);
  }
  return out;
}

function encodeRecord(labels: Uint8Array[], type: number, klass: number, ttl: number, rdata: Uint8Array): Uint8Array {
  const nameParts = labels.flatMap((label) => [new Uint8Array([label.length]), label]);
  nameParts.push(new Uint8Array([0]));
  const nameLength = nameParts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(nameLength + 10 + rdata.length);
  let offset = 0;
  for (const part of nameParts) { out.set(part, offset); offset += part.length; }
  writeU16(out, offset, type);
  writeU16(out, offset + 2, klass);
  writeU32(out, offset + 4, ttl);
  writeU16(out, offset + 8, rdata.length);
  out.set(rdata, offset + 10);
  return out;
}

export function formatIpv6(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error('dns64_bad_ipv6_bytes');
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  return parts.join(':');
}
