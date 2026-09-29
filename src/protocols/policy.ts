/**
 * Gozargah 2.3 — capability-aware protocol policy.
 *
 * This module never invents transports. It scores only profiles already present
 * in the capability catalog and keeps native Worker vs origin-engine semantics
 * explicit. The score is a bounded hint for config generation; actual health
 * remains the responsibility of the client/origin engine observatory.
 */

import type { ProtocolCapability, ProxyProtocol, Transport } from './catalog';

export type SecurityMode = 'tls' | 'reality' | 'none';

export interface AdaptiveProtocolProfile {
  id: string;
  protocol: ProxyProtocol;
  transport: Transport;
  security: SecurityMode;
  alpn: string[];
  mode: ProtocolCapability['mode'];
  ready: boolean;
  udp: boolean;
  score: number;
  rationale: string[];
}

const SECURITY_DEFAULTS: Record<Transport, SecurityMode[]> = {
  tcp: ['tls', 'reality'],
  kcp: ['tls'],
  ws: ['tls'],
  httpupgrade: ['tls'],
  xhttp: ['tls', 'reality'],
  grpc: ['tls', 'reality'],
  h2: ['tls'],
  'http/1.1': ['tls'],
  h3: ['tls'],
};

const UDP_PROTOCOLS = new Set<ProxyProtocol>(['wireguard', 'hysteria2']);

function score(c: ProtocolCapability, security: SecurityMode): { value: number; rationale: string[] } {
  let value = 50;
  const rationale: string[] = [];
  if (c.mode === 'native-edge') { value += 24; rationale.push('native-edge'); }
  else if (c.mode === 'origin-engine') { value += 8; rationale.push('origin-engine'); }
  if (c.transport === 'xhttp') { value += 14; rationale.push('xhttp'); }
  if (c.transport === 'grpc') { value += 8; rationale.push('multiplexed'); }
  if (c.transport === 'ws') { value += 5; rationale.push('websocket'); }
  if (c.transport === 'httpupgrade') { value -= 7; rationale.push('legacy-transport'); }
  if (c.transport === 'kcp') { value -= 12; rationale.push('udp-transport'); }
  if (c.transport === 'h3') { value += 4; rationale.push('http3-alpn'); }
  if (security === 'tls') { value += 3; rationale.push('tls'); }
  if (security === 'reality') { value += 6; rationale.push('reality'); }
  if (c.protocol === 'vless') value += 5;
  if (c.protocol === 'trojan') value += 3;
  if (c.protocol === 'vmess') value += 1;
  if (c.protocol === 'wireguard' || c.protocol === 'hysteria2') value -= 8;
  return { value: Math.max(0, Math.min(100, value)), rationale };
}

/** Generate a compatibility-aware matrix from the canonical catalog. */
export function buildAdaptiveProtocolPolicy(capabilities: ProtocolCapability[]): AdaptiveProtocolProfile[] {
  const out: AdaptiveProtocolProfile[] = [];
  for (const c of capabilities) {
    for (const security of SECURITY_DEFAULTS[c.transport]) {
      // REALITY is valid only for current Xray transports that explicitly support it.
      if (security === 'reality' && !['tcp', 'xhttp', 'grpc'].includes(c.transport)) continue;
      const scored = score(c, security);
      const id = [c.protocol, c.transport, security].join(':');
      out.push({
        id,
        protocol: c.protocol,
        transport: c.transport,
        security,
        alpn: c.alpn.filter(Boolean),
        mode: c.mode,
        ready: c.ready,
        udp: UDP_PROTOCOLS.has(c.protocol),
        score: scored.value,
        rationale: scored.rationale,
      });
    }
  }
  return out.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

export function choosePreferredProfiles(
  profiles: AdaptiveProtocolProfile[],
  limit = 12,
): AdaptiveProtocolProfile[] {
  const filtered = profiles.filter((p) => p.ready);
  const seen = new Set<string>();
  const result: AdaptiveProtocolProfile[] = [];
  for (const p of filtered) {
    // Keep diversity across protocol and transport instead of returning 12 near-duplicates.
    const family = p.protocol + ':' + p.transport;
    if (seen.has(family)) continue;
    seen.add(family);
    result.push(p);
    if (result.length >= Math.max(1, Math.min(limit, 24))) break;
  }
  return result;
}

export function policySummary(profiles: AdaptiveProtocolProfile[]): {
  ready: number;
  native: number;
  origin: number;
  udp: number;
  top: string[];
} {
  return {
    ready: profiles.filter((p) => p.ready).length,
    native: profiles.filter((p) => p.ready && p.mode === 'native-edge').length,
    origin: profiles.filter((p) => p.ready && p.mode === 'origin-engine').length,
    udp: profiles.filter((p) => p.ready && p.udp).length,
    top: profiles.slice(0, 8).map((p) => p.id),
  };
}
