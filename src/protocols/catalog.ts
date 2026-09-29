/**
 * Gozargah — protocol/transport capability catalog.
 *
 * The Worker is the HTTP/WebSocket control/data-plane edge. Protocols that
 * require native UDP (for example WireGuard/Hysteria2) are advertised as
 * origin-engine capabilities until an actual UDP-capable engine is configured.
 */

export type ProxyProtocol =
  | 'vless'
  | 'vmess'
  | 'shadowsocks'
  | 'http'
  | 'trojan'
  | 'wireguard'
  | 'hysteria2';

export type Transport =
  | 'tcp'
  | 'kcp'
  | 'ws'
  | 'httpupgrade'
  | 'xhttp'
  | 'grpc'
  | 'h2'
  | 'http/1.1'
  | 'h3';

export type CapabilityMode = 'native-edge' | 'origin-engine' | 'unsupported';

export interface ProtocolCapability {
  protocol: ProxyProtocol;
  transport: Transport;
  alpn: string[];
  mode: CapabilityMode;
  ready: boolean;
  reason: string;
}

export const ALPN_PROFILES: string[][] = [
  ['h3'],
  ['h2'],
  ['http/1.1'],
  ['h2', 'http/1.1'],
  ['h3', 'h2'],
  ['h3', 'h2', 'http/1.1'],
];

const HTTP12 = ['h2', 'http/1.1'];

/**
 * Native edge capabilities are intentionally conservative. Cloudflare Workers
 * currently accepts HTTP/WebSocket traffic; inbound raw TCP is not generally
 * exposed to Workers, so raw UDP/TCP protocols are origin-engine profiles.
 */
export function protocolCatalog(originEngineConfigured: boolean): ProtocolCapability[] {
  const native = (protocol: ProxyProtocol, transport: Transport, alpn: string[] = ['http/1.1']): ProtocolCapability => ({
    protocol, transport, alpn, mode: 'native-edge', ready: true, reason: 'Handled by the Worker HTTP/WebSocket data plane.',
  });
  const origin = (protocol: ProxyProtocol, transport: Transport, alpn: string[] = HTTP12, reason = 'Requires a compatible Xray/sing-box origin engine.'): ProtocolCapability => ({
    protocol, transport, alpn, mode: originEngineConfigured ? 'origin-engine' : 'unsupported',
    ready: originEngineConfigured,
    reason: originEngineConfigured ? reason : 'Origin engine host is not configured; profile generation is disabled.',
  });

  const out: ProtocolCapability[] = [
    native('vless', 'ws'),
    native('trojan', 'ws'),
    // HTTP-oriented transports are valid capability targets for an origin engine.
    origin('vless', 'tcp', HTTP12),
    origin('vless', 'xhttp', HTTP12),
    origin('vless', 'grpc', ['h2']),
    origin('vless', 'httpupgrade', ['http/1.1']),
    origin('vless', 'kcp', ['']),
    origin('vless', 'h2', ['h2']),
    origin('vless', 'http/1.1', ['http/1.1']),
    origin('vless', 'h3', ['h3']),
    origin('vmess', 'tcp', HTTP12),
    origin('vmess', 'ws', ['http/1.1']),
    origin('vmess', 'xhttp', HTTP12),
    origin('vmess', 'grpc', ['h2']),
    origin('vmess', 'httpupgrade', ['http/1.1']),
    origin('vmess', 'kcp', ['']),
    origin('vmess', 'h2', ['h2']),
    origin('vmess', 'http/1.1', ['http/1.1']),
    origin('vmess', 'h3', ['h3']),
    origin('shadowsocks', 'tcp', []),
    origin('shadowsocks', 'ws', ['http/1.1']),
    origin('shadowsocks', 'xhttp', HTTP12),
    origin('shadowsocks', 'grpc', ['h2']),
    origin('shadowsocks', 'httpupgrade', ['http/1.1']),
    origin('http', 'tcp', HTTP12),
    origin('http', 'h2', ['h2']),
    origin('http', 'http/1.1', ['http/1.1']),
    origin('http', 'h3', ['h3']),
    origin('trojan', 'tcp', HTTP12),
    origin('trojan', 'ws', ['http/1.1']),
    origin('trojan', 'xhttp', HTTP12),
    origin('trojan', 'grpc', ['h2']),
    origin('trojan', 'httpupgrade', ['http/1.1']),
    origin('trojan', 'kcp', ['']),
    origin('trojan', 'h2', ['h2']),
    origin('trojan', 'http/1.1', ['http/1.1']),
    origin('trojan', 'h3', ['h3']),
    origin('wireguard', 'h3', ['h3'], 'Requires a UDP-capable WireGuard engine; HTTP/3 is metadata only.'),
    origin('hysteria2', 'h3', ['h3'], 'Requires a UDP-capable Hysteria2 engine.'),
  ];
  return out;
}

export function bestAvailableCapabilities(originEngineConfigured: boolean): ProtocolCapability[] {
  return protocolCatalog(originEngineConfigured).filter((c) => c.ready);
}

/** Preferred order is conservative: native WebSocket first, then HTTP-origin profiles. */
export function adaptiveProtocolOrder(originEngineConfigured: boolean): Array<{ protocol: ProxyProtocol; transport: Transport; score: number }> {
  return bestAvailableCapabilities(originEngineConfigured)
    .map((c) => {
      let score = 50;
      if (c.mode === 'native-edge') score += 35;
      if (c.transport === 'ws') score += 12;
      if (c.transport === 'xhttp') score += 8;
      if (c.transport === 'grpc') score += 5;
      if (c.protocol === 'vless') score += 4;
      if (c.protocol === 'trojan') score += 3;
      if (c.transport === 'kcp') score -= 8;
      if (c.protocol === 'wireguard' || c.protocol === 'hysteria2') score -= 10;
      return { protocol: c.protocol, transport: c.transport, score };
    })
    .sort((a, b) => b.score - a.score);
}
