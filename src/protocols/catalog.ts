/**
 * Conservative protocol/transport capability registry.
 *
 * A row is generatable only when this repository has a matching profile
 * template. Merely setting ORIGIN_ENGINE_HOST is not a health check: origin
 * rows remain explicitly marked declared-but-unverified. UDP-only protocols
 * are unsupported here until a real UDP adapter and generator are installed.
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
  | 'udp'
  | 'kcp'
  | 'ws'
  | 'httpupgrade'
  | 'xhttp'
  | 'grpc'
  | 'h2'
  | 'http/1.1'
  | 'h3';

export type CapabilityMode = 'native-edge' | 'origin-engine' | 'unsupported';
export type CapabilityBoundary = 'WORKER_NATIVE' | 'ORIGIN_ENGINE_REQUIRED' | 'UNSUPPORTED';
export type CapabilityStatus = CapabilityBoundary | 'DISABLED' | 'EXPERIMENTAL';
export type CapabilityRisk = 'LOW' | 'MEDIUM' | 'HIGH';
export type SecurityMode = 'tls' | 'reality' | 'none';

export interface ProtocolCapability {
  protocol: ProxyProtocol;
  transport: Transport;
  alpn: string[];
  security: SecurityMode[];
  mode: CapabilityMode;
  boundary: CapabilityBoundary;
  status: CapabilityStatus;
  layer: 'worker' | 'origin';
  generatorAvailable: boolean;
  liveVerificationAvailable: boolean;
  clientSupportRequired: boolean;
  requirements: string[];
  incompatibilities: string[];
  riskClass: CapabilityRisk;
  /** True means this repository can generate the configured profile, not that a remote engine was probed. */
  ready: boolean;
  deploymentValidation: 'not-required' | 'declared-not-tested' | 'unsupported';
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

export const DEFAULT_ORIGIN_TRANSPORTS: Transport[] = ['xhttp', 'grpc', 'httpupgrade', 'ws'];
const SUPPORTED_ORIGIN_PAIRS = new Set<string>([
  'vless:xhttp',
  'vless:grpc',
  'vless:httpupgrade',
  'trojan:xhttp',
  'vmess:ws',
]);
const PROTOCOLS: ProxyProtocol[] = ['vless', 'vmess', 'shadowsocks', 'http', 'trojan', 'wireguard', 'hysteria2'];
const TRANSPORTS: Transport[] = ['tcp', 'udp', 'kcp', 'ws', 'httpupgrade', 'xhttp', 'grpc', 'h2', 'http/1.1', 'h3'];
const TRANSPORT_SET = new Set<string>(TRANSPORTS);

export function parseOriginTransports(value?: string): Transport[] {
  if (value == null || value.trim() === '') return [...DEFAULT_ORIGIN_TRANSPORTS];
  return [...new Set(value.split(',').map((item) => item.trim().toLowerCase()).filter((item): item is Transport => TRANSPORT_SET.has(item)))]
    .filter((transport) => DEFAULT_ORIGIN_TRANSPORTS.includes(transport));
}

function unsupportedReason(protocol: ProxyProtocol, transport: Transport): string {
  if (protocol === 'wireguard' || protocol === 'hysteria2' || transport === 'udp' || transport === 'kcp' || transport === 'h3') {
    return 'UNSUPPORTED: this Worker has no UDP-capable data plane or configured UDP origin adapter.';
  }
  return 'UNSUPPORTED: no validated profile generator exists for this protocol/transport pair.';
}

/**
 * Return a complete explicit matrix. `enabledOriginTransports` is a declaration
 * of which configured transports the operator permits this generator to emit;
 * it does not prove that Xray/sing-box is healthy or listening.
 */
export function protocolCatalog(
  originEngineConfigured: boolean,
  enabledOriginTransports: readonly Transport[] = DEFAULT_ORIGIN_TRANSPORTS,
): ProtocolCapability[] {
  const enabled = new Set(enabledOriginTransports);
  const knownPairs = new Set(['vless:ws', 'trojan:ws', 'shadowsocks:ws', ...SUPPORTED_ORIGIN_PAIRS]);
  const out: ProtocolCapability[] = [];

  for (const protocol of PROTOCOLS) {
    for (const transport of TRANSPORTS) {
      const key = protocol + ':' + transport;
      if (!knownPairs.has(key)) {
        const reason = unsupportedReason(protocol, transport);
        out.push({
          protocol, transport, alpn: [], security: [], mode: 'unsupported', boundary: 'UNSUPPORTED',
          status: 'UNSUPPORTED', layer: 'origin', generatorAvailable: false, liveVerificationAvailable: false,
          clientSupportRequired: false, requirements: [], incompatibilities: [reason], riskClass: 'HIGH',
          ready: false, deploymentValidation: 'unsupported', reason,
        });
        continue;
      }

      if (transport === 'ws' && (protocol === 'vless' || protocol === 'trojan')) {
        out.push({
          protocol, transport, alpn: ['http/1.1'], security: ['tls'], mode: 'native-edge',
          boundary: 'WORKER_NATIVE', status: 'WORKER_NATIVE', layer: 'worker',
          generatorAvailable: true, liveVerificationAvailable: false, clientSupportRequired: true,
          requirements: ['Cloudflare Worker WebSocket ingress', 'TLS at the configured Worker hostname', 'compatible VLESS/Trojan client'],
          incompatibilities: [], riskClass: 'LOW', ready: true, deploymentValidation: 'not-required',
          reason: 'Implemented by the Worker WebSocket data plane; client-to-Worker TLS is provided by the deployment. No live end-to-end probe is available.',
        });
        continue;
      }

      if (protocol === 'shadowsocks' && transport === 'ws') {
        out.push({
          protocol, transport, alpn: ['http/1.1'], security: ['tls'], mode: 'native-edge',
          boundary: 'WORKER_NATIVE', status: 'WORKER_NATIVE', layer: 'worker',
          generatorAvailable: true, liveVerificationAvailable: false, clientSupportRequired: true,
          requirements: ['Cloudflare Worker WebSocket ingress', 'TLS at the configured Worker hostname', 'Shadowsocks AES-256-GCM', 'SIP003 v2ray-plugin WebSocket client'],
          incompatibilities: ['TCP-only; arbitrary Shadowsocks UDP is not implemented'], riskClass: 'MEDIUM',
          ready: true, deploymentValidation: 'not-required',
          reason: 'SIP004 AES-256-GCM is terminated by the Worker over v2ray-plugin WebSocket. DNS-only VLESS UDP is separate; generic Shadowsocks UDP is unsupported.',
        });
        continue;
      }

      const transportEnabled = enabled.has(transport);
      const ready = originEngineConfigured && transportEnabled;
      const status: CapabilityStatus = !originEngineConfigured
        ? 'ORIGIN_ENGINE_REQUIRED'
        : !transportEnabled ? 'DISABLED' : 'ORIGIN_ENGINE_REQUIRED';
      const reason = !originEngineConfigured
        ? 'ORIGIN_ENGINE_REQUIRED: configure an origin host and transport; Worker-native generation is unavailable.'
        : !transportEnabled
          ? 'DISABLED: compatible pair, but this transport is not enabled in ORIGIN_ENGINE_TRANSPORTS.'
          : 'ORIGIN_ENGINE_REQUIRED: a matching client template can be generated, but remote engine compatibility and health have not been tested.';
      out.push({
        protocol, transport,
        alpn: transport === 'grpc' ? ['h2'] : transport === 'httpupgrade' || transport === 'ws' ? ['http/1.1'] : ['h2', 'http/1.1'],
        security: ['tls'],
        mode: 'origin-engine', boundary: 'ORIGIN_ENGINE_REQUIRED', status, layer: 'origin',
        generatorAvailable: true, liveVerificationAvailable: false, clientSupportRequired: true,
        requirements: ['ORIGIN_ENGINE_HOST', 'ORIGIN_ENGINE_TRANSPORTS includes ' + transport, 'compatible deployed Xray/sing-box listener', 'matching client implementation'],
        incompatibilities: transportEnabled ? [] : ['origin_transport_not_enabled'],
        riskClass: 'MEDIUM', ready, deploymentValidation: ready ? 'declared-not-tested' : 'unsupported', reason,
      });
    }
  }
  return out;
}

export function bestAvailableCapabilities(originEngineConfigured: boolean, enabledOriginTransports?: readonly Transport[]): ProtocolCapability[] {
  return protocolCatalog(originEngineConfigured, enabledOriginTransports).filter((c) => c.ready);
}

/** Preferred order is conservative: native WebSocket first, then declared origin profiles. */
export function adaptiveProtocolOrder(originEngineConfigured: boolean, enabledOriginTransports?: readonly Transport[]): Array<{ protocol: ProxyProtocol; transport: Transport; score: number }> {
  return bestAvailableCapabilities(originEngineConfigured, enabledOriginTransports)
    .map((c) => {
      let score = 50;
      if (c.mode === 'native-edge') score += 35;
      if (c.transport === 'ws') score += 12;
      if (c.transport === 'xhttp') score += 8;
      if (c.transport === 'grpc') score += 5;
      if (c.transport === 'h2') score += 4;
      if (c.protocol === 'vless') score += 4;
      if (c.protocol === 'trojan') score += 3;
      return { protocol: c.protocol, transport: c.transport, score };
    })
    .sort((a, b) => b.score - a.score);
}
