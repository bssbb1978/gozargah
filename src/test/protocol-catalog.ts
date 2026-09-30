import { protocolCatalog, adaptiveProtocolOrder, ALPN_PROFILES, parseOriginTransports } from '../protocols/catalog';
import { buildAdaptiveProtocolPolicy } from '../protocols/policy';

const native = protocolCatalog(false).filter((x) => x.boundary === 'WORKER_NATIVE' && x.ready);
if (native.length !== 3 || native[0].protocol !== 'vless' || native[1].protocol !== 'shadowsocks' || native[2].protocol !== 'trojan') throw new Error('worker-native capabilities mismatch');

const withoutEngine = protocolCatalog(false);
const xhttpNeedsEngine = withoutEngine.find((x) => x.protocol === 'vless' && x.transport === 'xhttp');
if (!xhttpNeedsEngine || xhttpNeedsEngine.boundary !== 'ORIGIN_ENGINE_REQUIRED' || xhttpNeedsEngine.status !== 'ORIGIN_ENGINE_REQUIRED' || xhttpNeedsEngine.ready) throw new Error('origin requirement must remain explicit');
if (withoutEngine.some((x) => !['WORKER_NATIVE', 'ORIGIN_ENGINE_REQUIRED', 'UNSUPPORTED', 'DISABLED', 'EXPERIMENTAL'].includes(x.status))) throw new Error('capability state missing');
if (withoutEngine.some((x) => x.ready && !x.generatorAvailable)) throw new Error('ready capability lacks a generator');
for (const protocol of ['wireguard', 'hysteria2']) {
  const udp = withoutEngine.find((x) => x.protocol === protocol && x.transport === 'udp');
  if (!udp || udp.boundary !== 'UNSUPPORTED' || udp.ready) throw new Error(protocol + ' must not be faked as Worker-native');
}

const withEngine = protocolCatalog(true);
const available = withEngine.filter((x) => x.ready);
for (const [protocol, transport] of [
  ['vless', 'xhttp'], ['vless', 'grpc'], ['vless', 'httpupgrade'], ['trojan', 'xhttp'], ['vmess', 'ws'],
]) {
  const row = available.find((x) => x.protocol === protocol && x.transport === transport);
  if (!row || row.boundary !== 'ORIGIN_ENGINE_REQUIRED' || row.deploymentValidation !== 'declared-not-tested') {
    throw new Error('missing/unverified origin capability ' + protocol + '/' + transport);
  }
}
if (available.some((x) => x.protocol === 'wireguard' || x.protocol === 'hysteria2' || x.protocol === 'http')) {
  throw new Error('unsupported protocols must not be marked ready');
}
if (!available.some((x) => x.protocol === 'shadowsocks' && x.transport === 'ws')) throw new Error('Shadowsocks AEAD WebSocket capability missing');
if (withEngine.find((x) => x.protocol === 'shadowsocks' && x.transport === 'udp')?.ready) throw new Error('generic Shadowsocks UDP must remain unsupported');
if (available.some((x) => x.alpn.includes('h3'))) throw new Error('no emitted profile currently supports HTTP/3');
const order = adaptiveProtocolOrder(true);
if (order[0].protocol !== 'vless' || order[0].transport !== 'ws') throw new Error('adaptive order mismatch');
const restricted = protocolCatalog(true, parseOriginTransports('grpc,not-a-transport'));
if (restricted.filter((x) => x.ready && x.mode === 'origin-engine').some((x) => x.transport !== 'grpc')) throw new Error('origin allowlist was not enforced');
if (restricted.find((x) => x.protocol === 'vless' && x.transport === 'xhttp')?.status !== 'DISABLED') throw new Error('disabled origin transport not labeled DISABLED');
if (restricted.find((x) => x.protocol === 'vless' && x.transport === 'xhttp')?.ready) throw new Error('disabled xhttp was emitted');
if (buildAdaptiveProtocolPolicy(withEngine).some((x) => x.protocol === 'wireguard' || x.protocol === 'hysteria2')) throw new Error('policy generated a profile without validated security/transport');
if (ALPN_PROFILES.length !== 6 || new Set(ALPN_PROFILES.map((x) => x.join(','))).size !== 6) throw new Error('alpn profile catalog mismatch');

// Strict capability schema: this exact key set and ready-pair golden are part
// of the release contract; adding a field or claiming a transport is deliberate.
const capabilityKeys = [
  'protocol', 'transport', 'alpn', 'security', 'mode', 'boundary', 'status', 'layer',
  'generatorAvailable', 'liveVerificationAvailable', 'clientSupportRequired', 'requirements',
  'incompatibilities', 'riskClass', 'ready', 'deploymentValidation', 'reason',
].sort().join(',');
for (const row of [...withoutEngine, ...withEngine]) {
  if (Object.keys(row).sort().join(',') !== capabilityKeys) throw new Error('capability schema key drift');
}
const readyGolden = [
  'shadowsocks:ws', 'trojan:ws', 'vless:grpc', 'vless:httpupgrade',
  'vless:ws', 'vless:xhttp', 'vmess:ws', 'trojan:xhttp',
].sort();
const readyActual = available.map((x) => x.protocol + ':' + x.transport).sort();
if (JSON.stringify(readyActual) !== JSON.stringify(readyGolden)) {
  throw new Error('ready capability golden drift: ' + JSON.stringify(readyActual));
}
const h2 = protocolCatalog(true, ['h2' as const]).filter((x) => x.transport === 'h2');
if (h2.some((x) => x.ready || x.generatorAvailable || x.deploymentValidation !== 'unsupported')) {
  throw new Error('HTTP/2 must not be emitted as a supported Xray origin transport');
}
if (parseOriginTransports('h2').length !== 0) throw new Error('HTTP/2 must not be operator-enableable');
console.log('protocol-catalog: strict schema + golden capabilities: ok');
