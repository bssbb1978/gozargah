import { protocolCatalog, adaptiveProtocolOrder, ALPN_PROFILES } from '../protocols/catalog';

const edge = protocolCatalog(false).filter((x) => x.mode === 'native-edge' && x.ready);
if (edge.length !== 2 || edge[0].protocol !== 'vless' || edge[1].protocol !== 'trojan') throw new Error('edge capabilities mismatch');
const noOrigin = protocolCatalog(false).filter((x) => x.mode === 'unsupported');
if (!noOrigin.some((x) => x.protocol === 'wireguard')) throw new Error('wireguard should require origin');
if (!noOrigin.some((x) => x.protocol === 'hysteria2')) throw new Error('hysteria2 should require origin');
const withOrigin = protocolCatalog(true).filter((x) => x.ready);
for (const want of [
  ['vmess','ws'], ['vless','xhttp'], ['shadowsocks','tcp'], ['wireguard','h3'], ['hysteria2','h3'],
]) if (!withOrigin.some((x) => x.protocol === want[0] && x.transport === want[1])) throw new Error('missing origin capability ' + want.join('/'));
const order = adaptiveProtocolOrder(true);
if (order[0].protocol !== 'vless' || order[0].transport !== 'ws') throw new Error('adaptive order mismatch');
if (ALPN_PROFILES.length !== 6) throw new Error('alpn profile count mismatch');
console.log('protocol-catalog: ok');
