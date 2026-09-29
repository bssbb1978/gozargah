import { GzError, type Env } from '../config';
import type { GzUser } from '../db/users';
import { getUserByIdFresh, isUserAllowed, recordUsageDelta } from '../db/users';
import { MAX_DNS_MESSAGE_BYTES, makeServfailResponse, parseDnsQuery } from '../dns/wire';
import { consumeUserDnsBudget, resolveVlessDnsDatagram } from './dns';
import { glog } from '../utils/log';

export type ReadVlessDnsBytes = (length: number, allowCleanEof?: boolean) => Promise<Uint8Array | null>;
export type VlessDnsSocket = Pick<WebSocket, 'send' | 'close'>;

/**
 * Process length-prefixed VLESS UDP datagrams for the DNS-only port-53 adapter.
 * The caller provides a stream reader so WebSocket framing remains in the ingress layer.
 */
export async function pumpVlessDns(
  server: VlessDnsSocket,
  readExactly: ReadVlessDnsBytes,
  env: Env,
  user: GzUser,
  version: number,
): Promise<void> {
  server.send(new Uint8Array([version, 0]));
  try {
    while (true) {
      const prefix = await readExactly(2, true);
      if (!prefix) break;
      const size = (prefix[0] << 8) | prefix[1];
      if (size < 12 || size > MAX_DNS_MESSAGE_BYTES) throw new GzError('invalid VLESS DNS datagram size', 'bad_request');
      const query = await readExactly(size);
      if (!query) throw new GzError('missing VLESS DNS datagram', 'bad_request');
      parseDnsQuery(query);

      if (env.GZ_DB && user.id > 0) {
        const fresh = await getUserByIdFresh(env.GZ_DB, user.id);
        if (!fresh || !isUserAllowed(fresh).ok) {
          try { server.close(1008); } catch { /* ignore */ }
          return;
        }
      }
      if (!await consumeUserDnsBudget(env, user)) {
        try { server.close(1013); } catch { /* ignore */ }
        return;
      }

      let answer: Uint8Array;
      try { answer = await resolveVlessDnsDatagram(query, env); }
      catch { answer = makeServfailResponse(query); }
      if (answer.length > 0xffff) throw new GzError('DNS response too large', 'bad_request');
      const frame = new Uint8Array(answer.length + 2);
      frame[0] = (answer.length >>> 8) & 255;
      frame[1] = answer.length & 255;
      frame.set(answer, 2);
      server.send(frame);
      if (env.GZ_DB && user.id > 0) await recordUsageDelta(env.GZ_DB, user.id, query.length + 2, answer.length + 2);
    }
  } catch (error) {
    glog('VLESS DNS stream closed: ' + (error instanceof Error ? error.message : String(error)));
    try { server.close(1008); } catch { /* ignore */ }
    return;
  }
  try { server.close(); } catch { /* ignore */ }
}
