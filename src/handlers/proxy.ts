/**
 * Gozargah — outbound TCP dialer with ProxyIP fallback chain.
 *
 * edgetunnel-style: try the target directly first; Cloudflare refuses
 * loopback connections to CF-fronted targets, so on failure we re-dial
 * through the configured proxyIP list (per-user stable start index,
 * nahan-style consistent hashing).
 */

import { connect } from 'cloudflare:sockets';
import { GzError } from '../config';
import { withTimeout } from '../utils/crypto';
import { glog } from '../utils/log';
import { normalizeSocketFailure } from '../ai/network-intelligence';

const DIAL_TIMEOUT_MS = 6000;

export interface DialResult {
  socket: Socket;
  via: string;
  latencyMs: number;
}

export interface DialAttempt {
  pathId: string;
  ok: boolean;
  latencyMs: number;
  error?: string;
}


export async function dialWithFallback(
  host: string,
  port: number,
  proxyIPs: string[],
  startIdx = 0,
  onAttempt?: (attempt: DialAttempt) => void,
): Promise<DialResult> {
  const candidates: string[] = [host + ':' + port];
  for (let k = 0; k < proxyIPs.length; k++) {
    const ip = proxyIPs[(startIdx + k) % proxyIPs.length];
    if (ip) candidates.push(ip + ':' + port);
  }

  let lastErr: unknown = null;
  for (const cand of candidates) {
    let sock: Socket | null = null;
    const started = Date.now();
    try {
      sock = connect(cand);
      await withTimeout(sock.opened, DIAL_TIMEOUT_MS, 'dial ' + cand);
      const latencyMs = Date.now() - started;
      glog('dial ok -> ' + cand + ' ' + latencyMs + 'ms');
      try { onAttempt?.({ pathId: cand.split(':')[0], ok: true, latencyMs }); } catch { /* telemetry is best effort */ }
      return { socket: sock, via: cand, latencyMs };
    } catch (e) {
      lastErr = e;
      const latencyMs = Date.now() - started;
      try { onAttempt?.({ pathId: cand.split(':')[0], ok: false, latencyMs, error: normalizeSocketFailure(e) }); } catch { /* telemetry is best effort */ }
      try { sock?.close(); } catch { /* ignore */ }
    }
  }
  throw new GzError('all dial attempts failed: ' + String(lastErr), 'dial_failed');
}
