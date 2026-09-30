import { describe, expect, it } from 'vitest';
import { requestWorkerHostname } from '../utils/request-host';

describe('requestWorkerHostname', () => {
  it('uses the Worker hostname for an IP URL with a valid Host header', () => {
    const request = new Request('https://104.16.0.1/p-route/key', { headers: { host: 'Panel.Workers.dev:443' } });
    expect(requestWorkerHostname(request, new URL(request.url))).toBe('panel.workers.dev');
  });

  it('does not let Host override an ordinary hostname URL', () => {
    const request = new Request('https://entry.example.com/p-route/key', { headers: { host: 'attacker.example' } });
    expect(requestWorkerHostname(request, new URL(request.url))).toBe('entry.example.com');
  });

  it('rejects malformed or IP Host overrides', () => {
    const url = new URL('https://104.16.0.1/p-route/key');
    expect(requestWorkerHostname(new Request(url, { headers: { host: '192.0.2.1' } }), url)).toBe('104.16.0.1');
    expect(requestWorkerHostname(new Request(url, { headers: { host: 'bad/path.example' } }), url)).toBe('104.16.0.1');
  });
});
