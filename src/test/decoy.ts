import { decoyResponse } from '../panel/decoy';
import { cleanIpHints } from '../subscription';

function req(path: string, headers?: Record<string, string>): Request {
  return new Request('https://test.local' + path, { headers });
}
function url(path: string): URL {
  return new URL('https://test.local' + path);
}

// 1) legitimate shapes fall through to the normal stealth landing (null)
{
  if (decoyResponse(req('/'), url('/')) !== null) throw new Error('/ must fall through to landing');
  if (decoyResponse(req('/some/ordinary/path'), url('/some/ordinary/path')) !== null) throw new Error('ordinary path must fall through');
  if (decoyResponse(req('/g/abc123?ed=2048'), url('/g/abc123')) !== null) throw new Error('ws-ish path must fall through');
}

// 2) scanner path shapes get benign HTML product pages
{
  const shapes = ['/.env', '/.git/config', '/api/v1/users', '/wp-login.php', '/admin', '/axr', '/status', '/phpmyadmin/index.php', '/.well-known/security.txt'];
  for (const p of shapes) {
    const res = decoyResponse(req(p), url(p));
    if (!res) throw new Error('scanner shape must be decoyed: ' + p);
    if (res.status !== 200) throw new Error('decoy must be 200: ' + p);
    const ct = res.headers.get('content-type') ?? '';
    if (!ct.includes('text/html')) throw new Error('decoy must be HTML: ' + p + ' got ' + ct);
    const body = await res.text();
    if (!body.includes('<title>')) throw new Error('decoy must look like a real page: ' + p);
    if (!/© \d{4}/.test(body)) throw new Error('decoy should carry a copyright line: ' + p);
  }
}

// 3) JSON-typed probes against API shapes get benign JSON APIs
{
  const res = decoyResponse(req('/api/status', { accept: 'application/json' }), url('/api/status'));
  if (!res) throw new Error('json api probe must be decoyed');
  const ct = res.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) throw new Error('json probe must get json, got ' + ct);
  const parsed = JSON.parse(await res.text()) as Record<string, unknown>;
  if (typeof parsed !== 'object' || Object.keys(parsed).length < 3) throw new Error('json decoy too sparse');
}

// 4) padding: two responses for the same path must differ byte-wise
{
  const a = await decoyResponse(req('/.env'), url('/.env'))!.text();
  const b = await decoyResponse(req('/.env'), url('/.env'))!.text();
  if (a === b) throw new Error('decoy padding must vary between responses');
}

// 5) HEAD requests are decoyed too; POST is not (real handlers own POST)
{
  if (!decoyResponse(new Request('https://test.local/.env', { method: 'HEAD' }), url('/.env'))) throw new Error('HEAD scanner must be decoyed');
  if (decoyResponse(new Request('https://test.local/.env', { method: 'POST' }), url('/.env')) !== null) throw new Error('POST must not be decoyed');
}

// 6) unknown-token machine-feed shape + JSON accept → benign JSON
{
  const res = decoyResponse(req('/sub/unknown-token-abc/axr-manifest', { accept: 'application/json' }), url('/sub/unknown-token-abc/axr-manifest'));
  if (!res) throw new Error('axr-manifest probe must be decoyed');
  const ct = res.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) throw new Error('axr-manifest probe must get json, got ' + ct);
}

// 7) cleanIpHints: parse, validate, bound
{
  if (cleanIpHints(undefined).length !== 0) throw new Error('empty hints');
  const got = cleanIpHints(' 104.16.0.1 , 172.64.0.2 , 999.1.1.1 , bad , 1.2.3.4');
  if (JSON.stringify(got) !== JSON.stringify(['104.16.0.1', '172.64.0.2', '1.2.3.4'])) throw new Error('hint parse failed: ' + JSON.stringify(got));
  const many = cleanIpHints(Array.from({ length: 12 }, (_, i) => '10.0.0.' + i).join(','));
  if (many.length !== 8) throw new Error('hints must cap at 8, got ' + many.length);
}

console.log('decoy: ok');
