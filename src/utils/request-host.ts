/**
 * Worker routing normally reflects the HTTP authority in Request.url. Some
 * custom clients dial an IP while sending a DNS hostname as TLS SNI and HTTP
 * Host. When the URL authority is an IP literal, prefer that valid DNS Host;
 * never let Host override a normal hostname URL.
 */
function isIpLike(host: string): boolean {
  const value = host.replace(/^\[|\]$/g, '');
  return value.includes(':') || /^[0-9.]+$/.test(value);
}

export function requestWorkerHostname(request: Request, url: URL): string {
  const urlHost = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!isIpLike(urlHost)) return urlHost;
  const rawHost = request.headers.get('host')?.trim() ?? '';
  if (!rawHost || ['/', '@', '?', '#'].some((part) => rawHost.includes(part))) return urlHost;
  try {
    const parsed = new URL('https://' + rawHost);
    const candidate = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!candidate || parsed.username || parsed.password || isIpLike(candidate)) return urlHost;
    return candidate;
  } catch {
    return urlHost;
  }
}
