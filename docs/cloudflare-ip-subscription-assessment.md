# Per-user subscriptions and Cloudflare IP dialing

## Implemented in this branch

- New users receive a random, opaque per-user route: `/<dynamic-prefix>/<route-key>`. The path does not expose the VLESS UUID. The prefix is random per account; the route key is a 256-bit random bearer credential.
- The route key is stored in D1 in plaintext so the authenticated panel can show the same URL again. Treat the D1 binding and admin panel as credential stores. The D1 table is `subscription_route_keys`; the up/down migration is `migrations/0002_subscription_route_keys.*.sql`. There is no route-key rotation control yet. Existing `/{subPath}/{derived-token}` links remain accepted for backwards compatibility, while the panel now emits the new route by default.
- Dynamic route lookup uses a bounded cache flow: isolate-local `Map` → `caches.default` → indexed D1 lookup. Successful user snapshots have a 30-second TTL, as explicitly selected for this rollout. A change to disable/expiry/quota can therefore take up to 30 seconds to reach a warm cache. Cache misses query the per-user route index instead of scanning the whole users table.
- AXR has optional `manifest_dial_ips` and `manifest_host` settings. It can dial a candidate IP while preserving TLS SNI, certificate verification, and HTTP `Host`. A direct-IP `manifest_url` requires `manifest_host`.
- The Worker continues to return its existing decoy for unknown routes and to emit `profile-title`, `profile-update-interval`, and usage headers.

No Worker was deployed, and no real Worker hostname was supplied. Therefore the client-side direct-IP request is implemented and unit-tested for SNI/Host/dial selection, but it has **not** been verified against a live Cloudflare route or from an Iranian network.

## Important limits

### `https://<IP>/...` is not an ordinary supported URL

Cloudflare documents Error 1003 for direct IP access and instructs clients to use a domain name ([Error 1003](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1003/)). A custom client can attempt an IP TCP connection while sending a valid Worker hostname as TLS SNI and HTTP `Host`; this is different from a browser opening a raw IP URL. Cloudflare may still reject or fail to route it. The Worker hostname must be real and attached to the Worker before this can be tested.

For a normal hostname URL, AXR can use `manifest_dial_ips` or matching entry IPs while keeping the URL hostname for TLS and HTTP routing. For an IP URL, AXR requires `manifest_host` and keeps normal certificate verification enabled. Generic v2rayNG, Sing-box, Shadowrocket, and other subscription importers do not inherit AXR's custom fetch transport; client support is app/version-specific.

### Per-user paths do not create per-user network failure domains

The route credential isolates authorization: leaking one user's opaque route key does not reveal another user's route. It cannot isolate a block of the shared Worker hostname, TLS SNI, or Cloudflare anycast address. A block at those layers can affect every user using the same entry. An IP selected for one user is also not a dedicated address unless Cloudflare explicitly provides such an architecture; unique paths cannot make a shared edge IP unique.

### RAM and Cache API are not global, durable caches

The module-scope `Map` is local to one Worker isolate; isolates can be created, restarted, or evicted independently. Cloudflare's Cache API is scoped to the originating data center and its contents do not automatically replicate to other data centers ([Cache API docs](https://developers.cloudflare.com/workers/runtime-apis/cache/)). Both are accelerators, not a global consistency layer. Cache eviction or a cold isolate sends lookups back to D1.

A 30-second positive cache also means that disabled, expired, quota-exhausted, or changed account data can remain usable/stale for up to that window. The cache stores the authorization/account snapshot (including subscription credentials and usage fields), not only a harmless route pointer. If immediate revocation is required, the auth snapshot must not be positively cached; that would increase D1 reads. The cache is bounded in memory and Cache API errors fall back to D1.

### Clean-IP hints are best-effort, not independently certified

The existing Worker pool is stored as one JSON row in `predictive_state` (`kind='harvest'`, `subject_id='clean_ips'`). Worker-side validation checks IPv4 syntax and token authorization; it does not independently prove Cloudflare ownership or current reachability. The selected policy is to publish authenticated client scan reports as **best-effort hints**, not label them globally verified. AXR verifies TLS against the configured hostname when using an IP, but a successful probe from one network does not prove reachability from another.

Google, Amazon, OVH, and Hetzner addresses are not Cloudflare edge IPs merely because they are public. They cannot route to this Worker without a proxy/server on those providers, which would violate the Cloudflare-only/no-VPS constraint. If a user submits such an address, TLS/route checks may fail; it must not be described as a Cloudflare IP.

## AXR client configuration

Normal hostname URL with optional IP dial candidates:

```json
{
  "manifest_url": "https://<WORKER_HOST>/<DYNAMIC_PREFIX>/<ROUTE_KEY>/axr-manifest",
  "manifest_dial_ips": ["<CLIENT-MEASURED-IP>"],
  "entries": [
    { "host": "<WORKER_HOST>", "ips": ["<CLIENT-MEASURED-IP>"] }
  ]
}
```

Direct-IP subscription fetch, when the client has a configured hostname/SNI anchor:

```json
{
  "manifest_url": "https://<CLOUDFLARE-IP>/<DYNAMIC_PREFIX>/<ROUTE_KEY>/axr-manifest",
  "manifest_host": "<WORKER_HOST>",
  "manifest_dial_ips": ["<CLIENT-MEASURED-IP>"]
}
```

AXR validates every candidate as an IP literal, preserves the hostname for SNI and `Host`, verifies the certificate, tries configured candidates and then DNS (where applicable), and avoids logging the subscription path/key. Use the actual hostname and a candidate measured from the intended client network. No live hostname is currently configured, so the direct-IP example is a client capability to validate after the operator supplies one—not a guarantee that Cloudflare accepts every edge IP.

## Free-tier and availability limits

Cloudflare publishes Workers Free at 100,000 requests/day and D1 Free at 5 million rows read/day and 100,000 rows written/day ([Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/), [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)). An indexed cold lookup is constant-sized; warm isolate/cache hits can avoid a D1 lookup. But cache locality/eviction, other app queries, writes, scheduled probes, and total traffic prevent a zero-cost guarantee at arbitrary usage. The free-tier thresholds are limits, not a guarantee of availability or zero cost for every account/usage pattern.

The adaptive component remains a deterministic **adaptive policy/decision engine** over measured, configured paths. It is not an autonomous model that can invent a route. If the client's network has no route to Cloudflare or another pre-provisioned reachable hostname, Worker code cannot create one; a complete international route cut cannot be bypassed from the serverless Worker alone. No claim of 100% DPI bypass, total-blackout connectivity, or guaranteed free operation is made.

## Operator action still needed

Provide the real Worker hostname (workers.dev or a custom hostname attached to this Worker) before validating direct-IP access end-to-end. Do not deploy until that hostname and account routing are confirmed. The route-key migration is additive; existing `/sub/` URLs remain supported during transition.
