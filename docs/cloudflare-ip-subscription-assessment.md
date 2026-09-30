# Cloudflare-only subscription URLs and clean-IP access

**Decision:** the requested system cannot be implemented exactly as stated. In particular, a Worker cannot turn a generic `https://<Cloudflare-IP>/<path>` subscription URL into a reliable, supported endpoint or guarantee that filtering will not disconnect users. This repository already has per-user bearer-token subscriptions, one configurable deployment-wide prefix, decoy handling, and an AXR-only clean-IP dial path. This guide distinguishes those implemented behaviors from the unsupported proposal.

No runtime code or D1 schema was changed for this assessment. A new indexed route-key table or a server-verified IP-pool table would be a D1 migration and a trust-boundary change; those require explicit approval before implementation.

## Feasibility at a glance

| Request | Current status | Important limit |
|---|---|---|
| Separate subscription authorization per user | Implemented | URL is `/<subPath>/<derived-token>`, not the raw UUID. |
| Change the subscription prefix | Implemented globally | `subPath` is one setting for the deployment, not a different prefix per account. |
| Fetch a subscription as `https://<CF-IP>/<path>` | **Not supported as a general URL** | Cloudflare documents Error 1003 for direct IP access; a Worker cannot run before the edge accepts/routes the request. |
| Dial a tunnel entry by a measured Cloudflare IP | Implemented for native AXR | AXR keeps the entry hostname for TLS SNI, certificate verification, and WebSocket `Host`, while dialing an IP. This is not the same as fetching the subscription from an IP. |
| Add more endpoint hostnames | Partially supported | Up to four configured backup entry hosts can point at the same Worker. A hostname under a blocked registrable root still shares that root's DNS/SNI failure domain. |
| Guarantee free operation at any scale | **Not possible to guarantee** | Cloudflare publishes daily free-tier quotas; traffic and D1 rows read/written must stay within them. |
| Guarantee bypass of DPI or a complete international route cut | **Not possible** | The Worker cannot create a reachable route when none exists from the client network. Heuristics can rank measured configured paths only. |

Cloudflare's own [Error 1003 documentation](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1003/) says direct access to a Cloudflare IP is not allowed and directs clients to use a domain name. HTTP `Host` is sent only after TLS is established; it cannot repair a rejected TLS/SNI connection or cause a Worker to execute before Cloudflare routes the request.

## What this checkout actually does

### Subscription route and per-user isolation

`src/index.ts` recognizes `/{subPath}/{token}` (and an optional format suffix). `subPath` comes from the settings row and is validated as a deployment-wide path segment in `src/panel/api.ts`. For each hostname and user UUID, `src/subscription.ts::subTokenFor` derives a distinct 20-hex-character bearer token. The UUID is not placed directly in the URL. The request resolves that token to a user, then checks enabled/expiry/quota before issuing a subscription. Unknown tokens fall through to the existing benign decoy behavior.

Thus the supported shape is:

```text
https://<WORKER_HOST>/<GLOBAL_SUB_PATH>/<USER_TOKEN>
```

It is **not** `https://<IP>/sub/<UUID>`, and the prefix is not currently per-user. A path token can isolate authorization and make accidental disclosure of one user's URL affect that user; it does not isolate users from a hostname/SNI block. A block of the common hostname can affect every user using that hostname.

### Clean IPs are tunnel dial hints, not subscription hosts

The native AXR client can use explicit or harvested IPs as alternate TCP dial addresses while retaining the configured entry hostname for TLS SNI, certificate verification, and the WebSocket `Host`. Its `axr scan` verifies candidates from the scanning client's network; the repo's design describes certificate verification and optional colo trace checks in `docs/AXR-V3-HYPER-RESILIENCE.md`.

The Worker merges `CLEAN_EDGE_IPS` and client-submitted harvest data into `clean_ip_hints`; the current pool is a JSON row in `predictive_state` (`kind='harvest'`, `subject_id='clean_ips'`), not a dedicated, independently verified IP inventory. `src/panel/api.ts` checks that submitted values are syntactically IPv4 and token-authorized, but the Worker does not independently prove that every submitted address belongs to Cloudflare or currently serves this Worker. Treat these values as advisory client-measured hints, not a globally certified “clean IP” list. IPv6 is not accepted by this harvest path.

These hints do not rewrite the subscription URL, do not make generic v2rayNG/Sing-box/Shadowrocket subscription fetches use an IP, and do not help the first fetch if the manifest hostname is unreachable and the client has no cached configuration.

### Headers, formats, and decoys

The existing response code sets a Base64-prefixed `profile-title` (for Unicode compatibility), `profile-update-interval`, and `subscription-userinfo` when usage/expiry metadata is available. Format selection uses the user agent or explicit app suffix. This is not arbitrary encrypted-JSON obfuscation; HTTPS provides transport encryption, while the generated subscription formats remain their normal client formats.

The unknown-token path uses the existing decoy responses. Decoys reduce information returned by unauthenticated probes; they do not make a blocked hostname reachable or constitute a guarantee against active probing.

## Client guidance

### Ordinary subscription import (supported)

Use the URL produced by the panel, with the actual Worker hostname and the per-user token:

```text
https://<WORKER_HOST>/<GLOBAL_SUB_PATH>/<USER_TOKEN>
```

Keep the hostname in the URL so normal TLS SNI and HTTP authority agree. The client-specific import mechanisms for v2rayNG, Sing-box, Shadowrocket, Hiddify, and other apps are not interchangeable; use each client's normal subscription importer and the format already generated for it.

### AXR tunnel entry with an explicit clean-IP dial address (supported by AXR)

Keep `manifest_url` on a hostname that resolves/routes to this Worker. Put candidate IPs on an entry; do not replace the manifest URL with an IP URL:

```json
{
  "manifest_url": "https://<WORKER_HOST>/<GLOBAL_SUB_PATH>/<USER_TOKEN>/axr-manifest",
  "uuid": "<USER_UUID>",
  "entries": [
    {
      "host": "<WORKER_HOST>",
      "ips": ["<CLIENT-MEASURED-CLOUDFLARE-IP>"],
      "fp": "chrome"
    }
  ]
}
```

AXR uses the IP as the TCP dial address and keeps `host` for TLS identity, certificate checks, and WebSocket `Host`. This is a client capability, not a universal URL syntax. The IP must be tested from the user's own network; a scan from another ISP/region is not evidence it works for this user. Use the AXR config/manifest documentation and keep the subscription token private.

Some other clients expose separate fields for address, TLS server name/SNI, and WebSocket Host. **Only if a particular client supports all three**, its tunnel node can be configured with the IP as the dial address and the Worker hostname as both TLS SNI and HTTP Host. This does not make a generic `https://<IP>/...` subscription URL work. If the client only accepts one server hostname or offers only an HTTP Host override but no independent TLS SNI/dial address, this method is not supported by that client. Verify against the exact client version before documenting it as supported.

Do not substitute Google, Amazon, OVH, or Hetzner IPs as Cloudflare edge addresses. They do not route to this Worker merely because they are public IPs. A proxy hosted on those providers would be a different architecture and is outside the Cloudflare-only design.

## D1 and free-tier limits

The current D1 `users` table stores UUID, enabled state, expiry/quota, and account data. Deployment settings—including the single `subPath`—are stored separately in `kv_store`. The harvested IP hint list is the generic `predictive_state` JSON row described above.

There is also a scale concern in the current lookup path: `findUserByToken` calls `listUsersFresh`, which reads the full users table and checks derived tokens in application code. That is O(number of users) rows read per subscription lookup, rather than an indexed token lookup. At 100,000 subscription requests/day and 50 rows scanned per request, that alone is about 5 million row reads/day, before other D1 work. An indexed per-host route-key table could reduce reads, but requires a migration, lifecycle updates on user/host changes, and an approval decision about how those bearer keys are stored and rotated.

Cloudflare currently documents Workers Free at 100,000 requests/day and 10 ms CPU per invocation, and D1 Free at 5 million rows read/day, 100,000 rows written/day, and 5 GB total storage; see [Workers and D1 pricing](https://developers.cloudflare.com/workers/platform/pricing/). These are quotas, not a zero-cost guarantee for arbitrary usage. This repository's scheduled probes, client scans, API writes, user count, and request rate must all be included in capacity planning. Quotas and plan terms can change.

## Why the requested guarantee is impossible

- A unique path does not change TLS SNI or make a filtered hostname reachable.
- If the root hostname/SNI is blocked, every user sharing it can be affected even when each has a unique token path.
- If the client has no path to Cloudflare or any pre-provisioned reachable mirror, neither Worker code nor a local heuristic can create one remotely.
- The internal adaptive engine is deterministic policy/decision logic over measured paths; it is not a model that can infer an unseen route or guarantee censorship bypass. Optional Workers AI advice does not change the transport or network boundary.
- A new per-user domain scheme would require domains/hostnames and routing configuration; random subdomains under one root still share that root's failure domain. It would not meet the requested root-domain independence by itself.

## Proposed D1 design (review only; not applied)

If per-user prefixes and indexed lookups are approved, keep the account UUID/status in the existing `users` table and map each user to a random, revocable bearer path key. Store only a digest of the raw key. The request lookup can then use `(host, path_prefix, token_hash)` directly instead of scanning every user's UUID. The UUID should remain an internal account identifier, not the public bearer credential.

```sql
CREATE TABLE subscription_route_keys (
  host TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (host, path_prefix, token_hash),
  CHECK (length(path_prefix) BETWEEN 3 AND 32),
  CHECK (length(token_hash) = 64)
);
CREATE INDEX idx_subscription_route_keys_user_host
  ON subscription_route_keys(user_id, host, revoked_at, expires_at);
```

The raw path key should be generated from a cryptographically secure random source, returned only to that account, and hashed before persistence. A route is eligible only when the key is not revoked/expired and the joined user is enabled and within quota. Multiple rows allow rotation with an explicitly bounded old-key overlap; the migration must define that policy. `host` must be canonicalized before lookup.

For edge addresses, keep untrusted reports as candidates, separate from the list that is distributed to clients. This table is a starting point only; it deliberately does not claim a client report is independently verified:

```sql
CREATE TABLE clean_ip_candidates (
  ip TEXT NOT NULL,
  relay_host TEXT NOT NULL,
  source TEXT NOT NULL,
  source_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  probe_report_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(probe_report_json)),
  status TEXT NOT NULL DEFAULT 'candidate'
    CHECK (status IN ('candidate', 'approved', 'rejected')),
  approved_at INTEGER NOT NULL DEFAULT 0,
  approved_by_user_id INTEGER REFERENCES users(id),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (ip, relay_host)
);
CREATE INDEX idx_clean_ip_candidates_status_expiry
  ON clean_ip_candidates(status, expires_at, last_seen_at);
```

Application validation must still parse/validate IPs and canonicalize the SNI anchor. Only explicitly approved, fresh candidates should be published as AXR hints. The approval mechanism must be chosen first: an authenticated client's scan report is useful per-network evidence, but is not cryptographic proof that the address is a Cloudflare edge or globally “clean.” If operator promotion is the policy, it needs an authenticated panel action and audit record. If automatic promotion is desired, the independent verification/quorum and poisoning controls must be specified first.

## Approval needed before implementation

Applying the above is a D1 migration and changes the trust boundary for bearer keys and client-contributed addresses. Before implementation, approve (1) the per-host route-key table and key-rotation/revocation policy, (2) who may submit IP candidates and what independent verification or operator promotion is required, and (3) which actual Worker hostname clients will use for TLS SNI/Host. A naked IP URL is not a substitute for those decisions, and no claim of 100% bypass or connectivity should be made.
