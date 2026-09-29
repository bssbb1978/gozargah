# D1 per-user controls and audit

The authenticated panel API's `POST /users`, `PATCH /users/:id`, `DELETE /users/:id`, and `GET /user-audit` routes are protected by the signed panel-admin session and an atomic D1-backed budget of 30 requests per minute per hashed client IP. The separately allowlisted private Telegram admin route uses the same budget keyed by a hash of the Telegram admin id. Raw client IP addresses and raw Telegram ids are not stored in the throttle table.

User writes and their audit entries are submitted together with `D1Database.batch()`. `user_control_audit` records the admin D1 user id, target user id, action, timestamp, and bounded JSON details for control fields only. UUIDs, Trojan credentials, and traffic content are not included. Database triggers reject updates and deletes to audit rows. The audit history has no foreign keys to user rows, so deleting a user does not erase their audit records.

New disables, quota/expiry changes, and enables are committed to D1 before the API returns. Proxy admission re-reads the user row from D1, and subscription-token lookups bypass the isolate user cache and withhold configuration for disabled, expired, or quota-exhausted users. Resolving a host-bound token still scans the user rows to find the matching derived token, so subscription fetch cost grows with account count. An already-established WebSocket session is revalidated on the existing 120-second supervision interval; immediate termination of every live stream across Worker isolates is not provided by this design.

## Schema application

`ensureSchema()` creates the new tables and append-only triggers idempotently on first database use. The equivalent explicit migration is `migrations/0001_user_controls.up.sql` and is safe to apply repeatedly:

```sh
npx wrangler d1 execute gozargah --remote --file migrations/0001_user_controls.up.sql
```

Before rollback, deploy an application version predating this migration so its `ensureSchema()` does not recreate the objects. Export the database first if audit history must be retained; the down migration intentionally deletes it:

```sh
npx wrangler d1 export gozargah --remote --output d1-before-user-controls-rollback.sql
npx wrangler d1 execute gozargah --remote --file migrations/0001_user_controls.down.sql
```

The Miniflare migration test applies the up and down SQL and verifies the audit immutability triggers, JSON constraint, retained row contents, and object removal after rollback. No remote D1 migration has been run as part of this change.
