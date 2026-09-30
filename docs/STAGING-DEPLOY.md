# Staging deployment and smoke test

A staging environment is declared in `wrangler.toml` as `env.staging`, with its own Worker name and D1 binding. Its D1 ID is intentionally all zeroes as a marked placeholder. **Do not deploy until a dedicated staging D1 database ID replaces it.** The live-deploy guard in `.github/workflows/deploy.yml` fails closed when the target D1 binding is missing or still has the placeholder. Wrangler dry-runs remain allowed.

## Provision and deploy

1. Authenticate in the staging operator environment using `npx wrangler login` or provide a least-privilege Cloudflare API token/account ID through protected CI secrets. Never put credentials in the repository or chat.
2. Create an isolated database:

   ```sh
   npx wrangler d1 create gozargah-staging
   ```

   Copy its returned ID into `env.staging.d1_databases.database_id` in `wrangler.toml`. Do not use the production database ID. Keep the staging Worker name `gozargah-staging` and its `FORCE_INITIAL_PASSWORD_CHANGE = "true"` variable.
3. Apply migrations, verify the bundle, then deploy:

   ```sh
   npx wrangler d1 migrations apply gozargah-staging --env staging --remote
   npx wrangler deploy --env staging --dry-run
   npx wrangler deploy --env staging
   ```

   The first-login flow enforces a password change while the initial default password remains active: after login, the server blocks all other authenticated panel APIs until a new password of at least eight characters is set. The update endpoint clears the initial session, requiring a fresh login. This is a staging-only Worker variable; production behavior is unchanged.
4. Change the initial panel password immediately. The bootstrap default is currently `admin`; use the staging panel at `/gozargah`, sign in once, and complete the mandatory change prompt. Do not reuse a production password.
5. Run the health and database smoke checks against the deployed staging URL (not a local preview):

   ```sh
   STAGING_BASE_URL="https://<staging-worker-url>" npm run smoke:staging
   ```

   The script reads the expected version from `package.json`, checks `/healthz` for `ok: true` and that version, then checks `/gozargah/api/status` for `dbOk: true` and the same version. Set `STAGING_PANEL_PATH` if the panel path differs. Both endpoints are public read-only status endpoints; the script does not submit credentials.

## Current execution status

No staging deployment or live smoke test has been executed in this workspace. Cloudflare credentials were unavailable, and the staging D1 ID remains a placeholder. CI's mock-response smoke-script tests are simulations of response validation, not a deployment or network measurement.
