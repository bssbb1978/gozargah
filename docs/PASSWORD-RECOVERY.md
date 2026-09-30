# Initial panel password enforcement and recovery

## Normal first login

Production requires a password change when the PBKDF2 hash in D1 still matches the bootstrap password. The decision is made server-side; the persisted `isDefaultPassword` boolean is not trusted for that decision. This avoids blocking an older installation whose password was changed but whose marker was stale. Staging retains `FORCE_INITIAL_PASSWORD_CHANGE = "true"` as a force-on override.

After a successful login with the initial password, only the password-change endpoint and logout remain available to that session. A successful change invalidates the old HMAC session and clears its cookie; sign in again using the new password. Login failures continue to use the D1-backed rate limit.

Passwords are never included in events or logs. The emergency rollback variable `ALLOW_DEFAULT_PASSWORD = "true"` disables only automatic enforcement for the built-in password. It is a temporary break-glass setting: remove it as soon as access is restored. It does not override the staging force-on setting or an explicit recovery marker.

## Forgot the panel password (operator recovery)

This procedure edits only the panel settings row in the configured D1 database. It does not deploy a Worker, modify user records, or place a plaintext password in the repository.

1. On a trusted local machine, generate a random one-time temporary password and a random 16-byte salt. Compute `PBKDF2-SHA256(temporary_password, salt, 100000 iterations, 32 bytes)` locally. Use a private password tool/script that does not echo or log the password. Keep only the temporary password in a password manager; do not paste it into SQL, chat, or shell history.
2. Create a temporary SQL file outside the repository with permissions `0600`. Replace the two marked placeholders with the generated hex values. They must contain only hexadecimal characters.

   ```sql
   UPDATE kv_store
   SET value = json_set(
         value,
         '$.passwordSalt', '<GENERATED_32_HEX_CHARACTER_SALT>',
         '$.passwordHash', '<GENERATED_64_HEX_CHARACTER_PBKDF2_HASH>',
         '$.pwIterations', 100000,
         '$.isDefaultPassword', false,
         '$.forcePasswordChange', true
       ),
       rev = rev + 1,
       updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000
   WHERE key = 'settings';
   ```

3. Apply the temporary file to the intended database only (the production database name in the current `wrangler.toml` is `gozargah`):

   ```sh
   chmod 600 "$HOME/.config/gozargah/recover-panel-password.sql"
   npx wrangler d1 execute gozargah --remote --file "$HOME/.config/gozargah/recover-panel-password.sql"
   ```

4. Sign in with the temporary password. The explicit recovery marker forces a change even though the temporary password is not the bootstrap password. Choose a permanent password; the Worker clears the session, so sign in again. Confirm `/gozargah/api/status` reports `passwordChangeRequired: false`, then securely delete the temporary SQL file.

If the SQL update affects zero rows, stop and inspect the target database and `kv_store` settings row before retrying. Never disable TLS verification or print password material as a troubleshooting step. Use Wrangler's normal account access controls; do not add API tokens or passwords to this repository.
