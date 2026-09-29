-- User-control audit and authenticated-admin rate limiting.
-- Rollback: migrations/0001_user_controls.down.sql (drops audit history).
CREATE TABLE IF NOT EXISTS user_control_throttle (
  ip_hash TEXT PRIMARY KEY,
  count INTEGER NOT NULL CHECK (count >= 0),
  window_start INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_control_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER NOT NULL CHECK (actor_user_id > 0),
  target_user_id INTEGER NOT NULL CHECK (target_user_id > 0),
  action TEXT NOT NULL CHECK (action IN ('user_created', 'user_updated', 'user_enabled', 'user_disabled', 'user_deleted')),
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  created_at INTEGER NOT NULL CHECK (created_at > 0)
);

CREATE INDEX IF NOT EXISTS idx_user_control_audit_target
  ON user_control_audit(target_user_id, id DESC);

CREATE TRIGGER IF NOT EXISTS user_control_audit_no_update
BEFORE UPDATE ON user_control_audit
BEGIN
  SELECT RAISE(ABORT, 'user control audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS user_control_audit_no_delete
BEFORE DELETE ON user_control_audit
BEGIN
  SELECT RAISE(ABORT, 'user control audit is append-only');
END;
