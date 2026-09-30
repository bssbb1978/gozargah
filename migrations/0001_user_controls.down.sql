-- Rollback for 0001_user_controls.up.sql.
-- This intentionally destroys user-control audit history; export it first if it must be retained.
DROP TRIGGER IF EXISTS user_control_audit_no_update;
DROP TRIGGER IF EXISTS user_control_audit_no_delete;
DROP INDEX IF EXISTS idx_user_control_audit_target;
DROP TABLE IF EXISTS user_control_audit;
DROP TABLE IF EXISTS user_control_throttle;
