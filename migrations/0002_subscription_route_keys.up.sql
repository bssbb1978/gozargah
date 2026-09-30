-- Per-user opaque subscription routes. The route key is a random bearer secret;
-- existing users are backfilled lazily by the Worker on the next panel access.
CREATE TABLE IF NOT EXISTS subscription_route_keys (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  dynamic_prefix TEXT NOT NULL UNIQUE,
  route_key TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subscription_route_keys_prefix_key
  ON subscription_route_keys(dynamic_prefix, route_key);
