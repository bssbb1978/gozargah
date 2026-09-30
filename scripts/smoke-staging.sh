#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${1:-${STAGING_BASE_URL:-}}"
PANEL_PATH="${STAGING_PANEL_PATH:-gozargah}"
CURL_BIN="${CURL_BIN:-curl}"
CURL_TIMEOUT="${CURL_TIMEOUT:-15}"

[[ -n "$BASE_URL" ]] || fail 'STAGING_BASE_URL is required. Usage: STAGING_BASE_URL=https://<worker>.workers.dev scripts/smoke-staging.sh'
[[ "$BASE_URL" == https://* ]] || fail 'staging base URL must use HTTPS.'
[[ "$BASE_URL" != *\?* && "$BASE_URL" != *\#* ]] || fail 'staging base URL must not include a query string or fragment.'
BASE_URL="${BASE_URL%/}"
[[ "$PANEL_PATH" =~ ^[A-Za-z0-9][A-Za-z0-9-]{2,31}$ ]] || fail 'STAGING_PANEL_PATH must match the panel path format (3–32 letters, digits, or hyphens).'
[[ "$CURL_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || fail 'CURL_TIMEOUT must be a positive integer number of seconds.'

EXPECTED_VERSION="$(node -e 'console.log(require(process.argv[1]).version)' "$ROOT_DIR/package.json")" \
  || fail 'could not read expected version from package.json.'
[[ -n "$EXPECTED_VERSION" ]] || fail 'package.json does not declare a version.'

check_response() {
  local check="$1"
  local body="$2"
  if ! printf '%s' "$body" | node -e '
    let data;
    try { data = JSON.parse(require("node:fs").readFileSync(0, "utf8")); }
    catch { console.error("response is not valid JSON"); process.exit(1); }
    const [check, expected] = process.argv.slice(1);
    if (data.version !== expected) {
      console.error(`version mismatch: got ${String(data.version)}, expected ${expected}`);
      process.exit(1);
    }
    if (check === "healthz" && data.ok !== true) {
      console.error("health response did not contain ok=true");
      process.exit(1);
    }
    if (check === "status" && data.dbOk !== true) {
      console.error("panel API status reports dbOk is not true (D1 is unavailable)");
      process.exit(1);
    }
  ' "$check" "$EXPECTED_VERSION"; then
    fail "/$check smoke check failed. Confirm staging deployment, Worker version, and D1 binding/migrations."
  fi
}

if ! health_body="$("$CURL_BIN" --fail --show-error --silent --max-time "$CURL_TIMEOUT" "$BASE_URL/healthz")"; then
  fail "GET $BASE_URL/healthz failed (network, TLS, HTTP status, or timeout)."
fi
check_response healthz "$health_body"
printf 'OK: GET %s/healthz reports ok=true, version=%s.\n' "$BASE_URL" "$EXPECTED_VERSION"

STATUS_URL="$BASE_URL/$PANEL_PATH/api/status"
if ! status_body="$("$CURL_BIN" --fail --show-error --silent --max-time "$CURL_TIMEOUT" "$STATUS_URL")"; then
  fail "GET $STATUS_URL failed (network, TLS, HTTP status, or timeout)."
fi
check_response status "$status_body"
printf 'OK: GET %s reports dbOk=true, version=%s.\n' "$STATUS_URL" "$EXPECTED_VERSION"
printf 'Staging smoke checks passed.\n'
