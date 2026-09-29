import assert from 'node:assert/strict';
import {
  classifyFailureDomain,
  classifyNetworkCondition,
  normalizeFetchFailure,
  normalizeSocketFailure,
} from '../ai/network-intelligence';

const now = 1_900_000_000_000;
const row = (pathId: string, ok: boolean, lastError = '', checkedAt = now) => ({
  pathId, ok, lastError, checkedAt, latencyMs: ok ? 180 : null,
  failures: ok ? 1 : 4, successes: ok ? 4 : 0, consecutiveFailures: ok ? 0 : 3,
});

const healthy = classifyNetworkCondition(['a.example', 'b.example', 'c.example'], [
  row('a.example', true), row('b.example', true), row('c.example', true),
], now);
assert.equal(healthy.state, 'HEALTHY');
assert.equal(healthy.physicalUpstreamDisconnectionProven, false);
assert.equal(healthy.dpiProven, false);
assert.equal(healthy.scope, 'WORKER_EGRESS_CONFIGURED_PATHS');

const partial = classifyNetworkCondition(['a.example', 'b.example', 'c.example'], [
  row('a.example', true), row('b.example', false, 'dns_failure'), row('c.example', false, 'tcp_failure'),
], now);
assert.equal(partial.state, 'PARTIALLY_UNREACHABLE');
assert.ok(partial.suspectedDomains.includes('DNS_FAILURE'));
assert.ok(partial.suspectedDomains.includes('TCP_FAILURE'));
assert.match(partial.recommendedAction, /healthy paths/i);

const allDown = classifyNetworkCondition(['a.example', 'b.example', 'c.example'], [
  row('a.example', false, 'tcp_failure'), row('b.example', false, 'tcp_failure'), row('c.example', false, 'unknown_socket_failure'),
], now);
assert.equal(allDown.state, 'UPSTREAM_UNAVAILABLE');
assert.equal(allDown.physicalUpstreamDisconnectionProven, false);
assert.ok(allDown.confidence <= 0.8);
assert.match(allDown.recommendedAction, /Worker vantage/i);
assert.ok(allDown.lastKnownGood === null);

const singlePathDown = classifyNetworkCondition(['only.example'], [row('only.example', false, 'tcp_failure')], now);
assert.equal(singlePathDown.state, 'SEVERELY_DEGRADED');
assert.notEqual(singlePathDown.state, 'UPSTREAM_UNAVAILABLE');

const stale = classifyNetworkCondition(['a.example'], [row('a.example', true, '', now - 11 * 60_000)], now);
assert.equal(stale.state, 'UNKNOWN');
assert.equal(stale.confidence, 0);

const future = classifyNetworkCondition(['a.example'], [row('a.example', true, '', now + 5 * 60_000)], now);
assert.equal(future.state, 'UNKNOWN');

const unconfigured = classifyNetworkCondition([], [], now);
assert.equal(unconfigured.state, 'UNKNOWN');
assert.ok(unconfigured.evidence.includes('no_configured_paths'));

assert.equal(classifyFailureDomain('dns_failure'), 'DNS_FAILURE');
assert.equal(classifyFailureDomain('tcp_failure'), 'TCP_FAILURE');
assert.equal(classifyFailureDomain('tls_failure'), 'TLS_FAILURE');
assert.equal(classifyFailureDomain('http_failure:503'), 'DOMAIN_FAILURE');
assert.equal(classifyFailureDomain('websocket_failure'), 'WEBSOCKET_FAILURE');
assert.equal(classifyFailureDomain('origin_failure'), 'ORIGIN_FAILURE');
assert.equal(classifyFailureDomain('auth_failed'), 'AUTHENTICATION_FAILURE');
assert.equal(classifyFailureDomain('invalid_config'), 'CONFIGURATION_FAILURE');
assert.equal(classifyFailureDomain('opaque socket error'), 'UNKNOWN');
assert.equal(normalizeSocketFailure(new Error('connect timed out')), 'unknown_socket_timeout');
assert.equal(normalizeSocketFailure(new Error('ECONNREFUSED')), 'tcp_failure');
assert.equal(normalizeSocketFailure(new Error('EAI_AGAIN')), 'dns_failure');
assert.equal(normalizeFetchFailure(new Error('certificate verify failed')), 'tls_failure');
assert.equal(normalizeFetchFailure(new Error('fetch failed')), 'unknown_https_probe_failure');

// Only configured endpoint IDs are considered. Duplicate samples use the newest valid timestamp.
const filtered = classifyNetworkCondition(['a.example'], [
  row('a.example', false, 'tcp_failure', now - 1_000),
  row('a.example', true, '', now),
  row('unconfigured.example', false, 'tcp_failure', now),
], now);
assert.equal(filtered.state, 'HEALTHY');
assert.equal(filtered.freshPathCount, 1);
console.log('network-intelligence: ok');
