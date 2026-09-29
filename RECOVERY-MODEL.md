# Recovery Model — Gozargah 2.10.0

## Existing recovery path

1. Scheduled checks probe only configured fallback endpoints (one selected port per endpoint/cycle, bounded endpoint/port counts).
2. Actual proxy dial attempts also update path and profile history.
3. Failure streaks trigger quarantine/backoff in the existing resilience layer; scoring uses freshness and historical outcomes.
4. The controller orders only generator-ready capability profiles and creates a bounded, diverse fallback ladder.
5. Adaptive Guard stages candidates, enforces the 15-minute hold and 3-change/30-minute budget, then promotes only when evidence/health gates permit. Previous plans remain in D1 for rollback.
6. Fresh recovery observations can clear quarantine gradually; failed probes do not imply that the physical upstream has returned.

## 2.10 condition transition

The scheduler runs the condition estimator over configured Worker-egress TCP checks. It stores only a `condition_<state>` reason code in the existing `network_state.reason_codes` and writes an audit event when the condition changes. `/api/network/state` independently constructs the richer response from latest source-tagged samples.

On `UPSTREAM_UNAVAILABLE`, the diagnostic recommends retaining last-known-good and bounded recovery probes. It does not instruct the controller to rotate profiles endlessly or declare service restored. The core controller still uses the existing network quorum and guard.

## Exact limits

- This release has not introduced a new explicit `OFFLINE` mode in the profile controller; `UPSTREAM_UNAVAILABLE` is an observational condition, and existing `recovery/no_healthy_path` modes remain.
- D1 failure behavior remains existing best-effort/worker error handling; no new generic D1 retry framework was added.
- No Xray/sing-box process is controlled by the Worker, and no origin health check adapter is deployed.
- Client-side fragmentation settings are not dynamically tuned. Existing opt-in/static client profile behavior is unchanged.
- No physical route can be created if all upstream connectivity is disconnected.
