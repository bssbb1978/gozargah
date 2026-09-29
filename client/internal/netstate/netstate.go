// Package netstate is the AXR client-side route-regime state machine
// (2.17 — AXR-v3.1 "Deep Evasion").
//
// The problem it solves: during a net-e-melli window the INTERNATIONAL
// routes die while the domestic CDN fronting entry (and the clean-IP
// ladder) may still carry traffic. A static priority ladder keeps trying
// the dead international entries first and wastes the connection budget.
// netstate watches the client's OWN entry observations (ok/fail per
// tunnel attempt + the canary liveness probes) and, with hysteresis,
// labels the route regime:
//
//	stable     — no evidence of trouble
//	degraded   — the primary (international) entries are failing while
//	             something else (fronting/canary) still succeeds: the
//	             net-e-melli signature
//	cut        — nothing in the window succeeds anymore (domestic
//	             included): a total local-route cut
//	recovering — after degraded/cut, a streak of fresh successes
//
// The regime drives a priority POLICY (fronting-first under stress) that
// the axr core applies to the failover ladder, an aggressive probe
// cadence, and the bandit context's regime feature (the ordinal widens
// the confidence interval on purpose: unexplored conditions deserve
// exploration).
//
// Honesty rules (same as measure / regime.ts):
//   - the input is the client's own connection outcomes (ok/fail flags);
//     no payload inspection, no DPI identification, no attribution;
//   - the label describes delivery quality as seen from THIS network;
//     "cut" means "no candidate carried traffic in the window", which has
//     multiple explanations (filter, incident, operator);
//   - a canary success deliberately PREVENTS a "cut" verdict: a live
//     global liveness signal says the route is only partially degraded.
package netstate

import (
	"sync"
	"time"
)

// Regime is the route-regime label.
type Regime int

// The route regimes (ordinal doubles as the bandit context rank source).
const (
	RegimeUnknown Regime = iota
	RegimeStable
	RegimeDegraded
	RegimeCut
	RegimeRecovering
)

// Label is the wire/string form (bandit context + audit logs).
func (r Regime) Label() string {
	switch r {
	case RegimeStable:
		return "stable"
	case RegimeDegraded:
		return "degraded"
	case RegimeCut:
		return "cut"
	case RegimeRecovering:
		return "recovering"
	default:
		return "unknown"
	}
}

// Rank orders regimes for merging with the measure package's regime label
// (higher = worse). It is deliberately the same scale the bandit's
// regime-ordinal feature expects.
func (r Regime) Rank() int {
	switch r {
	case RegimeCut:
		return 3
	case RegimeDegraded:
		return 2
	case RegimeRecovering:
		return 1
	default: // stable, unknown
		return 0
	}
}

// String implements fmt.Stringer (audit logs).
func (r Regime) String() string { return r.Label() }

// Role tags an observation with the class of entry it came from.
type Role string

// The observation roles.
const (
	RolePrimary  Role = "primary"  // operator-configured / manifest entries
	RoleFronting Role = "fronting" // the domestic-CDN fronting entry
	RoleCanary   Role = "canary"   // the fleet liveness canary probe
)

// Observation is one client-measured outcome.
type Observation struct {
	Role Role
	OK   bool
	At   time.Time
}

const (
	// windowN: the sliding evidence window (observations).
	windowN = 12
	// minWindowCut: minimum window fill before a "cut" verdict is allowed
	// (a brand-new client must not scream "cut" after two dials).
	minWindowCut = 6
	// minDistinct: a cut/degraded verdict needs evidence from at least
	// this many DISTINCT roles (one flapping entry is not a regime).
	minDistinct = 2
	// recoveryStreak: consecutive fresh successes required to declare
	// recovery (and, with primary evidence, stability).
	recoveryStreak = 4
)

// Policy is the priority table the regime imposes on the failover ladder.
// Priorities are failover-style (LOWER = preferred): config entries start
// at 0, the fronting hint at 50, manifest backups at 100.
type Policy struct {
	Fronting   int
	Primary    int
	Backup     int
	Aggressive bool // use the aggressive probe cadence
}

// Policy returns the regime's priority table.
//
//	stable:     normal ladder (config primary 0 < fronting 50 < backup 100)
//	degraded:   fronting (10) and primaries (20) ahead of backups (40) —
//	            the international primaries are the failing class
//	cut:        fronting FIRST (0), everything else demoted — when even the
//	            domestic route is gone, the ladder order is least-worst
//	            ordering for the moment the route reopens
func (r Regime) Policy() Policy {
	switch r {
	case RegimeCut:
		return Policy{Fronting: 0, Primary: 30, Backup: 40, Aggressive: true}
	case RegimeDegraded, RegimeRecovering:
		return Policy{Fronting: 10, Primary: 20, Backup: 40, Aggressive: true}
	default: // stable, unknown
		return Policy{Fronting: 50, Primary: 0, Backup: 100, Aggressive: false}
	}
}

// Detector is the hysteresis state machine. Safe for concurrent use.
type Detector struct {
	mu     sync.Mutex
	window []Observation
	regime Regime
}

// NewDetector returns a detector in the stable regime.
func NewDetector() *Detector {
	return &Detector{regime: RegimeStable}
}

// Record adds one observation and returns the (possibly changed) regime.
func (d *Detector) Record(o Observation) Regime {
	d.mu.Lock()
	defer d.mu.Unlock()
	if o.At.IsZero() {
		o.At = time.Now()
	}
	d.window = append(d.window, o)
	if len(d.window) > windowN {
		d.window = d.window[len(d.window)-windowN:]
	}
	return d.stepLocked()
}

// Regime returns the current regime.
func (d *Detector) Regime() Regime {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.regime
}

// Policy returns the current regime's priority table.
func (d *Detector) Policy() Policy { return d.Regime().Policy() }

// IsStressed reports degraded-or-cut (the fronting-first + aggressive
// cadence conditions).
func (d *Detector) IsStressed() bool {
	switch d.Regime() {
	case RegimeDegraded, RegimeCut:
		return true
	}
	return false
}

// stepLocked applies the hysteresis rules (caller holds d.mu).
//
// Evidence from the sliding window (last windowN observations):
//
//	allFail      = zero successes, window filled >= minWindowCut, from
//	                   >= minDistinct distinct roles
//	frontingDead = >=1 fronting observation, ALL failed
//	primaryDead  = >=2 primary observations, ALL failed
//	canaryLive   = the NEWEST canary observation in the window succeeded
//	recovery     = the last recoveryStreak observations all succeeded
//
// Transitions:
//
//	stable/unknown -> degraded : primaryDead && !allFail  (net-e-melli)
//	stable/unknown -> cut      : allFail && !canaryLive && frontingDead
//	degraded       -> cut      : allFail && !canaryLive
//	degraded/cut   -> recovering: recovery
//	recovering     -> stable   : recovery && >=2 primary successes in window
//	recovering     -> cut      : allFail && !canaryLive
//
// The canary is the freshness guard for cut verdicts: a canary that LATEST
// succeeded is a live global liveness signal — the route is at most
// PARTIALLY degraded while it is up (a total cut takes it down too, since
// the canary travels the same international pipe).
func (d *Detector) stepLocked() Regime {
	w := d.window
	n := len(w)
	okCount := 0
	distinct := map[Role]bool{}
	primaryOK, primaryFail, frontingOK, frontingFail := 0, 0, 0, 0
	canaryLive := false
	for _, o := range w {
		if o.OK {
			okCount++
		}
		distinct[o.Role] = true
		switch o.Role {
		case RolePrimary:
			if o.OK {
				primaryOK++
			} else {
				primaryFail++
			}
		case RoleFronting:
			if o.OK {
				frontingOK++
			} else {
				frontingFail++
			}
		case RoleCanary:
			// ascending iteration: the last (newest) canary obs wins
			canaryLive = o.OK
		}
	}
	allFail := okCount == 0 && n >= minWindowCut && len(distinct) >= minDistinct
	frontingDead := frontingFail >= 1 && frontingOK == 0
	primaryDead := primaryFail >= 2 && primaryOK == 0
	// a canary with NO observation in the window is not "live" — it is
	// simply silent (the guard is only a veto, never a trigger)
	canaryCut := allFail && !canaryLive

	recovery := false
	if n >= recoveryStreak {
		recovery = true
		for i := len(w) - recoveryStreak; i < len(w); i++ {
			if !w[i].OK {
				recovery = false
				break
			}
		}
	}

	switch d.regime {
	case RegimeCut:
		if recovery {
			d.regime = RegimeRecovering
		}
	case RegimeDegraded:
		if canaryCut {
			d.regime = RegimeCut
		} else if recovery {
			d.regime = RegimeRecovering
		}
	case RegimeRecovering:
		if canaryCut {
			d.regime = RegimeCut
		} else if recovery && primaryOK >= 2 {
			d.regime = RegimeStable
		}
	default: // RegimeUnknown / RegimeStable
		if canaryCut && frontingDead {
			d.regime = RegimeCut
		} else if primaryDead && !allFail {
			d.regime = RegimeDegraded
		}
	}
	return d.regime
}
