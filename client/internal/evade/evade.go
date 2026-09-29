// Package evade is the adaptive evasion governor (2.19) — the client-side
// policy brain that watches local evidence (net-e-melli route regime, the
// measured delivery vector, failover stress) and continuously re-tunes the
// SHAPE of the traffic (ClientHello surgery, post-handshake flow morphing,
// WebSocket frame rhythm) to the intensity the current network demands.
//
// Design rules:
//
//  1. Bounded: every parameter lives in a fixed, operator-auditable
//     table (the stance ladder). The governor picks a stance; it never
//     invents out-of-table parameters. Ranges are element-wise maxed
//     with the operator's configured baseline by the caller, so the
//     governor can widen a shape but never narrow one.
//  2. Escalation is fast, de-escalation is slow (hysteresis): a stressed
//     network gets the stronger shape after 2 consecutive samples, but
//     returning to the calm shape needs 4 — no flapping.
//  3. Internal AI: a per-stance Beta posterior fed with tunnel outcomes
//     tilts the choice UP (by at most one level, with a margin) when the
//     posterior says the stronger stance is working better than the rule
//     floor suggests. A periodic single-connection trial of the next
//     stance up gives the posterior its contrast (exploration), so the
//     tilt has data to learn from.
//  4. The operator's hard switch wins: with surgery disabled the caller
//     ignores the escalation entirely; the governor keeps learning so a
//     re-enable starts informed.
package evade

import (
	"sync"

	"github.com/bssbb1978/gozargah/axr/internal/measure"
	"github.com/bssbb1978/gozargah/axr/internal/netstate"
)

// Stance names a point on the bounded evasion-intensity ladder.
type Stance int

const (
	// StanceSteady is the calm baseline: the operator's configured shape
	// untouched, plus the default frame rhythm.
	StanceSteady Stance = iota
	// StanceCautious adds shape variation under mild stress (degraded
	// route, elevated drops/RSTs, failover pressure).
	StanceCautious
	// StanceAggressive is the maximum bounded variation, for strong
	// filtering evidence (route cut, sustained drops, TLS-level
	// failures, CUSUM step alarm).
	StanceAggressive
)

// String is for logs and the decision audit trail.
func (s Stance) String() string {
	switch s {
	case StanceCautious:
		return "cautious"
	case StanceAggressive:
		return "aggressive"
	default:
		return "steady"
	}
}

// Escalation is the governor's concrete per-connection parameters at one
// stance. Cuts/Writes/MicroGapMS are RANGES to be element-wise maxed with
// the operator's configured baseline (0 0 = "no opinion"); FlowRank is a
// flow-profile floor (0 web, 1 chat, 2 video); WS* configure the 2.18
// frame-rhythm fragmenter.
type Escalation struct {
	Stance     Stance
	Cuts       [2]int // ClientHello split points [lo,hi]
	Writes     [2]int // client-flight writes that get cut [lo,hi]
	MicroGapMS [2]int // inter-segment gap window, ms (multi-cut only)
	FlowRank   int    // flow-profile floor
	WSMinB     int    // WS fragment: min fragment bytes
	WSMaxB     int    // WS fragment: max fragment bytes
	WSCount    int    // WS fragment: max fragments per message
	WSGapMS    int    // WS fragment: skewed gap bound, ms
}

// The stance ladder — the only parameters the governor may emit.
var stances = [...]Escalation{
	{Stance: StanceSteady, Cuts: [2]int{0, 0}, Writes: [2]int{0, 0}, MicroGapMS: [2]int{0, 0}, FlowRank: 0, WSMinB: 256, WSMaxB: 16384, WSCount: 4, WSGapMS: 3},
	{Stance: StanceCautious, Cuts: [2]int{2, 3}, Writes: [2]int{1, 3}, MicroGapMS: [2]int{1, 10}, FlowRank: 1, WSMinB: 256, WSMaxB: 16384, WSCount: 5, WSGapMS: 4},
	{Stance: StanceAggressive, Cuts: [2]int{2, 4}, Writes: [2]int{2, 3}, MicroGapMS: [2]int{2, 12}, FlowRank: 2, WSMinB: 192, WSMaxB: 16384, WSCount: 6, WSGapMS: 6},
}

// Evidence is one point-in-time snapshot of the local network state.
type Evidence struct {
	Regime   netstate.Regime // route-regime hysteresis (net-e-melli)
	Measure  measure.Vector  // measured delivery vector for the entry
	FailAggr bool            // failover engine in its aggressive state
}

const (
	holdUp     = 2  // consecutive samples required to escalate
	holdDown   = 4  // consecutive samples required to de-escalate
	explore    = 20 // trial the next stance up on every Nth sample
	tiltMargin = 0.15
)

// Governor is the adaptive policy brain. All methods are safe for
// concurrent use.
type Governor struct {
	mu       sync.Mutex
	current  Stance
	upHits   int
	downHits int
	samples  int
	// per-stance Beta posterior, +1/+1 (uniform) prior.
	alpha [3]float64
	beta  [3]float64
}

// NewGovernor returns a governor at the calm stance.
func NewGovernor() *Governor {
	g := &Governor{current: StanceSteady}
	for i := range g.alpha {
		g.alpha[i] = 1
		g.beta[i] = 1
	}
	return g
}

// severity maps the evidence to a 0..2 stress level (the rule floor).
func (g *Governor) severity(ev Evidence) int {
	sev := 0
	switch ev.Regime {
	case netstate.RegimeDegraded, netstate.RegimeRecovering:
		sev = 1
	case netstate.RegimeCut:
		sev = 2
	}
	v := ev.Measure
	if v.DropRate >= 0.2 || v.RSTRate >= 0.2 || ev.FailAggr {
		if sev < 1 {
			sev = 1
		}
	}
	if v.DropRate >= 0.5 || v.TLSErrRate >= 0.3 || v.StepAlarm {
		sev = 2
	}
	return sev
}

// mean is the posterior mean of one stance (uniform prior counted).
func (g *Governor) mean(s Stance) float64 {
	i := int(s)
	return g.alpha[i] / (g.alpha[i] + g.beta[i])
}

// Update consumes one evidence sample and returns the per-connection
// escalation to use for the NEXT connection. The returned Escalation's
// Stance field is the stance actually used (which may be a one-sample
// exploration trial of the next level up).
func (g *Governor) Update(ev Evidence) Escalation {
	g.mu.Lock()
	defer g.mu.Unlock()

	floor := g.severity(ev)
	target := floor
	// Internal-AI tilt: the posterior may lift the target by exactly one
	// level when it believes the stronger stance is working meaningfully
	// better. It can never lower the target and never exceed the top.
	if floor < int(StanceAggressive) && g.mean(Stance(floor+1))-g.mean(Stance(floor)) > tiltMargin {
		target = floor + 1
	}

	switch {
	case target > int(g.current):
		g.upHits++
		g.downHits = 0
		if g.upHits >= holdUp {
			g.current = Stance(target)
			g.upHits = 0
		}
	case target < int(g.current):
		g.downHits++
		g.upHits = 0
		if g.downHits >= holdDown {
			g.current = Stance(target)
			g.downHits = 0
		}
	default:
		g.upHits = 0
		g.downHits = 0
	}

	g.samples++
	// Exploration: once the current stance is at or above the target and
	// not already at the top, trial the next level up for this ONE
	// connection (hysteresis still gates any committed change). This is
	// what gives the posterior contrast to learn from.
	if g.samples%explore == 0 && int(g.current) >= target && g.current < StanceAggressive {
		return stances[g.current+1]
	}
	return stances[g.current]
}

// Outcome feeds the per-stance posterior with the result of a connection
// that used the given stance: success raises alpha, failure beta.
func (g *Governor) Outcome(stance Stance, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	i := int(stance)
	if i < 0 || i > int(StanceAggressive) {
		return
	}
	if ok {
		g.alpha[i]++
	} else {
		g.beta[i]++
	}
}

// Stance returns the currently committed stance (audit/logs).
func (g *Governor) Stance() Stance {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.current
}
