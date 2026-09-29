package evade

import (
	"sync"
	"testing"

	"github.com/bssbb1978/gozargah/axr/internal/measure"
	"github.com/bssbb1978/gozargah/axr/internal/netstate"
)

func clean() Evidence {
	return Evidence{Regime: netstate.RegimeStable, Measure: measure.Vector{}}
}

func TestSeverityTable(t *testing.T) {
	g := NewGovernor()

	if sev := g.severity(clean()); sev != 0 {
		t.Fatalf("clean stable must be 0, got %d", sev)
	}
	e := clean()
	e.Measure.DropRate = 0.2
	if sev := g.severity(e); sev != 1 {
		t.Fatalf("drop 0.2 must be 1, got %d", sev)
	}
	e = clean()
	e.Measure.RSTRate = 0.2
	if sev := g.severity(e); sev != 1 {
		t.Fatalf("rst 0.2 must be 1, got %d", sev)
	}
	e = clean()
	e.FailAggr = true
	if sev := g.severity(e); sev != 1 {
		t.Fatalf("failover aggressive must be 1, got %d", sev)
	}
	e = clean()
	e.Regime = netstate.RegimeDegraded
	if sev := g.severity(e); sev != 1 {
		t.Fatalf("degraded route must be 1, got %d", sev)
	}
	e = clean()
	e.Regime = netstate.RegimeRecovering
	if sev := g.severity(e); sev != 1 {
		t.Fatalf("recovering route must be 1, got %d", sev)
	}
	e = clean()
	e.Regime = netstate.RegimeCut
	if sev := g.severity(e); sev != 2 {
		t.Fatalf("cut route must be 2, got %d", sev)
	}
	e = clean()
	e.Measure.DropRate = 0.5
	if sev := g.severity(e); sev != 2 {
		t.Fatalf("drop 0.5 must be 2, got %d", sev)
	}
	e = clean()
	e.Measure.TLSErrRate = 0.3
	if sev := g.severity(e); sev != 2 {
		t.Fatalf("tls err 0.3 must be 2, got %d", sev)
	}
	e = clean()
	e.Measure.StepAlarm = true
	if sev := g.severity(e); sev != 2 {
		t.Fatalf("step alarm must be 2, got %d", sev)
	}
	// Unknown regime is not stress by itself.
	e = clean()
	e.Regime = netstate.RegimeUnknown
	if sev := g.severity(e); sev != 0 {
		t.Fatalf("unknown regime must be 0, got %d", sev)
	}
}

func TestHysteresisEscalation(t *testing.T) {
	g := NewGovernor()
	for i := 0; i < 5; i++ {
		if e := g.Update(clean()); e.Stance != StanceSteady {
			t.Fatalf("stable %d: %s", i, e.Stance)
		}
	}
	deg := clean()
	deg.Regime = netstate.RegimeDegraded
	// One stressed sample: escalation is armed but not committed.
	if e := g.Update(deg); e.Stance != StanceSteady {
		t.Fatalf("first degraded sample must hold steady, got %s", e.Stance)
	}
	// Second consecutive sample: committed.
	if e := g.Update(deg); e.Stance != StanceCautious {
		t.Fatalf("second degraded sample must escalate, got %s", e.Stance)
	}
	// De-escalation needs four consecutive calm samples.
	for i := 0; i < 3; i++ {
		if e := g.Update(clean()); e.Stance != StanceCautious {
			t.Fatalf("de-escalation %d: still cautious expected, got %s", i, e.Stance)
		}
	}
	if e := g.Update(clean()); e.Stance != StanceSteady {
		t.Fatalf("fourth calm sample must de-escalate, got %s", e.Stance)
	}
}

func TestHysteresisResetOnCalm(t *testing.T) {
	g := NewGovernor()
	deg := clean()
	deg.Regime = netstate.RegimeCut // severity 2
	// Escalate fully: 2 consecutive cut samples -> aggressive.
	if e := g.Update(deg); e.Stance != StanceSteady {
		t.Fatalf("cut 1: %s", e.Stance)
	}
	if e := g.Update(deg); e.Stance != StanceAggressive {
		t.Fatalf("cut 2 must escalate to aggressive (2 hits), got %s", e.Stance)
	}
	// A calm sample mid-way resets the escalation counter: three more
	// cut samples must need two more CONSECUTIVE hits to re-escalate from
	// steady — here we verify the reset on the up-path from steady.
	g2 := NewGovernor()
	_ = g2.Update(deg)   // upHits 1
	_ = g2.Update(clean()) // reset
	_ = g2.Update(deg)   // upHits 1 again
	if e := g2.Update(deg); e.Stance != StanceAggressive {
		t.Fatalf("two consecutive after reset must escalate, got %s", e.Stance)
	}
}

func TestTiltRaisesByOne(t *testing.T) {
	g := NewGovernor()
	// The cautious shape has been connecting reliably.
	for i := 0; i < 10; i++ {
		g.Outcome(StanceCautious, true)
	}
	// Rule floor says steady, posterior says cautious: the tilt lifts the
	// target by one, hysteresis commits after two samples.
	if e := g.Update(clean()); e.Stance != StanceSteady {
		t.Fatalf("tilt sample 1 must still hold steady, got %s", e.Stance)
	}
	if e := g.Update(clean()); e.Stance != StanceCautious {
		t.Fatalf("tilt sample 2 must commit to cautious, got %s", e.Stance)
	}
}

func TestTiltNeverLowersAndNeverSkips(t *testing.T) {
	g := NewGovernor()
	// Strong posterior on the TOP stance, but the rule floor is steady:
	// the tilt may only compare ADJACENT levels, so the target stays 0
	// (one up), never jumps to aggressive.
	for i := 0; i < 20; i++ {
		g.Outcome(StanceAggressive, true)
	}
	for i := 0; i < 6; i++ {
		if e := g.Update(clean()); e.Stance != StanceSteady {
			t.Fatalf("no adjacent posterior: steady expected, got %s", e.Stance)
		}
	}
	// And a balanced posterior (2/4 = 0.5 == steady 0.5) must not tilt.
	g3 := NewGovernor()
	g3.Outcome(StanceCautious, true)
	g3.Outcome(StanceCautious, false)
	for i := 0; i < 6; i++ {
		if e := g3.Update(clean()); e.Stance != StanceSteady {
			t.Fatalf("equal posteriors must not tilt, got %s", e.Stance)
		}
	}
}

func TestExplorationTrial(t *testing.T) {
	g := NewGovernor()
	for i := 1; i <= 21; i++ {
		e := g.Update(clean())
		// Feed the outcome with the stance actually used.
		g.Outcome(e.Stance, true)
		if i == 20 && e.Stance != StanceCautious {
			t.Fatalf("sample 20 must trial cautious, got %s", e.Stance)
		}
		if i != 20 && e.Stance != StanceSteady {
			t.Fatalf("sample %d must be steady, got %s", i, e.Stance)
		}
	}
	// The trial must not have committed a stance change.
	if g.Stance() != StanceSteady {
		t.Fatalf("trial must not commit, committed stance = %s", g.Stance())
	}
}

func TestPolicyLadderMonotone(t *testing.T) {
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			a, b := stances[i], stances[j]
			if b.Cuts[0] < a.Cuts[0] || b.Cuts[1] < a.Cuts[1] ||
				b.Writes[0] < a.Writes[0] || b.Writes[1] < a.Writes[1] ||
				b.MicroGapMS[0] < a.MicroGapMS[0] || b.MicroGapMS[1] < a.MicroGapMS[1] ||
				b.FlowRank < a.FlowRank || b.WSCount < a.WSCount || b.WSGapMS < a.WSGapMS {
				t.Fatalf("ladder not monotone %s -> %s: %+v vs %+v", a.Stance, b.Stance, a, b)
			}
			if b.WSMinB > a.WSMinB || b.WSMaxB > a.WSMaxB {
				t.Fatalf("WS bounds not contained %s -> %s", a.Stance, b.Stance)
			}
		}
	}
	// Steady must be a pure no-op on the surgery ranges.
	s := stances[StanceSteady]
	if s.Cuts != [2]int{0, 0} || s.Writes != [2]int{0, 0} || s.MicroGapMS != [2]int{0, 0} || s.FlowRank != 0 {
		t.Fatalf("steady must not touch the configured surgery shape: %+v", s)
	}
}

func TestConcurrentGovernor(t *testing.T) {
	g := NewGovernor()
	deg := clean()
	deg.Regime = netstate.RegimeDegraded
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = g.Stance()
			}
		}
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				e := g.Update(clean())
				g.Outcome(e.Stance, true)
				if j%7 == 0 {
					g.Update(deg)
					g.Outcome(StanceCautious, j%14 != 0)
				}
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	// Posterior invariants: counts never go negative, means in [0,1].
	g.mu.Lock()
	for i := 0; i < 3; i++ {
		if g.alpha[i] < 1 || g.beta[i] < 1 {
			t.Fatalf("posterior corrupted: %+v", g)
		}
		m := g.alpha[i] / (g.alpha[i] + g.beta[i])
		if m < 0 || m > 1 {
			t.Fatalf("posterior mean out of range: %f", m)
		}
	}
	g.mu.Unlock()
}
