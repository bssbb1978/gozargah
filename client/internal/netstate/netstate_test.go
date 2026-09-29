package netstate

import (
	"testing"
	"time"
)

func obs(role Role, ok bool, i int) Observation {
	return Observation{Role: role, OK: ok, At: time.Now().Add(time.Duration(i) * time.Second)}
}

// TestStableStaysStable: a healthy mixed stream must not trigger stress.
func TestStableStaysStable(t *testing.T) {
	d := NewDetector()
	for i := 0; i < 20; i++ {
		r := d.Record(obs(RolePrimary, true, i))
		if r != RegimeStable {
			t.Fatalf("obs %d: expected stable, got %s", i, r)
		}
	}
	if d.IsStressed() {
		t.Fatal("healthy stream must not be stressed")
	}
}

// TestNetEMelliSignature: international primaries fail while the fronting
// entry succeeds -> degraded (NOT cut — something still carries).
func TestNetEMelliSignature(t *testing.T) {
	d := NewDetector()
	d.Record(obs(RolePrimary, false, 0))
	if d.Regime() != RegimeStable {
		t.Fatalf("one failure must not change the regime, got %s", d.Regime())
	}
	// Two failed user-connections on the primary class is already strong
	// evidence (each observation is a whole tunnel attempt, not a packet).
	if r := d.Record(obs(RolePrimary, false, 1)); r != RegimeDegraded {
		t.Fatalf("two primary failures must be degraded, got %s", r)
	}
	// A live fronting success keeps it degraded (recovery needs a streak).
	if r := d.Record(obs(RoleFronting, true, 2)); r != RegimeDegraded {
		t.Fatalf("live fronting after primary failures must stay degraded, got %s", r)
	}
	if !d.IsStressed() {
		t.Fatal("degraded must be stressed")
	}
	pol := d.Policy()
	if pol.Fronting >= pol.Primary {
		t.Fatalf("degraded policy must prefer fronting (%d) over primary (%d)", pol.Fronting, pol.Primary)
	}
	if !pol.Aggressive {
		t.Fatal("degraded policy must use the aggressive cadence")
	}
}

// TestCutWhenDomesticDies: degraded -> cut once EVERYTHING in the window
// fails (fronting included).
func TestCutWhenDomesticDies(t *testing.T) {
	d := NewDetector()
	// enter degraded: 2 primary fails + 1 fronting ok
	d.Record(obs(RolePrimary, false, 0))
	d.Record(obs(RolePrimary, false, 1))
	d.Record(obs(RoleFronting, true, 2))
	// now push failures until the lone success slides out of the 12-window
	for i := 3; i < 18; i++ {
		if d.Regime() == RegimeCut {
			break
		}
		r := RoleFronting
		if i%2 == 0 {
			r = RolePrimary
		}
		d.Record(obs(r, false, i))
	}
	if d.Regime() != RegimeCut {
		t.Fatalf("all-fail window with dead fronting must be cut, got %s", d.Regime())
	}
	pol := d.Policy()
	if pol.Fronting != 0 {
		t.Fatalf("cut policy must put fronting first (0), got %d", pol.Fronting)
	}
}

// TestCanaryPreventsCut: a canary that LATEST succeeded is a live global
// liveness signal — the cut verdict is vetoed while it is in the window
// (the canary travels the same international pipe, so a total cut takes it
// down too).
func TestCanaryPreventsCut(t *testing.T) {
	d := NewDetector()
	// P f, P f -> degraded; then the canary is probed and succeeds.
	d.Record(obs(RolePrimary, false, 0))
	d.Record(obs(RolePrimary, false, 1))
	if d.Regime() != RegimeDegraded {
		t.Fatalf("setup: two primary failures must be degraded, got %s", d.Regime())
	}
	d.Record(obs(RoleCanary, true, 2))
	// Six more failures from both other roles fill the window — but the
	// newest canary observation is a success, so the cut is vetoed.
	for i := 3; i < 9; i++ {
		r := RolePrimary
		if i%2 == 1 {
			r = RoleFronting
		}
		d.Record(obs(r, false, i))
	}
	if d.Regime() == RegimeCut {
		t.Fatal("a live canary must veto the cut verdict")
	}
	if d.Regime() != RegimeDegraded {
		t.Fatalf("failing primaries + dead fronting + live canary must be degraded, got %s", d.Regime())
	}
	// Once the canary itself starts failing, the veto lifts: enough further
	// failures must then produce a cut verdict.
	for i := 9; i < 26; i++ {
		r := RolePrimary
		if i%2 == 1 {
			r = RoleFronting
		} else if i%7 == 6 {
			r = RoleCanary // the canary now fails too
		}
		d.Record(obs(r, false, i))
	}
	if d.Regime() != RegimeCut {
		t.Fatalf("canary dead + all-fail window must be cut, got %s", d.Regime())
	}
}

// TestRecoveryCycle: cut -> recovering -> stable on a streak of successes,
// and recovering -> cut on a relapse.
func TestRecoveryCycle(t *testing.T) {
	d := NewDetector()
	// force cut
	d.Record(obs(RolePrimary, false, 0))
	d.Record(obs(RolePrimary, false, 1))
	d.Record(obs(RoleFronting, true, 2))
	for i := 3; i < 18 && d.Regime() != RegimeCut; i++ {
		r := RoleFronting
		if i%2 == 0 {
			r = RolePrimary
		}
		d.Record(obs(r, false, i))
	}
	if d.Regime() != RegimeCut {
		t.Fatalf("setup: expected cut, got %s", d.Regime())
	}
	// recovery: a streak of 4 successes (fronting first, as the ladder dictates)
	d.Record(obs(RoleFronting, true, 18))
	d.Record(obs(RoleFronting, true, 19))
	if d.Regime() != RegimeCut {
		t.Fatalf("2 successes are not recovery yet, got %s", d.Regime())
	}
	d.Record(obs(RoleFronting, true, 20))
	d.Record(obs(RoleFronting, true, 21))
	if d.Regime() != RegimeRecovering {
		t.Fatalf("4-success streak after cut must be recovering, got %s", d.Regime())
	}
	// stability: the primary also starts carrying again
	d.Record(obs(RolePrimary, true, 22))
	d.Record(obs(RolePrimary, true, 23))
	if d.Regime() != RegimeStable {
		t.Fatalf("recovery + fresh primary successes must be stable, got %s", d.Regime())
	}
	// relapse from recovering must go straight back to cut
	d2 := NewDetector()
	d2.Record(obs(RolePrimary, false, 0))
	d2.Record(obs(RolePrimary, false, 1))
	d2.Record(obs(RoleFronting, true, 2))
	for i := 3; i < 18 && d2.Regime() != RegimeCut; i++ {
		r := RoleFronting
		if i%2 == 0 {
			r = RolePrimary
		}
		d2.Record(obs(r, false, i))
	}
	for i := 18; i < 22; i++ {
		d2.Record(obs(RoleFronting, true, i))
	}
	if d2.Regime() != RegimeRecovering {
		t.Fatalf("setup: expected recovering, got %s", d2.Regime())
	}
	// Twelve fresh failures: the window is 12 wide, so the four recovery
	// successes eventually flush out and the all-fail condition holds.
	for i := 22; i < 34; i++ {
		r := RolePrimary
		if i%2 == 0 {
			r = RoleFronting
		}
		d2.Record(obs(r, false, i))
	}
	if d2.Regime() != RegimeCut {
		t.Fatalf("relapse after recovery must be cut, got %s", d2.Regime())
	}
}

// TestPolicyTable: the priority table per regime.
func TestPolicyTable(t *testing.T) {
	cases := []struct {
		r        Regime
		front    int
		primary  int
		backup   int
		aggr     bool
	}{
		{RegimeStable, 50, 0, 100, false},
		{RegimeUnknown, 50, 0, 100, false},
		{RegimeDegraded, 10, 20, 40, true},
		{RegimeRecovering, 10, 20, 40, true},
		{RegimeCut, 0, 30, 40, true},
	}
	for _, c := range cases {
		p := c.r.Policy()
		if p.Fronting != c.front || p.Primary != c.primary || p.Backup != c.backup || p.Aggressive != c.aggr {
			t.Errorf("policy(%s) = %+v, want {Fronting:%d Primary:%d Backup:%d Aggressive:%v}",
				c.r, p, c.front, c.primary, c.backup, c.aggr)
		}
	}
}

// TestConcurrency: hammer the detector from many goroutines; it must not
// race or panic (run under -race).
func TestConcurrency(t *testing.T) {
	d := NewDetector()
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				d.Record(obs(RolePrimary, i%3 != 0, i))
				_ = d.Policy()
			}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
	if d.Regime() == RegimeUnknown {
		t.Fatal("regime must be set after observations")
	}
}
