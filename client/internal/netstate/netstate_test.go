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
// entry succeeds -> degraded while no working domestic path is proven, then
// the declared net-e-melli window once it is (NOT cut — something carries).
//
// 2.21 refinement: "primaries dead + fronting ALIVE" used to be reported as
// plain `degraded`. It is now its own label, `netemelli`, because the
// evidence supports a strictly stronger statement (the international route
// is down and a domestic path demonstrably works) and because the ladder
// reacts differently: the international classes go behind the blackout-quiet
// gate instead of being re-dialed every round. Severity is unchanged
// (Rank 2, still stressed, still the aggressive cadence), so this is a more
// precise label for the same evidence — never a weaker one.
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
	// No fronting success yet: the label must stay the softer `degraded`
	// (we know international is bad, we do NOT know domestic is good).
	if d.Regime() != RegimeDegraded {
		t.Fatalf("without a working domestic path the regime must stay degraded, got %s", d.Regime())
	}
	// A live fronting success proves the domestic path: net-e-melli window.
	if r := d.Record(obs(RoleFronting, true, 2)); r != RegimeNetEMelli {
		t.Fatalf("live fronting after primary failures must declare netemelli, got %s", r)
	}
	if !d.IsStressed() {
		t.Fatal("netemelli must be stressed")
	}
	if !d.IsBlackout() {
		t.Fatal("netemelli is a blackout regime (no international path)")
	}
	if d.Regime().Rank() != RegimeDegraded.Rank() {
		t.Fatalf("netemelli must not be MORE severe than degraded: %d vs %d",
			d.Regime().Rank(), RegimeDegraded.Rank())
	}
	pol := d.Policy()
	if pol.Fronting >= pol.Primary {
		t.Fatalf("netemelli policy must prefer fronting (%d) over primary (%d)", pol.Fronting, pol.Primary)
	}
	if pol.Primary > pol.Fronting && !pol.QuietPrimary {
		t.Fatal("netemelli policy must put the international primaries behind the quiet gate")
	}
	if !pol.QuietPrimary || !pol.QuietBackup {
		t.Fatalf("netemelli must quiet the international classes, got %+v", pol)
	}
	if !pol.Aggressive {
		t.Fatal("netemelli policy must use the aggressive cadence")
	}
	// The steady policy must NOT quiet anything (no behaviour change when
	// the network is healthy).
	if s := RegimeStable.Policy(); s.QuietPrimary || s.QuietBackup {
		t.Fatal("the stable policy must never quiet an entry class")
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
	// 2.21: the first thing that carries after a cut is the domestic
	// fronting entry, so the correct intermediate label is the declared
	// net-e-melli window — still a blackout regime, still NOT recovery
	// (which needs the full streak).
	if d.Regime() != RegimeNetEMelli {
		t.Fatalf("2 successes are not recovery yet, got %s", d.Regime())
	}
	if !d.IsStressed() {
		t.Fatalf("a 2-success streak after a cut must still read as stressed, got %s", d.Regime())
	}
	d.Record(obs(RoleFronting, true, 20))
	d.Record(obs(RoleFronting, true, 21))
	// 2.21: a DOMESTIC-only success streak does NOT close an intranet
	// window. The window was declared by evidence about the INTERNATIONAL
	// class, so it is closed by evidence about the international class —
	// this is the "never false-positive out of a blackout on a domestic
	// hiccup" rule. Four fronting successes in a row are still netemelli.
	if d.Regime() != RegimeNetEMelli {
		t.Fatalf("domestic-only successes must not close the intranet window, got %s", d.Regime())
	}
	// The international class carries again -> the window closes.
	//   first international success -> softer degraded
	if r := d.Record(obs(RolePrimary, true, 22)); r != RegimeDegraded {
		t.Fatalf("a live international primary must relax netemelli to degraded, got %s", r)
	}
	//   the streak + two primary successes -> recovering, then stable
	d.Record(obs(RolePrimary, true, 23))
	if d.Regime() != RegimeRecovering {
		t.Fatalf("recovery + fresh primary successes must be recovering, got %s", d.Regime())
	}
	d.Record(obs(RolePrimary, true, 24))
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
	if d2.Regime() != RegimeNetEMelli {
		t.Fatalf("setup: expected netemelli, got %s", d2.Regime())
	}
	// 2.21: entering `recovering` requires international evidence, so the
	// setup closes the intranet window the same way a real recovery does.
	d2.Record(obs(RolePrimary, true, 22))
	d2.Record(obs(RolePrimary, true, 23))
	if d2.Regime() != RegimeRecovering {
		t.Fatalf("setup: expected recovering, got %s", d2.Regime())
	}
	// Fresh failures: the window is 12 wide, so the recovery successes
	// eventually flush out and the all-fail condition holds (the loop is
	// bounded, the asserted invariant is the relapse itself).
	for i := 24; i < 48 && d2.Regime() != RegimeCut; i++ {
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
		r       Regime
		front   int
		primary int
		backup  int
		aggr    bool
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

// TestNetEMelliCanaryGuard: a LIVE canary is decisive evidence that the
// international route still works from this network, so the declared
// intranet window must NOT open — even when every primary observation in the
// window failed. This is the "never false-positive into a blackout on a
// regional domestic hiccup" rule (2.21): the canary is a veto for the
// net-e-melli label exactly as it is for `cut`.
func TestNetEMelliCanaryGuard(t *testing.T) {
	d := NewDetector()
	// International liveness proven by the canary...
	d.Record(obs(RoleCanary, true, 0))
	// ...while every primary attempt fails and the domestic relay carries.
	d.Record(obs(RolePrimary, false, 1))
	d.Record(obs(RolePrimary, false, 2))
	d.Record(obs(RoleFronting, true, 3))
	if got := d.Regime(); got == RegimeNetEMelli {
		t.Fatal("a live canary must veto the netemelli label")
	}
	if got := d.Regime(); got != RegimeDegraded {
		t.Fatalf("with a live canary the softer degraded label applies, got %s", got)
	}
	if d.IsBlackout() {
		t.Fatal("with a live canary the client is not in a blackout")
	}
	// The canary goes down: now the intranet window is the best-supported
	// label for the same connection evidence.
	if got := d.Record(obs(RoleCanary, false, 4)); got != RegimeNetEMelli {
		t.Fatalf("a dead canary + live domestic path must declare netemelli, got %s", got)
	}
	if !d.IsBlackout() {
		t.Fatal("netemelli must report as a blackout")
	}
	// Fresh international liveness must close the domestic-only classification
	// and relax the blackout gate so bounded primary probes can resume.
	if got := d.Record(obs(RoleCanary, true, 5)); got != RegimeDegraded {
		t.Fatalf("a recovered international canary must leave netemelli, got %s", got)
	}
	if d.IsBlackout() {
		t.Fatal("a fresh live international canary must clear the blackout label")
	}
}

// TestNetEMelliWithoutACanary: a client with no canary configured has no
// international liveness channel at all. "Domestic works, international does
// not" is then the best-supported reading of the same evidence, so the
// window must still open (the canary is a veto, never a precondition).
func TestNetEMelliWithoutACanary(t *testing.T) {
	d := NewDetector()
	d.Record(obs(RolePrimary, false, 0))
	d.Record(obs(RolePrimary, false, 1))
	if got := d.Record(obs(RoleFronting, true, 2)); got != RegimeNetEMelli {
		t.Fatalf("without a canary the intranet window must still open, got %s", got)
	}
	// A single international success closes it again (window -> degraded).
	if got := d.Record(obs(RolePrimary, true, 3)); got != RegimeDegraded {
		t.Fatalf("one international success must close the window, got %s", got)
	}
}

// TestNetEMelliPolicyIsBounded: the label must never widen the shape ladder
// beyond the declared table, and the quiet flags exist only for the
// international classes (a policy that quieted the DOMESTIC relay would
// silence the only working path).
func TestNetEMelliPolicyIsBounded(t *testing.T) {
	p := RegimeNetEMelli.Policy()
	if p.QuietPrimary != p.QuietBackup {
		t.Fatalf("both international classes must be treated alike: %+v", p)
	}
	if p.Fronting != 0 {
		t.Fatalf("the domestic relay must lead the ladder, got %d", p.Fronting)
	}
	for _, r := range []Regime{RegimeStable, RegimeDegraded, RegimeCut, RegimeRecovering, RegimeNetEMelli} {
		if r.Policy().Fronting < 0 {
			t.Fatalf("%s: fronting priority must be non-negative", r)
		}
	}
	if RegimeCut.Policy().QuietPrimary {
		t.Fatal("a plain cut must not quiet a class (nothing is proven reachable)")
	}
	if !RegimeNetEMelli.IsBlackout() || !RegimeCut.IsBlackout() {
		t.Fatal("both intranet-only regimes are blackouts")
	}
	if RegimeStable.IsBlackout() || RegimeDegraded.IsBlackout() {
		t.Fatal("stable/degraded are not blackouts")
	}
}
