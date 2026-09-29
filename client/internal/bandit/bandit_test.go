package bandit

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func testArms() []Arm {
	return []Arm{
		{Host: "a.example", Transport: "ws", FP: "chrome"},
		{Host: "a.example", Transport: "ws", FP: "firefox"},
		{Host: "b.example", Transport: "ws", FP: "chrome"},
	}
}

// cleanCtx is the all-zero-measurement context (bias feature only).
func cleanCtx(now int64) Context { return Context{Regime: "stable", NowMS: now} }

// badCtx models a degraded network: a high RST rate. It deliberately changes
// a SINGLE feature dimension (rst) so the conditioning test can verify the
// learned conditional means in closed form, free of multi-feature coupling.
func badCtx(now int64) Context {
	return Context{Regime: "watch", NowMS: now, RSTRate: 0.8}
}

func TestRewardBounds(t *testing.T) {
	cases := []struct {
		o  Outcome
		lo float64
		hi float64
	}{
		{Outcome{OK: true}, 0.5, 1.0},
		{Outcome{OK: true, Throughput: 1e9}, 0.5, 1.0},
		{Outcome{OK: true, Throughput: 2 * 1000 * 1000, RTTMS: 0}, 0.75, 1.0},
		{Outcome{OK: true, Throughput: 2 * 1000 * 1000, RTTMS: 4000}, 0, 0.75},
		{Outcome{OK: false, Reason: "rst"}, 0, 0},
		{Outcome{OK: false, Reason: "timeout"}, 0, 0},
	}
	for i, c := range cases {
		r := reward(c.o)
		if r < c.lo || r > c.hi {
			t.Fatalf("case %d: reward %v outside [%v, %v]", i, r, c.lo, c.hi)
		}
		if r < 0 || r > 1 {
			t.Fatalf("reward must stay in [0,1], got %v", r)
		}
	}
}

func TestInvertRoundTrip(t *testing.T) {
	// A = λI + Σ x xᵀ must invert to ≈ identity under the product.
	m := mat{}
	m.identityScale(ridge)
	x := features(Context{RTTMS: 800, JitterMS: 200, RSTRate: 0.4, TLSDrop: 0.1, LossStep: 2, HTTPAnom: 1})
	for i := 0; i < 4; i++ {
		m.addOuter(&x)
	}
	inv, ok := m.invert()
	if !ok {
		t.Fatal("SPD matrix must invert")
	}
	// identity column j of the target: e_j
	for j := 0; j < dim; j++ {
		var ej vec
		ej[j] = 1
		got := m.matVec(&inv.matVec(&ej))
		for i := 0; i < dim; i++ {
			want := 0.0
			if i == j {
				want = 1
			}
			if math.Abs(got[i]-want) > 1e-9 {
				t.Fatalf("A·A⁻¹[%d][%d] = %v, want %v", i, j, got[i], want)
			}
		}
	}
}

func TestExplorationPreferUntried(t *testing.T) {
	b := New(1.0, 1, testArms())
	a, scores, err := b.Select(cleanCtx(1000))
	if err != nil {
		t.Fatal(err)
	}
	// All arms untried: equal boosts; deterministic tie-break by ID.
	if a.ID() != "a.example|ws|chrome" {
		t.Fatalf("expected deterministic first pick, got %s (scores=%+v)", a.ID(), scores)
	}
}

func TestExploitationAfterSuccess(t *testing.T) {
	b := New(1.0, 1, testArms())
	now := int64(0)
	winner := testArms()[0]
	loser := testArms()[1]
	third := testArms()[2]
	// winner: 30 successes; loser: 30 failures (same clean context).
	for i := 0; i < 30; i++ {
		now += 100
		b.Observe(winner, Outcome{OK: true, Throughput: 4 * 1000 * 1000, RTTMS: 120}, cleanCtx(now), now)
		now += 100
		b.Observe(loser, Outcome{OK: false, Reason: "rst"}, cleanCtx(now), now)
	}
	// The untried third arm is explored first (untried boost dominates).
	a, _, err := b.Select(cleanCtx(now))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != third.ID() {
		t.Fatalf("expected exploration of untried arm, got %s", a.ID())
	}
	// Keep the third arm failing: once tried enough, its LinUCB score
	// (≈0 mean + shrinking width) cannot compete with the winner.
	for i := 0; i < 10; i++ {
		now += 100
		b.Observe(third, Outcome{OK: false, Reason: "timeout"}, cleanCtx(now), now)
	}
	a2, _, err := b.Select(cleanCtx(now))
	if err != nil {
		t.Fatal(err)
	}
	if a2.ID() != winner.ID() {
		t.Fatalf("expected exploitation of winner, got %s", a2.ID())
	}
}

func TestLinUCBConditionsOnContext(t *testing.T) {
	// One arm: successes happen under a clean context, failures under a
	// degraded one. LinUCB must learn the *conditional* means: high under
	// clean, low under degraded — something a plain mean (UCB1) cannot do.
	b := New(1.0, 1, []Arm{{Host: "h", Transport: "ws", FP: "chrome"}})
	id := "h|ws|chrome"
	a := b.Arms()[0]
	now := int64(0)
	for i := 0; i < 12; i++ {
		now += 50
		b.Observe(a, Outcome{OK: true, Throughput: 10 * 1000 * 1000}, cleanCtx(now), now)
	}
	for i := 0; i < 12; i++ {
		now += 50
		b.Observe(a, Outcome{OK: false, Reason: "rst"}, badCtx(now), now)
	}
	good := features(cleanCtx(now))
	bad := features(badCtx(now))
	muGood, _ := b.linScore(id, &good)
	muBad, _ := b.linScore(id, &bad)
	if muGood <= 0.6 {
		t.Fatalf("clean-context mean too low: %v", muGood)
	}
	if muBad >= 0.4 {
		t.Fatalf("degraded-context mean too high: %v", muBad)
	}
	// Select must still return the arm (only choice) but the score table
	// must reflect the conditional split.
	scores := b.Scores(badCtx(now))
	if len(scores) != 1 || scores[0].Arm.ID() != id {
		t.Fatalf("score table wrong: %+v", scores)
	}
}

func TestQuarantineAfterFailures(t *testing.T) {
	b := New(1.0, 1, testArms())
	now := int64(0)
	a := testArms()[0]
	for i := 0; i < 5; i++ {
		now += 100
		b.Observe(a, Outcome{OK: false, Reason: "rst"}, cleanCtx(now), now)
	}
	st := b.Snapshot().Stats[a.ID()]
	if st.QuarantinedUntilMS == 0 {
		t.Fatal("expected quarantine after 5 consecutive failures")
	}
	// Backoff grows with the failure run: 5th failure -> step 2 -> 4 min.
	want := int64(60 * 1000) << 2
	if st.QuarantinedUntilMS != now+want {
		t.Fatalf("backoff = %d, want %d", st.QuarantinedUntilMS, now+want)
	}
	// A quarantined arm is only selected when nothing else exists.
	alone := New(1.0, 1, []Arm{a})
	alone.Observe(a, Outcome{OK: false, Reason: "rst"}, cleanCtx(now), now)
	alone.Observe(a, Outcome{OK: false, Reason: "rst"}, cleanCtx(now+100), now+100)
	alone.Observe(a, Outcome{OK: false, Reason: "rst"}, cleanCtx(now+200), now+200)
	got, _, err := alone.Select(Context{Regime: "stable", NowMS: now + 300})
	if err != nil {
		t.Fatalf("a lone quarantined arm must still be selectable, got err %v", err)
	}
	if got.ID() != a.ID() {
		t.Fatalf("expected lone arm, got %s", got.ID())
	}
	// A success clears the quarantine.
	alone.Observe(a, Outcome{OK: true}, cleanCtx(now+400), now+400)
	if st := alone.Snapshot().Stats[a.ID()]; st.QuarantinedUntilMS != 0 {
		t.Fatal("success must clear quarantine")
	}
}

func TestPruneKeepsMinArms(t *testing.T) {
	arms := []Arm{
		{Host: "h", Transport: "ws", FP: "chrome"},
		{Host: "h", Transport: "ws", FP: "firefox"},
		{Host: "h", Transport: "ws", FP: "safari"},
		{Host: "h", Transport: "ws", FP: "randomized"},
	}
	b := New(1.0, 1, arms)
	now := int64(0)
	// All arms get 15 pulls: first two succeed, last two fail everything.
	for i := 0; i < 15; i++ {
		now += 10
		b.Observe(arms[0], Outcome{OK: true, Throughput: 3 * 1000 * 1000}, cleanCtx(now), now)
		now += 10
		b.Observe(arms[1], Outcome{OK: true, Throughput: 3 * 1000 * 1000}, cleanCtx(now), now)
		now += 10
		b.Observe(arms[2], Outcome{OK: false, Reason: "rst"}, cleanCtx(now), now)
		now += 10
		b.Observe(arms[3], Outcome{OK: false, Reason: "rst"}, cleanCtx(now), now)
	}
	pruned := b.Prune()
	if len(pruned) != 2 {
		t.Fatalf("expected 2 pruned, got %v", pruned)
	}
	if len(b.Prune()) != 0 {
		t.Fatal("second prune must be a no-op")
	}
	// Pruned arms are never selected.
	for i := 0; i < 5; i++ {
		got, _, err := b.Select(cleanCtx(now))
		if err != nil {
			t.Fatal(err)
		}
		if got.ID() == arms[2].ID() || got.ID() == arms[3].ID() {
			t.Fatalf("pruned arm selected: %s", got.ID())
		}
	}
}

func TestSuspectedChangeBoostsExploration(t *testing.T) {
	b := New(1.0, 1, testArms())
	now := int64(0)
	// Make arm0 dominant so a stable regime would stay on it.
	for i := 0; i < 20; i++ {
		now += 10
		b.Observe(testArms()[0], Outcome{OK: true, Throughput: 3 * 1000 * 1000}, cleanCtx(now), now)
	}
	// Under suspected_change the exploration term is multiplied by 1.8:
	// check via the score table (dominant arm vs an untried arm).
	scStable := b.Scores(Context{Regime: "stable", NowMS: now})
	scChange := b.Scores(Context{Regime: "suspected_change", NowMS: now})
	u := func(scores []Score, id string) float64 {
		for _, s := range scores {
			if s.Arm.ID() == id {
				return s.Ucb
			}
		}
		t.Fatalf("arm %s missing from scores", id)
		return 0
	}
	dStable := u(scStable, testArms()[0].ID()) - u(scStable, testArms()[1].ID())
	dChange := u(scChange, testArms()[0].ID()) - u(scChange, testArms()[1].ID())
	if dStable == 0 {
		t.Fatal("degenerate gap")
	}
	if math.Abs((dChange/dStable-1.8)/1.8) > 0.05 {
		t.Fatalf("expected ~1.8x exploration scaling, got %.3f vs %.3f", dChange, dStable)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bandit.json")
	b := New(1.2, 7, testArms())
	now := int64(0)
	for i := 0; i < 10; i++ {
		now += 10
		b.Observe(testArms()[0], Outcome{OK: true, Throughput: 1 * 1000 * 1000, RTTMS: 100}, cleanCtx(now), now)
		now += 10
		b.Observe(testArms()[1], Outcome{OK: false, Reason: "rst"}, badCtx(now), now)
	}
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	snap, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	b2 := New(1.0, 0, testArms())
	if err := b2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if b2.C != 1.2 {
		t.Fatalf("C not restored: %v", b2.C)
	}
	s1 := b.Snapshot().Stats[testArms()[0].ID()]
	s2 := b2.Snapshot().Stats[testArms()[0].ID()]
	if s1.Pulls != s2.Pulls || math.Abs(s1.TotalReward-s2.TotalReward) > 1e-9 || math.Abs(s1.RTTEWMA-s2.RTTEWMA) > 1e-9 {
		t.Fatalf("stats mismatch: %+v vs %+v", s1, s2)
	}
	// Lin state must survive the round trip exactly.
	l1 := b.Snapshot().Lin[testArms()[0].ID()]
	l2 := b2.Snapshot().Lin[testArms()[0].ID()]
	if l1 == nil || l2 == nil {
		t.Fatal("lin state missing after round trip")
	}
	for i := 0; i < dim; i++ {
		for j := 0; j < dim; j++ {
			if l1.A[i][j] != l2.A[i][j] {
				t.Fatalf("A[%d][%d] mismatch: %v vs %v", i, j, l1.A[i][j], l2.A[i][j])
			}
		}
		for j := 0; j < dim; j++ {
			if l1.B[i] != l2.B[i] {
				t.Fatalf("B[%d] mismatch: %v vs %v", i, l1.B[i], l2.B[i])
			}
		}
	}
	// Scores under the same context must match after restore.
	for _, ctx := range []Context{cleanCtx(now), badCtx(now)} {
		a1 := b.Scores(ctx)
		a2 := b2.Scores(ctx)
		for i := range a1 {
			if math.Abs(a1[i].Ucb-a2[i].Ucb) > 1e-9 {
				t.Fatalf("ucb mismatch after restore for arm %s: %v vs %v", a1[i].Arm.ID(), a1[i].Ucb, a2[i].Ucb)
			}
		}
	}
}

func TestRestoreLegacySnapshot(t *testing.T) {
	// A pre-2.15 snapshot has no Lin state; restore must rebuild the λI prior.
	b := New(1.0, 1, testArms())
	snap := b.Snapshot()
	snap.Lin = nil
	b2 := New(1.0, 0, testArms())
	if err := b2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if l := b2.Snapshot().Lin[testArms()[0].ID()]; l == nil || l.A[0][0] != ridge {
		t.Fatalf("legacy restore must rebuild ridge prior, got %+v", l)
	}
}

func TestRestoreRejectsEmpty(t *testing.T) {
	b := New(1.0, 1, testArms())
	if err := b.Restore(Snapshot{}); err == nil {
		t.Fatal("empty snapshot must be rejected")
	}
}

func TestAddArm(t *testing.T) {
	b := New(1.0, 1, testArms())
	n := len(b.Arms())
	b.AddArm(Arm{Host: "c.example", Transport: "ws-alt"})
	if len(b.Arms()) != n+1 {
		t.Fatal("AddArm did not grow the arm set")
	}
	// Default FP applied, fresh lin state allocated.
	found := false
	for _, a := range b.Arms() {
		if a.Host == "c.example" && a.FP == "chrome" {
			found = true
		}
	}
	if !found {
		t.Fatal("added arm missing default fingerprint")
	}
	if l := b.Snapshot().Lin["c.example|ws-alt|chrome"]; l == nil || l.A[0][0] != ridge {
		t.Fatal("added arm must start from the ridge prior")
	}
}

func TestSaveAtomicNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bandit.json")
	b := New(1.0, 1, testArms())
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly the target file, got %v", entries)
	}
}
