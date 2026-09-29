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

func ctxAt(ms int64) Context { return Context{Regime: "stable", NowMS: ms} }

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

func TestExplorationPreferUntried(t *testing.T) {
	b := New(1.0, 1, testArms())
	a, scores, err := b.Select(ctxAt(1000))
	if err != nil {
		t.Fatal(err)
	}
	// All arms untried: UCB equal; deterministic tie-break by ID.
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
	// winner: 30 successes; loser: 30 failures.
	for i := 0; i < 30; i++ {
		now += 100
		b.Observe(winner, Outcome{OK: true, Throughput: 4 * 1000 * 1000, RTTMS: 120}, now)
		now += 100
		b.Observe(loser, Outcome{OK: false, Reason: "rst"}, now)
	}
	// The untried third arm is explored first (highest UCB).
	a, _, err := b.Select(ctxAt(now))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != third.ID() {
		t.Fatalf("expected exploration of untried arm, got %s", a.ID())
	}
	// Keep the third arm failing: once it has been tried enough, its mean
	// (0) cannot compete with the winner's (~1.0) at equal exploration.
	for i := 0; i < 10; i++ {
		now += 100
		b.Observe(third, Outcome{OK: false, Reason: "timeout"}, now)
	}
	a2, _, err := b.Select(ctxAt(now))
	if err != nil {
		t.Fatal(err)
	}
	if a2.ID() != winner.ID() {
		t.Fatalf("expected exploitation of winner, got %s", a2.ID())
	}
}

func TestQuarantineAfterFailures(t *testing.T) {
	b := New(1.0, 1, testArms())
	now := int64(0)
	a := testArms()[0]
	for i := 0; i < 5; i++ {
		now += 100
		b.Observe(a, Outcome{OK: false, Reason: "rst"}, now)
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
	alone.Observe(a, Outcome{OK: false, Reason: "rst"}, now)
	alone.Observe(a, Outcome{OK: false, Reason: "rst"}, now+100)
	alone.Observe(a, Outcome{OK: false, Reason: "rst"}, now+200)
	got, _, err := alone.Select(Context{Regime: "stable", NowMS: now + 300})
	if err != nil {
		t.Fatalf("a lone quarantined arm must still be selectable, got err %v", err)
	}
	if got.ID() != a.ID() {
		t.Fatalf("expected lone arm, got %s", got.ID())
	}
	// A success clears the quarantine.
	alone.Observe(a, Outcome{OK: true}, now+400)
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
		b.Observe(arms[0], Outcome{OK: true, Throughput: 3 * 1000 * 1000}, now)
		now += 10
		b.Observe(arms[1], Outcome{OK: true, Throughput: 3 * 1000 * 1000}, now)
		now += 10
		b.Observe(arms[2], Outcome{OK: false, Reason: "rst"}, now)
		now += 10
		b.Observe(arms[3], Outcome{OK: false, Reason: "rst"}, now)
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
		got, _, err := b.Select(ctxAt(now))
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
		b.Observe(testArms()[0], Outcome{OK: true, Throughput: 3 * 1000 * 1000}, now)
	}
	// Under suspected_change the exploration term is multiplied by 1.8:
	// check via the score table, not the pick (untried arms dominate both).
	scStable := b.Scores(Context{Regime: "stable", NowMS: now})
	scChange := b.Scores(Context{Regime: "suspected_change", NowMS: now})
	// The dominant arm's UCB gap should be larger under change.
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
		b.Observe(testArms()[0], Outcome{OK: true, Throughput: 1 * 1000 * 1000, RTTMS: 100}, now)
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
	b.AddArm(Arm{Host: "c.example", Transport: "ws"})
	if len(b.Arms()) != n+1 {
		t.Fatal("AddArm did not grow the arm set")
	}
	// Default FP applied.
	found := false
	for _, a := range b.Arms() {
		if a.Host == "c.example" && a.FP == "chrome" {
			found = true
		}
	}
	if !found {
		t.Fatal("added arm missing default fingerprint")
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
