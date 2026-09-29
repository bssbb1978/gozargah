package bandit

import (
	"math"
	"math/rand"
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
		mid := inv.matVec(&ej)
		got := m.matVec(&mid)
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
	// Under suspected_change the same arm's exploration term must be
	// materially amplified: the regime multiplier is 1.8x AND the regime
	// ordinal feature (2.16) widens the confidence interval because the
	// regime has never been observed for this arm. We assert amplification
	// of the exploration part (Ucb - Mean) rather than a fixed ratio, since
	// the width change is data-dependent by design.
	scStable := b.Scores(Context{Regime: "stable", NowMS: now})
	scChange := b.Scores(Context{Regime: "suspected_change", NowMS: now})
	expl := func(scores []Score, id string) float64 {
		for _, s := range scores {
			if s.Arm.ID() == id {
				return s.Ucb - s.Mean
			}
		}
		t.Fatalf("arm %s missing from scores", id)
		return 0
	}
	id0 := testArms()[0].ID()
	eStable := expl(scStable, id0)
	eChange := expl(scChange, id0)
	if eStable <= 0 {
		t.Fatalf("degenerate stable exploration: %v", eStable)
	}
	if eChange < 1.3*eStable {
		t.Fatalf("suspected_change must amplify exploration: stable=%.3f change=%.3f", eStable, eChange)
	}
	// And the regime ordinal feature must actually move the vector.
	xStable := features(Context{Regime: "stable", NowMS: now})
	xChange := features(Context{Regime: "suspected_change", NowMS: now})
	if xStable[dim-1] == xChange[dim-1] {
		t.Fatal("regime ordinal feature must differ between regimes")
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

func TestRestoreDimMigration(t *testing.T) {
	// A 2.15 snapshot carried 7×7 Lin state. After the 2.16 upgrade to
	// 16 dims, restore must KEEP the learned stats but rebuild the ridge
	// prior (the old matrices are the wrong shape, not garbage to reuse).
	b := New(1.0, 1, testArms())
	now := int64(0)
	for i := 0; i < 8; i++ {
		now += 10
		b.Observe(testArms()[0], Outcome{OK: true, Throughput: 2 * 1000 * 1000, RTTMS: 90}, cleanCtx(now), now)
	}
	snap := b.Snapshot()
	// Forge the snapshot into the old 7-dim shape.
	seven := 7
	for k := range snap.Lin {
		ls := snap.Lin[k]
		na := make([][]float64, seven)
		for i := 0; i < seven; i++ {
			na[i] = append([]float64{}, ls.A[i][:seven]...)
		}
		ls.A = na
		ls.B = append([]float64{}, ls.B[:seven]...)
	}
	snap.Dim = seven
	b2 := New(1.0, 0, testArms())
	if err := b2.Restore(snap); err != nil {
		t.Fatal(err)
	}
	s1 := b.Snapshot().Stats[testArms()[0].ID()]
	s2 := b2.Snapshot().Stats[testArms()[0].ID()]
	if s1.Pulls != s2.Pulls || math.Abs(s1.TotalReward-s2.TotalReward) > 1e-9 {
		t.Fatalf("dim migration must keep stats: %+v vs %+v", s1, s2)
	}
	l2 := b2.Snapshot().Lin[testArms()[0].ID()]
	if l2 == nil || len(l2.A) != dim || l2.A[0][0] != ridge || l2.A[5][5] != ridge {
		t.Fatalf("dim migration must rebuild the 16x16 ridge prior, got %+v", l2)
	}
	// A current-dim snapshot must still restore Lin exactly.
	snapOK := b.Snapshot()
	b3 := New(1.0, 0, testArms())
	if err := b3.Restore(snapOK); err != nil {
		t.Fatal(err)
	}
	l1 := b.Snapshot().Lin[testArms()[0].ID()]
	l3 := b3.Snapshot().Lin[testArms()[0].ID()]
	for i := 0; i < dim; i++ {
		if l1.A[i][0] != l3.A[i][0] || l1.B[i] != l3.B[i] {
			t.Fatalf("same-dim restore lost Lin state at row %d", i)
		}
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

// ---- 2.17 — ensemble (LinUCB + Beta-TS, meta-blended) tests ----

// TestBetaSampleMoments: the gamma/beta sampler must produce the right
// moments (fixed seed => fully deterministic check).
func TestBetaSampleMoments(t *testing.T) {
	rng := newSeededRand()
	const n = 20000
	// Beta(2,1): mean 2/3, std sqrt(2*1/(9*4)) = 1/6 ≈ 0.1667
	mean := 0.0
	var ss float64
	for i := 0; i < n; i++ {
		x := betaSample(2, 1, rng)
		if x < 0 || x > 1 {
			t.Fatalf("Beta(2,1) sample %v outside [0,1]", x)
		}
		mean += x
		ss += x * x
	}
	mean /= float64(n)
	variance := ss/float64(n) - mean*mean
	if math.Abs(mean-2.0/3.0) > 0.02 {
		t.Fatalf("Beta(2,1) mean = %f, want ~0.667", mean)
	}
	if math.Abs(variance-1.0/18.0) > 0.01 {
		t.Fatalf("Beta(2,1) variance = %f, want ~0.0556", variance)
	}
	// Beta(5,5): symmetric, mean 0.5
	mean = 0.0
	for i := 0; i < n; i++ {
		mean += betaSample(5, 5, rng)
	}
	mean /= float64(n)
	if math.Abs(mean-0.5) > 0.02 {
		t.Fatalf("Beta(5,5) mean = %f, want ~0.5", mean)
	}
}

// TestEnsembleConvergesToGoodArm: with a persistent good arm and a
// persistent bad arm, the TS posteriors must separate and the ensemble must
// settle on the good arm.
func TestEnsembleConvergesToGoodArm(t *testing.T) {
	arms := []Arm{
		{Host: "good.example", Transport: "ws", FP: "chrome"},
		{Host: "bad.example", Transport: "ws", FP: "chrome"},
	}
	b := New(1.0, 7, arms)
	ctx := cleanCtx(1_700_000_000_000)
	// The good arm also saturates the throughput bonus (4 MB/s), so its
	// shaped reward is ~1.0 — the TS posterior converges near 1, not 0.5.
	for i := 0; i < 80; i++ {
		arm, _, err := b.Select(ctx)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if arm == arms[0] {
			b.Observe(arm, Outcome{OK: true, RTTMS: 60, Throughput: 4_000_000}, ctx, int64(1_700_000_000_000+i*1000))
		} else {
			b.Observe(arm, Outcome{OK: false, Reason: "rst"}, ctx, int64(1_700_000_000_000+i*1000))
		}
	}
	if mg := b.tsMean(arms[0].ID()); mg < 0.7 {
		t.Fatalf("good arm posterior mean = %f, want >= 0.7", mg)
	}
	if mb := b.tsMean(arms[1].ID()); mb > 0.5+1e-9 {
		t.Fatalf("bad arm posterior mean = %f, want <= 0.5 (failures cannot raise the prior)", mb)
	}
	// After enough evidence the ensemble must pick the good arm most of the
	// time (the TS draw rarely upsets a strongly separated posterior).
	good := 0
	for i := 0; i < 40; i++ {
		arm, _, err := b.Select(ctx)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if arm == arms[0] {
			good++
		}
	}
	if good < 36 {
		t.Fatalf("ensemble picked good arm %d/40, want >= 36", good)
	}
}

// TestEnsembleArbitration: the meta-weight must actually arbitrate between
// the members. Setup: B has 100 proven successes (TS posterior strongly
// favors B) while A is untried — LinUCB's untried-boost (1+alpha) still
// tops B's converged confidence-bound score, so the members DISAGREE.
func TestEnsembleArbitration(t *testing.T) {
	arms := []Arm{
		{Host: "h.example", Transport: "ws", FP: "chrome"},   // A: untried
		{Host: "h.example", Transport: "ws", FP: "firefox"},  // B: proven
	}
	b := New(1.0, 42, arms)
	A, B := arms[0], arms[1]
	ctx := cleanCtx(1_700_000_000_000)
	// 200 proven successes at saturating throughput: shaped reward ~0.994,
	// so B's posterior mean converges to ~0.99 (draws rarely upset A).
	for i := 0; i < 200; i++ {
		b.Observe(B, Outcome{OK: true, RTTMS: 50, Throughput: 4_000_000}, ctx, int64(1_700_000_000_000+i*1000))
	}
	if m := b.tsMean(B.ID()); m < 0.9 {
		t.Fatalf("setup: B posterior mean = %f, want >= 0.9", m)
	}
	// metaW >= 0.5 -> the LinUCB pick must carry every round.
	b.mu.Lock()
	b.metaW = 0.9
	b.mu.Unlock()
	linPicks := 0
	for i := 0; i < 20; i++ {
		arm, scores, err := b.Select(ctx)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if arm == A {
			linPicks++
		}
		found := false
		for _, sc := range scores {
			if sc.Arm == arm && sc.Model != "" {
				found = sc.Model == "lin"
			}
		}
		if !found {
			t.Fatalf("round %d: chosen arm's score must be stamped model=lin", i)
		}
	}
	if linPicks != 20 {
		t.Fatalf("metaW=0.9 must pick the LinUCB argmax 20/20, got %d", linPicks)
	}
	// metaW < 0.5 -> the Thompson pick carries: B (posterior ~0.98) wins the
	// draw except in a vanishing tail; allow at most 2 upsets.
	b.mu.Lock()
	b.metaW = 0.2
	b.mu.Unlock()
	tsPicks := 0
	for i := 0; i < 20; i++ {
		arm, _, err := b.Select(ctx)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if arm == B {
			tsPicks++
		}
	}
	if tsPicks < 18 {
		t.Fatalf("metaW=0.2 should pick the TS argmax (B) in >=18/20, got %d", tsPicks)
	}
}

// TestMetaWeightFormula: the arbitration weight is the tanh-combination of
// the members' realized-reward EMAs (white-box, deterministic).
func TestMetaWeightFormula(t *testing.T) {
	b := New(1.0, 1, testArms())
	b.mu.Lock()
	b.emaLin = 0.8
	b.emaTs = 0.2
	b.mu.Unlock()
	// Any Observe re-computes metaW from the EMAs.
	b.Observe(testArms()[2], Outcome{OK: false}, cleanCtx(1_700_000_000_000), 1_700_000_000_000)
	// The observed arm is a third arm neither member ranked first, so the
	// EMAs are untouched by this observation.
	want := 0.5 + 0.5*math.Tanh(2*(0.8-0.2))
	b.mu.Lock()
	got := b.metaW
	b.mu.Unlock()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("metaW = %f, want %f", got, want)
	}
}

// TestEnsemblePersistence: the ensemble state round-trips through the
// snapshot, and a 2.16-era snapshot (no Ts/Meta fields) restores to the
// neutral ensemble (fresh posteriors, metaW 0.5).
func TestEnsemblePersistence(t *testing.T) {
	dir := t.TempDir()
	b := New(1.0, 9, testArms())
	ctx := cleanCtx(1_700_000_000_000)
	for i := 0; i < 25; i++ {
		arm := testArms()[i%2]
		ok := i%3 != 0
		b.Observe(arm, Outcome{OK: ok, RTTMS: 40}, ctx, int64(1_700_000_000_000+i*1000))
	}
	if err := b.Save(dir + "/bandit.json"); err != nil {
		t.Fatalf("save: %v", err)
	}
	snap, err := LoadSnapshot(dir + "/bandit.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// 2.17 snapshot carries the ensemble state.
	if len(snap.Ts) == 0 {
		t.Fatal("2.17 snapshot must carry Ts state")
	}
	b2 := New(1.0, 1, testArms())
	if err := b2.Restore(snap); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for id, pair := range snap.Ts {
		b2.mu.Lock()
		ts := b2.ts[id]
		var gotA, gotB float64
		if ts != nil {
			gotA, gotB = ts.alpha, ts.beta
		}
		b2.mu.Unlock()
		if ts == nil || gotA != pair[0] || gotB != pair[1] {
			t.Fatalf("arm %s: restored TS (%v,%v), want (%v,%v)", id, gotA, gotB, pair[0], pair[1])
		}
	}
	b.mu.Lock()
	w1, e1, e2 := b.metaW, b.emaLin, b.emaTs
	b.mu.Unlock()
	b2.mu.Lock()
	w2, e1b, e2b := b2.metaW, b2.emaLin, b2.emaTs
	b2.mu.Unlock()
	if math.Abs(w1-w2) > 1e-12 || math.Abs(e1-e1b) > 1e-12 || math.Abs(e2-e2b) > 1e-12 {
		t.Fatalf("meta state mismatch: (%v,%v,%v) vs (%v,%v,%v)", w1, e1, e2, w2, e1b, e2b)
	}
	// 2.16-era snapshot: strip the ensemble fields -> neutral restore.
	old := snap
	old.Ts = nil
	old.MetaW = 0
	old.EmaLin = 0
	old.EmaTs = 0
	b3 := New(1.0, 1, testArms())
	if err := b3.Restore(old); err != nil {
		t.Fatalf("restore 2.16 snapshot: %v", err)
	}
	for _, a := range old.Arms {
		b3.mu.Lock()
		ts := b3.ts[a.ID()]
		var gotA, gotB float64
		if ts != nil {
			gotA, gotB = ts.alpha, ts.beta
		}
		b3.mu.Unlock()
		if ts == nil || gotA != 1 || gotB != 1 {
			t.Fatalf("arm %s: 2.16 restore must give fresh (1,1), got (%v,%v)", a.ID(), gotA, gotB)
		}
	}
	b3.mu.Lock()
	if b3.metaW != 0.5 {
		b3.mu.Unlock()
		t.Fatalf("2.16 restore must give neutral metaW 0.5, got %f", b3.metaW)
	}
	b3.mu.Unlock()
}

// TestEnsembleDeterminism: same seed + same call sequence => identical
// selections (the Thompson draws are seeded, not wall-clock).
func TestEnsembleDeterminism(t *testing.T) {
	arms := testArms()
	ctxs := []Context{
		cleanCtx(1_700_000_000_000),
		{Regime: "watch", NowMS: 1_700_000_060_000, RTTMS: 300, RSTRate: 0.2},
		{Regime: "suspected_change", NowMS: 1_700_000_120_000, TLSDrop: 0.5, LossStep: 2},
	}
	run := func() []string {
		b := New(1.0, 31, arms)
		out := make([]string, 0, 30)
		for i := 0; i < 30; i++ {
			ctx := ctxs[i%len(ctxs)]
			arm, _, err := b.Select(ctx)
			if err != nil {
				t.Fatalf("select: %v", err)
			}
			out = append(out, arm.ID())
			ok := i%4 != 0
			b.Observe(arm, Outcome{OK: ok, RTTMS: 80}, ctx, int64(1_700_000_000_000+i*1000))
		}
		return out
	}
	a, bRun := run(), run()
	if len(a) != len(bRun) {
		t.Fatalf("sequence length mismatch %d vs %d", len(a), len(bRun))
	}
	for i := range a {
		if a[i] != bRun[i] {
			t.Fatalf("round %d: %s vs %s — ensemble must be deterministic under a fixed seed", i, a[i], bRun[i])
		}
	}
}

// newSeededRand is a deterministic rand source for sampler moment checks.
func newSeededRand() *rand.Rand { return rand.New(rand.NewSource(1234)) }
