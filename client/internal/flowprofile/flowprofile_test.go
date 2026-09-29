package flowprofile

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

func meanLength(t *testing.T, id ProfileID) float64 {
	t.Helper()
	p := Get(id)
	r := rand.New(rand.NewSource(99))
	n := 5000
	sum := 0
	for i := 0; i < n; i++ {
		sum += SampleLength(p, r.Float64, 1<<30) // huge remaining: unclamped histogram draw
	}
	return float64(sum) / float64(n)
}

func meanIPD(t *testing.T, id ProfileID) time.Duration {
	t.Helper()
	p := Get(id)
	r := rand.New(rand.NewSource(1234))
	n := 5000
	var sum time.Duration
	for i := 0; i < n; i++ {
		sum += SampleIPD(p, r.Float64)
	}
	return sum / time.Duration(n)
}

func TestSampleLengthBounds(t *testing.T) {
	for _, id := range []ProfileID{ProfileWeb, ProfileVideo, ProfileChat} {
		p := Get(id)
		r := rand.New(rand.NewSource(7))
		for i := 0; i < 2000; i++ {
			n := 100 + r.Intn(1<<20)
			v := SampleLength(p, r.Float64, n)
			if v < 1 || v > n {
				t.Fatalf("%s: length %d out of [1, %d]", id, v, n)
			}
		}
	}
}

func TestLengthOrdering(t *testing.T) {
	// video (full-size chunks) > web (mixed) > chat (tiny) on average.
	mv := meanLength(t, ProfileVideo)
	mw := meanLength(t, ProfileWeb)
	mc := meanLength(t, ProfileChat)
	if !(mv > mw && mw > mc) {
		t.Fatalf("length ordering wrong: video=%.0f web=%.0f chat=%.0f", mv, mw, mc)
	}
	// Loose sanity: video skews high, chat skews low.
	if mv < 900 {
		t.Fatalf("video mean too low: %.0f", mv)
	}
	if mc > 450 {
		t.Fatalf("chat mean too high: %.0f", mc)
	}
}

func TestSampleIPDBoundsAndOrdering(t *testing.T) {
	for _, id := range []ProfileID{ProfileWeb, ProfileVideo, ProfileChat} {
		p := Get(id)
		r := rand.New(rand.NewSource(11))
		for i := 0; i < 2000; i++ {
			d := SampleIPD(p, r.Float64)
			if d < p.IPDMin || d > p.IPDMax {
				t.Fatalf("%s: IPD %v outside [%v, %v]", id, d, p.IPDMin, p.IPDMax)
			}
		}
	}
	// chat pauses (human-paced) >> web gaps >> video gaps.
	mv := meanIPD(t, ProfileVideo)
	mw := meanIPD(t, ProfileWeb)
	mc := meanIPD(t, ProfileChat)
	if !(mc > mw && mw > mv) {
		t.Fatalf("IPD ordering wrong: video=%v web=%v chat=%v", mv, mw, mc)
	}
}

func TestSampleLengthDeterministicWithSeed(t *testing.T) {
	p := Get(ProfileWeb)
	run := func(seed int64) []int {
		r := rand.New(rand.NewSource(seed))
		out := make([]int, 20)
		for i := range out {
			out[i] = SampleLength(p, r.Float64, 5000)
		}
		return out
	}
	a, b := run(5), run(5)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("same seed must give same sequence at %d: %d vs %d", i, a[i], b[i])
		}
	}
}

func TestNormalDrawFinite(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 10000; i++ {
		z := normalDraw(r)
		if z != z { // NaN
			t.Fatal("normalDraw returned NaN")
		}
	}
}

func TestForRegime(t *testing.T) {
	cases := map[string]ProfileID{
		"stable":             ProfileWeb,
		"watch":              ProfileChat,
		"suspected_change":   ProfileVideo,
		"recovering":         ProfileWeb,
		"unknown-regime":     ProfileWeb,
	}
	for regime, want := range cases {
		if got := ForRegime(regime); got != want {
			t.Fatalf("ForRegime(%q) = %s, want %s", regime, got, want)
		}
	}
}

func TestGetUnknownFallsBackToWeb(t *testing.T) {
	if p := Get(ProfileID("nope")); p.ID != ProfileWeb {
		t.Fatalf("unknown profile must fall back to web, got %s", p.ID)
	}
}

func TestSlicerNext(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	s := NewSlicer(ProfileChat, r.Float64)
	for i := 0; i < 500; i++ {
		n := 100 + r.Intn(10000)
		size, gap := s.Next(n)
		if size < 1 || size > n {
			t.Fatalf("slicer size %d out of [1,%d]", size, n)
		}
		p := Get(ProfileChat)
		if gap < p.IPDMin || gap > p.IPDMax {
			t.Fatalf("slicer gap %v out of bounds", gap)
		}
	}
	// Slicer satisfies the surgery.Slicer interface shape:
	var _ interface {
		Next(remaining int) (int, time.Duration)
	} = s
}

func TestSlicerNilRng(t *testing.T) {
	s := NewSlicer(ProfileWeb, nil)
	size, _ := s.Next(1000)
	if size < 1 || size > 1000 {
		t.Fatalf("nil-rng slicer size %d out of bounds", size)
	}
}

// ---- 2.16 — KLDiv / TargetBins self-monitoring ----

func TestTargetBinsSumsToOne(t *testing.T) {
	for _, id := range []ProfileID{ProfileWeb, ProfileVideo, ProfileChat} {
		bins := TargetBins(Get(id))
		if len(bins) != len(FrameBucketEdges)-1 {
			t.Fatalf("%s: bucket count %d want %d", id, len(bins), len(FrameBucketEdges)-1)
		}
		sum := 0.0
		for _, v := range bins {
			if v < 0 || v > 1 {
				t.Fatalf("%s: bin weight out of [0,1]: %v", id, v)
			}
			sum += v
		}
		if math.Abs(sum-1) > 1e-9 {
			t.Fatalf("%s: TargetBins must sum to 1, got %v", id, sum)
		}
	}
}

func TestTargetBinsClassSeparation(t *testing.T) {
	web := TargetBins(Get(ProfileWeb))
	video := TargetBins(Get(ProfileVideo))
	chat := TargetBins(Get(ProfileChat))
	// web and chat both mass in the low buckets, but video is dominated by
	// the 1200-1400 band -> a higher index. video's peak index must exceed
	// chat's peak index.
	peak := func(v []float64) int {
		mi := 0
		for i, x := range v {
			if x > v[mi] {
				mi = i
			}
		}
		return mi
	}
	if peak(video) <= peak(chat) {
		t.Fatalf("video peak %d must exceed chat peak %d", peak(video), peak(chat))
	}
	_ = web
}

func TestKLDivBasics(t *testing.T) {
	// identical -> ~0
	p := []float64{0.5, 0.25, 0.25}
	if got := KLDiv(p, p); got > 1e-9 {
		t.Fatalf("KL(p,p) must be 0, got %v", got)
	}
	// empty / mismatched -> 0
	if KLDiv(nil, nil) != 0 {
		t.Fatal("empty KL must be 0")
	}
	if KLDiv([]float64{1}, nil) != 0 {
		t.Fatal("mismatched length must be 0")
	}
	// zero target mass never explodes (epsilon floor)
	q := []float64{1, 0, 0}
	if got := KLDiv([]float64{0.5, 0.25, 0.25}, q); math.IsInf(got, 0) || got > 30 {
		t.Fatalf("KL with zero target mass must stay finite, got %v", got)
	}
	// KL is never negative
	if got := KLDiv([]float64{0.1, 0.9}, []float64{0.9, 0.1}); got < 0 {
		t.Fatalf("KL negative: %v", got)
	}
}

func TestKLDivDriftDetection(t *testing.T) {
	// A histogram that matches the target sits near 0; a shifted one is large.
	target := TargetBins(Get(ProfileWeb))
	match := make([]float64, len(target))
	copy(match, target)
	if got := KLDiv(match, target); got > 1e-6 {
		t.Fatalf("matching histogram KL must be ~0, got %v", got)
	}
	// Shift all mass into the top bucket -> large divergence.
	shifted := make([]float64, len(target))
	shifted[len(shifted)-1] = 1.0
	if got := KLDiv(shifted, target); got < 1.0 {
		t.Fatalf("shifted histogram must yield KL >= 1, got %v", got)
	}
}

// ---- 2.17 — rank ladder + netstate regime labels ----

func TestRankLadderAndEscalate(t *testing.T) {
	if Rank(ProfileWeb) != 0 || Rank(ProfileChat) != 1 || Rank(ProfileVideo) != 2 {
		t.Fatal("rank ladder must be web < chat < video")
	}
	if Rank("unknown-mode") != 0 {
		t.Fatal("unknown profiles rank as web (0)")
	}
	if ProfileByRank(2) != ProfileVideo || ProfileByRank(1) != ProfileChat ||
		ProfileByRank(0) != ProfileWeb || ProfileByRank(9) != ProfileWeb || ProfileByRank(-3) != ProfileWeb {
		t.Fatal("ProfileByRank must map ranks to profiles, unknown ranks to web")
	}
	// Floor semantics: escalate never goes down.
	if Escalate(ProfileVideo, ProfileWeb) != ProfileVideo {
		t.Fatal("Escalate(video, web) must stay video")
	}
	if Escalate(ProfileWeb, ProfileChat) != ProfileChat {
		t.Fatal("Escalate(web, chat) must be chat")
	}
	if Escalate(ProfileChat, ProfileChat) != ProfileChat {
		t.Fatal("Escalate(chat, chat) must be chat")
	}
}

func TestForRegimeNetstateLabels(t *testing.T) {
	// 2.17 — the netstate route labels join the local regime driver.
	if got := ForRegime("degraded"); got != ProfileChat {
		t.Fatalf("ForRegime(degraded) = %s, want chat", got)
	}
	if got := ForRegime("cut"); got != ProfileVideo {
		t.Fatalf("ForRegime(cut) = %s, want video", got)
	}
	// pre-2.17 labels unchanged
	if got := ForRegime("watch"); got != ProfileChat {
		t.Fatalf("ForRegime(watch) = %s, want chat", got)
	}
	if got := ForRegime("suspected_change"); got != ProfileVideo {
		t.Fatalf("ForRegime(suspected_change) = %s, want video", got)
	}
	if got := ForRegime("stable"); got != ProfileWeb {
		t.Fatalf("ForRegime(stable) = %s, want web", got)
	}
	if got := ForRegime(""); got != ProfileWeb {
		t.Fatalf("ForRegime(\"\") = %s, want web", got)
	}
}
