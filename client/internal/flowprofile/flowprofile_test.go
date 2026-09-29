package flowprofile

import (
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
		sum += SampleLength(p, r, 1<<30) // huge remaining: unclamped histogram draw
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
		sum += SampleIPD(p, r)
	}
	return sum / time.Duration(n)
}

func TestSampleLengthBounds(t *testing.T) {
	for _, id := range []ProfileID{ProfileWeb, ProfileVideo, ProfileChat} {
		p := Get(id)
		r := rand.New(rand.NewSource(7))
		for i := 0; i < 2000; i++ {
			n := 100 + r.Intn(1<<20)
			v := SampleLength(p, r, n)
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
			d := SampleIPD(p, r)
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
			out[i] = SampleLength(p, r, 5000)
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
	s := NewSlicer(ProfileChat, r)
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
