package measure

import (
	"math"
	"sync"
	"testing"
)

func okSample(rtt float64) Sample { return Sample{OK: true, RTTMS: rtt, Transport: "ws"} }

func TestStableStreamStaysStable(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 30; i++ {
		tr.Feed(okSample(120))
	}
	v := tr.Vector()
	if v.Regime != "stable" {
		t.Fatalf("expected stable, got %s (%s)", v.Regime, v)
	}
	if v.RTTMS < 110 || v.RTTMS > 130 {
		t.Fatalf("rtt ewma off: %v", v.RTTMS)
	}
	if v.JitterMS > 1 {
		t.Fatalf("flat rtt should have ~0 jitter, got %v", v.JitterMS)
	}
	if v.DropRate != 0 {
		t.Fatalf("drop rate should be 0, got %v", v.DropRate)
	}
}

func TestRSTStormRaisesRegime(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 30; i++ {
		tr.Feed(okSample(120))
	}
	for i := 0; i < 12; i++ {
		tr.Feed(Sample{OK: false, ErrClass: ErrRST, Transport: "ws"})
	}
	v := tr.Vector()
	if v.Regime != "suspected_change" {
		t.Fatalf("expected suspected_change after sustained RST, got %s (%s)", v.Regime, v)
	}
	if !v.StepAlarm {
		t.Fatal("CUSUM should be in alarm")
	}
	if v.RSTRate < 0.25 {
		t.Fatalf("rst rate should be high, got %v", v.RSTRate)
	}
}

func TestRecoveryTransitions(t *testing.T) {
	tr := NewTracker()
	// Long bad stretch to build a bad baseline.
	for i := 0; i < 40; i++ {
		tr.Feed(Sample{OK: false, ErrClass: ErrTimeout, Transport: "ws"})
	}
	for i := 0; i < 40; i++ {
		tr.Feed(okSample(90))
	}
	v := tr.Vector()
	if v.Regime != "recovering" {
		t.Fatalf("expected recovering, got %s (%s)", v.Regime, v)
	}
}

func TestPartialDegradationIsWatch(t *testing.T) {
	tr := NewTracker()
	// Alternating: 50% loss, no collapse in the recent-10 slice.
	for i := 0; i < 40; i++ {
		if i%2 == 0 {
			tr.Feed(okSample(120))
		} else {
			tr.Feed(Sample{OK: false, ErrClass: ErrRST, Transport: "ws"})
		}
	}
	v := tr.Vector()
	if v.Regime != "watch" {
		t.Fatalf("expected watch at 50%% alternating loss, got %s (%s)", v.Regime, v)
	}
}

func TestTimeoutRateAccounting(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 20; i++ {
		tr.Feed(okSample(120))
	}
	for i := 0; i < 20; i++ {
		tr.Feed(Sample{OK: false, ErrClass: ErrTimeout, Transport: "ws"})
	}
	v := tr.Vector()
	if math.Abs(v.TimeoutRate-0.5) > 1e-9 {
		t.Fatalf("timeout rate = %v, want 0.5", v.TimeoutRate)
	}
	if v.RSTRate != 0 {
		t.Fatalf("rst rate should be 0, got %v", v.RSTRate)
	}
}

func TestWeakestTransportDetection(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 12; i++ {
		tr.Feed(Sample{OK: true, RTTMS: 100, Transport: "ws"})
	}
	// h2: 1 of 12 ok.
	tr.Feed(Sample{OK: true, RTTMS: 100, Transport: "h2"})
	for i := 0; i < 11; i++ {
		tr.Feed(Sample{OK: false, ErrClass: ErrRST, Transport: "h2"})
	}
	v := tr.Vector()
	if v.WeakestTransport != "h2" {
		t.Fatalf("expected weakest=h2, got %q (%s)", v.WeakestTransport, v)
	}
}

func TestAnomalyCodeCarried(t *testing.T) {
	tr := NewTracker()
	tr.Feed(okSample(100))
	tr.Feed(Sample{OK: false, ErrClass: ErrAnomaly, Anomaly: 403, Transport: "ws"})
	v := tr.Vector()
	if v.LastAnomaly != 403 {
		t.Fatalf("expected anomaly 403, got %d", v.LastAnomaly)
	}
}

func TestJitterTracksVariance(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			tr.Feed(okSample(50))
		} else {
			tr.Feed(okSample(450))
		}
	}
	v := tr.Vector()
	if v.JitterMS < 100 {
		t.Fatalf("jitter should track ~400ms swings, got %v", v.JitterMS)
	}
	// RTT EWMA sits between the extremes.
	if v.RTTMS <= 50 || v.RTTMS >= 450 {
		t.Fatalf("rtt ewma outside extremes: %v", v.RTTMS)
	}
}

func TestEmptyTrackerIsStable(t *testing.T) {
	v := NewTracker().Vector()
	if v.Regime != "stable" || v.Observations != 0 {
		t.Fatalf("empty tracker should be stable with 0 obs, got %+v", v)
	}
}

func TestWindowSlides(t *testing.T) {
	tr := NewTracker()
	// 100 failures then 100 successes: after sliding, the window is all OK.
	for i := 0; i < 100; i++ {
		tr.Feed(Sample{OK: false, ErrClass: ErrRST})
	}
	for i := 0; i < 100; i++ {
		tr.Feed(okSample(100))
	}
	v := tr.Vector()
	if v.DropRate != 0 {
		t.Fatalf("sliding window should have forgotten the failures, drop=%v", v.DropRate)
	}
}

// 2.17 CI — the per-entry Tracker is shared across tunnel goroutines
// (trackerFor hands out the same *Tracker for one host while several
// SOCKS connections pump at once). Concurrent Feed + Vector must be
// race-free; this is what `go test -race` verifies in the CI matrix.
func TestConcurrentFeedVector(t *testing.T) {
	tr := NewTracker()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tr.Feed(Sample{
					OK:         (i+g)%3 != 0,
					RTTMS:      float64(50 + i%50),
					Throughput: 1_000_000,
					ErrClass:   ErrRST,
					Transport:  "ws",
					UnixMS:     int64(i),
				})
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			v := tr.Vector()
			if v.Observations < 0 || v.Observations > windowSize {
				t.Errorf("Vector(): observations %d outside [0,%d]", v.Observations, windowSize)
				return
			}
		}
	}()
	wg.Wait()
	if v := tr.Vector(); v.Observations != windowSize {
		t.Fatalf("window should be full after 1600 feeds, got %d observations", v.Observations)
	}
}
