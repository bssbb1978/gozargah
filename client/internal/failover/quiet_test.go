package failover

import (
	"testing"
	"time"
)

// quietEntries is a two-host ladder (one international primary, one domestic
// fronting relay) — the shape a net-e-melli window produces.
func quietEntries() []Endpoint {
	return []Endpoint{
		{Host: "intl.example", Transport: "ws", FP: "chrome", Priority: 0},
		{Host: "domestic.example", Transport: "ws", FP: "chrome", Priority: 0},
	}
}

// hostsIn returns the distinct endpoint hosts present in an order.
func hostsIn(cands []Candidate) map[string]bool {
	out := map[string]bool{}
	for _, c := range cands {
		out[c.Endpoint.Host] = true
	}
	return out
}

// endpointByHost looks an endpoint up by host (New sorts the matrix, so
// index-based assumptions are not safe).
func endpointByHost(t *testing.T, e *Engine, host string) Endpoint {
	t.Helper()
	for _, ep := range e.Entries() {
		if ep.Host == host {
			return ep
		}
	}
	t.Fatalf("endpoint %s not found", host)
	return Endpoint{}
}

// TestQuietDisabledByDefault: a bare Engine must behave exactly as before —
// the gate is opt-in (cmd/axr installs DefaultQuietPolicy), so library users
// and every pre-2.21 test keep the old ladder semantics.
func TestQuietDisabledByDefault(t *testing.T) {
	e := New(quietEntries(), nil)
	now := time.Now()
	for i := 0; i < 6; i++ {
		e.Observe(endpointByHost(t, e, "intl.example"), "intl.example:443", false, 0, "timeout", now)
	}
	if q := e.Quiet(); q.Enabled {
		t.Fatalf("quiet gate must be disabled by default, got %+v", q)
	}
	if got := hostsIn(e.FailoverOrder(nil)); !got["intl.example"] {
		t.Fatal("a disabled gate must never remove a candidate")
	}
}

// TestQuietGateRemovesRepeatFailures: after quietMinFails consecutive
// failures the dial address leaves the ladder, and the still-healthy rest of
// the fleet keeps its place.
func TestQuietGateRemovesRepeatFailures(t *testing.T) {
	e := New(quietEntries(), nil)
	e.SetQuietPolicy(DefaultQuietPolicy())
	now := time.Now()
	intl := endpointByHost(t, e, "intl.example")
	domestic := endpointByHost(t, e, "domestic.example")
	// The domestic relay works.
	e.Observe(domestic, "domestic.example:443", true, 40, "", now)
	// The international primary fails quietMinFails times.
	for i := 0; i < quietMinFails; i++ {
		if q := e.Quiet(); q.Quiet != 0 {
			t.Fatalf("failure %d must not gate yet, got %d gated", i+1, q.Quiet)
		}
		e.Observe(intl, "intl.example:443", false, 0, "timeout", now)
	}
	q := e.Quiet()
	if !q.Enabled || q.Quiet != 1 {
		t.Fatalf("expected exactly 1 gated address, got %+v", q)
	}
	got := hostsIn(e.FailoverOrder(nil))
	if got["intl.example"] {
		t.Fatal("a repeatedly failing address must leave the ladder")
	}
	if !got["domestic.example"] {
		t.Fatal("the healthy domestic entry must stay on the ladder")
	}
}

// TestQuietGateNeverSilencesEverything: if EVERY candidate is gated the
// ladder must still hand back a tryable order — a client that refuses to
// dial anything can never discover that the route came back.
func TestQuietGateNeverSilencesEverything(t *testing.T) {
	e := New(quietEntries(), nil)
	e.SetQuietPolicy(DefaultQuietPolicy())
	now := time.Now()
	for _, ep := range e.Entries() {
		for i := 0; i < quietMinFails+2; i++ {
			e.Observe(ep, ep.Host+":443", false, 0, "timeout", now)
		}
	}
	if q := e.Quiet(); q.Quiet != q.Total || q.Total == 0 {
		t.Fatalf("expected every tracked address gated, got %+v", q)
	}
	order := e.FailoverOrder(nil)
	if len(order) == 0 {
		t.Fatal("invariant violated: the ladder must never be empty")
	}
	if len(hostsIn(order)) != 2 {
		t.Fatalf("the all-gated fallback must return every endpoint, got %v", hostsIn(order))
	}
}

// TestQuietGateClearsOnSuccess: one success un-gates the address
// immediately, so a recovered route is usable on the very next dial.
func TestQuietGateClearsOnSuccess(t *testing.T) {
	e := New(quietEntries(), nil)
	e.SetQuietPolicy(DefaultQuietPolicy())
	now := time.Now()
	ep := endpointByHost(t, e, "intl.example")
	for i := 0; i < quietMinFails; i++ {
		e.Observe(ep, ep.Host+":443", false, 0, "timeout", now)
	}
	if e.Quiet().Quiet != 1 {
		t.Fatal("setup: expected the address gated")
	}
	e.Observe(ep, ep.Host+":443", true, 30, "", now)
	if q := e.Quiet(); q.Quiet != 0 {
		t.Fatalf("a success must clear the gate, got %+v", q)
	}
	if !hostsIn(e.FailoverOrder(nil))[ep.Host] {
		t.Fatal("a cleared address must return to the ladder")
	}
}

func TestClearQuietReleasesEveryAddress(t *testing.T) {
	e := New(quietEntries(), nil)
	e.SetQuietPolicy(DefaultQuietPolicy())
	now := time.Now()
	for _, ep := range e.Entries() {
		for i := 0; i < quietMinFails; i++ {
			e.Observe(ep, ep.Host+":443", false, 0, "timeout", now)
		}
	}
	if q := e.Quiet(); q.Quiet != 2 {
		t.Fatalf("setup: expected both addresses quiet, got %+v", q)
	}
	e.ClearQuiet()
	if q := e.Quiet(); q.Quiet != 0 {
		t.Fatalf("fresh external liveness must release all quiet gates, got %+v", q)
	}
}

// TestQuietWindowBacksOffAndIsBounded: the window grows with the failure run
// and is capped by MaxMS — the bound is what guarantees a recovered route is
// always rediscovered.
func TestQuietWindowBacksOffAndIsBounded(t *testing.T) {
	p := QuietPolicy{BaseMS: 1_000, MaxMS: 8_000}
	if got := p.quietFor(quietMinFails - 1); got != 0 {
		t.Fatalf("below the arming threshold the window must be 0, got %d", got)
	}
	if got := p.quietFor(quietMinFails); got != 1_000 {
		t.Fatalf("first armed window = %d, want 1000", got)
	}
	if got := p.quietFor(quietMinFails + 1); got != 2_000 {
		t.Fatalf("second window = %d, want 2000 (doubling)", got)
	}
	if got := p.quietFor(quietMinFails + 2); got != 4_000 {
		t.Fatalf("third window = %d, want 4000", got)
	}
	if got := p.quietFor(quietMinFails + 3); got != 8_000 {
		t.Fatalf("fourth window = %d, want the 8000 cap", got)
	}
	for run := quietMinFails + 4; run < 40; run++ {
		if got := p.quietFor(run); got != 8_000 {
			t.Fatalf("window at run %d = %d, must stay at the cap", run, got)
		}
	}
	if (QuietPolicy{}).Enabled() {
		t.Fatal("a zero policy must be disabled")
	}
	if !DefaultQuietPolicy().Enabled() {
		t.Fatal("the default policy must be enabled")
	}
}

// TestProbeRoundProbesOnceWhenAllQuiet: under a full blackout the sweep must
// collapse to a SINGLE probe instead of hammering the whole ladder every
// round — the failed-attempt burst is itself a recognisable signature.
func TestProbeRoundProbesOnceWhenAllQuiet(t *testing.T) {
	probed := 0
	probe := func(ep Endpoint, addr string, timeout time.Duration) (bool, float64, string) {
		probed++
		return false, 0, "timeout"
	}
	e := New(quietEntries(), probe)
	e.SetQuietPolicy(DefaultQuietPolicy())
	now := time.Now()

	rounds := 0
	for probed < 2*quietMinFails {
		e.ProbeRound(now)
		rounds++
		if rounds > 20 {
			t.Fatalf("probe rounds did not converge (probed=%d)", probed)
		}
	}
	before := probed
	// Every address is now gated: exactly one probe per round.
	e.ProbeRound(now)
	if probed != before+1 {
		t.Fatalf("the blackout round must probe exactly once, probed %d extra", probed-before)
	}
	if !e.Quiet().Enabled {
		t.Fatal("gate must be reported as enabled")
	}
	// And it must not have quieted away the ability to recover.
	if e.ProbeRound(now); probed != before+2 {
		t.Fatal("subsequent blackout rounds must keep probing a single candidate")
	}
}
