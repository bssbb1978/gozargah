package main

import (
	"testing"

	"github.com/bssbb1978/gozargah/axr/internal/failover"
)

// The port is the one connection parameter that decides whether a client can
// reach a non-443 edge deployment or a local test harness at all. It was
// hardcoded to 443 end to end, so these tests pin the resolution order:
// Entry.Port > Config.Port > 443 (failover substitutes 443 for 0).
func TestBuildArmsPortResolution(t *testing.T) {
	cfg := Config{
		Port: 8443,
		Entries: []Entry{
			{Host: "edge-a.example", FP: "chrome"}, // → Config.Port
			{Host: "edge-b.example", Port: 9443},   // → Entry.Port wins
			{Host: "edge-c.example", Port: 443, IPs: []string{"10.0.0.1"}},
		},
	}
	arms, eps := buildArms(cfg)

	if len(arms) != 6 || len(eps) != 6 {
		t.Fatalf("expected 6 arms/endpoints (2 transports × 3 entries), got %d/%d", len(arms), len(eps))
	}
	want := map[string]int{
		"edge-a.example": 8443,
		"edge-b.example": 9443,
		"edge-c.example": 443,
	}
	for _, ep := range eps {
		if got := ep.Port; got != want[ep.Host] {
			t.Errorf("%s: port = %d, want %d", ep.Host, got, want[ep.Host])
		}
	}
	// Arm identity must NOT include the port: the ladder may dial the same
	// host on a different port, but the learned shape is the same shape.
	seen := map[string]int{}
	for _, a := range arms {
		seen[a.Host]++
	}
	for host, n := range seen {
		if n != len(transportsPerEntry) {
			t.Errorf("%s: %d arms, want %d (one per transport shape)", host, n, len(transportsPerEntry))
		}
	}
}

func TestBuildArmsZeroConfigPortMeans443(t *testing.T) {
	_, eps := buildArms(Config{Entries: []Entry{{Host: "edge.example"}}})
	for _, ep := range eps {
		if ep.Port != 0 {
			t.Fatalf("config port 0 must stay 0 here (failover resolves it to 443), got %d", ep.Port)
		}
	}
	// And the ladder really does resolve it.
	e := failover.New(eps, nil)
	for _, addr := range e.CandidatesFor(eps[0]) {
		if addr != "edge.example:443" {
			t.Errorf("dial addr = %q, want edge.example:443", addr)
		}
	}
}

func TestBuildArmsHonoursExplicitPortOnEveryAddress(t *testing.T) {
	_, eps := buildArms(Config{
		Port:    8787,
		Entries: []Entry{{Host: "edge.example", IPs: []string{"203.0.113.7", "203.0.113.8"}}},
	})
	e := failover.New(eps, nil)
	var got []string
	for _, ep := range eps {
		if ep.Transport != "ws" {
			continue
		}
		got = append(got, e.CandidatesFor(ep)...)
	}
	want := map[string]bool{
		"203.0.113.7:8787":  true,
		"203.0.113.8:8787":  true,
		"edge.example:8787": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d addresses", got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected dial addr %q (want port 8787 on every address)", g)
		}
	}
}
