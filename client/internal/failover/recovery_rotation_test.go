package failover

import (
	"testing"
	"time"
)

// A blackout still gets only one probe per round, but quieting the whole
// ladder must not pin every future round to the same dead first endpoint.
func TestAllQuietProbeRoundRotatesAndFindsRecoveredAlternate(t *testing.T) {
	probed := make([]string, 0, 2)
	probe := func(ep Endpoint, _ string, _ time.Duration) (bool, float64, string) {
		probed = append(probed, ep.Host)
		return ep.Host == "intl.example", 25, "simulated_route_recovered"
	}
	entries := []Endpoint{
		{Host: "intl.example", Transport: "ws", FP: "chrome", Priority: 0},
		{Host: "domestic.example", Transport: "ws", FP: "chrome", Priority: 0},
	}
	e := New(entries, probe)
	e.SetQuietPolicy(DefaultQuietPolicy())
	now := time.Now()
	for _, ep := range e.Entries() {
		for i := 0; i < quietMinFails; i++ {
			e.Observe(ep, ep.Host+":443", false, 0, "simulated_blackout", now)
		}
	}
	if got := e.Quiet(); got.Quiet != got.Total || got.Total != 2 {
		t.Fatalf("setup must quiet both endpoints, got %+v", got)
	}

	first := e.ProbeRound(now)
	if len(first) != 0 || len(probed) != 1 || probed[0] != "domestic.example" {
		t.Fatalf("first blackout round should try one ordered candidate, probes=%v healthy=%v", probed, first)
	}
	second := e.ProbeRound(now.Add(time.Second))
	if len(probed) != 2 || probed[1] != "intl.example" {
		t.Fatalf("next blackout round must rotate to the alternate, probes=%v", probed)
	}
	if len(second) != 1 || second[0].Endpoint.Host != "intl.example" {
		t.Fatalf("recovered alternate must be returned as healthy, got %v", second)
	}
	if health := e.Health()["intl.example|intl.example:443"]; health.QuietUntilMS != 0 || health.ConsecOK != 1 {
		t.Fatalf("a recovered route must immediately clear its quiet gate, got %+v", health)
	}
}
