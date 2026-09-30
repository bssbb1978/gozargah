package main

import (
	"testing"
	"time"

	"github.com/bssbb1978/gozargah/axr/internal/failover"
	"github.com/bssbb1978/gozargah/axr/internal/netstate"
)

// The fake probe injects failure signatures at the socket boundary; these
// tests validate the actual client failover/regime wiring without claiming
// that a CI runner is connected to any filtered network.
func TestSimulatedDPIFailureSignaturesFallBackToConfiguredDomesticEntry(t *testing.T) {
	cases := []struct {
		name       string
		errorClass string
		latencyMS  float64
	}{
		{name: "packet drop", errorClass: "simulated_packet_drop_timeout"},
		{name: "SNI blocking", errorClass: "simulated_tls_sni_block"},
		{name: "RST injection", errorClass: "simulated_tcp_rst_injected"},
		{name: "throttling", errorClass: "simulated_throttled_timeout", latencyMS: 2600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detector := netstate.NewDetector()
			probe := func(ep failover.Endpoint, _ string, _ time.Duration) (bool, float64, string) {
				if ep.Host == "intl.example.com" {
					detector.Record(netstate.Observation{Role: netstate.RolePrimary, OK: false, At: time.Now()})
					return false, tc.latencyMS, tc.errorClass
				}
				detector.Record(netstate.Observation{Role: netstate.RoleFronting, OK: true, At: time.Now()})
				return true, 420, ""
			}
			engine := failover.New([]failover.Endpoint{
				{Host: "intl.example.com", Transport: "ws", FP: "chrome", Priority: 0},
				{Host: testFronting, Transport: "ws", FP: "chrome", Priority: 50},
			}, probe)
			engine.SetQuietPolicy(failover.DefaultQuietPolicy())
			s := &server{
				failover:     engine,
				netstate:     detector,
				frontingHost: testFronting,
				lastRegime:   netstate.RegimeStable,
				configHosts:  map[string]bool{"intl.example.com": true},
				log:          newLogger(false),
			}

			for round := 0; round < 2; round++ {
				healthy := engine.ProbeRound(time.Now().Add(time.Duration(round) * time.Second))
				if len(healthy) != 1 || healthy[0].Endpoint.Host != testFronting {
					t.Fatalf("round %d must fall back to domestic entry, got %v", round+1, healthy)
				}
				s.applyPolicy()
			}
			if got := detector.Regime(); got != netstate.RegimeNetEMelli {
				t.Fatalf("two failed international observations plus domestic success should enter netemelli, got %s", got)
			}
			order := engine.FailoverOrder(nil)
			if len(order) == 0 || order[0].Endpoint.Host != testFronting {
				t.Fatalf("domestic entry must lead the measured fallback ladder, got %v", order)
			}
			if health := engine.Health()["intl.example.com|ws|intl.example.com:443"]; health.LastErr != tc.errorClass {
				t.Fatalf("simulated failure evidence was not retained as a bounded class: %+v", health)
			}
		})
	}
}

func TestLiveCanaryRecoveryReleasesOldBlackoutQuietGates(t *testing.T) {
	detector := netstate.NewDetector()
	engine := failover.New([]failover.Endpoint{
		{Host: "intl.example.com", Transport: "ws", FP: "chrome", Priority: 0},
		{Host: testFronting, Transport: "ws", FP: "chrome", Priority: 50},
	}, nil)
	engine.SetQuietPolicy(failover.DefaultQuietPolicy())
	now := time.Now()
	primary := engine.Entries()[0]
	engine.Observe(primary, "intl.example.com:443", false, 0, "timeout", now)
	engine.Observe(primary, "intl.example.com:443", false, 0, "timeout", now)
	engine.Observe(primary, "intl.example.com:443", false, 0, "timeout", now)
	if got := engine.Quiet(); got.Quiet != 1 {
		t.Fatalf("setup: primary should be blackout-quiet, got %+v", got)
	}
	detector.Record(netstate.Observation{Role: netstate.RolePrimary, OK: false, At: now})
	detector.Record(netstate.Observation{Role: netstate.RolePrimary, OK: false, At: now})
	if got := detector.Record(netstate.Observation{Role: netstate.RoleFronting, OK: true, At: now}); got != netstate.RegimeNetEMelli {
		t.Fatalf("setup: expected domestic-only classification, got %s", got)
	}
	s := &server{
		failover:     engine,
		netstate:     detector,
		frontingHost: testFronting,
		lastRegime:   netstate.RegimeStable,
		configHosts:  map[string]bool{"intl.example.com": true},
		log:          newLogger(false),
	}
	s.applyPolicy()
	if got := engine.Quiet(); got.MaxMS != 30*60_000 {
		t.Fatalf("netemelli must install the extended bounded gate, got %+v", got)
	}
	if got := detector.Record(netstate.Observation{Role: netstate.RoleCanary, OK: true, At: now.Add(time.Second)}); got != netstate.RegimeDegraded {
		t.Fatalf("fresh canary should end domestic-only classification, got %s", got)
	}
	s.applyPolicy()
	if got := engine.Quiet(); got.Quiet != 0 {
		t.Fatalf("canary recovery must release stale quiet addresses for a primary re-check, got %+v", got)
	}
}

func TestSimulatedFullInternationalCutRecoversThroughDomesticPath(t *testing.T) {
	detector := netstate.NewDetector()
	domesticReachable := false
	probe := func(ep failover.Endpoint, _ string, _ time.Duration) (bool, float64, string) {
		if ep.Host == testFronting {
			ok := domesticReachable
			detector.Record(netstate.Observation{Role: netstate.RoleFronting, OK: ok, At: time.Now()})
			if ok {
				return true, 500, ""
			}
			return false, 0, "simulated_international_cut"
		}
		detector.Record(netstate.Observation{Role: netstate.RolePrimary, OK: false, At: time.Now()})
		return false, 0, "simulated_international_cut"
	}
	engine := failover.New([]failover.Endpoint{
		{Host: "intl.example.com", Transport: "ws", FP: "chrome", Priority: 0},
		{Host: testFronting, Transport: "ws", FP: "chrome", Priority: 50},
	}, probe)
	engine.SetQuietPolicy(failover.DefaultQuietPolicy())
	s := &server{
		failover:     engine,
		netstate:     detector,
		frontingHost: testFronting,
		lastRegime:   netstate.RegimeStable,
		configHosts:  map[string]bool{"intl.example.com": true},
		log:          newLogger(false),
	}

	start := time.Now()
	for round := 0; round < 8 && detector.Regime() != netstate.RegimeCut; round++ {
		if healthy := engine.ProbeRound(start.Add(time.Duration(round) * time.Second)); len(healthy) != 0 {
			t.Fatalf("no route should carry during the simulated full cut, got %v", healthy)
		}
		s.applyPolicy()
	}
	if got := detector.Regime(); got != netstate.RegimeCut {
		t.Fatalf("sustained failures across both path classes should reach cut, got %s", got)
	}
	if engine.State() != failover.StateAggressive {
		t.Fatalf("sustained all-candidate failures should enable bounded aggressive probing, got %s", engine.State())
	}

	// Advance through the all-quiet ladder one candidate per round. The first
	// probe still sees the dead fronting route; then only the domestic relay
	// recovers while the cursor points at the international primary.
	if healthy := engine.ProbeRound(start.Add(3 * time.Second)); len(healthy) != 0 {
		t.Fatalf("first all-quiet probe should still fail, got %v", healthy)
	}
	domesticReachable = true
	if healthy := engine.ProbeRound(start.Add(4 * time.Second)); len(healthy) != 0 {
		t.Fatalf("rotated probe should still see the failed international path, got %v", healthy)
	}
	healthy := engine.ProbeRound(start.Add(5 * time.Second))
	if len(healthy) != 1 || healthy[0].Endpoint.Host != testFronting {
		t.Fatalf("rotating all-quiet probe should find the reopened domestic route, got %v", healthy)
	}
	s.applyPolicy()
	if got := detector.Regime(); got != netstate.RegimeNetEMelli {
		t.Fatalf("domestic success with international failures should resolve cut to netemelli, got %s", got)
	}
}
