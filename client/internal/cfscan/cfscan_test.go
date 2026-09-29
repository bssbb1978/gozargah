package cfscan

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestSampleCandidatesBasics(t *testing.T) {
	// /32 yields exactly itself
	got := SampleCandidates([]string{"1.2.3.4/32"}, nil, nil, 4, func() float64 { return 0.5 })
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("/32 sampling: %v", got)
	}
	// /24 yields `per` distinct usable host addresses inside the range
	// (varying rng so the draws do not collide on one address).
	got = SampleCandidates([]string{"10.0.0.0/24"}, nil, nil, 4, varyingRng())
	if len(got) != 4 {
		t.Fatalf("/24 sampling count: %v", got)
	}
	for _, ip := range got {
		if !strings.HasPrefix(ip, "10.0.0.") {
			t.Fatalf("sample outside prefix: %s", ip)
		}
		if ip == "10.0.0.0" || ip == "10.0.0.255" {
			t.Fatalf("network/broadcast must be skipped: %s", ip)
		}
	}
	// Determinism: same inputs, same output
	again := SampleCandidates([]string{"10.0.0.0/24"}, nil, nil, 4, varyingRng())
	if strings.Join(got, ",") != strings.Join(again, ",") {
		t.Fatalf("sampling not deterministic: %v vs %v", got, again)
	}
}

// varyingRng cycles through distinct values so /24 sampling draws distinct
// host addresses (a constant rng would collide on one address).
func varyingRng() Rng {
	vals := []float64{0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80}
	idx := 0
	return func() float64 {
		v := vals[idx%len(vals)]
		idx++
		return v
	}
}

func TestSampleCandidatesPriorityAndBlocked(t *testing.T) {
	rng := varyingRng()
	// Priority CIDRs come first in the candidate order.
	got := SampleCandidates(
		[]string{"100.0.0.0/24"},
		[]string{"200.0.0.0/24"},
		nil,
		2,
		rng,
	)
	if len(got) != 6 {
		t.Fatalf("expected priority (4) + normal (2) samples, got %v", got)
	}
	for i, ip := range got {
		if i < 4 && !strings.HasPrefix(ip, "200.0.0.") {
			t.Fatalf("priority CIDR must be sampled first: %v", got)
		}
		if i >= 4 && !strings.HasPrefix(ip, "100.0.0.") {
			t.Fatalf("normal CIDR must follow priority: %v", got)
		}
	}
	// Blocked range removes all candidates inside it (bare IP = /32 too).
	blocked := SampleCandidates(
		[]string{"100.0.0.1/32", "100.0.0.2/32", "100.0.0.0/24"},
		nil,
		[]string{"100.0.0.1", "100.0.0.2/32"},
		4,
		rng,
	)
	for _, ip := range blocked {
		if ip == "100.0.0.1" || ip == "100.0.0.2" {
			t.Fatalf("blocked IP leaked into candidates: %v", blocked)
		}
	}
	// Dedup across CIDRs
	dup := SampleCandidates([]string{"9.9.9.9/32", "9.9.9.9/32"}, nil, nil, 2, rng)
	if len(dup) != 1 {
		t.Fatalf("duplicate /32 not deduped: %v", dup)
	}
}

func TestMedian(t *testing.T) {
	if Median(nil) != 0 {
		t.Fatal("empty median must be 0")
	}
	if Median([]float64{5}) != 5 {
		t.Fatal("single median")
	}
	if Median([]float64{1, 3, 2}) != 2 {
		t.Fatal("odd median")
	}
	if got := Median([]float64{4, 1, 3, 2}); got != 2.5 {
		t.Fatalf("even median: %v", got)
	}
}

func TestTopNRanking(t *testing.T) {
	rs := []ProbeResult{
		{IP: "3.3.3.3", OK: false, RTTMS: 0, Loss: 1, Attempts: 3, Error: "dial"},
		{IP: "1.1.1.1", OK: true, RTTMS: 120, Loss: 0.333, Attempts: 3, Colo: "FRA"},
		{IP: "2.2.2.2", OK: true, RTTMS: 45, Loss: 0, Attempts: 3, Colo: "FRA"},
		{IP: "2.2.2.3", OK: true, RTTMS: 45, Loss: 0, Attempts: 3, Colo: "FRA"},
	}
	top := TopN(rs, 2)
	if len(top) != 2 {
		t.Fatalf("topN length: %v", top)
	}
	if top[0].IP != "2.2.2.2" || top[1].IP != "2.2.2.3" {
		t.Fatalf("ranking wrong: %v", top)
	}
	// Failed results always sink below OK ones
	top3 := TopN(rs, 3)
	if top3[2].OK {
		t.Fatalf("failed result must sink: %v", top3)
	}
}

func TestReports(t *testing.T) {
	rep := Report{
		Schema: Schema, RelayHost: "relay.example",
		GeneratedAtMS: 1, Source: "api", Candidates: 2, Probed: 2, TopN: 2,
		Results: []ProbeResult{
			{IP: "1.1.1.1", OK: true, RTTMS: 42.5, Loss: 0, Colo: "FRA", Attempts: 3},
			{IP: "2.2.2.2", OK: false, Loss: 1, Attempts: 3, Error: "handshake\nrefused"},
		},
	}
	j := ReportJSON(rep)
	var back Report
	if err := json.Unmarshal([]byte(j), &back); err != nil {
		t.Fatalf("ReportJSON must be valid JSON: %v", err)
	}
	if back.Results[0].Colo != "FRA" || back.Source != "api" {
		t.Fatalf("JSON round trip lost fields: %+v", back)
	}
	csv := ReportCSV(rep)
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 3 {
		t.Fatalf("CSV must have header + 2 rows: %q", csv)
	}
	if !strings.HasPrefix(lines[0], "ip,ok,rtt_ms,loss,colo,attempts,error") {
		t.Fatalf("CSV header: %q", lines[0])
	}
	if !strings.Contains(lines[1], "FRA") {
		t.Fatalf("CSV lost colo: %q", lines[1])
	}
	if strings.Contains(lines[2], "\n") {
		t.Fatal("CSV must flatten newlines inside error text")
	}
}

// fakeProber lets the orchestration run network-free.
type fakeProber struct {
	good map[string]bool
	mu   sync.Mutex // ProbeIP is called concurrently by Run's goroutines
	seen []string
}

func (f *fakeProber) ProbeIP(_ context.Context, ip string, opts Options) ProbeResult {
	f.mu.Lock()
	f.seen = append(f.seen, ip)
	f.mu.Unlock()
	res := ProbeResult{IP: ip, Attempts: opts.Attempts}
	if f.good[ip] {
		res.OK = true
		res.RTTMS = 30 + float64(len(ip)) // deterministic pseudo-rtt
	} else {
		res.Loss = 1
		res.Error = "fake dial refused"
	}
	return res
}

func TestRunOrchestration(t *testing.T) {
	// The fake prober ignores colo entirely; keep the check off anyway so
	// the test never depends on production defaults.
	noColo := false
	opts := Options{
		RelayHost: "relay.example",
		Cidrs:     []string{"10.1.0.1/32", "10.1.0.2/32", "10.1.0.3/32", "10.1.0.4/32"},
		Attempts:  3,
		TopN:      2,
		Blocked:   []string{"10.1.0.4/32"},
	}
	opts.VerifyColo = &noColo
	fake := &fakeProber{good: map[string]bool{"10.1.0.1": true, "10.1.0.3": true}}
	rep, err := Run(context.Background(), opts, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != "explicit" {
		t.Fatalf("source: %s", rep.Source)
	}
	if rep.Candidates != 3 {
		t.Fatalf("blocked candidate must be excluded from sampling: %d", rep.Candidates)
	}
	if rep.Probed != 3 {
		t.Fatalf("probed: %d", rep.Probed)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("topN: %v", rep.Results)
	}
	for _, r := range rep.Results {
		if !r.OK {
			t.Fatalf("topN must be all-OK when OK candidates exist: %v", rep.Results)
		}
	}
	if !fakeProberSawNone(fake, "10.1.0.4") {
		t.Fatal("blocked IP must never be probed")
	}
	// Both OK candidates have rtt 30+len(ip)=38 → tie resolves by IP asc.
	if rep.Results[0].IP != "10.1.0.1" || rep.Results[1].IP != "10.1.0.3" {
		t.Fatalf("tie-break by IP asc: %+v", rep.Results)
	}
}

func fakeProberSawNone(f *fakeProber, ip string) bool {
	for _, s := range f.seen {
		if s == ip {
			return false
		}
	}
	return true
}

func TestRunRequiresRelay(t *testing.T) {
	if _, err := Run(context.Background(), Options{}, nil, nil); err == nil {
		t.Fatal("missing relay host must error")
	}
}
