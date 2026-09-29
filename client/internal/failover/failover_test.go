package failover

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testEntries() []Endpoint {
	return []Endpoint{
		{Host: "primary.example", IPs: []string{"1.1.1.1", "2.2.2.2"}, Transport: "ws", FP: "chrome", Priority: 0},
		{Host: "backup.example", Transport: "ws", FP: "firefox", Priority: 1},
	}
}

func fakeProbe(results map[string]struct {
	ok  bool
	rtt float64
}) ProbeFunc {
	return func(ep Endpoint, addr string, timeout time.Duration) (bool, float64, string) {
		key := ep.Host + "|" + addr
		if r, ok := results[key]; ok {
			return r.ok, r.rtt, ""
		}
		return false, 0, "timeout"
	}
}

func TestProbeRoundFindsHealthyAndStops(t *testing.T) {
	now := time.Unix(1700000000, 0)
	probed := 0
	probe := func(ep Endpoint, addr string, timeout time.Duration) (bool, float64, string) {
		probed++
		if addr == "1.1.1.1:443" {
			return true, 90, ""
		}
		return false, 0, "timeout"
	}
	e := New(testEntries(), probe)
	healthy := e.ProbeRound(now)
	if len(healthy) != 1 {
		t.Fatalf("expected 1 healthy candidate, got %d", len(healthy))
	}
	if healthy[0].DialAddr != "1.1.1.1:443" {
		t.Fatalf("expected 1.1.1.1:443 first (priority IP), got %s", healthy[0].DialAddr)
	}
	// Stops at first healthy: probed at most the candidates up to it.
	if probed > 2 {
		t.Fatalf("probe round should stop at first healthy, probed %d", probed)
	}
}

func TestHealthScoringAndFailoverOrder(t *testing.T) {
	now := time.Unix(1700000000, 0)
	e := New(testEntries(), fakeProbe(map[string]struct {
		ok  bool
		rtt float64
	}{}))
	// All fail initially.
	e.Observe(testEntries()[0], "1.1.1.1:443", false, 0, "rst", now)
	e.Observe(testEntries()[0], "1.1.1.1:443", false, 0, "rst", now.Add(time.Second))
	// 2.2.2.2 is healthy.
	e.Observe(testEntries()[0], "2.2.2.2:443", true, 80, "", now.Add(2*time.Second))
	h := e.Health()
	bad := h["primary.example|1.1.1.1:443"]
	good := h["primary.example|2.2.2.2:443"]
	if bad.Score >= good.Score {
		t.Fatalf("failed IP must rank below healthy IP: bad=%.3f good=%.3f", bad.Score, good.Score)
	}
	if good.Score < 0.9 {
		t.Fatalf("healthy low-rtt IP should score high, got %.3f", good.Score)
	}
	if bad.ConsecFail != 2 {
		t.Fatalf("expected 2 consecutive failures, got %d", bad.ConsecFail)
	}
	// CandidatesFor must put the healthy IP before the dead one.
	cands := e.CandidatesFor(testEntries()[0])
	if cands[0] != "2.2.2.2:443" {
		t.Fatalf("expected healthy IP first, got %v", cands)
	}
}

func TestAggressiveModeTransitions(t *testing.T) {
	now := time.Unix(1700000000, 0)
	probe := func(ep Endpoint, addr string, timeout time.Duration) (bool, float64, string) {
		return false, 0, "timeout"
	}
	e := New(testEntries(), probe)
	if e.State() != StateNormal {
		t.Fatal("should start normal")
	}
	e.ProbeRound(now) // streak 1
	if e.State() != StateNormal {
		t.Fatal("should stay normal after one bad round")
	}
	e.ProbeRound(now.Add(time.Second)) // streak 2 -> aggressive
	if e.State() != StateAggressive {
		t.Fatalf("expected aggressive after 2 bad rounds, got %s", e.State())
	}
	// A success drops back to normal.
	okProbe := func(ep Endpoint, addr string, timeout time.Duration) (bool, float64, string) {
		return true, 100, ""
	}
	e2 := New(testEntries(), okProbe)
	e2.state = StateAggressive
	e2.ProbeRound(now)
	if e2.State() != StateNormal {
		t.Fatal("success must return to normal")
	}
}

func TestAggressiveUsesWiderTimeout(t *testing.T) {
	var seen time.Duration
	probe := func(ep Endpoint, addr string, timeout time.Duration) (bool, float64, string) {
		seen = timeout
		return true, 50, ""
	}
	e := New(testEntries(), probe)
	e.state = StateAggressive
	e.ProbeRound(time.Unix(1700000000, 0))
	if seen != aggressiveTimeout {
		t.Fatalf("aggressive timeout = %v, want %v", seen, aggressiveTimeout)
	}
}

func TestCachePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routing.json")
	now := time.Unix(1700000000, 0)
	e := New(testEntries(), fakeProbe(map[string]struct {
		ok  bool
		rtt float64
	}{}))
	e.Observe(testEntries()[0], "1.1.1.1:443", true, 120, "", now)
	if err := e.SaveCache(path); err != nil {
		t.Fatal(err)
	}
	e2 := New(testEntries(), nil)
	if err := e2.LoadCache(path); err != nil {
		t.Fatal(err)
	}
	h := e2.Health()
	if h["primary.example|1.1.1.1:443"].Score < 0.5 {
		t.Fatal("persisted health not restored")
	}
	// LoadCache tolerates a missing file.
	if err := e2.LoadCache(filepath.Join(dir, "nope.json")); err != nil {
		t.Fatalf("missing cache file should be a no-op, got %v", err)
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected only the cache file, got %v", entries)
	}
}

func TestFailoverOrderRespectsBanditScore(t *testing.T) {
	e := New(testEntries(), nil)
	// Bandit score: backup beats primary (opposite of priority order).
	scores := map[string]float64{
		"backup.example|ws|firefox":  0.9,
		"primary.example|ws|chrome":  0.4,
	}
	order := e.FailoverOrder(func(a Arm) float64 {
		return scores[a.Host+"|"+a.Transport+"|"+a.FP]
	})
	if len(order) == 0 {
		t.Fatal("empty failover order")
	}
	if order[0].Endpoint.Host != "backup.example" {
		t.Fatalf("expected bandit-preferred backup first, got %s", order[0].Endpoint.Host)
	}
}

func TestAddEntryReplacesSameHostTransport(t *testing.T) {
	e := New(testEntries(), nil)
	e.AddEntry(Endpoint{Host: "backup.example", Transport: "ws", FP: "safari", Priority: 1})
	if len(e.Entries()) != 2 {
		t.Fatalf("expected replacement, got %d entries", len(e.Entries()))
	}
	for _, ep := range e.Entries() {
		if ep.Host == "backup.example" && ep.FP != "safari" {
			t.Fatal("entry was not updated")
		}
	}
}

func TestBestReturnsTopWhenAllDead(t *testing.T) {
	now := time.Unix(1700000000, 0)
	e := New(testEntries(), nil)
	e.Observe(testEntries()[0], "1.1.1.1:443", false, 0, "rst", now)
	e.Observe(testEntries()[0], "1.1.1.1:443", false, 0, "rst", now)
	e.Observe(testEntries()[0], "2.2.2.2:443", false, 0, "rst", now)
	e.Observe(testEntries()[0], "2.2.2.2:443", false, 0, "rst", now)
	e.Observe(testEntries()[0], "primary.example:443", false, 0, "rst", now)
	e.Observe(testEntries()[0], "primary.example:443", false, 0, "rst", now)
	e.Observe(testEntries()[1], "backup.example:443", false, 0, "rst", now)
	e.Observe(testEntries()[1], "backup.example:443", false, 0, "rst", now)
	best, err := e.Best(nil)
	if err != nil {
		t.Fatalf("Best must still return a candidate when all are dead, got %v", err)
	}
	if best.Endpoint.Host != "primary.example" {
		t.Fatalf("expected priority-ordered top candidate, got %s", best.Endpoint.Host)
	}
}
