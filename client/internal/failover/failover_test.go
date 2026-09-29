package failover

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
	now := time.Now()
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
	bad := h["primary.example|ws|1.1.1.1:443"]
	good := h["primary.example|ws|2.2.2.2:443"]
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

func TestTransportHealthIsIsolatedPerPath(t *testing.T) {
	now := time.Now()
	ws := Endpoint{Host: "edge.example", IPs: []string{"1.1.1.1"}, Transport: "ws", FP: "chrome"}
	alt := Endpoint{Host: "edge.example", IPs: []string{"1.1.1.1"}, Transport: "ws-alt", FP: "chrome"}
	e := New([]Endpoint{ws, alt}, nil)
	e.Observe(ws, "1.1.1.1:443", false, 0, "simulated_rst", now)
	e.Observe(alt, "1.1.1.1:443", true, 70, "", now)

	health := e.Health()
	if health["edge.example|ws|1.1.1.1:443"].Score >= health["edge.example|ws-alt|1.1.1.1:443"].Score {
		t.Fatalf("transport outcomes must remain isolated: %+v", health)
	}
	if got := e.CandidatesFor(ws)[0]; got != "edge.example:443" {
		t.Fatalf("failed WS hint should be below the unmeasured host fallback, got %v", e.CandidatesFor(ws))
	}
	if got := e.CandidatesFor(alt)[0]; got != "1.1.1.1:443" {
		t.Fatalf("measured WS-alt success should lead its path, got %v", e.CandidatesFor(alt))
	}
}

func TestProbeRoundUsesMeasuredTransportFallback(t *testing.T) {
	probe := func(ep Endpoint, _ string, _ time.Duration) (bool, float64, string) {
		if ep.Transport == "ws" {
			return false, 25, "simulated_sni_block"
		}
		return true, 80, ""
	}
	entries := []Endpoint{
		{Host: "edge.example", Transport: "ws", FP: "chrome", Priority: 0},
		{Host: "edge.example", Transport: "ws-alt", FP: "chrome", Priority: 0},
	}
	e := New(entries, probe)
	healthy := e.ProbeRound(time.Now())
	if len(healthy) != 1 || healthy[0].Endpoint.Transport != "ws-alt" {
		t.Fatalf("expected measured fallback to ws-alt, got %+v", healthy)
	}
	health := e.Health()
	if health["edge.example|ws|edge.example:443"].Score >= health["edge.example|ws-alt|edge.example:443"].Score {
		t.Fatalf("failed and successful transport measurements were not ranked separately: %+v", health)
	}
}

func TestTransportHealthDecaysTowardUnknown(t *testing.T) {
	now := time.Now()
	good := &IPHealth{Score: 1, CheckedAtMS: now.UnixMilli()}
	bad := &IPHealth{Score: 0, CheckedAtMS: now.UnixMilli()}
	atHalfLife := now.Add(6 * time.Hour).UnixMilli()
	if got := decayedHealthScore(good, atHalfLife); got < 0.749 || got > 0.751 {
		t.Fatalf("good evidence should decay halfway toward neutral after one half-life, got %.4f", got)
	}
	if got := decayedHealthScore(bad, atHalfLife); got < 0.249 || got > 0.251 {
		t.Fatalf("bad evidence should decay halfway toward neutral after one half-life, got %.4f", got)
	}
	atFourHalfLives := now.Add(24 * time.Hour).UnixMilli()
	if got := decayedHealthScore(good, atFourHalfLives); got < 0.53 || got > 0.532 {
		t.Fatalf("stale success should approach, not exceed, neutral, got %.4f", got)
	}
	if got := decayedHealthScore(bad, atFourHalfLives); got < 0.468 || got > 0.47 {
		t.Fatalf("stale failure should approach, not stay pinned below, neutral, got %.4f", got)
	}
}

func TestEqualHealthCleanIPsRotateAndPersistCursor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routing.json")
	entries := []Endpoint{{Host: "edge.example", IPs: []string{"1.1.1.1", "2.2.2.2"}, Transport: "ws", FP: "chrome"}}
	e := New(entries, nil)
	first := e.CandidatesFor(entries[0])[0]
	if first != "1.1.1.1:443" {
		t.Fatalf("initial clean-IP order changed unexpectedly: %s", first)
	}
	if err := e.SaveCache(path); err != nil {
		t.Fatal(err)
	}
	e2 := New(entries, nil)
	if err := e2.LoadCache(path); err != nil {
		t.Fatal(err)
	}
	second := e2.CandidatesFor(entries[0])[0]
	if second != "2.2.2.2:443" {
		t.Fatalf("persisted pool cursor should rotate to the next equal-health IP, got %s", second)
	}
}

func TestLegacyHealthCacheSeedsTransportScopedRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-routing.json")
	now := time.Now().UnixMilli()
	data := []byte(`{"updated_at_ms":` + strconv.FormatInt(now, 10) + `,"health":{"edge.example|1.1.1.1:443":{"dial_addr":"1.1.1.1:443","score":0.9,"last_ok_ms":` + strconv.FormatInt(now, 10) + `}}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	entries := []Endpoint{
		{Host: "edge.example", Transport: "ws", FP: "chrome"},
		{Host: "edge.example", Transport: "ws-alt", FP: "chrome"},
	}
	e := New(entries, nil)
	if err := e.LoadCache(path); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"ws", "ws-alt"} {
		if _, ok := e.Health()["edge.example|"+transport+"|1.1.1.1:443"]; !ok {
			t.Fatalf("legacy reachability seed missing for %s", transport)
		}
	}
	if _, ok := e.Health()["edge.example|1.1.1.1:443"]; ok {
		t.Fatal("legacy aggregate row should be removed after transport-scoped migration")
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
	if h["primary.example|ws|1.1.1.1:443"].Score < 0.5 {
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
		"backup.example|ws|firefox": 0.9,
		"primary.example|ws|chrome": 0.4,
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

// fakeResolver is a deterministic Resolver for tests.
type fakeResolver struct {
	records map[string][]string
	err     error
}

func (f fakeResolver) LookupA(ctx context.Context, host string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[host], nil
}

func TestHarvestedIPsMergesDedupesCaps(t *testing.T) {
	ctx := context.Background()
	r := fakeResolver{records: map[string][]string{
		"p.example": {"9.9.9.9", "1.1.1.1", "9.9.9.10", "9.9.9.11", "9.9.9.12"},
	}}
	// explicit 1.1.1.1 already present -> deduped; 9.9.9.9 harvested.
	got := HarvestedIPs(ctx, []string{"1.1.1.1"}, "p.example", r)
	want := []string{"1.1.1.1", "9.9.9.9", "9.9.9.10", "9.9.9.11", "9.9.9.12"}
	if len(got) != len(want) {
		t.Fatalf("harvested %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("harvested %v, want %v", got, want)
		}
	}
}

func TestHarvestedIPsExplicitFirstAndCap(t *testing.T) {
	ctx := context.Background()
	r := fakeResolver{records: map[string][]string{
		"p.example": {"3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8", "9.9.9.9", "10.10.10.10"},
	}}
	// 6 explicit + 8 harvested must cap at MaxHarvestedIPs, explicit first.
	explicit := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"}
	got := HarvestedIPs(ctx, explicit, "p.example", r)
	if len(got) != MaxHarvestedIPs {
		t.Fatalf("expected cap at %d, got %d (%v)", MaxHarvestedIPs, len(got), got)
	}
	for i := 0; i < 6; i++ {
		if got[i] != explicit[i] {
			t.Fatalf("explicit IP must stay first at %d: %v", i, got)
		}
	}
	// 3.3.3.3/4.4.4.4/5.5.5.5/6.6.6.6 are explicit dupes; next harvested are 7.7.7.7, 8.8.8.8, 9.9.9.9.
	if got[6] != "7.7.7.7" || got[7] != "8.8.8.8" {
		t.Fatalf("harvested tail wrong: %v", got)
	}
}

func TestHarvestedIPsDropsInvalidAndCapsAtEight(t *testing.T) {
	ctx := context.Background()
	r := fakeResolver{records: map[string][]string{
		"p.example": {"not-an-ip", "8.8.4.4", "8.8.8.8", "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7"},
	}}
	// no explicit; 10 records (1 invalid) -> cap at 8, invalid dropped.
	got := HarvestedIPs(ctx, nil, "p.example", r)
	if len(got) != 8 {
		t.Fatalf("expected 8 (cap), got %d: %v", len(got), got)
	}
	for _, ip := range got {
		if ip == "not-an-ip" {
			t.Fatalf("invalid IP must be dropped: %v", got)
		}
	}
}

func TestHarvestedIPSErrorKeepsExisting(t *testing.T) {
	ctx := context.Background()
	r := fakeResolver{err: errors.New("dns failure")}
	got := HarvestedIPs(ctx, []string{"1.1.1.1"}, "p.example", r)
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("resolver error must keep existing list, got %v", got)
	}
}

func TestHarvestedIPsNilResolver(t *testing.T) {
	ctx := context.Background()
	got := HarvestedIPs(ctx, []string{"1.1.1.1", "1.1.1.1", "2.2.2.2"}, "p.example", nil)
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("nil resolver must dedupe explicit only, got %v", got)
	}
}

func TestHarvestEntriesUpdatesMatrix(t *testing.T) {
	ctx := context.Background()
	e := New(testEntries(), nil)
	r := fakeResolver{records: map[string][]string{
		"primary.example": {"9.9.9.9"},
		"backup.example":  {"8.8.8.8"},
	}}
	added := e.HarvestEntries(ctx, r)
	if added != 2 {
		t.Fatalf("expected 2 added (one per entry), got %d", added)
	}
	for _, ep := range e.Entries() {
		switch ep.Host {
		case "primary.example":
			if len(ep.IPs) != 3 || ep.IPs[2] != "9.9.9.9" {
				t.Fatalf("primary IPs wrong: %v", ep.IPs)
			}
		case "backup.example":
			if len(ep.IPs) != 1 || ep.IPs[0] != "8.8.8.8" {
				t.Fatalf("backup IPs wrong: %v", ep.IPs)
			}
		}
	}
	// Idempotent: a second harvest adds nothing.
	if again := e.HarvestEntries(ctx, r); again != 0 {
		t.Fatalf("second harvest must add 0, got %d", again)
	}
}
