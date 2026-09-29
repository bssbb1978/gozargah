package main

// 2.21 — tests for the net-e-melli blackout bootstrap: the manifest mirror
// ladder, the last-known-good fallback, and the per-round probe
// de-synchronization budget.

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bssbb1978/gozargah/axr/internal/failover"
	"github.com/bssbb1978/gozargah/axr/internal/netstate"
)

const (
	testToken      = "0123456789abcdef0123"
	testManifestU  = "https://intl.example.com/gozargah/sub/" + testToken + "/axr-manifest"
	testFronting   = "cdn.domestic.example"
	testBackupHost = "backup.example.com"
)

// signedTestManifest returns a manifest whose HMAC verifies under testToken
// and whose fronting hint is host.
func signedTestManifest(t *testing.T, host string) ([]byte, manifestV3) {
	t.Helper()
	m := manifestV3{
		Schema:              "gozargah-axr-manifest/v3",
		Version:             "2.21.0",
		Host:                "intl.example.com",
		WSPathBase:          "/rotated-path",
		PathRotationMinutes: 360,
		Transports:          []string{"ws", "ws-alt"},
		CleanIPHints:        []string{"104.16.13.37"},
		FrontingHint:        host,
	}
	m.Entries = make([]struct {
		Host string `json:"host"`
		Role string `json:"role"`
	}, 0)
	m.Fingerprint.Current = "chrome"
	m.FlowProfile.Mode = "web"
	m.Reconnect.ProbeIntervalMS = 90000
	m.Canary.Host = "canary.example.com"
	m.Canary.Expect = "ok"
	m.Canary.IntervalMS = 300000
	m.ManifestSig = manifestHMAC(canonicalFromManifest(&m), testToken)
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return body, m
}

// testServer builds the minimum server state the manifest bootstrap needs —
// no network, no goroutines.
func testServer(t *testing.T, cacheDir string) *server {
	t.Helper()
	fo := failover.New([]failover.Endpoint{
		{Host: "intl.example.com", Transport: "ws", FP: "chrome", Priority: 0},
		{Host: testFronting, Transport: "ws", FP: "chrome", Priority: 50},
	}, nil)
	return &server{
		cfg:         Config{ManifestURL: testManifestU, UUID: "0123456789abcdef0123456789abcdef", CacheDir: cacheDir},
		log:         newLogger(false),
		failover:    fo,
		netstate:    netstate.NewDetector(),
		lastRegime:  netstate.RegimeStable,
		configHosts: map[string]bool{"intl.example.com": true},
		probeInt:    [2]time.Duration{90 * time.Second, 30 * time.Second},
	}
}

func TestManifestMirrorURLKeepsSchemePathAndToken(t *testing.T) {
	got := manifestMirrorURL(testManifestU, testFronting)
	if got != "https://"+testFronting+"/gozargah/sub/"+testToken+"/axr-manifest" {
		t.Fatalf("mirror URL = %q", got)
	}
	// The mirror must carry the SAME token: the HMAC the client verifies is
	// bound to it, so a mirror can serve the manifest but never forge one.
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("mirror URL does not parse: %v", err)
	}
	if subTokenFromURL(got) != subTokenFromURL(testManifestU) {
		t.Fatalf("mirror token %q != primary token %q", subTokenFromURL(got), subTokenFromURL(testManifestU))
	}
	if u.Path != "/gozargah/sub/"+testToken+"/axr-manifest" {
		t.Fatalf("mirror path = %q", u.Path)
	}
	// Degenerate inputs must not produce a URL.
	if got := manifestMirrorURL(testManifestU, ""); got != "" {
		t.Fatalf("empty host must yield no mirror, got %q", got)
	}
	if got := manifestMirrorURL("://not a url", testFronting); got != "" {
		t.Fatalf("unparseable primary must yield no mirror, got %q", got)
	}
}

func TestManifestLadderIsPrimaryThenDomesticMirrors(t *testing.T) {
	s := testServer(t, t.TempDir())
	if got := s.manifestLadder(); len(got) != 1 || got[0] != testManifestU {
		t.Fatalf("ladder without mirrors = %v", got)
	}
	mirror := manifestMirrorURL(testManifestU, testFronting)
	s.setMirrors([]string{mirror, mirror, "", testManifestU, "https://b.example/x"})
	got := s.manifestLadder()
	if len(got) != 3 {
		t.Fatalf("ladder = %v, want the primary + 2 distinct mirrors", got)
	}
	if got[0] != testManifestU {
		t.Fatalf("the primary must be tried first, got %v", got)
	}
	if got[1] != mirror {
		t.Fatalf("the domestic mirror must come second, got %v", got)
	}
	seen := map[string]int{}
	for _, u := range got {
		seen[u]++
		if seen[u] > 1 {
			t.Fatalf("duplicate URL in ladder: %v", got)
		}
	}
	if seen[testManifestU] != 1 {
		t.Fatalf("the primary URL must appear exactly once: %v", got)
	}
}

// TestSeedMirrorsFromCacheRequiresAValidSignature: a cached manifest that
// carries a signature which does not verify must not contribute a mirror
// (its fronting hint is attacker-controlled until the HMAC says otherwise).
func TestSeedMirrorsFromCacheRequiresAValidSignature(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(m *manifestV3)
		armored bool
	}{
		{name: "valid signature", mutate: func(m *manifestV3) {}, armored: true},
		{name: "forged signature", mutate: func(m *manifestV3) { m.ManifestSig = strings.Repeat("ab", 32) }, armored: false},
		{name: "tampered fronting after signing", mutate: func(m *manifestV3) { m.FrontingHint = "attacker.example" }, armored: false},
		{name: "unsigned pre-2.16 worker", mutate: func(m *manifestV3) { m.ManifestSig = "" }, armored: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, m := signedTestManifest(t, testFronting)
			if tc.name == "tampered fronting after signing" {
				// Sign the honest body, then flip the host: the HMAC must
				// fail even though the signature field is well-formed.
				var raw map[string]any
				if err := json.Unmarshal(body, &raw); err != nil {
					t.Fatal(err)
				}
				raw["fronting_hint"] = "attacker.example"
				b2, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				body = b2
			} else {
				tc.mutate(&m)
				var err error
				body, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest-lastgood.json"), body, 0o600); err != nil {
				t.Fatal(err)
			}
			s := testServer(t, dir)
			s.seedMirrorsFromCache()
			got := s.lastGoodMirrors
			if tc.armored && len(got) == 0 {
				t.Fatal("a trusted cache entry must arm the domestic mirror")
			}
			if !tc.armored {
				if len(got) != 0 {
					t.Fatalf("an unverifiable cache entry must not arm a mirror, got %v", got)
				}
				// ...and the rejected host must never appear.
				for _, u := range got {
					if strings.Contains(u, "attacker.example") {
						t.Fatalf("forged hint leaked into the ladder: %v", got)
					}
				}
			}
		})
	}
}

// TestLoadLastGoodManifestRoundTrip: the persisted body is returned verbatim
// so it can be re-verified and applied by the same code path as a live fetch.
func TestLoadLastGoodManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	body, _ := signedTestManifest(t, testFronting)
	if err := os.WriteFile(filepath.Join(dir, "manifest-lastgood.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, src, err := loadLastGoodManifest(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(got) != string(body) {
		t.Fatal("cached body must be returned byte-identical (it is re-verified)")
	}
	if !strings.Contains(src, "manifest-lastgood.json") {
		t.Fatalf("source label = %q", src)
	}
	if _, _, err := loadLastGoodManifest(t.TempDir()); err == nil {
		t.Fatal("a missing cache must report an error so the caller can log it")
	}
}

// TestProbeIntervalStaysWithinTheDynamicBand: the per-round jitter must stay
// inside the cadence plus the manifest width, and must actually VARY (a
// constant interval is the signature the de-sync exists to remove).
func TestProbeIntervalStaysWithinTheDynamicBand(t *testing.T) {
	s := testServer(t, t.TempDir())
	s.failover.SetQuietPolicy(failover.DefaultQuietPolicy())
	if s.failover.State() != failover.StateNormal {
		t.Fatal("setup: expected the normal probe state")
	}
	// No manifest jitter: the interval is exactly the cadence.
	if got := s.probeInterval(); got != s.probeInt[0] {
		t.Fatalf("without a jitter width the interval must be the cadence, got %v", got)
	}
	width := 8 * time.Second
	s.probeJitterWidth = width
	s.probeJitterOffset = width / 2 // the FNV-32a phase
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		got := s.probeInterval()
		if got < s.probeInt[0] {
			t.Fatalf("interval %v is below the cadence %v", got, s.probeInt[0])
		}
		max := s.probeInt[0] + s.probeJitterOffset + width
		if got >= max {
			t.Fatalf("interval %v reached the exclusive ceiling %v (draw out of range)", got, max)
		}
		seen[got] = true
	}
	if len(seen) < 50 {
		t.Fatalf("the per-round draw must vary the interval, saw only %d distinct values", len(seen))
	}
	// A width wider than the cap is clamped: the aggressive cadence must not
	// be stretched into uselessness by an over-wide manifest value.
	s.probeJitterWidth = 10 * time.Minute
	s.probeJitterOffset = 0
	for i := 0; i < 200; i++ {
		if got := s.probeInterval(); got >= s.probeInt[0]+probeRedrawCap {
			t.Fatalf("redraw %v exceeds the %v cap", got, probeRedrawCap)
		}
	}
}

// TestApplyPolicyInstallsTheBlackoutQuietGate: the net-e-melli regime must
// widen the failover quiet window, and the steady regime must restore the
// baseline. This is the wiring that turns "the route is dead" into "stop
// dialing it every round".
func TestApplyPolicyInstallsTheBlackoutQuietGate(t *testing.T) {
	s := testServer(t, t.TempDir())
	s.frontingHost = testFronting
	// Force the detector into the net-e-melli window: international
	// primaries dead, the domestic fronting entry alive.
	s.netstate.Record(netstate.Observation{Role: netstate.RolePrimary, OK: false})
	s.netstate.Record(netstate.Observation{Role: netstate.RolePrimary, OK: false})
	s.netstate.Record(netstate.Observation{Role: netstate.RoleFronting, OK: true})
	if got := s.netstate.Regime(); got != netstate.RegimeNetEMelli {
		t.Fatalf("setup: detector regime = %s, want netemelli", got)
	}
	s.applyPolicy()
	pol := s.netstate.Regime().Policy()
	if !pol.QuietPrimary || !pol.QuietBackup {
		t.Fatalf("the netemelli policy must quiet the international classes: %+v", pol)
	}
	q := s.failover.Quiet()
	if !q.Enabled {
		t.Fatal("applyPolicy must enable the quiet gate")
	}
	if q.BaseMS != 120_000 || q.MaxMS != 30*60_000 {
		t.Fatalf("blackout quiet window = %d/%d, want the widened 120000/1800000", q.BaseMS, q.MaxMS)
	}
	// Priorities: the domestic fronting entry leads the ladder.
	frontingPri, primaryPri := -1, -1
	for _, ep := range s.failover.Entries() {
		switch ep.Host {
		case testFronting:
			frontingPri = ep.Priority
		case "intl.example.com":
			primaryPri = ep.Priority
		}
	}
	if frontingPri >= primaryPri {
		t.Fatalf("fronting (%d) must be preferred over primary (%d)", frontingPri, primaryPri)
	}
	// Back to a healthy network: the policy must relax to the baseline gate.
	for i := 0; i < 8; i++ {
		s.netstate.Record(netstate.Observation{Role: netstate.RolePrimary, OK: true})
	}
	if got := s.netstate.Regime(); got != netstate.RegimeRecovering && got != netstate.RegimeStable {
		t.Fatalf("healthy evidence must leave the blackout, got %s", got)
	}
	s.applyPolicy()
	if q := s.failover.Quiet(); q.BaseMS != failover.DefaultQuietPolicy().BaseMS {
		t.Fatalf("a relaxed regime must restore the baseline width, got %d", q.BaseMS)
	}
}
