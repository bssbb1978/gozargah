// Command axr is the native AXR client core: a SOCKS5 TCP inbound that
// tunnels each stream over a bandit-selected VLESS-over-WebSocket path,
// with client-side ClientHello segmentation, post-handshake TCP chunking,
// a live routing cache, and a normal/aggressive probe state machine.
//
// It is the client half of the gozargah AXR framework. TLS terminates at the
// Cloudflare edge, so ALL fingerprint morphing, ClientHello surgery, and
// path/IP selection happens here, locally, before the bytes leave the host.
//
// Honest boundaries (see docs/AXR-SPEC.md):
//   - this is transport obfuscation and adaptive path selection, not payload
//     inspection and not a guarantee against any specific filter
//   - a total route cut (no path from the local network to any entry) cannot
//     be created from the client; the binary reports it instead of looping
//   - VLESS-over-WS ("ws") is the shipped transport; "ws-alt" is the same WS
//     over a different path/query shape (gz_profile=fragmented); h2/h3/grpc
//     arms are interface stubs reserved for later releases
//   - 2.15 additions: LinUCB contextual bandit, regime-driven flow profiles
//     (length-histogram morphing + IPD), TCP socket surgery (Nagle off +
//     randomized SO_SNDBUF), warm-session reuse (<=30s same-destination),
//     A-record clean-IP harvesting, and a decision.jsonl audit log
package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bssbb1978/gozargah/axr/internal/bandit"
	"github.com/bssbb1978/gozargah/axr/internal/evade"
	"github.com/bssbb1978/gozargah/axr/internal/failover"
	"github.com/bssbb1978/gozargah/axr/internal/flowprofile"
	"github.com/bssbb1978/gozargah/axr/internal/measure"
	"github.com/bssbb1978/gozargah/axr/internal/netstate"
	"github.com/bssbb1978/gozargah/axr/internal/sockopt"
	"github.com/bssbb1978/gozargah/axr/internal/surgery"
	"github.com/bssbb1978/gozargah/axr/internal/vlessws"
)

// transportsPerEntry: every entry runs the primary WS arm plus the "ws-alt"
// shape arm (same host, gz_profile=fragmented) so the bandit can learn which
// path/query shape is healthier under the current conditions.
var transportsPerEntry = []string{"ws", "ws-alt"}

// Config is the operator-supplied entry set (axr.json).
type Config struct {
	// Entries is the local entry matrix.
	Entries []Entry `json:"entries"`
	// UUID is the VLESS user UUID (dashed or plain hex).
	UUID string `json:"uuid"`
	// ManifestURL is the worker axr-manifest feed, e.g.
	// https://host/sub/<token>/axr-manifest. It bootstraps the rotated WS
	// path, live regime/backup entries, and the probe cadence. Optional when
	// WSPath is set explicitly.
	ManifestURL string `json:"manifest_url,omitempty"`
	// WSPath is the full WebSocket path incl. query, e.g.
	// /sub/<token>/<pathbase>?ed=2048. Used when ManifestURL is absent.
	WSPath string `json:"ws_path,omitempty"`
	// CacheDir for the routing/bandit state. Default: ~/.axr
	CacheDir string `json:"cache_dir,omitempty"`
	// Surgery toggles ClientHello split + post-handshake chunking (default on).
	Surgery *bool `json:"surgery,omitempty"`
	// SplitGapMS bounds the randomized inter-segment gap in ms (used when
	// the ClientHello is cut once).
	SplitGapMS [2]int `json:"split_gap_ms,omitempty"`
	// Probes cadence in ms (0 = defaults: 90s normal / 30s aggressive).
	Probes struct {
		NormalMS     int `json:"normal_ms"`
		AggressiveMS int `json:"aggressive_ms"`
	} `json:"probes,omitempty"`
	// ---- 2.16 — AXR-v3 fields ----
	// FragCuts is the [min,max] range of ClientHello split points per
	// connection (default [2,3]: the fragA/fragB multi-segment shape).
	// 0 0 keeps the legacy single cut with SplitGapMS.
	FragCuts [2]int `json:"frag_cuts,omitempty"`
	// FragWindow is the cut window as percent-of-record bounds (default
	// [40,90] = the SNI extension region).
	FragWindow [2]int `json:"frag_window,omitempty"`
	// FragMicroGapMS bounds the inter-segment micro-gap in ms for
	// multi-cut splits (default [1,8]).
	FragMicroGapMS [2]int `json:"frag_micro_gap_ms,omitempty"`
	// HarvestURL is the Worker clean-IP harvest endpoint (default derived
	// from ManifestURL: https://<host>/gozargah/api/network/harvest).
	HarvestURL string `json:"harvest_url,omitempty"`
	// HarvestToken for `axr scan -upload` (default: the manifest URL token).
	HarvestToken string `json:"harvest_token,omitempty"`
	// ---- 2.17 — AXR-v3.1 fields ----
	// FragWrites is the [min,max] range of the FIRST WRITES that get
	// multi-segment surgery per connection (default [1,3]: the ClientHello
	// plus the next one or two client-flight writes). 0 0 keeps the 2.16
	// single-write behaviour.
	FragWrites [2]int `json:"frag_writes,omitempty"`
	// Port is the entry TCP port (default 443). Non-standard ports let the
	// client reach non-443 edge deployments and LOCAL test harnesses
	// (e.g. `wrangler dev` on 8787) — before 2.21 every dial address was
	// pinned to :443, which made end-to-end verification impossible
	// without a privileged bind.
	Port int `json:"port,omitempty"`
	// InsecureSkipVerify disables certificate verification on the entry
	// TLS handshake (default false). Documented escape hatch for local
	// harnesses and pinned self-signed edge certs; NEVER leave it on
	// against the public internet.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// CanaryIntervalMS bounds the canary liveness probe cadence (default
	// 300000; the manifest's canary.interval_ms overrides it when sane,
	// [60000, 3600000]).
	CanaryIntervalMS int `json:"canary_interval_ms,omitempty"`
}

// Entry is one candidate entry path.
type Entry struct {
	Host     string   `json:"host"`
	IPs      []string `json:"ips,omitempty"` // explicit clean edge IPs
	FP       string   `json:"fp,omitempty"`  // chrome|firefox|safari|randomized
	Priority int      `json:"priority,omitempty"`
	// Port overrides Config.Port for this entry (0 → Config.Port → 443).
	Port int `json:"port,omitempty"`
}

// Options from flags.
type options struct {
	configPath string
	socksAddr  string
	surgeryOn  bool
	verbose    bool
	timeout    time.Duration
}

func main() {
	// 2.16 — subcommands (parsed before the default server flagset).
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		runScan(os.Args[2:])
		return
	}

	var opt options
	flag.StringVar(&opt.configPath, "config", "", "path to axr.json config")
	flag.StringVar(&opt.socksAddr, "socks", "127.0.0.1:1080", "SOCKS5 TCP listen address")
	flag.BoolVar(&opt.surgeryOn, "surgery", true, "enable ClientHello split + post-handshake chunking")
	flag.BoolVar(&opt.verbose, "v", false, "verbose logging (score table, attempts)")
	flag.DurationVar(&opt.timeout, "timeout", 12*time.Second, "per-tunnel dial+handshake budget")
	flag.Parse()

	if opt.configPath == "" {
		fatalf("-config is required")
	}
	cfg, err := loadConfig(opt.configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	if !opt.surgeryOn {
		off := false
		cfg.Surgery = &off
	}
	l := newLogger(opt.verbose)
	srv, err := newServer(cfg, l, opt.timeout)
	if err != nil {
		fatalf("init: %v", err)
	}
	srv.startProbes()
	defer srv.shutdown()

	ln, err := net.Listen("tcp", opt.socksAddr)
	if err != nil {
		fatalf("listen %s: %v", opt.socksAddr, err)
	}
	l.logf("SOCKS5 listening on %s (%d entries, surgery=%v)", opt.socksAddr, len(cfg.Entries), surgeryEnabled(cfg))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		l.logf("shutting down")
		_ = ln.Close()
	}()
	srv.serveSOCKS(ln)
}

// ---- server ----

// warmTTL is how long a finished, still-open tunnel stays adoptable for a
// same-destination CONNECT (session reuse).
const warmTTL = 30 * time.Second

// warmSession is a finished tunnel whose WS connection is still open and may
// be adopted by the NEXT CONNECT to the same destination (host:port). The
// worker's WS session carries exactly one backend stream, so adoption is
// strictly same-destination — anything else closes it and dials fresh.
type warmSession struct {
	ws      *vlessws.Client
	arm     bandit.Arm
	profile flowprofile.ProfileID
	dstHost string
	dstPort int
	endedAt int64 // unix ms
}

type server struct {
	cfg     Config
	log     *logger
	timeout time.Duration

	bandit   *bandit.Bandit
	failover *failover.Engine

	mu       sync.Mutex
	trackers map[string]*measure.Tracker // per-entry client state vector
	pathBase string                      // rotated ws path base from the manifest
	probeInt [2]time.Duration            // [normal, aggressive]

	// 2.16 — AXR-v3 state.
	startedAt time.Time // session-age feature
	sigWarned bool      // one-time "manifest unverified" note

	// 2.17 — AXR-v3.1 state.
	netstate     *netstate.Detector // route-regime hysteresis (net-e-melli)
	gov          *evade.Governor    // 2.19 — adaptive evasion governor
	policyMu     sync.Mutex         // guards lastRegime (tunnel + canary goroutines)
	lastRegime   netstate.Regime    // last regime the policy was applied for
	frontingHost string             // manifest fronting_hint host (role tag)
	configHosts  map[string]bool    // operator-configured entry hosts (role tag)
	canaryHost   string             // manifest canary host ("" = disabled)
	canaryInt    time.Duration      // canary probe cadence
	flowFloor    int                // manifest flow-profile floor (Rank units)
	// probeJitterOffset: the per-client deterministic draw (UUID-derived,
	// uniform in [0, probe_jitter_ms]) added to every probe cadence —
	// fleet de-synchronization (2.17). Written once during manifest
	// bootstrap (before any goroutine starts), read by the probe loop.
	probeJitterOffset time.Duration
	// probeJitterWidth is the manifest's de-sync width W (ms). The probe
	// loop adds a FRESH uniform draw in [0, min(W, probeRedrawCap)] on top
	// of the stable phase each round (2.21): a fixed per-client phase is
	// itself a constant, learnable inter-arrival signature, so the width is
	// re-drawn every round while the phase keeps clients mutually
	// decorrelated. Written at bootstrap; read by the probe loop.
	probeJitterWidth time.Duration

	// manifestBootstrap records how the manifest was obtained (live URL,
	// domestic mirror, or the persisted last-known-good copy) — the honest
	// provenance line for the audit log and for the blackout diagnosis.
	manifestBootstrap string
	// lastGoodMirrors are the manifest URLs derived from the last-known-good
	// manifest's fronting host — tried in order when the primary URL is
	// unreachable (net-e-melli: the international route is gone, the
	// domestic CDN still answers).
	lastGoodMirrors []string

	// 2.20 — stable per-client upgrade-shape identity (UUID-derived,
	// like the probe-jitter offset): one locale/UA/origin per user.
	langIdx   int
	uaIdx     int
	originIdx int

	// churnMu guards the last-good dial-address pair (entry-churn feature).
	churnMu      sync.Mutex
	prevGoodDial string
	lastGoodDial string

	// frameMu guards the outflow frame-size histogram (flow-KL feature).
	frameMu   sync.Mutex
	frameHist []int // counts per flowprofile.FrameBucketEdges bucket

	warmMu sync.Mutex
	warm   *warmSession
}

func surgeryEnabled(cfg Config) bool { return cfg.Surgery == nil || *cfg.Surgery }

// buildArms expands the operator entry matrix into bandit arms and failover
// endpoints. Every entry runs the primary "ws" arm plus the "ws-alt" shape
// arm (same host over the gz_profile=fragmented path/query shape), so the
// bandit can learn which shape is healthier under the current conditions —
// arm identity is (host, transport, fingerprint), NOT port: the port is a
// connection detail of the entry, not a different path shape.
//
// Port resolution is per entry: Entry.Port wins, else Config.Port, else 443
// (failover treats 0 as 443).
func buildArms(cfg Config) ([]bandit.Arm, []failover.Endpoint) {
	arms := make([]bandit.Arm, 0, len(cfg.Entries)*len(transportsPerEntry))
	foEntries := make([]failover.Endpoint, 0, len(cfg.Entries)*len(transportsPerEntry))
	for _, e := range cfg.Entries {
		fp := e.FP
		if fp == "" {
			fp = "chrome"
		}
		port := e.Port
		if port == 0 {
			port = cfg.Port
		}
		for _, tr := range transportsPerEntry {
			arms = append(arms, bandit.Arm{Host: e.Host, Transport: tr, FP: fp})
			foEntries = append(foEntries, failover.Endpoint{
				Host: e.Host, IPs: e.IPs, Transport: tr, FP: fp,
				Priority: e.Priority, Port: port,
			})
		}
	}
	return arms, foEntries
}

func newServer(cfg Config, l *logger, timeout time.Duration) (*server, error) {
	if len(cfg.Entries) == 0 {
		return nil, fmt.Errorf("no entries configured")
	}
	if cfg.UUID == "" {
		return nil, fmt.Errorf("uuid is required")
	}
	if _, err := vlessws.UUIDFromString(cfg.UUID); err != nil {
		return nil, fmt.Errorf("uuid: %v", err)
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port %d out of range", cfg.Port)
	}
	if cfg.CacheDir == "" {
		home, _ := os.UserHomeDir()
		cfg.CacheDir = home + "/.axr"
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("cache dir: %v", err)
	}

	arms, foEntries := buildArms(cfg)
	b := bandit.New(1.0, 1, arms)
	if snap, err := bandit.LoadSnapshot(cfg.CacheDir + "/bandit.json"); err == nil {
		if rerr := b.Restore(snap); rerr != nil {
			l.logf("bandit restore failed (%v); using fresh", rerr)
		} else {
			// Restore replaces the arm set with the snapshot's; re-add the
			// current config arms (no-op for existing ones) so upgraded
			// cores keep their learned state AND gain the new shapes
			// (e.g. ws-alt) with fresh ridge priors.
			for _, a := range arms {
				b.AddArm(a)
			}
			l.logf("restored bandit state (%d arms, %d after current-config merge)", len(snap.Arms), len(b.Arms()))
		}
	}
	fo := failover.New(foEntries, nil)
	if cerr := fo.LoadCache(cfg.CacheDir + "/routing.json"); cerr != nil {
		l.logf("routing cache load failed (%v); using fresh", cerr)
	}
	// 2.15 — clean edge-IP harvesting: merge each entry's live A records
	// into its IP set (dedup, capped). Best-effort: DNS may be filtered, in
	// which case the operator's explicit IPs remain untouched.
	hctx, hcancel := context.WithTimeout(context.Background(), 6*time.Second)
	if n := fo.HarvestEntries(hctx, failover.DefaultResolver{}); n > 0 {
		l.logf("harvested %d clean edge IP(s) from entry A records", n)
	}
	hcancel()
	// 2.16 — merge the local `axr scan` clean-IP pool (probe survivors from
	// this exact network — the strongest local evidence available).
	if n := mergeCleanIPsFile(fo, cfg.CacheDir+"/clean-ips.json"); n > 0 {
		l.logf("merged %d local scan clean IP(s) into the entry ladder", n)
	}

	// 2.20 — stable per-client upgrade-shape identity (one locale/UA/
	// origin per user, derived from the UUID like the probe offset).
	uidx := fnv.New32a()
	_, _ = uidx.Write([]byte(cfg.UUID))
	uid := uidx.Sum32()

	s := &server{
		cfg:       cfg,
		log:       l,
		timeout:   timeout,
		langIdx:   int(uid % uint32(len(vlessws.LocalePool))),
		uaIdx:     int((uid >> 8) % uint32(len(vlessws.UAPool))),
		originIdx: int((uid >> 16) % uint32(len(vlessws.OriginPool))),
		bandit:    b,
		failover:  fo,
		trackers:  make(map[string]*measure.Tracker),
		probeInt:  [2]time.Duration{90 * time.Second, 30 * time.Second},
		startedAt: time.Now(),
		frameHist: make([]int, len(flowprofile.FrameBucketEdges)-1),
		// 2.17 — net-e-melli regime hysteresis + canary defaults.
		netstate:    netstate.NewDetector(),
		gov:         evade.NewGovernor(),
		lastRegime:  netstate.RegimeStable,
		canaryInt:   300 * time.Second,
		configHosts: make(map[string]bool, len(cfg.Entries)),
	}
	for _, e := range cfg.Entries {
		s.configHosts[e.Host] = true
	}
	if c := cfg.CanaryIntervalMS; c >= 60_000 && c <= 3_600_000 {
		s.canaryInt = time.Duration(c) * time.Millisecond
	}
	if p := cfg.Probes; p.NormalMS > 0 {
		s.probeInt[0] = time.Duration(p.NormalMS) * time.Millisecond
	}
	if p := cfg.Probes; p.AggressiveMS > 0 {
		s.probeInt[1] = time.Duration(p.AggressiveMS) * time.Millisecond
	}
	// Best-effort manifest bootstrap (path base, backup entries, cadence).
	if cfg.ManifestURL != "" {
		// 2.21 — seed the domestic mirror ladder from the cached
		// last-known-good manifest FIRST, so the very first fetch of this
		// session already has the domestic CDN as a fallback. Without this
		// a cold start during an international cut wastes the whole 8 s
		// fetch timeout on a dead route before trying the one host that
		// still answers.
		s.seedMirrorsFromCache()
		s.refreshManifest()
	}
	if cfg.WSPath == "" && s.pathBase == "" {
		return nil, fmt.Errorf("set ws_path or manifest_url")
	}
	return s, nil
}

func (s *server) surgeryOn() bool { return surgeryEnabled(s.cfg) }

func (s *server) trackerFor(host string) *measure.Tracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.trackers[host]
	if !ok {
		t = measure.NewTracker()
		s.trackers[host] = t
	}
	return t
}

// manifestMirrorURL returns the same manifest path on another host (the
// domestic-CDN fronting relay). Scheme, path and token are preserved, so the
// HMAC the client verifies is bound to the same subscription token — a
// mirror can serve the manifest but can never forge one.
func manifestMirrorURL(manifestURL, host string) string {
	u, err := url.Parse(manifestURL)
	if err != nil || host == "" {
		return ""
	}
	return u.Scheme + "://" + host + u.Path
}

// manifestLadder is the fetch order for the signed manifest:
//
//  1. the configured manifest URL (the international route),
//  2. every last-known-good fronting host — the domestic CDN mirror of the
//     SAME path/token. Under net-e-melli the international URL is dead while
//     the domestic mirror still answers, so the client can keep receiving
//     fresh regime/pressure intelligence through the blackout instead of
//     falling back to static local state.
func (s *server) manifestLadder() []string {
	out := []string{}
	if s.cfg.ManifestURL != "" {
		out = append(out, s.cfg.ManifestURL)
	}
	for _, m := range s.lastGoodMirrors {
		if m != "" && m != s.cfg.ManifestURL {
			out = append(out, m)
		}
	}
	return out
}

// fetchManifestBody performs one HTTP GET of a manifest URL.
func fetchManifestBody(url string) ([]byte, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// refreshManifest fetches, verifies and applies the AXR manifest. It is the
// net-e-melli bootstrap path as much as the online path:
//
//	try each URL in the ladder (primary, then domestic mirrors)
//	-> on total failure, fall back to the persisted last-known-good copy
//	-> verify the HMAC of whichever body won
//	-> apply it, and persist it as the new last-known-good
//
// The last-known-good fallback is what makes a COLD START during an
// international cut work at all: without it the core would fall back to a
// bare `ws_path` and never learn the rotated path base, the domestic
// fronting relay, or the canary target — precisely the facts it needs to
// cross the blackout.
func (s *server) refreshManifest() {
	token := subTokenFromURL(s.cfg.ManifestURL)
	var body []byte
	var source string
	for _, u := range s.manifestLadder() {
		b, err := fetchManifestBody(u)
		if err != nil {
			s.log.logf("manifest fetch %s failed: %v", u, err)
			continue
		}
		body, source = b, u
		break
	}
	if body == nil {
		cached, src, err := loadLastGoodManifest(s.cfg.CacheDir)
		if err != nil {
			s.log.logf("manifest unreachable and no last-known-good copy (%v); running on config alone", err)
			return
		}
		body, source = cached, src+" (last-known-good)"
		s.log.logf("manifest unreachable: bootstrapping from the cached last-known-good copy (this is the net-e-melli path)")
	}
	var m manifestV3
	if err := json.Unmarshal(body, &m); err != nil {
		s.log.logf("manifest decode failed: %v", err)
		return
	}
	// 2.16 — manifest v3 integrity: verify the HMAC before trusting ANY
	// field. A tampered/altered manifest is rejected outright and the core
	// keeps its last-known-good state (already in memory; the last-good raw
	// JSON is persisted for audit). An absent signature (older worker)
	// degrades to unverified mode with a one-time note. The CACHED copy is
	// re-verified here too: a tampered cache file is exactly as untrusted as
	// a tampered network response.
	if valid, present := verifyManifestSig(&m, token); !valid {
		if present {
			s.log.logf("manifest REJECTED: manifest_sig mismatch from %s (keeping last-known-good state)", source)
			return
		}
		if !s.sigWarned {
			s.sigWarned = true
			s.log.logf("note: manifest carries no signature (pre-2.16 worker); running unverified")
		}
	}
	// A verified body becomes the new last-known-good, and its fronting host
	// becomes tomorrow's domestic mirror.
	if fromCache := strings.HasSuffix(source, "(last-known-good)"); !fromCache {
		if err := os.WriteFile(s.cfg.CacheDir+"/manifest-lastgood.json", body, 0o600); err != nil {
			s.log.logf("last-good manifest persist failed: %v", err)
		}
	}
	s.manifestBootstrap = source
	s.applyManifest(&m)
}

// seedMirrorsFromCache pre-loads the domestic manifest-mirror ladder from
// the persisted last-known-good manifest. The cached fronting hint is only
// used as a FETCH TARGET (its response is HMAC-verified before any field is
// applied), but it is still authenticated first: a cached copy that carries a
// signature which does not verify under this subscription token contributes
// nothing to the ladder. The cache is 0600 inside a 0700 directory, so this
// is defence in depth rather than the primary control.
func (s *server) seedMirrorsFromCache() {
	body, _, err := loadLastGoodManifest(s.cfg.CacheDir)
	if err != nil {
		return
	}
	var m manifestV3
	if json.Unmarshal(body, &m) != nil {
		return
	}
	if valid, present := verifyManifestSig(&m, subTokenFromURL(s.cfg.ManifestURL)); present && !valid {
		s.log.logf("cached manifest failed signature re-check; ignoring its fronting hint")
		return
	}
	if m.FrontingHint == "" {
		return
	}
	if mu := manifestMirrorURL(s.cfg.ManifestURL, m.FrontingHint); mu != "" {
		s.setMirrors([]string{mu})
		s.log.logf("domestic manifest mirror armed from cache: %s", mu)
	}
}

// loadLastGoodManifest reads the persisted last-known-good manifest body.
func loadLastGoodManifest(cacheDir string) ([]byte, string, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, "manifest-lastgood.json"))
	if err != nil {
		return nil, "", err
	}
	if len(data) == 0 {
		return nil, "", fmt.Errorf("cached manifest is empty")
	}
	return data, "manifest-lastgood.json", nil
}

// applyManifest applies a verified manifest to the running core. Every field
// is advisory: a malformed or out-of-range value is ignored rather than
// propagated, and the last-known-good state stays in force.
func (s *server) applyManifest(m *manifestV3) {
	if m.WSPathBase != "" {
		s.pathBase = m.WSPathBase
	}
	fp := m.Fingerprint.Current
	if fp == "" {
		fp = "chrome"
	}
	// 2.15 — clean IP hints (worker: env ∪ D1 harvest, validated there):
	// merge into every entry's IP set (dedup + cap, best effort).
	// AddEntry replaces the same (host, transport) row, so this is a clean
	// in-place IP-set upgrade.
	if len(m.CleanIPHints) > 0 {
		for _, ep := range s.failover.Entries() {
			merged := failover.HarvestedIPs(context.Background(),
				append(append([]string{}, ep.IPs...), m.CleanIPHints...), "", nil)
			up := ep
			up.IPs = merged
			s.failover.AddEntry(up)
		}
		s.log.logf("manifest applied %d clean IP hint(s)", len(m.CleanIPHints))
	}
	// 2.16 — domestic-CDN fronting hint: the same Worker deployed to a
	// domestic CDN domain. Merged as a high-priority backup (before
	// ordinary backups, after the primary config entries).
	if m.FrontingHint != "" && !s.hasEntry(m.FrontingHint) {
		for _, tr := range transportsPerEntry {
			s.failover.AddEntry(failover.Endpoint{Host: m.FrontingHint, Transport: tr, FP: fp, Priority: 50, Port: s.cfg.Port})
			s.bandit.AddArm(bandit.Arm{Host: m.FrontingHint, Transport: tr, FP: fp})
		}
		s.log.logf("manifest added fronting entry %s", m.FrontingHint)
	}
	// 2.17 — the fronting host is the netstate role tag: the net-e-melli
	// priority inversion is applied to it (fronting-first under stress).
	if m.FrontingHint != "" {
		s.frontingHost = m.FrontingHint
		// 2.21 — and it is the DOMESTIC MIRROR for the next manifest fetch:
		// the same path/token on the domestic CDN. During an international
		// cut this is the only channel that can still deliver fleet
		// intelligence, and it is HMAC-bound to the same subscription token,
		// so it can serve the manifest but cannot forge one.
		if mu := manifestMirrorURL(s.cfg.ManifestURL, m.FrontingHint); mu != "" {
			s.setMirrors([]string{mu})
		}
	}
	for _, e := range m.Entries {
		// role "canary" is a PROBE TARGET, never a tunnel arm: it is
		// consumed by the canary loop below, not the ladder.
		if e.Role == "backup" && !s.hasEntry(e.Host) {
			for _, tr := range transportsPerEntry {
				s.failover.AddEntry(failover.Endpoint{Host: e.Host, Transport: tr, FP: fp, Priority: 100, Port: s.cfg.Port})
				s.bandit.AddArm(bandit.Arm{Host: e.Host, Transport: tr, FP: fp})
			}
			s.log.logf("manifest added backup entry %s", e.Host)
		}
	}
	// 2.17 — fleet-pressure dynamics (the Worker's pressure engine):
	// faster aggressive probe cadence + an outflow-profile floor. Both are
	// advisory fleet intelligence; the client keeps its local regime driver
	// as the other input (Escalate takes the harsher one).
	if p := m.Reconnect.ProbeIntervalMS; p >= 15_000 && p <= 90_000 {
		s.probeInt[1] = time.Duration(p) * time.Millisecond
	}
	// 2.17 — probe de-synchronization: the manifest carries the uniform
	// offset WIDTH (wider under pressure); the client draws ITS OWN offset
	// deterministically from the UUID — stable across restarts, uniform in
	// [0, width], decorrelated across the fleet (phase-locked probing is
	// itself a fingerprint).
	//
	// 2.21 — the width is now ALSO re-drawn per probe round (see
	// probeInterval). A single fixed offset per client is a constant: a
	// classifier that has seen two probes can predict the third. Keeping
	// the UUID phase preserves the deterministic per-client component the
	// 2.17 design relies on for fleet decorrelation, while the per-round
	// draw removes the fixed-phase signature from any single client's
	// inter-arrival series.
	if j := m.Reconnect.ProbeJitterMS; j >= 0 && j <= 30_000 {
		w := time.Duration(j) * time.Millisecond
		h := fnv.New32a()
		_, _ = h.Write([]byte(s.cfg.UUID))
		s.probeJitterOffset = w * time.Duration(h.Sum32()%1024) / 1024
		s.probeJitterWidth = w
	}
	s.flowFloor = flowprofile.Rank(flowprofile.ProfileID(m.FlowProfile.Mode))
	// 2.17 — canary liveness target (authoritative source: the signed
	// entries field; this pointer is the convenience mirror).
	if m.Canary.Host != "" {
		s.canaryHost = m.Canary.Host
		if iv := m.Canary.IntervalMS; iv >= 60_000 && iv <= 3_600_000 {
			s.canaryInt = time.Duration(iv) * time.Millisecond
		}
		s.log.logf("manifest canary target: %s (every %v)", s.canaryHost, s.canaryInt)
	}
	s.log.logf("manifest loaded from %s (path_base=%s fp=%s sig=%v canary=%s fronting=%s)",
		s.manifestBootstrap, m.WSPathBase, fp, m.ManifestSig != "", s.canaryHost, s.frontingHost)
	// The regime policy is (re)applied after every manifest change: a
	// cold start that recovered its state from the cache must immediately
	// honour a persisted net-e-melli blackout instead of waiting for the
	// first probe round to re-derive it.
	s.applyPolicy()
}

// setMirrors replaces the domestic manifest-mirror ladder (deduped, capped).
func (s *server) setMirrors(urls []string) {
	seen := map[string]bool{}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if u == "" || seen[u] || len(out) >= 4 {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	s.lastGoodMirrors = out
}

func (s *server) hasEntry(host string) bool {
	for _, e := range s.failover.Entries() {
		if e.Host == host {
			return true
		}
	}
	return false
}

// mergeCleanIPsFile merges the local `axr scan` pool (clean-ips.json) into
// every entry's IP set. Pools older than 30 days are ignored (edge IPs
// churn; stale hints only add failing dials to the ladder).
func mergeCleanIPsFile(fo *failover.Engine, path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var f cleanIPsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return 0
	}
	if len(f.IPs) == 0 {
		return 0
	}
	if f.GeneratedAtMS > 0 && time.Since(time.UnixMilli(f.GeneratedAtMS)) > 30*24*time.Hour {
		return 0
	}
	added := 0
	for _, ep := range fo.Entries() {
		merged := failover.HarvestedIPs(context.Background(),
			append(append([]string{}, ep.IPs...), f.IPs...), "", nil)
		added = len(merged) - len(ep.IPs)
		up := ep
		up.IPs = merged
		fo.AddEntry(up)
	}
	return added
}

// upgradeShapeFor maps the 2.19 stance to the 2.20 WS upgrade header
// shape: steady = the light browser shape, cautious/aggressive = the
// full cross-site browser shape. Identity values (locale, user agent,
// page origin) are stable per client (UUID-derived); order/case jitter
// is per connection. nil (surgery off) keeps the classic request.
func (s *server) upgradeShapeFor(esc evade.Escalation) *vlessws.UpgradeShape {
	if !s.surgeryOn() {
		return nil
	}
	tpl := vlessws.UpgradeLite
	if esc.Stance == evade.StanceCautious || esc.Stance == evade.StanceAggressive {
		tpl = vlessws.UpgradeFull
	}
	return vlessws.NewUpgradeShape(s.rngFloat, tpl,
		vlessws.LocalePool[s.langIdx], vlessws.UAPool[s.uaIdx], vlessws.OriginPool[s.originIdx])
}

// fragParams returns the per-connection ClientHello surgery parameters:
// the randomized cut count, the split-write budget, cut window (SNI
// region), and micro-gap bounds. The operator's configured ranges are
// element-wise MAXED with the 2.19 governor's stance escalation: the
// governor can WIDEN the shape under stress, never narrow it (the steady
// stance is a pure no-op, so unconfigured behaviour is unchanged).
func (s *server) fragParams(esc evade.Escalation) (cuts, writes int, lo, hi float64, gapMin, gapMax time.Duration) {
	cuts, writes = 1, 1
	gapMin, gapMax = 20*time.Millisecond, 120*time.Millisecond
	if g := s.cfg.SplitGapMS; g[0] > 0 && g[1] > g[0] {
		gapMin, gapMax = time.Duration(g[0])*time.Millisecond, time.Duration(g[1])*time.Millisecond
	}
	fCuts := [2]int{max(s.cfg.FragCuts[0], esc.Cuts[0]), max(s.cfg.FragCuts[1], esc.Cuts[1])}
	fWrites := [2]int{max(s.cfg.FragWrites[0], esc.Writes[0]), max(s.cfg.FragWrites[1], esc.Writes[1])}
	fGap := [2]int{max(s.cfg.FragMicroGapMS[0], esc.MicroGapMS[0]), max(s.cfg.FragMicroGapMS[1], esc.MicroGapMS[1])}
	if fCuts[0] > 0 && fCuts[1] >= fCuts[0] {
		cuts = fCuts[0] + int(randFloat()*float64(fCuts[1]-fCuts[0]+1))
		// 2.17 — extend the fragmented shape past the ClientHello to the
		// next one or two client-flight writes (default [1,3] = 1-3 writes).
		writes = 1
		if fWrites[0] > 0 && fWrites[1] >= fWrites[0] {
			writes = fWrites[0] + int(randFloat()*float64(fWrites[1]-fWrites[0]+1))
			if writes > 5 {
				writes = 5
			}
		}
		gMin, gMax := 1, 8
		if fGap[0] > 0 && fGap[1] > fGap[0] {
			gMin, gMax = fGap[0], fGap[1]
		}
		gapMin, gapMax = time.Duration(gMin)*time.Millisecond, time.Duration(gMax)*time.Millisecond
	}
	wLo, wHi := 40, 90 // SNI extension region (percent of record)
	if w := s.cfg.FragWindow; w[0] > 0 && w[1] > w[0] {
		wLo, wHi = w[0], w[1]
	}
	return cuts, writes, float64(wLo) / 100, float64(wHi) / 100, gapMin, gapMax
}

// observeFrameSize records one outflow WS frame size into the shared
// histogram (feeds the flow-KL self-monitoring feature).
func (s *server) observeFrameSize(n int) {
	if n < 0 {
		return
	}
	s.frameMu.Lock()
	s.frameHist[flowprofile.BucketIndex(n)]++
	s.frameMu.Unlock()
}

// flowKLDiv is KL(empirical outflow || target profile) in nats, or 0 before
// enough frames have been observed to form a distribution.
func (s *server) flowKLDiv(profile flowprofile.ProfileID) float64 {
	s.frameMu.Lock()
	counts := append([]int{}, s.frameHist...)
	s.frameMu.Unlock()
	total := 0
	for _, c := range counts {
		total += c
	}
	if total < 64 { // not enough outflow to compare honestly
		return 0
	}
	emp := make([]float64, len(counts))
	for i, c := range counts {
		emp[i] = float64(c) / float64(total)
	}
	return flowprofile.KLDiv(emp, flowprofile.TargetBins(flowprofile.Get(profile)))
}

// entryChurn is the BGP-flap/anyshift proxy: 1 when the last two successful
// tunnels used different dial addresses (the route under our feet moved).
func (s *server) entryChurn() float64 {
	s.churnMu.Lock()
	defer s.churnMu.Unlock()
	if s.prevGoodDial != "" && s.lastGoodDial != "" && s.prevGoodDial != s.lastGoodDial {
		return 1
	}
	return 0
}

// noteGoodDial records a successful tunnel's dial address (churn feature).
func (s *server) noteGoodDial(addr string) {
	if addr == "" {
		return
	}
	s.churnMu.Lock()
	s.prevGoodDial = s.lastGoodDial
	s.lastGoodDial = addr
	s.churnMu.Unlock()
}

// wsPath is the full WebSocket request target. With a manifest, the token
// and sub path live in the manifest URL, so the WS path is derived from it:
//
//	https://host/sub/<token>/axr-manifest  ->  /sub/<token>/<pathbase>?ed=2048
func (s *server) wsPath() string {
	if s.cfg.WSPath != "" {
		return s.cfg.WSPath
	}
	if s.cfg.ManifestURL != "" && s.pathBase != "" {
		base := strings.TrimSuffix(s.cfg.ManifestURL, "/axr-manifest")
		if i := strings.Index(base, "://"); i >= 0 {
			if j := strings.Index(base[i+3:], "/"); j >= 0 {
				return base[i+3+j:] + "/" + s.pathBase + "?ed=2048"
			}
		}
	}
	return "/"
}

// wsPathFor returns the WS path for a transport shape. "ws-alt" is the same
// path over the worker's gz_profile=fragmented shape, giving the bandit a
// second path/query form to compare against the standard one.
func (s *server) wsPathFor(transport string) string {
	p := s.wsPath()
	if transport == "ws-alt" {
		sep := "?"
		if strings.Contains(p, "?") {
			sep = "&"
		}
		p += sep + "gz_profile=fragmented"
	}
	return p
}

// probeRedrawCap bounds the PER-ROUND de-synchronization component. The
// mandate band is "0 to 15 seconds" of dynamic, client-specific jitter: the
// stable FNV-32a phase may use the manifest's full width, but the fresh
// per-round draw is capped here so a wide width cannot stretch the aggressive
// cadence into uselessness.
const probeRedrawCap = 15 * time.Second

// probeInterval returns the sleep before the next probe round: the cadence in
// force (normal/aggressive) plus the de-synchronization budget.
//
//	|-- cadence --|-- FNV32a(UUID) phase --|-- fresh per-round draw --|
//
// The phase is the 2.17 per-client component: stable across restarts, so two
// clients never share a probe instant in expectation. The per-round draw is
// the 2.21 addition: a single fixed offset is a CONSTANT, and an adaptive
// classifier that observes a handful of probe instants can extrapolate the
// next one. Re-drawing inside the same width keeps each client's inter-arrival
// series unpredictable while preserving the fleet-level decorrelation the
// phase provides.
func (s *server) probeInterval() time.Duration {
	interval := s.probeInt[0]
	// 2.17 — netstate stress (degraded/cut) forces the aggressive
	// cadence too, not just the failover engine's own state.
	if s.failover.State() == failover.StateAggressive || s.netstate.IsStressed() {
		interval = s.probeInt[1]
	}
	interval += s.probeJitterOffset
	if w := s.probeJitterWidth; w > 0 {
		if w > probeRedrawCap {
			w = probeRedrawCap
		}
		interval += time.Duration(randFloat() * float64(w))
	}
	return interval
}

func (s *server) startProbes() {
	go func() {
		for {
			time.Sleep(s.probeInterval())
			healthy := s.failover.ProbeRound(time.Now())
			mode := s.failover.State()
			if len(healthy) == 0 {
				s.log.logf("probe round: no healthy candidate (mode=%s)", mode)
			} else {
				s.log.logf("probe round: %s via %s (mode=%s)", healthy[0].Endpoint.Host, healthy[0].DialAddr, mode)
			}
			_ = s.failover.SaveCache(s.cfg.CacheDir + "/routing.json")
		}
	}()
	// 2.17 — canary liveness loop. The manifest's canary host is probed as a
	// PLAIN TLS liveness check (not tunneled, not morphed — it measures the
	// route, not the tunnel); the outcome feeds the netstate hysteresis and
	// is reported to the fleet pressure engine via the harvest endpoint.
	// The host is set during manifest bootstrap (before this starts), so the
	// read is race-free by construction.
	if s.canaryHost != "" {
		go func() {
			ticker := time.NewTicker(s.canaryInt)
			defer ticker.Stop()
			for range ticker.C {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				okC, rtt := canaryProbe(ctx, s.canaryHost, s.cfg.Port)
				cancel()
				s.netstate.Record(netstate.Observation{Role: netstate.RoleCanary, OK: okC, At: time.Now()})
				s.applyPolicy()
				s.log.logf("canary probe %s: %s (rtt=%.0fms)", s.canaryHost, map[bool]string{true: "ok", false: "FAIL"}[okC], rtt)
				if err := postCanary(s.cfg, s.canaryHost, okC); err != nil {
					s.log.logf("canary report failed: %v", err)
				}
			}
		}()
	}
}

// canaryProbe is a plain TCP+TLS liveness check of host:port (SNI = host,
// real certificate verification, TLS >= 1.2; port 0 → 443). It measures
// reachability from THIS network with the OS's own identity — deliberately
// un-morphed, so the signal is about the route, not about our tunnel shape.
func canaryProbe(ctx context.Context, host string, port int) (bool, float64) {
	if port <= 0 || port > 65535 {
		port = 443
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, 0
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	herr := tlsConn.HandshakeContext(ctx)
	rtt := time.Since(start).Seconds() * 1000
	if herr != nil {
		_ = tlsConn.Close()
		return false, 0
	}
	_ = tlsConn.Close()
	return true, rtt
}

func (s *server) shutdown() {
	_ = s.bandit.Save(s.cfg.CacheDir + "/bandit.json")
	_ = s.failover.SaveCache(s.cfg.CacheDir + "/routing.json")
	s.warmMu.Lock()
	if s.warm != nil {
		_ = s.warm.ws.Close()
		s.warm = nil
	}
	s.warmMu.Unlock()
}

// ---- SOCKS5 (TCP only; UDP rejected by design — no UDP relay) ----

func (s *server) serveSOCKS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleSOCKS(conn)
	}
}

func (s *server) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	// Greeting: [ver=5][nmethods][methods...]
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if !containsByte(methods, 0x00) {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// Request: [ver][cmd][rsv][atyp][addr...][port:2]
	var rq [4]byte
	if _, err := io.ReadFull(conn, rq[:]); err != nil {
		return
	}
	cmd, atyp := rq[1], rq[3]
	host, err := readSocksAddr(conn, atyp)
	if err != nil {
		socksReply(conn, 0x04) // host unreachable
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return
	}
	dstPort := int(port[0])<<8 | int(port[1])

	if cmd != 0x01 {
		socksReply(conn, 0x07) // command not supported (CONNECT only)
		return
	}
	// RFC 1928 §6: the REPLY is the result of the CONNECT, so it is sent when
	// the upstream tunnel is established — not before. Replying 0x00 first
	// makes every application see a successful connect and then a silent EOF
	// when no candidate works (curl reports "empty reply" instead of a
	// connection failure, and retry logic never triggers). The reply is
	// emitted by openTunnel exactly once: 0x00 on success, 0x05 (connection
	// refused) when every candidate failed.
	s.openTunnel(conn, host, dstPort, func(code byte) { socksReply(conn, code) })
}

func readSocksAddr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", err
		}
		return net.IPv4(b[0], b[1], b[2], b[3]).String(), nil
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, d); err != nil {
			return "", err
		}
		return string(d), nil
	case 0x04: // IPv6
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", err
		}
		return net.IP(b[:]).String(), nil
	default:
		return "", fmt.Errorf("unsupported atyp %d", atyp)
	}
}

func containsByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

func socksReply(conn net.Conn, code byte) {
	_, _ = conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// ---- tunnel ----

// banditContext maps the measured state vector to the LinUCB context.
// The 2.16 v3 extensions (throughput, loss velocity, TLS error rate, entry
// churn, flow KL, session age) come from the server's local measurements;
// time-of-day and regime ordinal are derived by features() itself. The
// regime is the WORSE of the measured delivery regime and the 2.17
// netstate route regime (net-e-melli hysteresis).
func (s *server) banditContext(v measure.Vector, now int64, profile flowprofile.ProfileID) bandit.Context {
	anom := 0.0
	if v.LastAnomaly != 0 {
		anom = 1
	}
	return bandit.Context{
		Regime:           s.mergedRegime(v.Regime),
		WeakestTransport: v.WeakestTransport,
		NowMS:            now,
		RTTMS:            v.RTTMS,
		JitterMS:         v.JitterMS,
		RSTRate:          v.RSTRate,
		TLSDrop:          v.TimeoutRate,
		LossStep:         v.StepDelta,
		HTTPAnom:         anom,
		ThroughputBPS:    v.ThroughputBPS,
		LossVel:          v.LossVel,
		TLSErrRate:       v.TLSErrRate,
		EntryChurn:       s.entryChurn(),
		FlowKLDiv:        s.flowKLDiv(profile),
		SessionAgeH:      time.Since(s.startedAt).Hours(),
	}
}

// openTunnel picks a bandit arm, walks the failover candidates for it,
// establishes one VLESS-WS tunnel (or adopts a warm one), pumps traffic,
// and feeds every learner.
//
// reply is the SOCKS5 CONNECT reply hook. It is called EXACTLY once: with
// 0x00 as soon as a tunnel carries (including a re-used warm session), or
// 0x05 when every candidate failed. Until it is called the application is
// still waiting for its CONNECT result, so nothing is consumed from it.
func (s *server) openTunnel(client net.Conn, host string, port int, reply func(byte)) {
	l := s.log
	uuidBytes, _ := vlessws.UUIDFromString(s.cfg.UUID)
	header, err := vlessws.BuildVLESSHeader(uuidBytes, host, uint16(port), false)
	if err != nil {
		l.logf("vless header: %v", err)
		reply(0x01) // general SOCKS server failure
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	now := time.Now()
	vec := s.globalVector()
	// 2.17 — merged regime (measured ∪ netstate route regime) drives the
	// local profile, and the manifest's fleet-pressure floor can only
	// ESCALATE it (Escalate = harsher wins).
	regime := s.mergedRegime(vec.Regime)
	profile := flowprofile.ForRegime(regime)
	profile = flowprofile.Escalate(profile, flowprofile.ProfileByRank(s.flowFloor))
	// 2.19 — adaptive evasion governor: local evidence (route regime,
	// measured delivery, failover stress) picks the bounded shape
	// escalation for this connection setup; its flow floor sits on top
	// of the fleet floor (escalate = harsher wins).
	esc := s.gov.Update(evade.Evidence{
		Regime:   s.netstate.Regime(),
		Measure:  vec,
		FailAggr: s.failover.State() == failover.StateAggressive,
	})
	profile = flowprofile.Escalate(profile, flowprofile.ProfileByRank(esc.FlowRank))
	bctx := s.banditContext(vec, now.UnixMilli(), profile)

	// 2.15 — session reuse: adopt the previous tunnel for the SAME
	// destination if it is still open and within warmTTL. No new dial/TLS/
	// handshake — the stream just continues. A stale session is discarded on
	// the first pump error and we fall through to a fresh dial.
	if w := s.takeWarm(host, port); w != nil {
		l.logf("adopting warm session for %s:%d (age %v)", host, port, time.Since(time.UnixMilli(w.endedAt)))
		// The adopted session is already past its handshake and its VLESS
		// OK, so the CONNECT is successful the moment we take it.
		reply(0x00)
		meta := warmMeta{arm: w.arm, profile: w.profile, dstHost: host, dstPort: port}
		pr := s.pumpTunnel(w.ws, client, true, meta)
		if pr.clean {
			client.Close()
			s.logDecision(decisionRec{
				Ts: now.UnixMilli(), Regime: regime, FlowProfile: string(w.profile),
				Ctx: bctx, Arm: w.arm, Warm: true,
				OK: true, Reason: "warm", DialAddr: "",
			})
			if l.verbose {
				l.logf("tunnel OK %s:%d via warm session", host, port)
			}
			return
		}
		// Stale warm session: the client is still open (pumpTunnel never
		// closes it), so a fresh dial below reuses it as-is.
		l.logf("warm session stale (%s); dialing fresh", pr.reason)
	}

	// Ask the bandit for the best arm under the current context (LinUCB).
	arm, scores, err := s.bandit.Select(bctx)
	if err != nil {
		l.logf("no selectable arm: %v", err)
		return
	}
	if l.verbose {
		for _, sc := range scores {
			if !sc.Pruned {
				l.logf("score %s mean=%.2f ucb=%.2f div=%+.2f tot=%.2f q=%v",
					sc.Arm.ID(), sc.Mean, sc.Ucb, sc.Diversity, sc.Total, sc.Quarantined)
			}
		}
	}

	// One score table for the failover ordering (quarantined arms sink;
	// the LinUCB total — not the raw mean — is the learned ranking).
	scoreMap := make(map[string]float64, len(scores))
	for _, sc := range scores {
		if sc.Quarantined {
			scoreMap[sc.Arm.ID()] = -1
		} else {
			scoreMap[sc.Arm.ID()] = sc.Total
		}
	}
	order := s.failover.FailoverOrder(func(a failover.Arm) float64 {
		if v, ok := scoreMap[a.Host+"|"+a.Transport+"|"+a.FP]; ok {
			return v
		}
		return -1
	})
	// Prefer the chosen arm's host; fall back to the global order.
	var cands []failover.Candidate
	for _, c := range order {
		if c.Endpoint.Host == arm.Host {
			cands = append(cands, c)
		}
	}
	if len(cands) == 0 {
		cands = order
	}

	var last tunnelResult
	var tried []string
	replied := false
	for _, cand := range cands {
		tag := cand.Endpoint.Host + "/" + cand.DialAddr + "[" + cand.Endpoint.Transport + "]"
		tried = append(tried, tag)
		// replyOnce is handed to every attempt; only the first call wins, so
		// a candidate that reaches VLESS-OK emits the SOCKS5 success exactly
		// once even if a later one is tried after a stream-level failure.
		res := s.attemptTunnel(ctx, client, cand, header, profile, esc, host, port, func(code byte) {
			if !replied {
				replied = true
				reply(code)
			}
		})
		last = res
		if res.ok {
			break
		}
		l.logf("attempt %s failed: %s", tag, res.reason)
	}
	if last.reason == "" {
		last = tunnelResult{reason: "no_candidates"}
	}
	if !replied {
		// Nothing carried: tell the application the truth (RFC 1928 §6,
		// REP=0x05 connection refused) instead of closing a "successful"
		// connection with no data.
		reply(0x05)
	}

	// Credit the arm that actually carried (or last tried) the tunnel —
	// under ws-alt the chosen candidate's transport can differ from the
	// bandit's top pick after a host-level failover.
	usedArm := arm
	if last.entry.Host != "" {
		usedArm = bandit.Arm{Host: last.entry.Host, Transport: last.entry.Transport, FP: last.entry.FP}
	}
	s.bandit.Observe(usedArm, bandit.Outcome{
		OK:         last.ok,
		RTTMS:      last.rttMS,
		Throughput: last.through,
		Reason:     last.reason,
	}, bctx, time.Now().UnixMilli())
	if last.entry.Host != "" {
		s.trackerFor(last.entry.Host).Feed(measure.Sample{
			OK:         last.ok,
			RTTMS:      last.rttMS,
			Throughput: last.through,
			ErrClass:   classErr(last.reason),
			Transport:  last.entry.Transport,
			UnixMS:     time.Now().UnixMilli(),
		})
		if last.ok {
			s.noteGoodDial(last.dialAddr) // entry-churn (flap proxy) feature
		}
		s.failover.Observe(last.entry, last.dialAddr, last.ok, last.rttMS, last.reason, time.Now())
		_ = s.failover.SaveCache(s.cfg.CacheDir + "/routing.json")
		// 2.17 — feed the route-regime hysteresis (net-e-melli detection)
		// and apply its priority policy to the failover ladder.
		s.netstate.Record(netstate.Observation{
			Role: s.roleOf(last.entry.Host), OK: last.ok, At: time.Now(),
		})
		s.applyPolicy()
		// 2.19 — feed the governor's per-stance posterior with the
		// result of the connection that used that stance.
		s.gov.Outcome(esc.Stance, last.ok)
	}
	_ = s.bandit.Save(s.cfg.CacheDir + "/bandit.json")

	// 2.17 — which ensemble member chose the arm (audit trail).
	model := ""
	for _, sc := range scores {
		if sc.Arm.ID() == arm.ID() {
			model = sc.Model
			break
		}
	}
	s.logDecision(decisionRec{
		Ts: now.UnixMilli(), Regime: regime, FlowProfile: string(profile),
		Ctx: bctx, Arm: arm, Scores: scores, Tries: tried, Model: model,
		OK: last.ok, RTTMS: last.rttMS, Through: last.through,
		Reason: last.reason, DialAddr: last.dialAddr,
	})

	if l.verbose {
		l.logf("tunnel %s %s:%d via %s (rtt=%.0fms %s profile=%s)",
			map[bool]string{true: "OK", false: "FAIL"}[last.ok], host, port, last.dialAddr, last.rttMS, last.reason, profile)
	}
}

// tunnelResult carries the outcome of one candidate attempt.
type tunnelResult struct {
	ok       bool
	rttMS    float64
	through  float64
	reason   string
	entry    failover.Endpoint
	dialAddr string
}

// attemptTunnel dials one candidate, performs the full VLESS-WS handshake
// (with surgery), and hands the open tunnel to pumpTunnel. dstHost/dstPort
// are the SOCKS destination (label the warm session for reuse).
func (s *server) attemptTunnel(ctx context.Context, client net.Conn, cand failover.Candidate, header []byte, profile flowprofile.ProfileID, esc evade.Escalation, dstHost string, dstPort int, reply func(byte)) tunnelResult {
	res := tunnelResult{entry: cand.Endpoint, dialAddr: cand.DialAddr}
	start := time.Now()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", cand.DialAddr)
	if err != nil {
		res.reason = "dial:" + err.Error()
		return res
	}
	// 2.15 — TCP socket surgery: Nagle off + randomized SO_SNDBUF.
	_ = sockopt.Apply(raw, sockopt.Options{Rng: newSockRand(), NoNagle: true})

	inner := raw
	if s.surgeryOn() {
		// 2.16/2.17 — multi-segment ClientHello surgery (fragA/fragB style):
		// randomized 1-3 cuts in the SNI region, 1-8 ms SKEWED micro-gaps,
		// extended (2.17) across the first 1-3 client-flight writes.
		cuts, writes, lo, hi, gapMin, gapMax := s.fragParams(esc)
		inner = surgery.NewMultiSplitConnV2(raw, cuts, writes, lo, hi, gapMin, gapMax, s.rngFloat)
	}
	surg := s.surgeryOn()
	var frag *vlessws.Fragmenter
	var upgrade *vlessws.UpgradeShape
	if surg {
		// 2.18/2.19 — WS frame-rhythm fragmentation: each binary message
		// rides as 2-6 masked continuation frames with randomized sizes
		// and skewed micro-gaps (Worker reassembles natively); the
		// governor tunes the rhythm bounds per stance.
		frag = vlessws.NewFragmenterWith(s.rngFloat, esc.WSMinB, esc.WSMaxB, esc.WSCount, time.Duration(esc.WSGapMS)*time.Millisecond)
		// 2.20 — the governor's stance also picks the WS upgrade
		// header shape (steady = light, cautious/aggressive = full
		// browser shape) with the stable per-client identity.
		upgrade = s.upgradeShapeFor(esc)
	}
	ws, err := vlessws.DialConn(ctx, inner, vlessws.DialOptions{
		Host:       cand.Endpoint.Host,
		Port:       cand.Endpoint.Port,
		Path:       s.wsPathFor(cand.Endpoint.Transport),
		FP:         cand.Endpoint.FP,
		SkipCert:   s.cfg.InsecureSkipVerify,
		EarlyData:  header, // 0-RTT: VLESS header rides the upgrade
		Fragmenter: frag,
		Upgrade:    upgrade,
		AfterTLS: func(c net.Conn) net.Conn {
			if surg {
				// 2.15 — app-class flow morphing (length histogram + IPD).
				return surgery.NewChunkConnWith(c, flowprofile.NewSlicer(profile, s.rngFloat))
			}
			return c
		},
	})
	if err != nil {
		raw.Close()
		res.reason = "ws:" + err.Error()
		return res
	}
	// The VLESS header travelled as 0-RTT early data in the upgrade, so the
	// Worker already has it — do NOT resend. Wait for the 2-byte OK, but
	// bounded: DialConn cleared the handshake deadline, so without an
	// explicit one a silent edge hangs this CONNECT forever instead of
	// letting the ladder move to the next candidate.
	if err := ws.WaitVLESSOKUntil(time.Now().Add(s.timeout)); err != nil {
		ws.Close()
		res.reason = "vless-ok:" + err.Error()
		return res
	}
	res.rttMS = time.Since(start).Seconds() * 1000
	// The upstream stream is live end-to-end (Worker connected to the
	// destination and answered VLESS 0x00): THIS is the moment the SOCKS5
	// CONNECT succeeded, and the only correct moment to say so.
	reply(0x00)

	// Pump both directions; a clean local close may keep the session warm.
	// A fresh tunnel is established (ok) once the handshake succeeded — the
	// bandit's measurable signal is dial+handshake quality, not stream length.
	meta := warmMeta{
		arm:     bandit.Arm{Host: cand.Endpoint.Host, Transport: cand.Endpoint.Transport, FP: cand.Endpoint.FP},
		profile: profile, dstHost: dstHost, dstPort: dstPort,
	}
	pr := s.pumpTunnel(ws, client, true, meta)
	client.Close()
	res.ok = true
	res.reason = "ok"
	res.through = pr.through // 2.16 — measured bytes/sec of the stream
	return res
}

// warmMeta labels a warm session with the tunnel's identity so a later
// adoption can credit the right arm and re-serve the same destination.
type warmMeta struct {
	arm     bandit.Arm
	profile flowprofile.ProfileID
	dstHost string
	dstPort int
}

// pumpResult is the outcome of a two-direction pump.
type pumpResult struct {
	clean   bool    // ended without a transport error (clean local EOF or clean close)
	reason  string  // "" when clean, else the error text
	through float64 // 2.16 — measured average bytes/sec (0 for warm-kept streams)
}

// pumpTunnel moves data both directions over an open WS tunnel until one side
// closes. Contract: the caller owns the local client conn (pumpTunnel never
// closes it); the WS is closed by the pump unless the ending is a clean local
// close and allowWarm, in which case the session is kept warm for
// same-destination reuse. A fresh tunnel is considered established (ok) once
// the handshake succeeded — however the stream then ends. A warm session is
// only good when clean; a stale one is reported clean=false so the caller can
// dial fresh on the (still open) client.
func (s *server) pumpTunnel(ws *vlessws.Client, client net.Conn, allowWarm bool, meta warmMeta) pumpResult {
	done := make(chan struct{}, 2)
	var wg sync.WaitGroup
	var firstMu sync.Mutex
	var firstCleanLocal bool
	var firstErr error
	announce := func(cleanLocal bool, err error) {
		firstMu.Lock()
		defer firstMu.Unlock()
		if firstErr == nil && !firstCleanLocal {
			firstCleanLocal = cleanLocal
			firstErr = err
		}
	}
	// 2.16 — throughput + outflow shape accounting. Each counter is written
	// by exactly one goroutine and read only after wg.Wait().
	var upBytes, downBytes int64
	start := time.Now()
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := client.Read(buf)
			if n > 0 {
				s.observeFrameSize(n) // flow-KL self-monitoring histogram
				upBytes += int64(n)
				if serr := ws.SendBinary(buf[:n]); serr != nil {
					announce(false, serr)
					break
				}
			}
			if rerr != nil {
				announce(errors.Is(rerr, io.EOF), rerr)
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		defer wg.Done()
		for {
			msg, rerr := ws.RecvBinary()
			if len(msg) > 0 {
				downBytes += int64(len(msg))
				if _, werr := client.Write(msg); werr != nil {
					announce(false, werr)
					break
				}
			}
			if rerr != nil {
				announce(false, rerr)
				break
			}
		}
		done <- struct{}{}
	}()
	<-done // first side finished

	firstMu.Lock()
	cleanLocal := firstCleanLocal
	pumpErr := firstErr
	firstMu.Unlock()

	if cleanLocal && allowWarm {
		// The local app closed its side; the WS may still be healthy. Nudge
		// the remote pump out of its blocking read with a short deadline,
		// clear it, and keep the session warm for same-destination reuse.
		// The caller closes the (already EOF'd) client conn.
		_ = ws.Conn().SetReadDeadline(time.Now().Add(2 * time.Second))
		wg.Wait()
		_ = ws.Conn().SetReadDeadline(time.Time{})
		s.keepWarm(ws, meta)
		// The stream is still open (adoptable): no final throughput number
		// yet — an adoption re-serves it and accounts separately.
		return pumpResult{clean: true}
	}

	// Any other ending: tear the WS down (client is the caller's to close).
	ws.Close()
	wg.Wait()
	through := 0.0
	if elapsed := time.Since(start).Seconds(); elapsed > 0 {
		through = float64(upBytes+downBytes) / elapsed
	}
	if pumpErr != nil {
		return pumpResult{clean: false, reason: firstReason(pumpErr.Error()), through: through}
	}
	return pumpResult{clean: true, through: through}
}

func firstReason(r string) string {
	if i := strings.IndexByte(r, '\n'); i > 0 {
		return r[:i]
	}
	if len(r) > 96 {
		return r[:96]
	}
	return r
}

// ---- warm session (2.15 session reuse) ----

// keepWarm stores an open, finished tunnel for same-destination adoption.
// Only one warm session is kept; a previous one is closed.
func (s *server) keepWarm(ws *vlessws.Client, meta warmMeta) {
	s.warmMu.Lock()
	defer s.warmMu.Unlock()
	old := s.warm
	s.warm = nil
	if old != nil {
		_ = old.ws.Close()
	}
	s.warm = &warmSession{
		ws: ws, arm: meta.arm, profile: meta.profile,
		dstHost: meta.dstHost, dstPort: meta.dstPort,
		endedAt: time.Now().UnixMilli(),
	}
	go func() {
		time.Sleep(warmTTL)
		s.warmMu.Lock()
		if s.warm != nil && s.warm.ws == ws {
			_ = ws.Close()
			s.warm = nil
		}
		s.warmMu.Unlock()
	}()
}

func (s *server) takeWarm(host string, port int) *warmSession {
	s.warmMu.Lock()
	defer s.warmMu.Unlock()
	w := s.warm
	s.warm = nil
	if w == nil {
		return nil
	}
	if w.dstHost != host || w.dstPort != port ||
		time.Since(time.UnixMilli(w.endedAt)) > warmTTL {
		_ = w.ws.Close()
		return nil
	}
	return w
}

func (s *server) rngFloat() float64 {
	// crypto/rand is overkill for offsets; a locked math/rand keeps it simple.
	return randFloat()
}

func (s *server) globalVector() measure.Vector {
	s.mu.Lock()
	keys := make([]string, 0, len(s.trackers))
	for k := range s.trackers {
		keys = append(keys, k)
	}
	s.mu.Unlock()
	agg := measure.Vector{Regime: "stable"}
	for _, k := range keys {
		v := s.trackerFor(k).Vector()
		if worseRegime(v.Regime, agg.Regime) {
			agg = v
		}
	}
	return agg
}

// regimeRank ranks EVERY regime label the context can carry — the measure
// package's delivery labels and the netstate route labels (2.17); higher =
// worse. Unknown labels rank 0 (they are not evidence of trouble).
func regimeRank(label string) int {
	switch label {
	case "cut":
		return 3
	// "netemelli" is the declared national-intranet window: as severe as
	// degraded for the ladder and the bandit (the international class is
	// down), but with its own priority table and the blackout-quiet gate.
	case "degraded", "suspected_change", "netemelli":
		return 2
	case "watch", "recovering":
		return 1
	default: // stable, unknown
		return 0
	}
}

func worseRegime(a, b string) bool { return regimeRank(a) > regimeRank(b) }

// mergedRegime returns the worse of the measured delivery regime and the
// netstate route regime (the net-e-melli hysteresis label).
func (s *server) mergedRegime(measured string) string {
	if nr := s.netstate.Regime(); regimeRank(nr.Label()) > regimeRank(measured) {
		return nr.Label()
	}
	return measured
}

// roleOf tags an entry host with its netstate observation role: the
// manifest's fronting hint is RoleFronting, everything else (config +
// manifest backups) is RolePrimary. Canary probes record RoleCanary from
// the canary loop.
func (s *server) roleOf(host string) netstate.Role {
	if host == s.frontingHost {
		return netstate.RoleFronting
	}
	return netstate.RolePrimary
}

// applyPolicy applies the current netstate regime's priority policy to the
// failover ladder (lower = preferred) when the regime changed. This is the
// net-e-melli reflex: under degraded/cut the domestic fronting entry jumps
// ahead of the international entries instead of waiting for the bandit to
// quarantine them one by one.
func (s *server) applyPolicy() {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	r := s.netstate.Regime()
	if r == s.lastRegime {
		return
	}
	previous := s.lastRegime
	s.lastRegime = r
	pol := r.Policy()
	if previous == netstate.RegimeNetEMelli && r != netstate.RegimeNetEMelli && r != netstate.RegimeCut {
		// A fresh live canary ended the domestic-only classification. Old
		// blackout quiet deadlines would otherwise keep primary paths out of
		// the probe ladder even after the policy had relaxed.
		s.failover.ClearQuiet()
	}
	for _, ep := range s.failover.Entries() {
		p := pol.Backup
		switch {
		case ep.Host == s.frontingHost:
			p = pol.Fronting
		case s.configHosts[ep.Host]:
			p = pol.Primary
		}
		if p != ep.Priority {
			up := ep
			up.Priority = p
			s.failover.AddEntry(up)
		}
	}
	// 2.21 — blackout-quiet gate. The regime decides the WIDTH of the
	// per-dial-address quiet window; the failover engine decides WHEN an
	// address goes quiet (3 consecutive failures) and a success always
	// clears it. During a declared net-e-melli window the international
	// classes are known-dead, so re-dialing them only produces a dense,
	// fleet-synchronised burst of failed TLS handshakes — the width grows
	// and the ladder keeps probing a single candidate per round instead.
	qp := failover.DefaultQuietPolicy()
	if pol.QuietPrimary || pol.QuietBackup {
		qp = failover.QuietPolicy{BaseMS: 120_000, MaxMS: 30 * 60_000}
	}
	s.failover.SetQuietPolicy(qp)
	q := s.failover.Quiet()
	s.log.logf("netstate regime -> %s (priority: fronting=%d primary=%d backup=%d, aggressive=%v quiet=%v %d/%d)",
		r.Label(), pol.Fronting, pol.Primary, pol.Backup, pol.Aggressive,
		q.Enabled, q.Quiet, q.Total)
}

func classErr(reason string) string {
	switch {
	case strings.Contains(reason, "timeout"):
		return measure.ErrTimeout
	case strings.Contains(reason, "reset"):
		return measure.ErrRST
	case strings.Contains(reason, "tls"):
		return measure.ErrTLS
	default:
		return measure.ErrAnomaly
	}
}

// ---- shared random source (surgery offsets/gaps) ----

var (
	rngMu sync.Mutex
	rng   = newLockedRand()
)

// newSockRand returns a per-connection rand source for socket-option picks
// (SO_SNDBUF). Cheap to build; not shared so concurrent tunnels don't fight
// over one lock for a one-shot draw.
func newSockRand() *mrand.Rand {
	n, _ := crand.Int(crand.Reader, big.NewInt(1<<62))
	return mrand.New(mrand.NewSource(n.Int64()))
}

type lockedRand struct{ r *mrand.Rand }

func newLockedRand() *lockedRand {
	// Seed once from crypto/rand so offsets/gaps are unpredictable.
	n, _ := crand.Int(crand.Reader, big.NewInt(1<<62))
	return &lockedRand{r: mrand.New(mrand.NewSource(n.Int64()))}
}

func randFloat() float64 {
	rngMu.Lock()
	defer rngMu.Unlock()
	return rng.r.Float64()
}

// ---- config ----

func loadConfig(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if len(cfg.Entries) == 0 {
		return cfg, fmt.Errorf("entries is empty")
	}
	return cfg, nil
}

// ---- decision audit log (2.15) ----

// decisionRec is one JSON line appended to ~/.axr/decision.jsonl: the full
// transparent trace of a tunnel decision — the context that was measured,
// the arm the LinUCB picked, the score table, the candidates tried, and the
// outcome. Best-effort: logging must never break a tunnel.
type decisionRec struct {
	Ts          int64          `json:"ts"`
	Regime      string         `json:"regime"`
	FlowProfile string         `json:"flow_profile"`
	Ctx         bandit.Context `json:"ctx"`
	Arm         bandit.Arm     `json:"arm"`
	Warm        bool           `json:"warm,omitempty"`
	Model       string         `json:"model,omitempty"` // 2.17 — ensemble member that chose the arm
	Scores      []bandit.Score `json:"scores,omitempty"`
	Tries       []string       `json:"tries,omitempty"`
	OK          bool           `json:"ok"`
	RTTMS       float64        `json:"rtt_ms"`
	Through     float64        `json:"through"`
	Reason      string         `json:"reason"`
	DialAddr    string         `json:"dial_addr,omitempty"`
}

// logDecision appends rec to the audit log, rotating once the file passes
// ~4MB (to decision.jsonl.old). All errors are swallowed by design.
func (s *server) logDecision(rec decisionRec) {
	path := filepath.Join(s.cfg.CacheDir, "decision.jsonl")
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if st, err := os.Stat(path); err == nil && st.Size() > 4<<20 {
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}

// ---- logging ----

type logger struct{ verbose bool }

func newLogger(v bool) *logger { return &logger{verbose: v} }

func (l *logger) logf(format string, args ...any) {
	if l.verbose {
		log.Printf("axr: "+format, args...)
	}
}

func fatalf(format string, args ...any) {
	log.Printf("axr: "+format, args...)
	os.Exit(1)
}
