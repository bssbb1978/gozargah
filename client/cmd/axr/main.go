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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bssbb1978/gozargah/axr/internal/bandit"
	"github.com/bssbb1978/gozargah/axr/internal/failover"
	"github.com/bssbb1978/gozargah/axr/internal/flowprofile"
	"github.com/bssbb1978/gozargah/axr/internal/measure"
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
}

// Entry is one candidate entry path.
type Entry struct {
	Host     string   `json:"host"`
	IPs      []string `json:"ips,omitempty"` // explicit clean edge IPs
	FP       string   `json:"fp,omitempty"`  // chrome|firefox|safari|randomized
	Priority int      `json:"priority,omitempty"`
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
	pathBase string                       // rotated ws path base from the manifest
	probeInt [2]time.Duration             // [normal, aggressive]

	// 2.16 — AXR-v3 state.
	startedAt time.Time // session-age feature
	sigWarned bool      // one-time "manifest unverified" note

	// churnMu guards the last-good dial-address pair (entry-churn feature).
	churnMu      sync.Mutex
	prevGoodDial string
	lastGoodDial string

	// frameMu guards the outflow frame-size histogram (flow-KL feature).
	frameMu  sync.Mutex
	frameHist []int // counts per flowprofile.FrameBucketEdges bucket

	warmMu sync.Mutex
	warm   *warmSession
}

func surgeryEnabled(cfg Config) bool { return cfg.Surgery == nil || *cfg.Surgery }

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
	if cfg.CacheDir == "" {
		home, _ := os.UserHomeDir()
		cfg.CacheDir = home + "/.axr"
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("cache dir: %v", err)
	}

	// Bandit arms: one arm per entry per transport shape (ws + ws-alt) with
	// its fingerprint. ws-alt is the same host over the gz_profile=fragmented
	// path/query shape, giving the bandit a second shape to compare.
	var arms []bandit.Arm
	foEntries := make([]failover.Endpoint, 0, len(cfg.Entries)*len(transportsPerEntry))
	for _, e := range cfg.Entries {
		fp := e.FP
		if fp == "" {
			fp = "chrome"
		}
		for _, tr := range transportsPerEntry {
			arms = append(arms, bandit.Arm{Host: e.Host, Transport: tr, FP: fp})
			foEntries = append(foEntries, failover.Endpoint{
				Host: e.Host, IPs: e.IPs, Transport: tr, FP: fp, Priority: e.Priority,
			})
		}
	}
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

	s := &server{
		cfg:       cfg,
		log:       l,
		timeout:   timeout,
		bandit:    b,
		failover:  fo,
		trackers:  make(map[string]*measure.Tracker),
		probeInt:  [2]time.Duration{90 * time.Second, 30 * time.Second},
		startedAt: time.Now(),
		frameHist: make([]int, len(flowprofile.FrameBucketEdges)-1),
	}
	if p := cfg.Probes; p.NormalMS > 0 {
		s.probeInt[0] = time.Duration(p.NormalMS) * time.Millisecond
	}
	if p := cfg.Probes; p.AggressiveMS > 0 {
		s.probeInt[1] = time.Duration(p.AggressiveMS) * time.Millisecond
	}
	// Best-effort manifest bootstrap (path base, backup entries, cadence).
	if cfg.ManifestURL != "" {
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

func (s *server) refreshManifest() {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(s.cfg.ManifestURL)
	if err != nil {
		s.log.logf("manifest fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		s.log.logf("manifest HTTP %d", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		s.log.logf("manifest read failed: %v", err)
		return
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
	// degrades to unverified mode with a one-time note.
	if valid, present := verifyManifestSig(&m, subTokenFromURL(s.cfg.ManifestURL)); !valid {
		if present {
			s.log.logf("manifest REJECTED: manifest_sig mismatch (keeping last-known-good state)")
			return
		}
		if !s.sigWarned {
			s.sigWarned = true
			s.log.logf("note: manifest carries no signature (pre-2.16 worker); running unverified")
		}
	}
	if err := os.WriteFile(s.cfg.CacheDir+"/manifest-lastgood.json", body, 0o600); err != nil {
		s.log.logf("last-good manifest persist failed: %v", err)
	}
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
			s.failover.AddEntry(failover.Endpoint{Host: m.FrontingHint, Transport: tr, FP: fp, Priority: 50})
			s.bandit.AddArm(bandit.Arm{Host: m.FrontingHint, Transport: tr, FP: fp})
		}
		s.log.logf("manifest added fronting entry %s", m.FrontingHint)
	}
	for _, e := range m.Entries {
		if e.Role == "backup" && !s.hasEntry(e.Host) {
			for _, tr := range transportsPerEntry {
				s.failover.AddEntry(failover.Endpoint{Host: e.Host, Transport: tr, FP: fp, Priority: 100})
				s.bandit.AddArm(bandit.Arm{Host: e.Host, Transport: tr, FP: fp})
			}
			s.log.logf("manifest added backup entry %s", e.Host)
		}
	}
	s.log.logf("manifest loaded (path_base=%s fp=%s sig=%v)", m.WSPathBase, fp, m.ManifestSig != "")
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

// fragParams returns the per-connection ClientHello surgery parameters:
// the randomized cut count, cut window (SNI region), and micro-gap bounds.
func (s *server) fragParams() (cuts int, lo, hi float64, gapMin, gapMax time.Duration) {
	cuts = 1
	gapMin, gapMax = 20*time.Millisecond, 120*time.Millisecond
	if g := s.cfg.SplitGapMS; g[0] > 0 && g[1] > g[0] {
		gapMin, gapMax = time.Duration(g[0])*time.Millisecond, time.Duration(g[1])*time.Millisecond
	}
	if f := s.cfg.FragCuts; f[0] > 0 && f[1] >= f[0] {
		cuts = f[0] + int(randFloat()*float64(f[1]-f[0]+1))
		gMin, gMax := 1, 8
		if g := s.cfg.FragMicroGapMS; g[0] > 0 && g[1] > g[0] {
			gMin, gMax = g[0], g[1]
		}
		gapMin, gapMax = time.Duration(gMin)*time.Millisecond, time.Duration(gMax)*time.Millisecond
	}
	wLo, wHi := 40, 90 // SNI extension region (percent of record)
	if w := s.cfg.FragWindow; w[0] > 0 && w[1] > w[0] {
		wLo, wHi = w[0], w[1]
	}
	return cuts, float64(wLo) / 100, float64(wHi) / 100, gapMin, gapMax
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
//   https://host/sub/<token>/axr-manifest  ->  /sub/<token>/<pathbase>?ed=2048
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

func (s *server) startProbes() {
	go func() {
		for {
			interval := s.probeInt[0]
			if s.failover.State() == failover.StateAggressive {
				interval = s.probeInt[1]
			}
			time.Sleep(interval)
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
	socksReply(conn, 0x00) // success; tunnel follows
	s.openTunnel(conn, host, dstPort)
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
// time-of-day and regime ordinal are derived by features() itself.
func (s *server) banditContext(v measure.Vector, now int64, profile flowprofile.ProfileID) bandit.Context {
	anom := 0.0
	if v.LastAnomaly != 0 {
		anom = 1
	}
	return bandit.Context{
		Regime:           v.Regime,
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
func (s *server) openTunnel(client net.Conn, host string, port int) {
	l := s.log
	uuidBytes, _ := vlessws.UUIDFromString(s.cfg.UUID)
	header, err := vlessws.BuildVLESSHeader(uuidBytes, host, uint16(port), false)
	if err != nil {
		l.logf("vless header: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	now := time.Now()
	vec := s.globalVector()
	profile := flowprofile.ForRegime(vec.Regime)
	bctx := s.banditContext(vec, now.UnixMilli(), profile)

	// 2.15 — session reuse: adopt the previous tunnel for the SAME
	// destination if it is still open and within warmTTL. No new dial/TLS/
	// handshake — the stream just continues. A stale session is discarded on
	// the first pump error and we fall through to a fresh dial.
	if w := s.takeWarm(host, port); w != nil {
		l.logf("adopting warm session for %s:%d (age %v)", host, port, time.Since(time.UnixMilli(w.endedAt)))
		meta := warmMeta{arm: w.arm, profile: w.profile, dstHost: host, dstPort: port}
		pr := s.pumpTunnel(w.ws, client, true, meta)
		if pr.clean {
			client.Close()
			s.logDecision(decisionRec{
				Ts: now.UnixMilli(), Regime: vec.Regime, FlowProfile: string(w.profile),
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
	for _, cand := range cands {
		tag := cand.Endpoint.Host + "/" + cand.DialAddr + "[" + cand.Endpoint.Transport + "]"
		tried = append(tried, tag)
		res := s.attemptTunnel(ctx, client, cand, header, profile, host, port)
		last = res
		if res.ok {
			break
		}
		l.logf("attempt %s failed: %s", tag, res.reason)
	}
	if last.reason == "" {
		last = tunnelResult{reason: "no_candidates"}
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
	}
	_ = s.bandit.Save(s.cfg.CacheDir + "/bandit.json")

	s.logDecision(decisionRec{
		Ts: now.UnixMilli(), Regime: vec.Regime, FlowProfile: string(profile),
		Ctx: bctx, Arm: arm, Scores: scores, Tries: tried,
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
func (s *server) attemptTunnel(ctx context.Context, client net.Conn, cand failover.Candidate, header []byte, profile flowprofile.ProfileID, dstHost string, dstPort int) tunnelResult {
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
		// 2.16 — multi-segment ClientHello surgery (fragA/fragB style):
		// randomized 1-3 cuts in the SNI region, 1-8 ms micro-gaps.
		cuts, lo, hi, gapMin, gapMax := s.fragParams()
		inner = surgery.NewMultiSplitConn(raw, cuts, lo, hi, gapMin, gapMax, s.rngFloat)
	}
	surg := s.surgeryOn()
	ws, err := vlessws.DialConn(ctx, inner, vlessws.DialOptions{
		Host:      cand.Endpoint.Host,
		Path:      s.wsPathFor(cand.Endpoint.Transport),
		FP:        cand.Endpoint.FP,
		EarlyData: header, // 0-RTT: VLESS header rides the upgrade
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
	// Worker already has it — do NOT resend. Wait for the 2-byte OK.
	if err := ws.WaitVLESSOK(); err != nil {
		ws.Close()
		res.reason = "vless-ok:" + err.Error()
		return res
	}
	res.rttMS = time.Since(start).Seconds() * 1000

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

func worseRegime(a, b string) bool {
	rank := map[string]int{"stable": 0, "watch": 1, "recovering": 1, "suspected_change": 2}
	return rank[a] > rank[b]
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
	Ts          int64           `json:"ts"`
	Regime      string          `json:"regime"`
	FlowProfile string          `json:"flow_profile"`
	Ctx         bandit.Context  `json:"ctx"`
	Arm         bandit.Arm      `json:"arm"`
	Warm        bool            `json:"warm,omitempty"`
	Scores      []bandit.Score  `json:"scores,omitempty"`
	Tries       []string        `json:"tries,omitempty"`
	OK          bool            `json:"ok"`
	RTTMS       float64         `json:"rtt_ms"`
	Through     float64         `json:"through"`
	Reason      string          `json:"reason"`
	DialAddr    string          `json:"dial_addr,omitempty"`
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
