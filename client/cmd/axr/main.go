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
//   - VLESS-over-WS is the shipped transport; h2/h3/grpc arms are interface
//     stubs reserved for later releases
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bssbb1978/gozargah/axr/internal/bandit"
	"github.com/bssbb1978/gozargah/axr/internal/failover"
	"github.com/bssbb1978/gozargah/axr/internal/measure"
	"github.com/bssbb1978/gozargah/axr/internal/surgery"
	"github.com/bssbb1978/gozargah/axr/internal/vlessws"
)

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
	// SplitGapMS bounds the randomized inter-segment gap in ms.
	SplitGapMS [2]int `json:"split_gap_ms,omitempty"`
	// Probes cadence in ms (0 = defaults: 90s normal / 30s aggressive).
	Probes struct {
		NormalMS     int `json:"normal_ms"`
		AggressiveMS int `json:"aggressive_ms"`
	} `json:"probes,omitempty"`
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

	// Bandit arms: one arm per entry on transport "ws" with its fingerprint.
	var arms []bandit.Arm
	foEntries := make([]failover.Endpoint, 0, len(cfg.Entries))
	for _, e := range cfg.Entries {
		fp := e.FP
		if fp == "" {
			fp = "chrome"
		}
		arms = append(arms, bandit.Arm{Host: e.Host, Transport: "ws", FP: fp})
		foEntries = append(foEntries, failover.Endpoint{
			Host: e.Host, IPs: e.IPs, Transport: "ws", FP: fp, Priority: e.Priority,
		})
	}
	b := bandit.New(1.0, 1, arms)
	if snap, err := bandit.LoadSnapshot(cfg.CacheDir + "/bandit.json"); err == nil {
		if rerr := b.Restore(snap); rerr != nil {
			l.logf("bandit restore failed (%v); using fresh", rerr)
		} else {
			l.logf("restored bandit state (%d arms)", len(snap.Arms))
		}
	}
	fo := failover.New(foEntries, nil)
	if cerr := fo.LoadCache(cfg.CacheDir + "/routing.json"); cerr != nil {
		l.logf("routing cache load failed (%v); using fresh", cerr)
	}

	s := &server{
		cfg:      cfg,
		log:      l,
		timeout:  timeout,
		bandit:   b,
		failover: fo,
		trackers: make(map[string]*measure.Tracker),
		probeInt: [2]time.Duration{90 * time.Second, 30 * time.Second},
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
	var m struct {
		WSPathBase  string `json:"ws_path_base"`
		Fingerprint struct {
			Current string `json:"current"`
		} `json:"fingerprint"`
		Entries []struct {
			Host string `json:"host"`
			Role string `json:"role"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		s.log.logf("manifest decode failed: %v", err)
		return
	}
	if m.WSPathBase != "" {
		s.pathBase = m.WSPathBase
	}
	fp := m.Fingerprint.Current
	if fp == "" {
		fp = "chrome"
	}
	for _, e := range m.Entries {
		if e.Role == "backup" && !s.hasEntry(e.Host) {
			s.failover.AddEntry(failover.Endpoint{Host: e.Host, Transport: "ws", FP: fp, Priority: 100})
			s.bandit.AddArm(bandit.Arm{Host: e.Host, Transport: "ws", FP: fp})
			s.log.logf("manifest added backup entry %s", e.Host)
		}
	}
	s.log.logf("manifest loaded (path_base=%s fp=%s)", m.WSPathBase, fp)
}

func (s *server) hasEntry(host string) bool {
	for _, e := range s.failover.Entries() {
		if e.Host == host {
			return true
		}
	}
	return false
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

// openTunnel picks a bandit arm, walks the failover candidates for it,
// establishes one VLESS-WS tunnel, pumps traffic, and feeds every learner.
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

	// Ask the bandit for the best arm under the current regime.
	vec := s.globalVector()
	arm, scores, err := s.bandit.Select(bandit.Context{
		Regime:           vec.Regime,
		WeakestTransport: vec.WeakestTransport,
		NowMS:            time.Now().UnixMilli(),
	})
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

	// One score table for the failover ordering (quarantined arms sink).
	scoreMap := make(map[string]float64, len(scores))
	for _, sc := range scores {
		if sc.Quarantined {
			scoreMap[sc.Arm.ID()] = -1
		} else {
			scoreMap[sc.Arm.ID()] = sc.Mean
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
	for _, cand := range cands {
		res := s.attemptTunnel(ctx, client, cand, header, arm)
		last = res
		if res.ok {
			break
		}
		l.logf("attempt %s/%s failed: %s", cand.Endpoint.Host, cand.DialAddr, res.reason)
	}
	if last.reason == "" {
		last = tunnelResult{reason: "no_candidates"}
	}

	now := time.Now()
	s.bandit.Observe(arm, bandit.Outcome{
		OK:         last.ok,
		RTTMS:      last.rttMS,
		Throughput: last.through,
		Reason:     last.reason,
	}, now.UnixMilli())
	if last.entry.Host != "" {
		s.trackerFor(last.entry.Host).Feed(measure.Sample{
			OK:        last.ok,
			RTTMS:     last.rttMS,
			ErrClass:  classErr(last.reason),
			Transport: "ws",
			UnixMS:    now.UnixMilli(),
		})
		s.failover.Observe(last.entry, last.dialAddr, last.ok, last.rttMS, last.reason, now)
		_ = s.failover.SaveCache(s.cfg.CacheDir + "/routing.json")
	}
	_ = s.bandit.Save(s.cfg.CacheDir + "/bandit.json")

	if l.verbose {
		l.logf("tunnel %s %s:%d via %s (rtt=%.0fms %s)",
			map[bool]string{true: "OK", false: "FAIL"}[last.ok], host, port, last.dialAddr, last.rttMS, last.reason)
	}
}

// tunnelResult carries the outcome of one candidate attempt.
type tunnelResult struct {
	ok      bool
	rttMS   float64
	through float64
	reason  string
	entry   failover.Endpoint
	dialAddr string
}

func (s *server) attemptTunnel(ctx context.Context, client net.Conn, cand failover.Candidate, header []byte, arm bandit.Arm) tunnelResult {
	res := tunnelResult{entry: cand.Endpoint, dialAddr: cand.DialAddr}
	start := time.Now()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", cand.DialAddr)
	if err != nil {
		res.reason = "dial:" + err.Error()
		return res
	}
	inner := raw
	if s.surgeryOn() {
		gapMin, gapMax := 20*time.Millisecond, 120*time.Millisecond
		if g := s.cfg.SplitGapMS; g[0] > 0 && g[1] > g[0] {
			gapMin, gapMax = time.Duration(g[0])*time.Millisecond, time.Duration(g[1])*time.Millisecond
		}
		inner = surgery.NewSplitConn(raw, gapMin, gapMax, s.rngFloat)
	}
	surg := s.surgeryOn()
	ws, err := vlessws.DialConn(ctx, inner, vlessws.DialOptions{
		Host:      cand.Endpoint.Host,
		Path:      s.wsPath(),
		FP:        arm.FP,
		EarlyData: header, // 0-RTT: VLESS header rides the upgrade
		AfterTLS: func(c net.Conn) net.Conn {
			if surg {
				return surgery.NewChunkConn(c, 512, 1400, 0, s.rngFloat)
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

	// Pump both directions until one side closes.
	done := make(chan struct{}, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := client.Read(buf)
			if n > 0 {
				if serr := ws.SendBinary(buf[:n]); serr != nil {
					break
				}
			}
			if rerr != nil {
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
				if _, werr := client.Write(msg); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done // first side finished
	ws.Close() // tears down both
	wg.Wait()
	client.Close()

	res.ok = true
	res.reason = "ok"
	res.through = 0 // per-frame throughput accounting is a v2 item
	return res
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
