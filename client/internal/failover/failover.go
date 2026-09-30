// Package failover is the AXR national-intranet failover engine:
//
//   - a client-side endpoint matrix (host × explicit clean-IP × transport × fp)
//   - a persistent local routing cache with live per-IP health (atomic JSON)
//   - a probing state machine (normal | aggressive) that mirrors the worker's
//     probe cadence but runs CLIENT-side, because only the client knows which
//     IP its own network can actually reach
//   - a deterministic failover order: bandit-score first, health-score tiebreak
//
// Honest boundary: probe outcomes are connectivity/latency measurements made
// by the client on its own network. A probe success proves "this IP is
// reachable from here right now"; it is not a statement about what any
// middlebox is doing. If no candidate is reachable, the engine says so
// instead of pretending.
package failover

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoint is one candidate entry path.
type Endpoint struct {
	Host      string   `json:"host"`
	IPs       []string `json:"ips,omitempty"` // explicit clean edge IPs (operator list)
	Transport string   `json:"transport"`
	FP        string   `json:"fp"`
	Priority  int      `json:"priority"` // lower = preferred
	// Port is the TCP port dialled on the host and on every explicit IP
	// (0 → 443). Non-standard ports make non-443 edge endpoints, split
	// deployments and LOCAL TEST HARNESSES reachable: without it the
	// ladder could only ever speak to :443, so no end-to-end test could
	// run against a dev server on a high port.
	Port int `json:"port,omitempty"`
}

// dialPort is the effective port (0 means the conventional 443).
func (e Endpoint) dialPort() int {
	if e.Port > 0 && e.Port <= 65535 {
		return e.Port
	}
	return 443
}

// IPHealth is the live health record for one (host, transport, dial-address).
type IPHealth struct {
	DialAddr    string  `json:"dial_addr"` // ip:port or host:port (port defaults to 443)
	RTTMS       float64 `json:"rtt_ms"`
	Score       float64 `json:"score"` // 0..1 composite health
	ConsecFail  int     `json:"consec_fail"`
	ConsecOK    int     `json:"consec_ok"`
	LastOKMS    int64   `json:"last_ok_ms"`
	CheckedAtMS int64   `json:"checked_at_ms"`
	LastErr     string  `json:"last_err"`
	// QuietUntilMS is the blackout-quiet gate (2.21): the dial address is
	// skipped by the ladder until this unix-ms instant. Cleared on the next
	// success. 0 = not quiet.
	QuietUntilMS int64 `json:"quiet_until_ms,omitempty"`
}

// QuietPolicy bounds the blackout-quiet window. A repeatedly failing dial
// address is not merely deprioritised, it is *taken off the wire* for a
// bounded period: during a net-e-melli window the international entries
// cannot carry traffic anyway, so re-dialing them every round only produces
// a dense, highly clusterable burst of failed TLS handshakes (RST/EOF at
// SNI time) from every client of the fleet at once — itself a fingerprint.
//
// The window is exponential in the consecutive-failure count and capped, so
// a recovered route is always rediscovered: after MaxMS the address returns
// to the ladder and gets a real attempt.
type QuietPolicy struct {
	// BaseMS is the quiet window after quietMinFails consecutive failures.
	BaseMS int64
	// MaxMS caps the window.
	MaxMS int64
}

// Enabled reports whether the gate is active.
func (p QuietPolicy) Enabled() bool { return p.BaseMS > 0 && p.MaxMS > 0 }

// quietFor returns the quiet window for a consecutive-failure count.
func (p QuietPolicy) quietFor(consecFail int) int64 {
	if !p.Enabled() || consecFail < quietMinFails {
		return 0
	}
	step := consecFail - quietMinFails
	if step > 6 {
		step = 6
	}
	d := p.BaseMS << step
	if d > p.MaxMS || d <= 0 {
		d = p.MaxMS
	}
	return d
}

// QuietState is the audit view of the blackout-quiet gate.
type QuietState struct {
	Enabled bool  `json:"enabled"`
	Quiet   int   `json:"quiet"` // dial addresses inside their quiet window
	Total   int   `json:"total"` // tracked dial addresses
	BaseMS  int64 `json:"base_ms"`
	MaxMS   int64 `json:"max_ms"`
}

// Cache is the persistable routing cache.
type Cache struct {
	UpdatedAtMS int64                `json:"updated_at_ms"`
	Health      map[string]*IPHealth `json:"health"`              // key: host|transport|dialaddr
	IPCursor    map[string]uint64    `json:"ip_cursor,omitempty"` // key: host|transport; rotates equal-health clean IPs
}

// ProbeFunc performs one connectivity probe and reports latency.
// Implementations must respect the given deadline.
type ProbeFunc func(endpoint Endpoint, dialAddr string, timeout time.Duration) (ok bool, rttMS float64, errClass string)

// Engine is the failover state machine. Safe for concurrent use.
type Engine struct {
	mu      sync.Mutex
	entries []Endpoint
	cache   *Cache
	probe   ProbeFunc
	state   string // "normal" | "aggressive"
	// failure streak that triggers aggressive mode
	streak int
	// When every address is quiet, probe one rotating candidate per round.
	// A fixed first-candidate retry could starve a recovered alternate route.
	quietCursor int
	// quiet is the blackout-quiet gate (disabled until SetQuietPolicy).
	quiet QuietPolicy
}

const (
	StateNormal     = "normal"
	StateAggressive = "aggressive"

	// Aggressive mode triggers after this many consecutive engine-level
	// failures (every candidate in a round failed).
	aggressiveStreak = 2
	// In aggressive mode the probe timeout is relaxed (deep-packet paths
	// answer slowly) and the candidate cap is raised.
	normalProbeTimeout     = 3 * time.Second
	aggressiveTimeout      = 5 * time.Second
	normalCandidateCap     = 3
	aggressiveCandidateCap = 6

	// health scoring
	healthOKBase     = 1.0
	healthDecay      = 0.6  // per consecutive failure
	healthRTTFloor   = 0.25 // 400ms+ RTT starts costing score
	healthRTTMax     = 400.0
	healthHalfLifeMS = int64(6 * time.Hour / time.Millisecond)

	// quietMinFails is the consecutive-failure count that arms the
	// blackout-quiet gate. Below it, a single unlucky dial never silences a
	// healthy entry.
	quietMinFails = 3
)

// DefaultQuietPolicy is the baseline blackout-quiet gate the axr core
// installs: after 3 consecutive failures a dial address goes quiet for 20 s,
// doubling per further failure up to 10 minutes. A netstate net-e-melli or
// cut regime widens it (see cmd/axr), and any success clears it instantly.
func DefaultQuietPolicy() QuietPolicy {
	return QuietPolicy{BaseMS: 20_000, MaxMS: 10 * 60_000}
}

// New builds an engine. probe may be nil (then the built-in TCP+TLS-dial
// probe is used by ProbeAll).
func New(entries []Endpoint, probe ProbeFunc) *Engine {
	if len(entries) == 0 {
		panic("failover.New: no entries")
	}
	e := &Engine{
		entries: entries,
		cache:   &Cache{Health: map[string]*IPHealth{}, IPCursor: map[string]uint64{}},
		probe:   probe,
		state:   StateNormal,
	}
	// Sort by priority, then host, for deterministic baseline order.
	sort.SliceStable(e.entries, func(i, j int) bool {
		if e.entries[i].Priority != e.entries[j].Priority {
			return e.entries[i].Priority < e.entries[j].Priority
		}
		return e.entries[i].Host < e.entries[j].Host
	})
	return e
}

// LoadCache restores a persisted routing cache.
func (e *Engine) LoadCache(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	if c.Health == nil {
		c.Health = map[string]*IPHealth{}
	}
	if c.IPCursor == nil {
		c.IPCursor = map[string]uint64{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// Upgrade the pre-transport cache shape (host|dialaddr) by seeding each
	// matching transport row. It is only a reachability prior; new real
	// tunnel outcomes immediately make the transport-specific rows diverge.
	legacyKeys := make([]string, 0)
	for key := range c.Health {
		legacyKeys = append(legacyKeys, key)
	}
	migratedLegacy := make(map[string]bool)
	for _, ep := range e.entries {
		prefix := ep.Host + "|"
		for _, key := range legacyKeys {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			addr := strings.TrimPrefix(key, prefix)
			if strings.Contains(addr, "|") {
				continue // already transport-scoped
			}
			if _, _, err := net.SplitHostPort(addr); err != nil {
				continue
			}
			newKey := healthKey(ep, addr)
			if _, exists := c.Health[newKey]; exists {
				migratedLegacy[key] = true
				continue
			}
			if old := c.Health[key]; old != nil {
				seed := *old
				if seed.CheckedAtMS == 0 {
					seed.CheckedAtMS = c.UpdatedAtMS
				}
				c.Health[newKey] = &seed
				migratedLegacy[key] = true
			}
		}
	}
	for key := range migratedLegacy {
		delete(c.Health, key)
	}
	e.cache = &c
	return nil
}

// SaveCache persists the routing cache atomically.
func (e *Engine) SaveCache(path string) error {
	e.mu.Lock()
	c := *e.cache
	c.Health = make(map[string]*IPHealth, len(e.cache.Health))
	c.IPCursor = make(map[string]uint64, len(e.cache.IPCursor))
	for k, v := range e.cache.IPCursor {
		c.IPCursor[k] = v
	}
	for k, v := range e.cache.Health {
		cp := *v
		c.Health[k] = &cp
	}
	c.UpdatedAtMS = time.Now().UnixMilli()
	e.mu.Unlock()
	data, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".axr-cache-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// AddEntry registers a new endpoint (e.g. from a refreshed manifest).
func (e *Engine) AddEntry(ep Endpoint) {
	if ep.Transport == "" {
		ep.Transport = "ws"
	}
	if ep.FP == "" {
		ep.FP = "chrome"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, cur := range e.entries {
		if cur.Host == ep.Host && cur.Transport == ep.Transport {
			e.entries[i] = ep
			return
		}
	}
	e.entries = append(e.entries, ep)
}

// Entries returns a copy of the matrix.
func (e *Engine) Entries() []Endpoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Endpoint, len(e.entries))
	copy(out, e.entries)
	return out
}

// State is the probe state-machine mode.
func (e *Engine) State() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

// CandidatesFor returns an endpoint's dial-address candidates, best health
// first. Equal-health explicit IPs rotate as a pool; the hostname remains a
// final fallback at the same health rank. Unknown health scores 0.5, between
// known-healthy and known-dead evidence.
func (e *Engine) CandidatesFor(ep Endpoint) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	cs := e.candidatesForLocked(ep, time.Now().UnixMilli(), true)
	addrs := make([]string, len(cs))
	for i, c := range cs {
		addrs[i] = c.addr
	}
	return addrs
}

// Candidate is one (endpoint, dial-address) pair ordered for failover.
type Candidate struct {
	Endpoint Endpoint
	DialAddr string
	Score    float64
}

// SetQuietPolicy installs the blackout-quiet gate. A zero/negative policy
// disables it (the default for a bare Engine; cmd/axr always installs
// DefaultQuietPolicy and widens it under a net-e-melli regime).
func (e *Engine) SetQuietPolicy(p QuietPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.quiet = p
}

// ClearQuiet releases every dial address from its current quiet window. The
// client calls this only after fresh independent liveness evidence ends a
// domestic-only blackout, so primary routes can be checked immediately.
func (e *Engine) ClearQuiet() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range e.cache.Health {
		h.QuietUntilMS = 0
	}
}

// Quiet returns the audit view of the blackout-quiet gate.
func (e *Engine) Quiet() QuietState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.quietLocked()
}

// QuietState reports the gate's current state (caller holds e.mu).
func (e *Engine) quietLocked() QuietState {
	now := time.Now().UnixMilli()
	qs := QuietState{Enabled: e.quiet.Enabled(), BaseMS: e.quiet.BaseMS, MaxMS: e.quiet.MaxMS}
	for _, h := range e.cache.Health {
		qs.Total++
		if h.QuietUntilMS > now {
			qs.Quiet++
		}
	}
	return qs
}

// quietNow reports whether a dial address is inside its quiet window
// (caller holds e.mu).
func (e *Engine) quietNow(h *IPHealth, nowMS int64) bool {
	return h != nil && h.QuietUntilMS > nowMS
}

// FailoverOrder returns the global ordered candidate list, capped per mode.
// orderFn (usually the bandit score for the arm) ranks endpoints; within an
// endpoint, health ranks dial addresses.
//
// Blackout-quiet: dial addresses inside their quiet window (see
// QuietPolicy) are omitted. The invariant "never silence everything" is
// enforced here: if every candidate is quiet the unfiltered order is
// returned, so a caller can always try *something*.
func (e *Engine) FailoverOrder(orderFn func(Arm) float64) []Candidate {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now().UnixMilli()
	out := e.failoverOrderLocked(orderFn, true, now, false)
	if len(out) == 0 {
		return e.failoverOrderLocked(orderFn, false, now, true)
	}
	return e.failoverOrderLocked(orderFn, true, now, true)
}

// failoverOrderLocked builds the ordered candidate list. skipQuiet drops
// addresses inside their quiet window; the caller decides what an empty
// result means.
func (e *Engine) failoverOrderLocked(orderFn func(Arm) float64, skipQuiet bool, nowMS int64, rotateIPs bool) []Candidate {
	cap := normalCandidateCap
	if e.state == StateAggressive {
		cap = aggressiveCandidateCap
	}
	type epRank struct {
		ep    Endpoint
		score float64
	}
	var ranks []epRank
	for _, ep := range e.entries {
		var s float64
		if orderFn != nil {
			s = orderFn(Arm{Host: ep.Host, Transport: ep.Transport, FP: ep.FP})
		} else {
			s = float64(-ep.Priority)
		}
		ranks = append(ranks, epRank{ep: ep, score: s})
	}
	sort.SliceStable(ranks, func(i, j int) bool {
		if ranks[i].score != ranks[j].score {
			return ranks[i].score > ranks[j].score
		}
		return ranks[i].ep.Host < ranks[j].ep.Host
	})
	var out []Candidate
	for _, r := range ranks {
		addrs := e.candidatesForLocked(r.ep, nowMS, rotateIPs)
		for _, a := range addrs {
			if skipQuiet && e.quietNow(e.cache.Health[healthKey(r.ep, a.addr)], nowMS) {
				continue
			}
			if len(out) >= cap {
				return out
			}
			out = append(out, Candidate{Endpoint: r.ep, DialAddr: a.addr, Score: a.score})
		}
	}
	return out
}

type cand struct {
	addr     string
	score    float64
	explicit bool
}

func healthKey(ep Endpoint, dialAddr string) string {
	transport := ep.Transport
	if transport == "" {
		transport = "ws"
	}
	return ep.Host + "|" + transport + "|" + dialAddr
}

// decayedHealthScore lets old evidence return toward an unknown prior rather
// than making a once-good or once-bad clean IP permanently dominant.
func decayedHealthScore(h *IPHealth, nowMS int64) float64 {
	if h.CheckedAtMS <= 0 || nowMS <= h.CheckedAtMS {
		return h.Score
	}
	age := float64(nowMS - h.CheckedAtMS)
	factor := math.Exp2(-age / float64(healthHalfLifeMS))
	return 0.5 + (h.Score-0.5)*factor
}

func (e *Engine) candidatesForLocked(ep Endpoint, nowMS int64, rotateIPs bool) []cand {
	var out []cand
	add := func(addr string, explicit bool) {
		h, ok := e.cache.Health[healthKey(ep, addr)]
		if !ok {
			out = append(out, cand{addr: addr, score: 0.5, explicit: explicit})
			return
		}
		out = append(out, cand{addr: addr, score: decayedHealthScore(h, nowMS), explicit: explicit})
	}
	port := strconv.Itoa(ep.dialPort())
	for _, ip := range ep.IPs {
		add(net.JoinHostPort(ip, port), true)
	}
	add(net.JoinHostPort(ep.Host, port), false)
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	if !rotateIPs {
		return out
	}

	// Rotate only equal-health explicit IPs. A measured healthier address
	// keeps its rank, while a pool of equally unknown/healthy hints does not
	// stick to the first configured IP on every connection.
	rotationKey := ep.Host + "|" + ep.Transport
	for i := 0; i < len(out); {
		if !out[i].explicit {
			i++
			continue
		}
		j := i + 1
		for j < len(out) && out[j].explicit && math.Abs(out[j].score-out[i].score) < 1e-9 {
			j++
		}
		if j-i > 1 {
			offset := int(e.cache.IPCursor[rotationKey] % uint64(j-i))
			if offset > 0 {
				group := append([]cand(nil), out[i:j]...)
				copy(out[i:j], append(group[offset:], group[:offset]...))
			}
			e.cache.IPCursor[rotationKey]++
		}
		i = j
	}
	return out
}

// Arm is the minimal arm shape FailoverOrder orders on (avoids importing
// the bandit package; structurally compatible).
type Arm struct {
	Host      string
	Transport string
	FP        string
}

// ProbeRound runs one probe sweep over the current failover order and
// records health. Returns the candidates that came back healthy, in order.
func (e *Engine) ProbeRound(now time.Time) []Candidate {
	e.mu.Lock()
	// Quiet-aware order first: addresses that repeatedly failed are off the
	// wire. If that leaves nothing, the whole ladder is quiet — the
	// blackout case, where one candidate per round is probed (the minimum
	// failed-attempt signature that still discovers a reopened route).
	order := e.failoverOrderLocked(nil, true, now.UnixMilli(), false)
	if len(order) == 0 {
		if full := e.failoverOrderLocked(nil, false, now.UnixMilli(), true); len(full) > 0 {
			// Keep blackout probe volume to one attempt per round, but rotate
			// across the bounded ladder so a recovered non-leading path is not
			// starved forever by one still-dead first entry.
			index := e.quietCursor % len(full)
			order = []Candidate{full[index]}
			e.quietCursor = (index + 1) % len(full)
		}
	} else {
		order = e.failoverOrderLocked(nil, true, now.UnixMilli(), true)
	}
	timeout := normalProbeTimeout
	if e.state == StateAggressive {
		timeout = aggressiveTimeout
	}
	probe := e.probe
	e.mu.Unlock()
	if probe == nil {
		probe = DefaultProbe
	}
	var healthy []Candidate
	anyOK := false
	for _, c := range order {
		ok, rtt, errClass := probe(c.Endpoint, c.DialAddr, timeout)
		e.observe(c.Endpoint, c.DialAddr, ok, rtt, errClass, now)
		if ok {
			anyOK = true
			healthy = append(healthy, c)
			break // one healthy candidate per round is enough for routing
		}
	}
	e.stepRound(anyOK)
	return healthy
}

// Observe feeds a real traffic outcome (not just probes) into the cache and
// the state machine.
func (e *Engine) Observe(ep Endpoint, dialAddr string, ok bool, rttMS float64, errClass string, now time.Time) {
	e.observe(ep, dialAddr, ok, rttMS, errClass, now)
	e.stepRound(ok)
}

func (e *Engine) observe(ep Endpoint, dialAddr string, ok bool, rttMS float64, errClass string, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := healthKey(ep, dialAddr)
	h, exists := e.cache.Health[key]
	if !exists {
		h = &IPHealth{DialAddr: dialAddr}
		e.cache.Health[key] = h
	}
	h.CheckedAtMS = now.UnixMilli()
	if ok {
		h.ConsecOK++
		h.ConsecFail = 0
		h.LastOKMS = now.UnixMilli()
		h.LastErr = ""
		// A single success un-gates the address immediately: the route
		// came back, and the next dial must be allowed to use it.
		h.QuietUntilMS = 0
		if rttMS > 0 {
			if h.RTTMS == 0 {
				h.RTTMS = rttMS
			} else {
				h.RTTMS = 0.7*h.RTTMS + 0.3*rttMS
			}
		}
		score := healthOKBase
		if h.RTTMS > healthRTTMax {
			pen := (h.RTTMS - healthRTTMax) / healthRTTMax
			if pen > 1 {
				pen = 1
			}
			score -= healthRTTFloor * pen
		}
		h.Score = math.Min(1.0, math.Max(0, score))
	} else {
		h.ConsecFail++
		h.ConsecOK = 0
		h.LastErr = errClass
		h.Score *= healthDecay
		if h.Score < 0.001 {
			h.Score = 0
		}
		if d := e.quiet.quietFor(h.ConsecFail); d > 0 {
			h.QuietUntilMS = now.UnixMilli() + d
		}
	}
	e.cache.UpdatedAtMS = now.UnixMilli()
}

// stepRound updates the probe state machine after a candidate-level outcome.
func (e *Engine) stepRound(ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ok {
		e.streak = 0
		if e.state == StateAggressive {
			e.state = StateNormal
		}
		return
	}
	e.streak++
	if e.streak >= aggressiveStreak && e.state == StateNormal {
		e.state = StateAggressive
	}
}

// Health exports a copy of the cache (for the local decision view/tests).
func (e *Engine) Health() map[string]IPHealth {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]IPHealth, len(e.cache.Health))
	for k, v := range e.cache.Health {
		out[k] = *v
	}
	return out
}

// DefaultProbe does a TCP dial + TLS handshake to dialAddr with ServerName
// set to the endpoint host, and reports the handshake RTT. It never sends
// application data.
func DefaultProbe(ep Endpoint, dialAddr string, timeout time.Duration) (bool, float64, string) {
	start := time.Now()
	d, err := net.DialTimeout("tcp", dialAddr, timeout)
	if err != nil {
		return false, 0, classifyErr(err)
	}
	_ = d.SetDeadline(time.Now().Add(timeout))
	conn, err := tlsDial(d, ep.Host, timeout-time.Since(start))
	if err != nil {
		d.Close()
		return false, 0, classifyErr(err)
	}
	rtt := time.Since(start).Seconds() * 1000
	conn.Close()
	return true, rtt, ""
}

// tlsDial completes a TLS handshake over the already-dialed conn, verifying
// the certificate against the endpoint hostname (even when dialing an
// explicit IP). It is probe-only: no application data is exchanged.
func tlsDial(conn net.Conn, host string, remaining time.Duration) (net.Conn, error) {
	if remaining <= 0 {
		remaining = time.Second
	}
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	tc := tls.Client(conn, cfg)
	deadline := time.Now().Add(remaining)
	_ = tc.SetDeadline(deadline)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	msg := err.Error()
	if len(msg) > 64 {
		msg = msg[:64]
	}
	return "dial_error:" + msg
}

// ErrNoHealthy is returned when a probe round found nothing reachable.
var ErrNoHealthy = errors.New("failover: no healthy candidate")

// Resolver is the injectable DNS A-record source for clean-IP harvesting.
// Production uses DefaultResolver (system resolver, IPv4 only); tests fake it.
type Resolver interface {
	LookupA(ctx context.Context, host string) ([]string, error)
}

// DefaultResolver resolves the A records of host via the system resolver,
// keeping IPv4 only (matching the worker's IPv4 clean-IP hints).
type DefaultResolver struct{}

// LookupA implements Resolver.
func (DefaultResolver) LookupA(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() == nil {
			continue
		}
		out = append(out, ip.To4().String())
	}
	return out, nil
}

// MaxHarvestedIPs caps the merged per-entry IP list (explicit + harvested).
const MaxHarvestedIPs = 8

// HarvestedIPs merges the explicit (operator) IPs with the A records of host:
// explicit IPs first (they are trusted), then deduplicated harvested ones,
// capped at MaxHarvestedIPs. Resolver errors keep the existing list intact —
// harvesting is an enhancement, never a regression.
func HarvestedIPs(ctx context.Context, explicit []string, host string, r Resolver) []string {
	out := make([]string, 0, len(explicit)+MaxHarvestedIPs)
	seen := make(map[string]bool, len(explicit)+MaxHarvestedIPs)
	add := func(ip string) {
		if ip == "" || seen[ip] || len(out) >= MaxHarvestedIPs {
			return
		}
		if net.ParseIP(ip) == nil {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	for _, ip := range explicit {
		add(ip)
	}
	if r != nil && host != "" {
		if ips, err := r.LookupA(ctx, host); err == nil {
			for _, ip := range ips {
				add(ip)
			}
		}
	}
	return out
}

// HarvestEntries resolves every entry's host and merges the A records into
// entry.IPs (dedup, capped). Returns the number of newly added IPs. Safe for
// concurrent use; the cache is untouched (health keys are per dial-addr and
// are filled on first probe/dial).
func (e *Engine) HarvestEntries(ctx context.Context, r Resolver) int {
	if r == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	added := 0
	for i := range e.entries {
		before := len(e.entries[i].IPs)
		e.entries[i].IPs = HarvestedIPs(ctx, e.entries[i].IPs, e.entries[i].Host, r)
		added += len(e.entries[i].IPs) - before
	}
	return added
}

// Best returns the single best candidate right now (cache-driven), without
// probing.
func (e *Engine) Best(orderFn func(Arm) float64) (Candidate, error) {
	order := e.FailoverOrder(orderFn)
	for _, c := range order {
		if c.Score > 0.05 {
			return c, nil
		}
	}
	if len(order) > 0 {
		// Nothing known-healthy: still return the top so the caller can try.
		return order[0], nil
	}
	return Candidate{}, ErrNoHealthy
}
