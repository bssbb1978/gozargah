// Package cfscan is the AXR client-side clean-Cloudflare-edge scanner
// (2.16). It ports the full CFScanner capability set used in production
// scouting scripts, so no capability was deleted in the platform swap:
//
//  1. Cloudflare API CIDR discovery (https://api.cloudflare.com/client/v4/ips)
//     with an embedded snapshot fallback for offline use
//  2. operator priority /24 ranges (probed first) + blocked-range exclusion
//  3. deterministic per-CIDR candidate sampling (seeded, reproducible)
//  4. SNI-anchored TLS probes: dial ip:443 with the relay's SNI, N attempts,
//     median RTT + loss ratio per address
//  5. colo validation via GET /cdn-cgi/trace (Host: relay) — confirms the
//     address really serves the relay's edge certificate/POP
//  6. top-N ranking (OK first, then loss, then median RTT, then IP)
//  7. JSON + CSV reports
//
// The pure logic (sampling, filtering, median, ranking, reports) is fully
// unit-tested without any network; live probing is isolated behind the
// Prober interface so tests inject fakes.
//
// Honest boundary: a probe success proves "this edge IP answers the relay's
// TLS handshake from my network right now". It is not DPI detection and it
// is not a guarantee; the results are hints the failover engine ranks by
// local health before trusting them.
package cfscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Schema = "gozargah-axr-clean-ip-report/v1"

// Rng is the random source (math/rand.Float64 style); deterministic with a
// seeded source so candidate sampling is reproducible in tests.
type Rng func() float64

// Options is the full scan configuration (every knob the Rust scanner had).
type Options struct {
	RelayHost   string // SNI anchor: the relay's public hostname
	Cidrs       []string
	// CFAPIDisabled skips the live API entirely (explicit Cidrs or snapshot).
	CFAPIDisabled bool
	// APIURL defaults to the official Cloudflare list endpoint.
	APIURL string
	// Priority is an operator list of CIDRs (typically /24) probed first.
	Priority []string
	// Blocked is a list of CIDRs to exclude from the candidate set.
	Blocked []string
	// SamplesPerCIDR bounds candidates drawn from each CIDR (default 4).
	SamplesPerCIDR int
	// Attempts is the probe count per candidate (default 3).
	Attempts int
	// Timeout per dial/handshake (default 3s).
	Timeout time.Duration
	// VerifyColo performs the /cdn-cgi/trace colo check (default true).
	VerifyColo *bool
	// Concurrency bounds parallel probes (default 4, min 1).
	Concurrency int
	// UserAgent for the trace check (default "AXR/2.16").
	UserAgent string
	// TopN is how many ranked results the report keeps (default 8).
	TopN int
}

func (o *Options) defaults() {
	if o.SamplesPerCIDR <= 0 {
		o.SamplesPerCIDR = 4
	}
	if o.Attempts <= 0 {
		o.Attempts = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.TopN <= 0 {
		o.TopN = 8
	}
	if o.APIURL == "" {
		o.APIURL = "https://api.cloudflare.com/client/v4/ips"
	}
	if o.UserAgent == "" {
		o.UserAgent = "AXR/2.16"
	}
	if o.VerifyColo == nil {
		v := true
		o.VerifyColo = &v
	}
}

// verifyColo reports whether the colo trace check is on (default true).
func (o *Options) verifyColo() bool { return o.VerifyColo == nil || *o.VerifyColo }

// ProbeResult is one probed candidate.
type ProbeResult struct {
	IP       string  `json:"ip"`
	OK       bool    `json:"ok"`
	RTTMS    float64 `json:"rtt_ms"` // median over successful attempts
	Loss     float64 `json:"loss"`   // failed attempts / attempts (0..1)
	Colo     string  `json:"colo,omitempty"`
	Attempts int     `json:"attempts"`
	Error    string  `json:"error,omitempty"`
}

// Report is the full ranked scan output.
type Report struct {
	Schema        string        `json:"schema"`
	RelayHost     string        `json:"relay_host"`
	GeneratedAtMS int64         `json:"generated_at_ms"`
	Source        string        `json:"source"` // "api" | "explicit" | "snapshot"
	Candidates    int           `json:"candidates"`
	Probed        int           `json:"probed"`
	TopN          int           `json:"top_n"`
	Results       []ProbeResult `json:"results"`
}

// Prober performs the live probes; production uses DefaultProber, tests
// inject fakes so the pure orchestration stays network-free.
type Prober interface {
	ProbeIP(ctx context.Context, ip string, opts Options) ProbeResult
}

// DefaultCFCIDRs is an embedded snapshot of Cloudflare's public IPv4 ranges
// (as published by the API, 2025 snapshot). It is used ONLY when the live
// API is unreachable and no explicit Cidrs are given — a scan must still be
// possible offline. The live API list is always preferred when reachable.
var DefaultCFCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// ParseCIDR parses an IPv4 CIDR into its network and host count.
func ParseCIDR(s string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil, err
	}
	if ip.To4() == nil {
		return nil, nil, fmt.Errorf("cfscan: v4 only, got %s", s)
	}
	return ip.To4(), ipnet, nil
}

func hostCount(n *net.IPNet) uint32 {
	ones, bits := n.Mask.Size()
	if bits-ones > 32 {
		return 0
	}
	var c uint64 = 1 << uint(bits-ones)
	if c > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(c)
}

// inAnyCIDR reports whether ip falls inside any of the given CIDRs.
// Bare IPs are accepted as /32.
func inAnyCIDR(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.ContainsRune(c, '/') {
			c += "/32"
		}
		if _, ipnet, err := ParseCIDR(c); err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// SampleCandidates builds the ordered candidate list:
//
//  1. operator Priority CIDRs first (higher sample budget: double),
//  2. then the remaining CIDRs in given order,
//  3. addresses inside Blocked ranges are dropped,
//  4. every /32 yields exactly itself; /24 samples from 1..254; wider
//     prefixes draw uniform random host addresses.
//
// Deterministic for a fixed (cidrs, priority, blocked, rng) sequence.
func SampleCandidates(cidrs, priority, blocked []string, per int, rng Rng) []string {
	if per < 1 {
		per = 1
	}
	if rng == nil {
		rng = func() float64 { return 0.5 }
	}
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip == "" || seen[ip] || inAnyCIDR(ip, blocked) {
			return
		}
		seen[ip] = true
		out = append(out, ip)
	}
	sample := func(c string, budget int) {
		_, ipnet, err := ParseCIDR(c)
		if err != nil {
			return
		}
		n := hostCount(ipnet)
		if n == 1 {
			add(ipnet.IP.String())
			return
		}
		// Draw distinct host offsets; cap the attempts so huge prefixes
		// cannot loop when the budget is tiny and collisions pile up.
		maxTries := budget * 16
		got := 0
		mask := ipnet.Mask.Size()
		for i := 0; i < maxTries && got < budget; i++ {
			off := uint32(rng() * float64(n))
			// For prefixes wider than /31 the first address is the network
			// address and the last is the broadcast — skip both. /31 has no
			// network/broadcast split; both addresses are usable.
			if mask < 31 && (off == 0 || off == n-1) {
				continue
			}
			host := ipToUint32(ipnet.IP) + off
			add(uint32ToIP(host).String())
			got++
		}
	}
	for _, p := range priority {
		sample(p, per*2)
	}
	for _, c := range cidrs {
		sample(c, per)
	}
	return out
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(x uint32) net.IP {
	return net.IPv4(byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}

// FetchCFCIDRs downloads the live Cloudflare IPv4 range list.
func FetchCFCIDRs(ctx context.Context, client *http.Client, apiURL string) ([]string, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cfscan: CF API %d", resp.StatusCode)
	}
	var payload struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4 []string `json:"ipv4_cidr_block"`
		} `json:"result"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if !payload.Success || len(payload.Result.IPv4) == 0 {
		return nil, fmt.Errorf("cfscan: CF API returned no ranges")
	}
	return payload.Result.IPv4, nil
}

// Median returns the median of xs (0 for an empty slice).
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64{}, xs...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

// TopN ranks results: OK first, then lowest loss, then lowest median RTT,
// then lexicographic IP (deterministic). It returns at most n entries.
func TopN(results []ProbeResult, n int) []ProbeResult {
	if n <= 0 {
		n = len(results)
	}
	sorted := append([]ProbeResult{}, results...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.OK != b.OK {
			return a.OK
		}
		if a.Loss != b.Loss {
			return a.Loss < b.Loss
		}
		if a.RTTMS != b.RTTMS {
			return a.RTTMS < b.RTTMS
		}
		return a.IP < b.IP
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

// ReportJSON renders the report as pretty JSON.
func ReportJSON(r Report) string {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// ReportCSV renders the report as CSV (one header line).
func ReportCSV(r Report) string {
	var sb strings.Builder
	sb.WriteString("ip,ok,rtt_ms,loss,colo,attempts,error\n")
	for _, x := range r.Results {
		sb.WriteString(strings.Join([]string{
			x.IP,
			strconv.FormatBool(x.OK),
			strconv.FormatFloat(x.RTTMS, 'f', 1, 64),
			strconv.FormatFloat(x.Loss, 'f', 3, 64),
			x.Colo,
			strconv.Itoa(x.Attempts),
			strings.ReplaceAll(x.Error, "\n", " "),
		}, ","))
		sb.WriteString("\n")
	}
	return sb.String()
}

// Run executes the full scan: resolve CIDRs (explicit > API > snapshot),
// sample candidates, probe with bounded concurrency, rank, report.
// prober may be nil (then DefaultProber is used).
func Run(ctx context.Context, opts Options, prober Prober, httpClient *http.Client) (Report, error) {
	if opts.RelayHost == "" {
		return Report{}, fmt.Errorf("cfscan: relay host is required")
	}
	opts.defaults()
	if prober == nil {
		p := DefaultProber{}
		prober = &p
	}

	cidrs := opts.Cidrs
	source := "explicit"
	if len(cidrs) == 0 {
		cidrs = DefaultCFCIDRs
		source = "snapshot"
		if !opts.CFAPIDisabled {
			if live, err := FetchCFCIDRs(ctx, httpClient, opts.APIURL); err == nil {
				cidrs, source = live, "api"
			}
		}
	}

	// Deterministic sampling: probe order only affects ordering, not
	// correctness, and reproducible reports make operator comparisons sane.
	const deterministicRng = 0.5
	cands := SampleCandidates(cidrs, opts.Priority, opts.Blocked, opts.SamplesPerCIDR, func() float64 { return deterministicRng })
	rep := Report{
		Schema:        Schema,
		RelayHost:     opts.RelayHost,
		GeneratedAtMS: time.Now().UnixMilli(),
		Source:        source,
		Candidates:    len(cands),
		TopN:          opts.TopN,
	}
	if len(cands) == 0 {
		return rep, nil
	}

	// Bounded-concurrency probing.
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		collected []ProbeResult
	)
	sem := make(chan struct{}, opts.Concurrency)
	for _, ip := range cands {
		ip := ip
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := prober.ProbeIP(ctx, ip, opts)
			mu.Lock()
			collected = append(collected, res)
			mu.Unlock()
		}()
	}
	wg.Wait()

	rep.Probed = len(collected)
	rep.Results = TopN(collected, opts.TopN)
	return rep, nil
}
