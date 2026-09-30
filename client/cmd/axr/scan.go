package main

// 2.16 — `axr scan`: the client-side clean-Cloudflare-edge scanner.
//
// It probes real CF edge addresses FROM THE LOCAL NETWORK (the only place
// that reachability is measurable), ranks them (median RTT / loss / colo),
// prints a JSON report, optionally writes report.json + report.csv, always
// refreshes ~/.axr/clean-ips.json (which the server merges into the failover
// ladder at startup), and with -upload POSTs the survivors to the Worker's
// harvest endpoint so every client on the same panel benefits.
//
// This is the full CFScanner capability set from the production scouting
// scripts: CF API CIDRs, priority /24 ranges, blocked ranges, SNI-anchored
// TLS probes x3, median RTT/loss, /cdn-cgi/trace colo validation, top-N,
// JSON + CSV reporting. No capability was dropped in the platform swap.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bssbb1978/gozargah/axr/internal/cfscan"
)

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", "", "path to axr.json (relay host, harvest URL/token)")
	top := fs.Int("top", 8, "top-N ranked results")
	outDir := fs.String("out", "", "also write report.json + report.csv into this directory")
	upload := fs.Bool("upload", false, "POST results to the Worker harvest endpoint")
	relay := fs.String("relay", "", "SNI anchor hostname (default: first config entry host)")
	probeTimeout := fs.Duration("timeout", 3*time.Second, "per-probe dial/handshake budget")
	attempts := fs.Int("attempts", 3, "TLS attempts per candidate")
	noAPI := fs.Bool("no-api", false, "skip the Cloudflare API (embedded snapshot or -cidrs)")
	cidrs := fs.String("cidrs", "", "comma-separated CIDRs (overrides API + snapshot)")
	priority := fs.String("priority", "", "comma-separated priority CIDRs (probed first, e.g. /24s)")
	blocked := fs.String("blocked", "", "comma-separated CIDRs to exclude")
	concurrency := fs.Int("concurrency", 4, "parallel probes")
	verifyColo := fs.Bool("verify-colo", true, "run the /cdn-cgi/trace colo check")
	keep := fs.Duration("keep", 20*time.Minute, "overall scan budget")
	_ = fs.Parse(args)

	var cfg Config
	if *configPath != "" {
		var err error
		cfg, err = loadConfig(*configPath)
		if err != nil {
			fatalf("load config: %v", err)
		}
	}
	relayHost := *relay
	if relayHost == "" && len(cfg.Entries) > 0 {
		relayHost = cfg.Entries[0].Host
	}
	if relayHost == "" {
		fatalf("scan: -relay (or a config entry host) is required — the SNI anchor")
	}

	opts := cfscan.Options{
		RelayHost:   relayHost,
		Attempts:    *attempts,
		Timeout:     *probeTimeout,
		TopN:        *top,
		Concurrency: *concurrency,
	}
	opts.VerifyColo = verifyColo
	if *cidrs != "" {
		opts.Cidrs = splitCSV(*cidrs)
	}
	opts.Priority = splitCSV(*priority)
	opts.Blocked = splitCSV(*blocked)
	if *noAPI {
		opts.CFAPIDisabled = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), *keep)
	defer cancel()

	fmt.Fprintf(os.Stderr, "axr scan: relay=%s source=api|snapshot|explicit top=%d attempts=%d\n",
		relayHost, *top, *attempts)
	rep, err := cfscan.Run(ctx, opts, nil, nil)
	if err != nil {
		fatalf("scan: %v", err)
	}
	fmt.Print(cfscan.ReportJSON(rep))

	okCount := 0
	var okIPs []string
	for _, r := range rep.Results {
		if r.OK {
			okCount++
			okIPs = append(okIPs, r.IP)
		}
	}
	fmt.Fprintf(os.Stderr, "axr scan: %d candidate(s), %d probed, %d healthy in top-%d (source=%s)\n",
		rep.Candidates, rep.Probed, okCount, *top, rep.Source)

	// Report files (optional explicit output dir).
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			fatalf("scan: out dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(*outDir, "report.json"), []byte(cfscan.ReportJSON(rep)), 0o600); err != nil {
			fatalf("scan: write report.json: %v", err)
		}
		if err := os.WriteFile(filepath.Join(*outDir, "report.csv"), []byte(cfscan.ReportCSV(rep)), 0o600); err != nil {
			fatalf("scan: write report.csv: %v", err)
		}
		fmt.Fprintf(os.Stderr, "axr scan: report written to %s\n", *outDir)
	}

	// Always refresh the local clean-IP pool the server merges at startup.
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = home + "/.axr"
	}
	if err := writeCleanIPsFile(filepath.Join(cacheDir, "clean-ips.json"), relayHost, okIPs); err != nil {
		fmt.Fprintf(os.Stderr, "axr scan: warn: %v\n", err)
	} else if len(okIPs) > 0 {
		fmt.Fprintf(os.Stderr, "axr scan: %d healthy IP(s) saved to %s/clean-ips.json\n", len(okIPs), cacheDir)
	}

	if *upload {
		if err := uploadHarvest(cfg, okIPs); err != nil {
			fmt.Fprintf(os.Stderr, "axr scan: upload failed: %v\n", err)
		}
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cleanIPsFile is the on-disk clean-IP pool (~/.axr/clean-ips.json).
type cleanIPsFile struct {
	Schema        string   `json:"schema"`
	RelayHost     string   `json:"relay_host"`
	GeneratedAtMS int64    `json:"generated_at_ms"`
	IPs           []string `json:"ips"`
}

func writeCleanIPsFile(path, relay string, ips []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cleanIPsFile{
		Schema:        "gozargah-axr-clean-ips/v1",
		RelayHost:     relay,
		GeneratedAtMS: time.Now().UnixMilli(),
		IPs:           ips,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// uploadHarvest POSTs the healthy IPs to the Worker harvest endpoint.
// Token resolution: config harvest_token > manifest URL token.
// URL resolution: config harvest_url > derived from the manifest URL.
func uploadHarvest(cfg Config, ips []string) error {
	if len(ips) == 0 {
		return fmt.Errorf("no healthy IPs to upload")
	}
	token := cfg.HarvestToken
	if token == "" {
		token = subTokenFromURL(cfg.ManifestURL)
	}
	if token == "" {
		return fmt.Errorf("no token (set harvest_token or manifest_url)")
	}
	urlStr := cfg.HarvestURL
	if urlStr == "" {
		urlStr = harvestURLFromManifest(cfg.ManifestURL, cfg.ManifestHost)
	}
	if urlStr == "" {
		return fmt.Errorf("no harvest URL (set harvest_url or manifest_url)")
	}
	payload := map[string]any{
		"token":  token,
		"ips":    ips,
		"source": "client-scan",
	}
	if prefix := subscriptionRoutePrefixFromURL(cfg.ManifestURL); prefix != "" {
		payload["dynamicPrefix"] = prefix
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(urlStr, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if resp.StatusCode != 200 {
		return fmt.Errorf("harvest HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf[:n])))
	}
	fmt.Fprintf(os.Stderr, "axr scan: uploaded %d IP(s): %s\n", len(ips), strings.TrimSpace(string(buf[:n])))
	return nil
}

// postCanary reports one canary liveness result to the Worker harvest
// endpoint (kind="canary", 2.17). Same token/URL resolution as the scan
// upload. Best-effort: a failed report never affects tunnels; the next
// ticker fires again.
func postCanary(cfg Config, host string, ok bool) error {
	token := cfg.HarvestToken
	if token == "" {
		token = subTokenFromURL(cfg.ManifestURL)
	}
	if token == "" {
		return fmt.Errorf("no token (set harvest_token or manifest_url)")
	}
	urlStr := cfg.HarvestURL
	if urlStr == "" {
		urlStr = harvestURLFromManifest(cfg.ManifestURL, cfg.ManifestHost)
	}
	if urlStr == "" {
		return fmt.Errorf("no harvest URL (set harvest_url or manifest_url)")
	}
	payload := map[string]any{
		"token":      token,
		"kind":       "canary",
		"canaryHost": host,
		"canaryOk":   ok,
	}
	if prefix := subscriptionRoutePrefixFromURL(cfg.ManifestURL); prefix != "" {
		payload["dynamicPrefix"] = prefix
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(urlStr, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if resp.StatusCode != 200 {
		return fmt.Errorf("canary report HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf[:n])))
	}
	return nil
}
