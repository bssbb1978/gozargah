package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type manifestFetchTarget struct {
	TLSName  string
	HTTPHost string
	DialAddr string
}

// buildManifestFetchTarget keeps routing identity separate from the TCP
// destination. An IP URL requires an explicit hostname for both SNI and Host;
// ordinary hostname URLs retain their own TLS/HTTP identity when dialing an IP.
func buildManifestFetchTarget(rawURL, manifestHost, dialIP string) (manifestFetchTarget, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return manifestFetchTarget{}, fmt.Errorf("manifest URL must be an absolute HTTPS URL without userinfo")
	}
	urlHost := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	tlsName := urlHost
	httpHost := u.Host
	if net.ParseIP(urlHost) != nil {
		if manifestHost == "" || net.ParseIP(manifestHost) != nil || strings.ContainsAny(manifestHost, "/?#@ :") {
			return manifestFetchTarget{}, fmt.Errorf("manifest_host must be a hostname when manifest_url uses an IP")
		}
		tlsName, httpHost = manifestHost, manifestHost
		if port != "443" {
			httpHost = net.JoinHostPort(manifestHost, port)
		}
	} else if manifestHost != "" && !strings.EqualFold(manifestHost, urlHost) {
		return manifestFetchTarget{}, fmt.Errorf("manifest_host may only override an IP-based manifest_url")
	}
	if dialIP != "" && net.ParseIP(dialIP) == nil {
		return manifestFetchTarget{}, fmt.Errorf("manifest dial candidate is not an IP address")
	}
	dialHost := urlHost
	if dialIP != "" {
		dialHost = net.ParseIP(dialIP).String()
	}
	return manifestFetchTarget{
		TLSName:  tlsName,
		HTTPHost: httpHost,
		DialAddr: net.JoinHostPort(dialHost, port),
	}, nil
}

func manifestTLSConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func fetchManifestBody(rawURL, manifestHost string, dialIPs []string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("manifest URL must be an absolute HTTPS URL")
	}
	candidates := validatedManifestDialIPs(dialIPs)
	if len(candidates) == 0 {
		candidates = []string{""}
	} else {
		// Preserve a DNS fallback after the advisory candidate set.
		candidates = append(candidates, "")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var lastErr error
	for _, candidate := range candidates {
		target, err := buildManifestFetchTarget(rawURL, manifestHost, candidate)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}
		transport := &http.Transport{
			TLSClientConfig:   manifestTLSConfig(target.TLSName),
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, target.DialAddr)
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, err
		}
		req.Host = target.HTTPHost
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			transport.CloseIdleConnections()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("manifest HTTP %d", resp.StatusCode)
			_ = resp.Body.Close()
			transport.CloseIdleConnections()
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no manifest dial candidates")
	}
	return nil, lastErr
}

func validatedManifestDialIPs(ips []string) []string {
	out := make([]string, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		parsed := net.ParseIP(ip)
		if parsed == nil || seen[parsed.String()] {
			continue
		}
		seen[parsed.String()] = true
		out = append(out, parsed.String())
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func (s *server) fetchManifest(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse manifest URL: %w", err)
	}
	ips := append([]string(nil), s.cfg.ManifestDialIPs...)
	for _, entry := range s.cfg.Entries {
		if strings.EqualFold(entry.Host, u.Hostname()) {
			ips = append(ips, entry.IPs...)
		}
	}
	for _, entry := range s.failover.Entries() {
		if strings.EqualFold(entry.Host, u.Hostname()) {
			ips = append(ips, entry.IPs...)
		}
	}
	manifestHost := ""
	if net.ParseIP(u.Hostname()) != nil {
		manifestHost = s.cfg.ManifestHost
	}
	return fetchManifestBody(rawURL, manifestHost, ips)
}

func safeManifestLabel(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-manifest-url>"
	}
	u.Path = "/<subscription>/axr-manifest"
	u.RawQuery = ""
	u.Fragment = ""
	return u.Scheme + "://" + u.Host + u.Path
}

func safeManifestSourceLabel(source string) string {
	const suffix = " (last-known-good)"
	cached := strings.HasSuffix(source, suffix)
	if cached {
		source = strings.TrimSuffix(source, suffix)
		if !strings.Contains(source, "://") {
			return "last-known-good manifest"
		}
	}
	label := safeManifestLabel(source)
	if cached {
		label += suffix
	}
	return label
}
