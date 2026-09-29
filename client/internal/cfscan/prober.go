package cfscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultProber is the production prober: SNI-anchored TLS handshakes against
// the candidate edge IP plus the optional /cdn-cgi/trace colo check.
//
// SNI anchoring means the handshake presents the RELAY's hostname while
// dialing the raw IP — exactly what a client doing IP-pinned dialing would
// do. Certificate verification is NOT skipped: the address must present the
// relay's genuine edge certificate, which is what separates a real edge
// address (or a hostile lookalike serving the same cert via anycast) from
// a random host that merely answers on 443.
type DefaultProber struct {
	// SystemPool lets tests inject a root pool; nil = system roots.
	SystemPool *x509.CertPool
	// Dialer override for tests.
	Dialer *net.Dialer
}

// ProbeIP implements Prober.
func (p *DefaultProber) ProbeIP(ctx context.Context, ip string, opts Options) ProbeResult {
	opts.defaults()
	res := ProbeResult{IP: ip, Attempts: opts.Attempts}
	dialer := p.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: opts.Timeout}
	}
	cfg := &tls.Config{
		ServerName:         opts.RelayHost,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	if p.SystemPool != nil {
		cfg.RootCAs = p.SystemPool
	}
	var rts []float64
	var lastErr string
	for i := 0; i < opts.Attempts; i++ {
		select {
		case <-ctx.Done():
			lastErr = ctx.Err().Error()
			i = opts.Attempts
			continue
		default:
		}
		t0 := time.Now()
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, "443"), cfg)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		_ = conn.Close()
		rts = append(rts, float64(time.Since(t0).Microseconds())/1000.0)
	}
	res.Loss = 1.0
	if len(rts) > 0 {
		fails := float64(opts.Attempts - len(rts))
		res.Loss = fails / float64(opts.Attempts)
		res.OK = true
		res.RTTMS = Median(rts)
	} else {
		res.Error = lastErr
	}
	if res.OK && opts.verifyColo() {
		res.Colo = fetchColo(ctx, ip, opts)
	}
	return res
}

// fetchColo performs GET https://<ip>/cdn-cgi/trace with Host: relay and
// parses the colo= field. The transport dials the IP but verifies the relay
// certificate (SNI anchoring, same contract as the handshake probe).
func fetchColo(ctx context.Context, ip string, opts Options) string {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: opts.Timeout}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         opts.RelayHost,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		},
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
	}
	client := &http.Client{Transport: transport, Timeout: opts.Timeout + time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(ip, "443")+"/cdn-cgi/trace", nil)
	if err != nil {
		return ""
	}
	req.Host = opts.RelayHost
	req.Header.Set("user-agent", opts.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "colo=") {
			return strings.TrimPrefix(line, "colo=")
		}
	}
	return ""
}

var _ Prober = (*DefaultProber)(nil)
