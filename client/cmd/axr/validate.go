package main

// `axr validate` records repeatable VLESS-over-WebSocket handshake outcomes
// from the machine and network on which the command is run. It never labels
// synthetic tests as measurements; synthetic DPI cases stay in Go tests.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bssbb1978/gozargah/axr/internal/evade"
	"github.com/bssbb1978/gozargah/axr/internal/flowprofile"
	"github.com/bssbb1978/gozargah/axr/internal/vlessws"
)

const validationSchema = "axr-network-validation/v2"

// validationReport is one locally measured run. `simulation` is always false
// here; tests do not construct/export this report from simulated probe data.
type validationProtocolCoverage struct {
	ClientProtocolsProbed []string `json:"client_protocols_probed"`
	NotImplementedByAXR   []string `json:"not_implemented_by_axr_client"`
	Note                  string   `json:"note"`
}

type validationTransportCoverage struct {
	ClientTransportShapes []string `json:"client_transport_shapes_available"`
	NotImplementedByAXR   []string `json:"not_implemented_by_axr_client"`
	Note                  string   `json:"note"`
}

type validationReport struct {
	Schema               string                      `json:"schema"`
	EvidenceClass        string                      `json:"evidence_class"`
	MeasurementScope     string                      `json:"measurement_scope"`
	Simulation           bool                        `json:"simulation"`
	RunID                string                      `json:"run_id"`
	StartedAtUTC         string                      `json:"started_at_utc"`
	FinishedAtUTC        string                      `json:"finished_at_utc"`
	NetworkLabel         string                      `json:"network_label"`
	ISPLabel             string                      `json:"isp_label"`
	Destination          string                      `json:"destination"`
	ProbeDefinition      string                      `json:"probe_definition"`
	FallbackOrder        string                      `json:"fallback_order"`
	ProtocolCoverage     validationProtocolCoverage  `json:"protocol_coverage"`
	TransportCoverage    validationTransportCoverage `json:"transport_coverage"`
	RequestedRepeats     int                         `json:"requested_repeats"`
	SuccessfulRepeats    int                         `json:"successful_repeats"`
	TotalHandshakes      int                         `json:"total_handshakes"`
	SuccessfulHandshakes int                         `json:"successful_handshakes"`
	FailedHandshakes     int                         `json:"failed_handshakes"`
	FallbackTierCounts   map[string]int              `json:"fallback_tier_counts"`
	Measurements         []validationMeasurement     `json:"measurements"`
}

type validationMeasurement struct {
	ObservedAtUTC string  `json:"observed_at_utc"`
	Repeat        int     `json:"repeat"`
	Attempt       int     `json:"attempt"`
	FallbackTier  int     `json:"fallback_tier"`
	EntryHost     string  `json:"entry_host"`
	DialAddress   string  `json:"dial_address"`
	Transport     string  `json:"transport"`
	HandshakeOK   bool    `json:"handshake_ok"`
	LatencyMS     float64 `json:"latency_ms"`
	FailurePhase  string  `json:"failure_phase,omitempty"`
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "", "path to axr.json (required; credentials stay local)")
	network := fs.String("network", "", "manual network label, e.g. mobile or fixed (required; never inferred)")
	isp := fs.String("isp", "", "manual ISP/carrier label (required; never inferred)")
	destination := fs.String("destination", "www.cloudflare.com:443", "TCP destination used to confirm the Worker-side VLESS connect")
	repeats := fs.Int("repeats", 5, "independent fallback runs (1..20)")
	timeout := fs.Duration("timeout", 12*time.Second, "maximum time per candidate handshake (1s..60s)")
	output := fs.String("out", "", "also write the JSON report to this file (mode 0600)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*configPath) == "" {
		fatalf("validate: -config is required")
	}
	networkLabel, err := validationLabel(*network)
	if err != nil {
		fatalf("validate: -network: %v", err)
	}
	ispLabel, err := validationLabel(*isp)
	if err != nil {
		fatalf("validate: -isp: %v", err)
	}
	destHost, destPort, err := parseValidationDestination(*destination)
	if err != nil {
		fatalf("validate: -destination: %v", err)
	}
	if *repeats < 1 || *repeats > 20 {
		fatalf("validate: -repeats must be between 1 and 20")
	}
	if *timeout < time.Second || *timeout > 60*time.Second {
		fatalf("validate: -timeout must be between 1s and 60s")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("validate: load config: %v", err)
	}
	server, err := newServer(cfg, newLogger(false), *timeout)
	if err != nil {
		fatalf("validate: initialize client: %v", err)
	}
	defer server.shutdown()

	uid, err := validationRunID()
	if err != nil {
		fatalf("validate: create run id: %v", err)
	}
	started := time.Now().UTC()
	report := newValidationReport(
		uid, started, networkLabel, ispLabel,
		net.JoinHostPort(destHost, strconv.Itoa(destPort)), *repeats,
	)

	uuid, _ := vlessws.UUIDFromString(cfg.UUID)
	header, err := vlessws.BuildVLESSHeader(uuid, destHost, uint16(destPort), false)
	if err != nil {
		fatalf("validate: build VLESS handshake: %v", err)
	}
	escalation := evade.Escalation{
		Stance: evade.StanceSteady, WSMinB: 256, WSMaxB: 16384, WSCount: 4, WSGapMS: 3,
	}

	for repeat := 1; repeat <= *repeats; repeat++ {
		candidates := server.failover.FailoverOrder(nil)
		if len(candidates) == 0 {
			fatalf("validate: no failover candidates are available")
		}
		for tier, candidate := range candidates {
			startedAttempt := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			probeConn, peerConn := net.Pipe()
			handshakeOK := false
			result := server.attemptTunnel(ctx, probeConn, candidate, header, flowprofile.ProfileWeb, escalation, destHost, destPort, func(code byte) {
				handshakeOK = code == 0
				// Use a non-EOF deadline so attemptTunnel's pump closes the
				// probe tunnel instead of retaining a warm user session.
				_ = probeConn.SetDeadline(time.Now().Add(-time.Second))
			})
			cancel()
			_ = probeConn.Close()
			_ = peerConn.Close()
			latency := result.rttMS
			if latency <= 0 {
				latency = float64(time.Since(startedAttempt).Microseconds()) / 1000
			}
			ok := result.ok && handshakeOK
			row := validationMeasurement{
				ObservedAtUTC: startedAttempt.UTC().Format(time.RFC3339Nano),
				Repeat:        repeat,
				Attempt:       tier + 1,
				FallbackTier:  tier,
				EntryHost:     candidate.Endpoint.Host,
				DialAddress:   candidate.DialAddr,
				Transport:     candidate.Endpoint.Transport,
				HandshakeOK:   ok,
				LatencyMS:     latency,
				FailurePhase:  validationFailurePhase(result.reason, ok),
			}
			report.Measurements = append(report.Measurements, row)
			report.TotalHandshakes++
			report.FallbackTierCounts[strconv.Itoa(tier)]++
			if ok {
				report.SuccessfulHandshakes++
				report.SuccessfulRepeats++
				server.failover.Observe(candidate.Endpoint, candidate.DialAddr, true, latency, "validation_ok", time.Now())
				break
			}
			report.FailedHandshakes++
			server.failover.Observe(candidate.Endpoint, candidate.DialAddr, false, latency, validationFailurePhase(result.reason, false), time.Now())
		}
	}
	report.FinishedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatalf("validate: encode report: %v", err)
	}
	encoded = append(encoded, '\n')
	if *output != "" {
		if dir := filepath.Dir(*output); dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				fatalf("validate: create output directory: %v", err)
			}
		}
		if err := os.WriteFile(*output, encoded, 0o600); err != nil {
			fatalf("validate: write report: %v", err)
		}
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		fatalf("validate: write report to stdout: %v", err)
	}
}

var notImplementedAXRProtocols = []string{"http", "hysteria2", "shadowsocks", "trojan", "vmess", "wireguard"}
var notImplementedAXRTransports = []string{"grpc", "http2", "http3", "httpupgrade", "kcp", "udp", "xhttp"}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func newValidationReport(runID string, started time.Time, network, isp, destination string, repeats int) validationReport {
	return validationReport{
		Schema:           validationSchema,
		EvidenceClass:    "live_socket_observation",
		MeasurementScope: "current host route; network and ISP labels are operator supplied and not independently verified",
		Simulation:       false,
		RunID:            runID,
		StartedAtUTC:     started.UTC().Format(time.RFC3339Nano),
		NetworkLabel:     network,
		ISPLabel:         isp,
		Destination:      destination,
		ProbeDefinition:  "TCP dial + TLS + WebSocket upgrade + VLESS OK + Worker-side TCP connect to destination; no application payload",
		FallbackOrder:    "AXR failover health/priority candidate order; tier is the zero-based attempted candidate index",
		ProtocolCoverage: validationProtocolCoverage{
			ClientProtocolsProbed: []string{"vless"},
			NotImplementedByAXR:   cloneStrings(notImplementedAXRProtocols),
			Note:                  "Only the native VLESS-over-WebSocket relay is probed. Other protocol profiles may be generated for an external engine but are not implemented by this Go client.",
		},
		TransportCoverage: validationTransportCoverage{
			ClientTransportShapes: cloneStrings(transportsPerEntry),
			NotImplementedByAXR:   cloneStrings(notImplementedAXRTransports),
			Note:                  "ws-alt is the same WebSocket protocol over an alternate path/query shape. The listed transports are not implemented by the native Go client; TCP here is only the socket substrate.",
		},
		RequestedRepeats:   repeats,
		FallbackTierCounts: map[string]int{},
		Measurements:       make([]validationMeasurement, 0, repeats),
	}
}

func validationLabel(input string) (string, error) {
	label := strings.TrimSpace(input)
	if label == "" {
		return "", fmt.Errorf("a manual label is required")
	}
	if len(label) > 64 {
		return "", fmt.Errorf("label exceeds 64 bytes")
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("control characters are not allowed")
		}
	}
	return label, nil
}

func parseValidationDestination(input string) (string, int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(input))
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port must be in 1..65535")
	}
	for _, r := range host {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", 0, fmt.Errorf("host contains whitespace or control characters")
		}
	}
	return host, port, nil
}

func validationRunID() (string, error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(bytes[:]), nil
}

func validationFailurePhase(reason string, success bool) string {
	if success {
		return ""
	}
	switch {
	case strings.HasPrefix(reason, "dial:"):
		return "tcp_dial_failed"
	case strings.HasPrefix(reason, "ws:"):
		return "tls_or_websocket_upgrade_failed"
	case strings.HasPrefix(reason, "vless-ok:"):
		return "vless_or_worker_destination_failed"
	case strings.Contains(strings.ToLower(reason), "timeout"), strings.Contains(strings.ToLower(reason), "deadline"):
		return "timeout"
	default:
		return "handshake_failed"
	}
}
