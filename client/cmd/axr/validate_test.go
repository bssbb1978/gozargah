package main

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestValidationLabelRequiresManualSafeInput(t *testing.T) {
	if _, err := validationLabel(" \t"); err == nil {
		t.Fatal("empty label accepted")
	}
	if _, err := validationLabel("mobile\ncarrier"); err == nil {
		t.Fatal("control character accepted")
	}
	if _, err := validationLabel("01234567890123456789012345678901234567890123456789012345678901234"); err == nil {
		t.Fatal("overlong label accepted")
	}
	if got, err := validationLabel("  Irancell  "); err != nil || got != "Irancell" {
		t.Fatalf("validationLabel = %q, %v", got, err)
	}
}

func TestParseValidationDestination(t *testing.T) {
	for _, test := range []struct {
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{input: "www.cloudflare.com:443", wantHost: "www.cloudflare.com", wantPort: 443},
		{input: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: 8443},
		{input: "host:0", wantErr: true},
		{input: "host:not-a-port", wantErr: true},
		{input: "host", wantErr: true},
	} {
		host, port, err := parseValidationDestination(test.input)
		if (err != nil) != test.wantErr {
			t.Fatalf("parseValidationDestination(%q) error = %v", test.input, err)
		}
		if !test.wantErr && (host != test.wantHost || port != test.wantPort) {
			t.Fatalf("parseValidationDestination(%q) = %q:%d", test.input, host, port)
		}
	}
}

func TestValidationFailurePhasesAreCoarseAndCredentialFree(t *testing.T) {
	for _, test := range []struct{ reason, want string }{
		{"dial:secret-host-token", "tcp_dial_failed"},
		{"ws:response echoed /sub/private-token", "tls_or_websocket_upgrade_failed"},
		{"vless-ok:remote said destination token", "vless_or_worker_destination_failed"},
		{"context deadline exceeded", "timeout"},
	} {
		if got := validationFailurePhase(test.reason, false); got != test.want {
			t.Fatalf("validationFailurePhase(%q) = %q, want %q", test.reason, got, test.want)
		}
	}
	if got := validationFailurePhase("anything", true); got != "" {
		t.Fatalf("successful handshake failure phase = %q", got)
	}
}

func TestValidationReportLabelsRealMeasurementSchema(t *testing.T) {
	report := newValidationReport("golden-run", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "mobile", "carrier", "www.cloudflare.com:443", 2)
	report.Measurements = []validationMeasurement{{FallbackTier: 1, HandshakeOK: true}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema"] != "axr-network-validation/v2" || decoded["simulation"] != false || decoded["evidence_class"] != "live_socket_observation" {
		t.Fatalf("report schema/evidence does not distinguish real measurement from simulation: %s", encoded)
	}
	rows, ok := decoded["measurements"].([]any)
	if !ok || len(rows) != 1 || rows[0].(map[string]any)["fallback_tier"] != float64(1) {
		t.Fatalf("fallback tier missing from JSON report: %s", encoded)
	}
	keys := make([]string, 0, len(decoded))
	for key := range decoded {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{
		"destination", "evidence_class", "failed_handshakes", "fallback_order", "fallback_tier_counts", "finished_at_utc",
		"isp_label", "measurement_scope", "measurements", "network_label", "probe_definition", "protocol_coverage",
		"requested_repeats", "run_id", "schema", "simulation", "started_at_utc", "successful_handshakes",
		"successful_repeats", "total_handshakes", "transport_coverage",
	}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("validation report schema drift: keys=%v want=%v", keys, wantKeys)
	}

	protocols, ok := decoded["protocol_coverage"].(map[string]any)
	if !ok || !reflect.DeepEqual(protocols["client_protocols_probed"], []any{"vless"}) ||
		!reflect.DeepEqual(protocols["not_implemented_by_axr_client"], []any{"http", "hysteria2", "shadowsocks", "trojan", "vmess", "wireguard"}) {
		t.Fatalf("report must name the exact native protocol boundary: %s", encoded)
	}
	coverage, ok := decoded["transport_coverage"].(map[string]any)
	if !ok || !reflect.DeepEqual(coverage["client_transport_shapes_available"], []any{"ws", "ws-alt"}) ||
		!reflect.DeepEqual(coverage["not_implemented_by_axr_client"], []any{"grpc", "http2", "http3", "httpupgrade", "kcp", "udp", "xhttp"}) {
		t.Fatalf("report must name supported and unimplemented native transports: %s", encoded)
	}
	if !reflect.DeepEqual(transportsPerEntry, []string{"ws", "ws-alt"}) {
		t.Fatalf("probe coverage drifted from the live client transport registry: %v", transportsPerEntry)
	}
}
