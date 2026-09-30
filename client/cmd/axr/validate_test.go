package main

import (
	"encoding/json"
	"testing"
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
	report := validationReport{
		Schema: validationSchema, EvidenceClass: "live_socket_observation", Simulation: false,
		NetworkLabel: "mobile", ISPLabel: "carrier",
		TransportCoverage: validationTransportCoverage{
			ClientTransportsProbed: []string{"ws", "ws-alt"},
			NotImplementedByAXR:    []string{"grpc", "http2", "xhttp"},
		},
		Measurements: []validationMeasurement{{FallbackTier: 1, HandshakeOK: true}},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["simulation"] != false || decoded["evidence_class"] != "live_socket_observation" {
		t.Fatalf("report does not distinguish real measurement from simulation: %s", encoded)
	}
	rows, ok := decoded["measurements"].([]any)
	if !ok || len(rows) != 1 || rows[0].(map[string]any)["fallback_tier"] != float64(1) {
		t.Fatalf("fallback tier missing from JSON report: %s", encoded)
	}
	coverage, ok := decoded["transport_coverage"].(map[string]any)
	if !ok || len(coverage["client_transports_probed"].([]any)) != 2 || len(coverage["not_implemented_by_axr_client"].([]any)) != 3 {
		t.Fatalf("report must name supported and unimplemented native transports: %s", encoded)
	}
}
