package main

import (
	"strings"
	"testing"
)

// Shared test vector — MUST stay byte-identical to the Worker's
// src/test/manifest-integrity.ts and docs/AXR-V3-HYPER-RESILIENCE.md.
const (
	vectorToken     = "0123456789abcdef0123"
	vectorCanonical = "gozargah-axr-manifest/v3|2.16.0|example.com|/abc123|360|ws,ws-alt|backup.example.com:backup,example.com:primary|104.16.13.37,172.67.0.1||web|90000"
	vectorSig       = "996daa7821aa8eae4b89608bff2b61a37cbf590f29826467006d80fbb7e952ac"
)

func TestManifestHMACSharedVector(t *testing.T) {
	if got := manifestHMAC(vectorCanonical, vectorToken); got != vectorSig {
		t.Fatalf("HMAC mismatch:\n got %s\n want %s", got, vectorSig)
	}
}

func TestCanonicalFromManifestMatchesVector(t *testing.T) {
	m := &manifestV3{
		Schema:              "gozargah-axr-manifest/v3",
		Version:             "2.16.0",
		Host:                "example.com",
		WSPathBase:          "/abc123",
		PathRotationMinutes: 360,
		Transports:          []string{"ws", "ws-alt"},
		Entries: []struct {
			Host string `json:"host"`
			Role string `json:"role"`
		}{
			{Host: "example.com", Role: "primary"},
			{Host: "backup.example.com", Role: "backup"}, // reverse order: must sort
		},
		CleanIPHints: []string{"104.16.13.37", "172.67.0.1"},
		FlowProfile: struct {
			Mode string `json:"mode"`
		}{Mode: "web"},
		Reconnect: struct {
			ProbeIntervalMS float64 `json:"probe_interval_ms"`
			ProbeJitterMS   float64 `json:"probe_jitter_ms"`
		}{ProbeIntervalMS: 90000},
	}
	if got := canonicalFromManifest(m); got != vectorCanonical {
		t.Fatalf("canonical mismatch:\n got %q\n want %q", got, vectorCanonical)
	}
}

func TestVerifyManifestSig(t *testing.T) {
	m := &manifestV3{
		Schema:              "gozargah-axr-manifest/v3",
		Version:             "2.16.0",
		Host:                "example.com",
		WSPathBase:          "/abc123",
		PathRotationMinutes: 360,
		Transports:          []string{"ws", "ws-alt"},
		Entries: []struct {
			Host string `json:"host"`
			Role string `json:"role"`
		}{
			{Host: "example.com", Role: "primary"},
			{Host: "backup.example.com", Role: "backup"},
		},
		CleanIPHints: []string{"104.16.13.37", "172.67.0.1"},
		FlowProfile: struct {
			Mode string `json:"mode"`
		}{Mode: "web"},
		Reconnect: struct {
			ProbeIntervalMS float64 `json:"probe_interval_ms"`
			ProbeJitterMS   float64 `json:"probe_jitter_ms"`
		}{ProbeIntervalMS: 90000},
		ManifestSig: vectorSig,
	}
	if valid, present := verifyManifestSig(m, vectorToken); !valid || !present {
		t.Fatalf("valid manifest must verify: valid=%v present=%v", valid, present)
	}
	// Tamper one structural field -> reject.
	tampered := *m
	tampered.CleanIPHints = []string{"104.16.13.37", "172.67.0.2"}
	if valid, _ := verifyManifestSig(&tampered, vectorToken); valid {
		t.Fatal("tampered manifest must fail verification")
	}
	// Wrong key -> reject.
	if valid, _ := verifyManifestSig(m, "ffffffffffffffffffff"); valid {
		t.Fatal("wrong key must fail verification")
	}
	// Absent signature -> unverified mode (not an error).
	noSig := *m
	noSig.ManifestSig = ""
	if valid, present := verifyManifestSig(&noSig, vectorToken); valid || present {
		t.Fatalf("absent signature must be (false, false), got (%v, %v)", valid, present)
	}
	// Uppercase hex from a different signer is still accepted.
	upper := *m
	upper.ManifestSig = strings.ToUpper(vectorSig)
	if valid, _ := verifyManifestSig(&upper, vectorToken); !valid {
		t.Fatal("uppercase hex signature must verify (case-insensitive compare)")
	}
}

func TestSubTokenFromURL(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://h.com/sub/0123456789abcdef0123/axr-manifest", "0123456789abcdef0123"},
		{"https://h.com/gozargah-sub/abc123/axr-manifest", "abc123"},
		{"https://h.com/sub/abc123/axr-manifest?x=1", "abc123"},
		{"https://h.com/sub/axr-manifest", ""},  // no token segment
		{"https://h.com/other/abc123/feed", ""}, // not a manifest URL
		{"not a url", ""},
	}
	for i, c := range cases {
		if got := subTokenFromURL(c.url); got != c.want {
			t.Fatalf("case %d: got %q want %q", i, got, c.want)
		}
	}
}

func TestSubscriptionRoutePrefixFromURL(t *testing.T) {
	if got := subscriptionRoutePrefixFromURL("https://worker.example.com/p-0123456789abcdef01234567/" + strings.Repeat("a", 64) + "/axr-manifest"); got != "p-0123456789abcdef01234567" {
		t.Fatalf("dynamic route prefix = %q", got)
	}
	if got := subscriptionRoutePrefixFromURL("https://worker.example.com/sub/token/axr-manifest"); got != "" {
		t.Fatalf("legacy subscription must not claim a dynamic prefix: %q", got)
	}
}

func TestHarvestURLFromManifest(t *testing.T) {
	got := harvestURLFromManifest("https://panel.example.com/sub/tok123/axr-manifest")
	want := "https://panel.example.com/gozargah/api/network/harvest"
	if got != want {
		t.Fatalf("harvest URL: got %q want %q", got, want)
	}
	if harvestURLFromManifest("bad") != "" {
		t.Fatal("bad URL must return empty")
	}
	if harvestURLFromManifest("https://104.16.0.1/prefix/key/axr-manifest") != "" {
		t.Fatal("IP manifest URL without hostname must not create a raw-IP harvest URL")
	}
	if got := harvestURLFromManifest("https://104.16.0.1/prefix/key/axr-manifest", "worker.example.com"); got != "https://worker.example.com/gozargah/api/network/harvest" {
		t.Fatalf("IP manifest harvest URL = %q", got)
	}
}

func TestJSNumberFormatting(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{360, "360"},
		{90000, "90000"},
		{0, "0"},
		{3.5, "3.5"},
	}
	for i, c := range cases {
		if got := jsNumber(c.in); got != c.want {
			t.Fatalf("case %d: jsNumber(%v) = %q want %q", i, c.in, got, c.want)
		}
	}
}
