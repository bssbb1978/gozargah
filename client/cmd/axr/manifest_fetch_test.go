package main

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestBuildManifestFetchTargetKeepsHostnameIdentityWhenDialingIP(t *testing.T) {
	target, err := buildManifestFetchTarget("https://entry.example.com/p-a/secret/axr-manifest", "", "104.16.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if target.TLSName != "entry.example.com" {
		t.Fatalf("TLS SNI = %q, want entry.example.com", target.TLSName)
	}
	if target.HTTPHost != "entry.example.com" {
		t.Fatalf("HTTP Host = %q, want entry.example.com", target.HTTPHost)
	}
	if target.DialAddr != "104.16.0.1:443" {
		t.Fatalf("dial address = %q, want 104.16.0.1:443", target.DialAddr)
	}
	cfg := manifestTLSConfig(target.TLSName)
	if cfg.InsecureSkipVerify {
		t.Fatal("manifest transport must keep certificate verification enabled")
	}
	if cfg.ServerName != target.TLSName || cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLS config does not preserve the hostname identity: %+v", cfg)
	}
}

func TestBuildManifestFetchTargetForDirectIPRequiresHostname(t *testing.T) {
	if _, err := buildManifestFetchTarget("https://104.16.0.1/p-a/secret/axr-manifest", "", ""); err == nil {
		t.Fatal("direct IP manifest URL without a hostname must be rejected")
	}
	target, err := buildManifestFetchTarget("https://104.16.0.1/p-a/secret/axr-manifest", "worker.example.com", "104.16.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if target.TLSName != "worker.example.com" || target.HTTPHost != "worker.example.com" || target.DialAddr != "104.16.0.2:443" {
		t.Fatalf("direct-IP target lost SNI/Host/dial separation: %+v", target)
	}
}

func TestManifestTargetRejectsMismatchedIdentityAndInvalidIP(t *testing.T) {
	if _, err := buildManifestFetchTarget("https://entry.example.com/path", "other.example.com", "104.16.0.1"); err == nil {
		t.Fatal("hostname override on a hostname URL must be rejected")
	}
	if _, err := buildManifestFetchTarget("https://entry.example.com/path", "", "not-an-ip"); err == nil {
		t.Fatal("invalid dial candidate must be rejected")
	}
	if _, err := buildManifestFetchTarget("http://entry.example.com/path", "", "104.16.0.1"); err == nil {
		t.Fatal("non-HTTPS manifest URL must be rejected")
	}
}

func TestSafeManifestLabelsDoNotExposeRouteKeys(t *testing.T) {
	got := safeManifestLabel("https://worker.example.com/prefix/supersecret/axr-manifest?x=y")
	if got != "https://worker.example.com/<subscription>/axr-manifest" {
		t.Fatalf("safe label = %q", got)
	}
	cached := safeManifestSourceLabel("https://worker.example.com/prefix/supersecret/axr-manifest (last-known-good)")
	if cached != "https://worker.example.com/<subscription>/axr-manifest (last-known-good)" {
		t.Fatalf("safe cached label = %q", cached)
	}
}

func TestValidatedManifestDialIPsDeduplicatesAndCanonicalizes(t *testing.T) {
	got := validatedManifestDialIPs([]string{" 104.16.0.1 ", "104.16.0.1", "2001:db8::1", "bad"})
	if len(got) != 2 || got[0] != net.ParseIP("104.16.0.1").String() || got[1] != net.ParseIP("2001:db8::1").String() {
		t.Fatalf("validated candidates = %#v", got)
	}
}
