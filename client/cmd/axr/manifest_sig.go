package main

// 2.16 — AXR manifest v3 integrity (client half).
//
// The Worker signs the structural fields of the AXR manifest with
// HMAC-SHA256 keyed by the user's subscription token. The client
// recomputes the same canonical string from the parsed JSON and verifies
// the tag in constant time. On mismatch the manifest is REJECTED and the
// core keeps its last-known-good state (persisted to manifest-lastgood.json
// for audit); on missing signature (older workers) it proceeds in
// unverified v2 mode with a one-time log note.
//
// CONTRACT: the canonical field order/format below must stay byte-identical
// to src/subscription.ts manifestCanonical() and the pinned test vector in
// docs/AXR-V3-HYPER-RESILIENCE.md.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// manifestV3 is the subset of the manifest the client consumes. Unknown
// fields are ignored by the JSON decoder.
type manifestV3 struct {
	Schema              string   `json:"schema"`
	Version             string   `json:"version"`
	Host                string   `json:"host"`
	WSPathBase          string   `json:"ws_path_base"`
	PathRotationMinutes float64  `json:"path_rotation_minutes"`
	Transports          []string `json:"transports"`
	Entries             []struct {
		Host string `json:"host"`
		Role string `json:"role"`
	} `json:"entries"`
	CleanIPHints []string `json:"clean_ip_hints"`
	FrontingHint string   `json:"fronting_hint"`
	Fingerprint  struct {
		Current string `json:"current"`
	} `json:"fingerprint"`
	FlowProfile struct {
		Mode string `json:"mode"`
	} `json:"flow_profile"`
	Reconnect struct {
		ProbeIntervalMS float64 `json:"probe_interval_ms"`
	} `json:"reconnect"`
	ManifestSig string `json:"manifest_sig"`
	// 2.17 — canary liveness target (convenience mirror; the authoritative
	// host is the signed entries field role "canary"). Absent when the
	// operator configured no AXR_CANARY_HOST.
	Canary struct {
		Host       string  `json:"host"`
		Expect     string  `json:"expect"`
		IntervalMS float64 `json:"interval_ms"`
	} `json:"canary,omitempty"`
}

// canonicalFromManifest builds the EXACT canonical string the Worker's
// manifestCanonical() builds: 11 fields, fixed order, '|'-joined:
//
//	schema | version | host | ws_path_base | path_rotation_minutes |
//	transports(csv) | entries(host:role, sorted,csv) | clean_ip_hints(csv) |
//	fronting_hint | flow_profile.mode | reconnect.probe_interval_ms
//
// Number formatting matches JavaScript's String(number) for the values this
// feed carries (integers without a decimal point).
func canonicalFromManifest(m *manifestV3) string {
	entryKeys := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		entryKeys = append(entryKeys, e.Host+":"+e.Role)
	}
	sort.Strings(entryKeys)
	return strings.Join([]string{
		m.Schema,
		m.Version,
		m.Host,
		m.WSPathBase,
		jsNumber(m.PathRotationMinutes),
		strings.Join(m.Transports, ","),
		strings.Join(entryKeys, ","),
		strings.Join(m.CleanIPHints, ","),
		m.FrontingHint,
		m.FlowProfile.Mode,
		jsNumber(m.Reconnect.ProbeIntervalMS),
	}, "|")
}

// jsNumber formats a finite number the way JavaScript's String() does for
// the integer-valued magnitudes this feed carries (no exponent, no trailing
// .0). Non-integer values fall back to the shortest round-trip form, which
// also matches JS for < 1e21.
func jsNumber(v float64) string {
	if v == float64(int64(v)) && v < 1e21 && v > -1e21 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// manifestHMAC is HMAC-SHA256 hex over the canonical string, keyed by token.
func manifestHMAC(canonical, token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyManifestSig reports whether m.ManifestSig authenticates under
// token. An empty signature is "absent" (older worker) -> (false, true).
func verifyManifestSig(m *manifestV3, token string) (valid, present bool) {
	if m.ManifestSig == "" {
		return false, false
	}
	if token == "" {
		return false, true
	}
	want := manifestHMAC(canonicalFromManifest(m), token)
	return hmac.Equal([]byte(want), []byte(strings.ToLower(m.ManifestSig))), true
}

// subTokenFromURL extracts the subscription token from a manifest URL of the
// form https://host/{subpath}/{token}/axr-manifest (the path segment
// directly before "axr-manifest"). Returns "" when it cannot.
func subTokenFromURL(manifestURL string) string {
	u, err := url.Parse(manifestURL)
	if err != nil {
		return ""
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] == "axr-manifest" && i >= 2 {
			return segs[i-1]
		}
	}
	return ""
}

// harvestURLFromManifest derives the default harvest endpoint from the
// manifest URL's host: https://<host>/<panelPath>/api/network/harvest with
// the Worker's default panel path ("gozargah"). An explicit config value
// always wins.
func harvestURLFromManifest(manifestURL string) string {
	u, err := url.Parse(manifestURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return "https://" + u.Hostname() + "/gozargah/api/network/harvest"
}
