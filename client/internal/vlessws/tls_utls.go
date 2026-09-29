//go:build axr_utls

package vlessws

import (
	"net"

	utls "github.com/refraction-networking/utls"
)

// idByFP maps AXR fingerprint names to uTLS ClientHello identities.
// Pinned to github.com/refraction-networking/utls v1.6.7 API:
// UClient(conn, *Config, ClientHelloID) + *_Auto presets.
func idByFP(fp string) utls.ClientHelloID {
	switch fp {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "randomized":
		return utls.HelloRandomized
	case "chrome", "":
		return utls.HelloChrome_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// tlsClient performs the TLS handshake with the selected uTLS identity.
// Certificate validation is against host even when the dial address is an
// explicit clean IP, unless skipCert is set.
func tlsClient(conn net.Conn, host, fp string, skipCert bool) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         host,
		MinVersion:         utls.VersionTLS12,
		InsecureSkipVerify: skipCert,
	}
	uc := utls.UClient(conn, cfg, idByFP(fp))
	if err := uc.Handshake(); err != nil {
		return nil, err
	}
	return uc, nil
}
