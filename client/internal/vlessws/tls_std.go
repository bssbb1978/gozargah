//go:build !axr_utls

package vlessws

import (
	"crypto/tls"
	"net"
)

// tlsClient is the default (stdlib) TLS dial. The fp argument is accepted
// for interface compatibility but NOT used in this build: the handshake is
// performed with the OS-native Go TLS identity. Build with -tags axr_utls
// to enable uTLS identity rotation (chrome/firefox/safari/randomized).
func tlsClient(conn net.Conn, host, fp string, skipCert bool) (net.Conn, error) {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipCert,
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return tc, nil
}
