//go:build !linux && !darwin && !windows

package sockopt

import "net"

// Unsupported platforms: the socket surgery is a documented no-op so the
// transport still works everywhere.
func setNoNagle(conn net.Conn) error { return nil }
func setSendBuf(conn net.Conn, size int) error { return nil }
