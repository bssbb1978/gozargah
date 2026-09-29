//go:build darwin

package sockopt

import (
	"net"
	"syscall"
)

func rawControl(conn net.Conn, fn func(fd uintptr) error) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil // not a TCP conn: nothing to configure
	}
	rc, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(raw syscall.RawConn) {
		_ = raw.Control(func(fd uintptr) { serr = fn(fd) })
	}); cerr != nil {
		return cerr
	}
	return serr
}

func setNoNagle(conn net.Conn) error {
	return rawControl(conn, func(fd uintptr) error {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	})
}

func setSendBuf(conn net.Conn, size int) error {
	return rawControl(conn, func(fd uintptr) error {
		return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	})
}
