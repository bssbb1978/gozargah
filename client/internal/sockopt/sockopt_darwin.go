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
	// Control runs the closure on a dedicated thread with the fd valid;
	// the callback returns no error — capture it into serr.
	if cerr := rc.Control(func(fd uintptr) {
		serr = fn(fd)
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
