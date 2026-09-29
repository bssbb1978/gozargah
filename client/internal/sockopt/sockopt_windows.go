//go:build windows

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
	if cerr := rc.Control(func(fd uintptr) error {
		return fn(fd)
	}); cerr != nil {
		return cerr
	}
	return nil
}

func setNoNagle(conn net.Conn) error {
	return rawControl(conn, func(fd uintptr) error {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	})
}

func setSendBuf(conn net.Conn, size int) error {
	return rawControl(conn, func(fd uintptr) error {
		return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	})
}
