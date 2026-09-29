package vlessws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// newTestClient builds a Client whose frame reader is a canned byte stream —
// the peer is the only untrusted input the tunnel has, so it must be
// fuzzable without a socket.
func newTestClient(raw []byte) *Client {
	return &Client{r: bufio.NewReader(bytes.NewReader(raw))}
}

// serverFrame builds one unmasked server frame with an explicit length
// encoding, so hostile length fields can be exercised directly.
func serverFrame(opcode byte, lengthField byte, ext []byte, payload []byte) []byte {
	out := []byte{opcode | 0x80, lengthField}
	out = append(out, ext...)
	return append(out, payload...)
}

// TestReadFrameRejectsOversized64BitLength: a peer that declares a 1 TiB
// message must be refused BEFORE the allocation. The pre-fix code called
// make([]byte, l) first, so a hostile or broken endpoint could make the
// client reserve arbitrary amounts of memory (and, on a 32-bit build, wrap
// the int conversion into a negative length and panic).
func TestReadFrameRejectsOversized64BitLength(t *testing.T) {
	var ext [8]byte
	for _, declared := range []uint64{
		1 << 40,            // 1 TiB
		1 << 62,            // absurd
		1<<64 - 1,          // all ones: no MSB check, wraps to -1
		0xFFFFFFFF00000010, // wraps to a small positive int on 64-bit? no: huge
		maxFrame + 1,       // just over the ceiling
	} {
		binary.BigEndian.PutUint64(ext[:], declared)
		c := newTestClient(serverFrame(opBinary, 127, ext[:], nil))
		_, _, err := c.readFrame()
		if err == nil {
			t.Fatalf("declared length %d must be rejected", declared)
		}
		if !errors.Is(err, errFrameTooLarge) {
			t.Fatalf("declared length %d: got %v, want errFrameTooLarge", declared, err)
		}
	}
}

// TestReadFrameAcceptsAtTheCeiling: the guard must not reject a legal frame
// that sits exactly on the limit.
func TestReadFrameAcceptsAtTheCeiling(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, maxFrame)
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], uint64(maxFrame))
	c := newTestClient(serverFrame(opBinary, 127, ext[:], payload))
	op, got, err := c.readFrame()
	if err != nil {
		t.Fatalf("a frame of exactly maxFrame must be accepted: %v", err)
	}
	if op != opBinary || len(got) != maxFrame {
		t.Fatalf("got opcode %d len %d, want %d/%d", op, len(got), opBinary, maxFrame)
	}
}

// TestReadFrameRejectsOversizedContinuation: the same ceiling applies to
// continuation fragments of a fragmented message.
func TestReadFrameRejectsOversizedContinuation(t *testing.T) {
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], 1<<50)
	first := serverFrame(opBinary, 126, []byte{0x00, 0x0A}, bytes.Repeat([]byte{1}, 10)) // FIN clear
	first[0] &^= 0x80                                                                    // clear FIN
	cont := serverFrame(opContinuation, 127, ext[:], nil)
	c := newTestClient(append(first, cont...))
	if _, _, err := c.readFrame(); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("oversized continuation: got %v, want errFrameTooLarge", err)
	}
}

// TestRecvBinaryRejectsOrphanContinuation: a message that STARTS with a
// continuation opcode is a protocol violation; delivering it as a complete
// message would hand the caller half a VLESS payload.
func TestRecvBinaryRejectsOrphanContinuation(t *testing.T) {
	c := newTestClient(serverFrame(opContinuation, 5, nil, []byte("hello")))
	if _, err := c.RecvBinary(); !errors.Is(err, errOrphanContinuation) {
		t.Fatalf("orphan continuation: got %v, want errOrphanContinuation", err)
	}
}

// TestRecvBinaryReassemblesFragmentedMessage: the legitimate counterpart —
// a fragmented message is reassembled and delivered with the FIRST frame's
// opcode.
func TestRecvBinaryReassemblesFragmentedMessage(t *testing.T) {
	first := serverFrame(opBinary, 3, nil, []byte("abc"))
	first[0] &^= 0x80
	mid := serverFrame(opContinuation, 3, nil, []byte("def"))
	mid[0] &^= 0x80
	last := serverFrame(opContinuation, 3, nil, []byte("ghi"))
	c := newTestClient(append(append(first, mid...), last...))
	op, msg, err := c.readFrame()
	if err != nil {
		t.Fatalf("reassembly failed: %v", err)
	}
	if op != opBinary || string(msg) != "abcdefghi" {
		t.Fatalf("got opcode %d payload %q, want %d/%q", op, msg, opBinary, "abcdefghi")
	}
}

// TestReadFrameRejectsMaskedServerFrame: RFC 6455 §5.1 forbids the server
// masking its frames; accepting one would mean XOR-ing nothing and parsing
// garbage as payload.
func TestReadFrameRejectsMaskedServerFrame(t *testing.T) {
	raw := []byte{0x82, 0x80 | 0x03, 0x01, 0x02, 0x03, 0x04, 'a', 'b', 'c'}
	c := newTestClient(raw)
	if _, _, err := c.readFrame(); err == nil {
		t.Fatal("a masked server frame must be rejected")
	}
}

// TestExtLenShortHeaderIsShortBuffer: a truncated extended length must
// surface as a read error, never as a bogus length.
func TestExtLenShortHeaderIsShortBuffer(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{0x01})) // 1 byte where 8 are needed
	if _, err := extLen(r, 127); err == nil {
		t.Fatal("truncated 64-bit length must error")
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("truncated length: got %v, want EOF", err)
	}
}

// silentConn accepts writes and never answers reads — an edge that completes
// the upgrade and then swallows the stream. Without an explicit deadline the
// VLESS-OK wait blocks forever and the caller's CONNECT hangs with it.
type silentConn struct {
	deadline chan struct{}
	once     sync.Once
}

func newSilentConn() *silentConn { return &silentConn{deadline: make(chan struct{})} }

func (s *silentConn) Read(b []byte) (int, error) {
	<-s.deadline
	return 0, os.ErrDeadlineExceeded
}
func (s *silentConn) Write(b []byte) (int, error) { return len(b), nil }
func (s *silentConn) Close() error                { return nil }
func (s *silentConn) LocalAddr() net.Addr         { return dummyAddr{} }
func (s *silentConn) RemoteAddr() net.Addr        { return dummyAddr{} }
func (s *silentConn) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}
func (s *silentConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		time.AfterFunc(time.Until(t), func() { s.once.Do(func() { close(s.deadline) }) })
	}
	return nil
}
func (s *silentConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "silent" }

func TestWaitVLESSOKUntilIsBounded(t *testing.T) {
	sc := newSilentConn()
	c := &Client{conn: sc, r: bufio.NewReader(sc)}

	start := time.Now()
	err := c.WaitVLESSOKUntil(time.Now().Add(150 * time.Millisecond))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a silent edge must not be reported as VLESS-OK")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("wait was not bounded: %v (err=%v)", elapsed, err)
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("returned before the deadline (%v): deadline plumbing is wrong", elapsed)
	}
}
