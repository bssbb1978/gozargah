package surgery

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// shortWriter is a net.Conn whose Write accepts at most `limit` bytes per
// call and reports the short count WITH a nil error — the case net.Conn's
// contract requires the caller to surface as io.ErrShortWrite.
type shortWriter struct {
	limit int
	got   int // total bytes accepted
}

func (s *shortWriter) Write(b []byte) (int, error) {
	if len(b) > s.limit {
		s.got += s.limit
		return s.limit, nil // short write, no error
	}
	s.got += len(b)
	return len(b), nil
}

func (s *shortWriter) Read(b []byte) (int, error)       { return 0, io.EOF }
func (s *shortWriter) Close() error                     { return nil }
func (s *shortWriter) LocalAddr() net.Addr              { return fakeAddr("local") }
func (s *shortWriter) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (s *shortWriter) SetDeadline(time.Time) error      { return nil }
func (s *shortWriter) SetReadDeadline(time.Time) error  { return nil }
func (s *shortWriter) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

func seq(values ...float64) Rng {
	i := 0
	return func() float64 {
		if i >= len(values) {
			return 0.5
		}
		v := values[i]
		i++
		return v
	}
}

// cycle repeats the given values forever — PlanCuts needs VARIED draws to
// place distinct cut points (a constant source can never satisfy the
// minimum-separation rule), while staying fully deterministic.
func cycle(values ...float64) Rng {
	i := 0
	return func() float64 {
		v := values[i%len(values)]
		i++
		return v
	}
}

// TestChunkConnReportsShortWrite: ChunkConn fragments one write into several
// inner writes. Before the fix a short inner write was counted as if it had
// been fully accepted, so the caller (the TLS layer) believed the record had
// been flushed while bytes were silently dropped — a corrupted stream with
// no error anywhere.
func TestChunkConnReportsShortWrite(t *testing.T) {
	inner := &shortWriter{limit: 100}
	c := NewChunkConn(inner, 512, 512, 0, seq(0.5))
	n, err := c.Write(make([]byte, 2048))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v (n=%d)", err, n)
	}
	if n != inner.got {
		t.Fatalf("reported %d bytes but the conn accepted %d", n, inner.got)
	}
	if n >= 2048 {
		t.Fatalf("a short write must not report the full length (got %d)", n)
	}
}

// TestSplitConnReportsShortWrite: same contract for the ClientHello splitter.
func TestSplitConnReportsShortWrite(t *testing.T) {
	inner := &shortWriter{limit: 10}
	s := NewSplitConn(inner, 0, 0, seq(0.9))
	n, err := s.Write(make([]byte, 512))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v (n=%d)", err, n)
	}
	if n != inner.got {
		t.Fatalf("reported %d bytes but the conn accepted %d", n, inner.got)
	}
}

// TestMultiSplitConnReportsShortWrite: the real-time segments must be exact;
// a partially written segment looks like a complete record boundary to the
// peer and corrupts the handshake.
func TestMultiSplitConnReportsShortWrite(t *testing.T) {
	inner := &shortWriter{limit: 32}
	m := NewMultiSplitConnV2(inner, 2, 1, 0.4, 0.9, 0, 0, cycle(0.9, 0.2, 0.6))
	n, err := m.Write(make([]byte, 2048))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected io.ErrShortWrite, got %v (n=%d)", err, n)
	}
	if n != inner.got {
		t.Fatalf("reported %d bytes but the conn accepted %d", n, inner.got)
	}
}

// TestExactWriteIsNotShortWrite: the guard must not fire when every inner
// write is complete (the common case).
func TestExactWriteIsNotShortWrite(t *testing.T) {
	inner := &shortWriter{limit: 1 << 20}
	c := NewChunkConn(inner, 256, 512, 0, seq(0.25, 0.75))
	n, err := c.Write(make([]byte, 1000))
	if err != nil {
		t.Fatalf("unexpected error on a complete write: %v", err)
	}
	if n != 1000 || inner.got != 1000 {
		t.Fatalf("n=%d inner=%d, want 1000/1000", n, inner.got)
	}
	m := NewMultiSplitConnV2(inner, 1, 1, 0.4, 0.9, 0, 0, cycle(0.7, 0.3))
	if n, err := m.Write(make([]byte, 512)); err != nil || n != 512 {
		t.Fatalf("multi-split complete write: n=%d err=%v, want 512/nil", n, err)
	}
}
