// Package surgery performs the AXR client-side low-level transport surgery.
//
// What it does (honestly named):
//
//  1. SplitConn wraps a fresh TCP connection and splits the FIRST write —
//     the TLS ClientHello record(s) — into two TCP segments at a randomized
//     byte offset inside the handshake body, separated by a randomized
//     20–120 ms gap. The kernel then emits ≥2 TCP segments for a single
//     logical ClientHello, with a timing inter-segment delta that varies
//     per connection. This targets the "single clean segment carrying SNI"
//     shape that passive filters look for.
//
//  2. ChunkConn wraps the post-handshake (TLS) connection and fragments
//     each application write into randomized 512–1400 B pieces with small
//     randomized gaps: TCP-level chunking, i.e. varied inter-segment
//     timing/length statistics.
//
// Honest boundary: this is TCP-level segmentation and chunking of bytes the
// TLS layer already produced. It is NOT TLS record padding (Go's TLS stack
// and refraction-networking/utls expose no record-padding control), and it
// does not rewrite extensions, ciphers, or SNI — those live in the uTLS
// identity selection (fingerprint rotation), not here.
package surgery

import (
	"net"
	"time"
)

// Rng is the random source used for offsets/gaps (math/rand.Float64 style).
type Rng func() float64

const (
	// minRecord is the smallest write that looks like a TLS handshake
	// record worth splitting; below that, leave it alone.
	minRecord = 96
	// split fraction bounds within the record (keeps the 5-byte TLS record
	// header plus part of the handshake body in segment one, and splits the
	// extensions block — where SNI lives — in a meaningful fraction).
	splitLo = 0.25
	splitHi = 0.85
)

// PlanHelloSplit returns a randomized split offset inside a record of
// length n, or (0, false) when the record is too small to split.
// The offset is deterministic for a given (n, rng) sequence, which keeps
// tests reproducible with a seeded source.
func PlanHelloSplit(n int, rng Rng) (int, bool) {
	if n < minRecord || rng == nil {
		return 0, false
	}
	frac := splitLo + (splitHi-splitLo)*rng()
	off := int(float64(n) * frac)
	if off < 8 || off >= n-8 {
		return 0, false
	}
	return off, true
}

// DefaultGap returns a randomized inter-segment gap within [min, max].
func DefaultGap(rng Rng, min, max time.Duration) time.Duration {
	if rng == nil || max <= min {
		return min
	}
	return min + time.Duration(rng()*float64(max-min))
}

// SplitConn splits only the first write (the ClientHello) into two segments.
// All subsequent writes pass through untouched. It implements net.Conn.
type SplitConn struct {
	inner  net.Conn
	done   bool
	gapMin time.Duration
	gapMax time.Duration
	rng    Rng
}

// NewSplitConn wraps c. gapMin/gapMax bound the randomized gap between the
// two ClientHello segments (typical: 20ms and 120ms).
func NewSplitConn(c net.Conn, gapMin, gapMax time.Duration, rng Rng) *SplitConn {
	return &SplitConn{inner: c, gapMin: gapMin, gapMax: gapMax, rng: rng}
}

func (s *SplitConn) Read(b []byte) (int, error) { return s.inner.Read(b) }

func (s *SplitConn) Write(b []byte) (int, error) {
	if !s.done {
		s.done = true // only the very first write is ever split
		if off, ok := PlanHelloSplit(len(b), s.rng); ok {
			if _, err := s.inner.Write(b[:off]); err != nil {
				return 0, err
			}
			if gap := DefaultGap(s.rng, s.gapMin, s.gapMax); gap > 0 {
				time.Sleep(gap)
			}
			n, err := s.inner.Write(b[off:])
			return off + n, err
		}
	}
	return s.inner.Write(b)
}

func (s *SplitConn) Close() error                                   { return s.inner.Close() }
func (s *SplitConn) LocalAddr() net.Addr                            { return s.inner.LocalAddr() }
func (s *SplitConn) RemoteAddr() net.Addr                           { return s.inner.RemoteAddr() }
func (s *SplitConn) SetDeadline(t time.Time) error                  { return s.inner.SetDeadline(t) }
func (s *SplitConn) SetReadDeadline(t time.Time) error              { return s.inner.SetReadDeadline(t) }
func (s *SplitConn) SetWriteDeadline(t time.Time) error             { return s.inner.SetWriteDeadline(t) }

// Slicer decides the size and pre-gap of each chunk (flowprofile implements
// this interface for app-class morphing). Next must return a size in
// [1, remaining]. The consumer never sleeps for the gap before the first
// chunk of a Write.
type Slicer interface {
	Next(remaining int) (size int, gap time.Duration)
}

// ChunkConn fragments post-handshake writes into randomized-sized pieces.
// It is deliberately named chunking (TCP-level), not padding. With a
// Slicer (NewChunkConnWith) the size/gap sequence is drawn from an
// application-class profile; without one it stays the original uniform
// [min, max] + fixed-gap behaviour.
type ChunkConn struct {
	inner net.Conn
	min   int
	max   int
	gap   time.Duration // fixed micro-gap; 0 disables it
	rng   Rng
	slice Slicer
}

// NewChunkConn wraps c with pieces in [min, max] bytes.
func NewChunkConn(c net.Conn, min, max int, gap time.Duration, rng Rng) *ChunkConn {
	if min < 128 {
		min = 128
	}
	if max < min {
		max = min
	}
	return &ChunkConn{inner: c, min: min, max: max, gap: gap, rng: rng}
}

// NewChunkConnWith wraps c and delegates all size/gap decisions to sl.
func NewChunkConnWith(c net.Conn, sl Slicer) *ChunkConn {
	return &ChunkConn{inner: c, slice: sl}
}

func (k *ChunkConn) Read(b []byte) (int, error) { return k.inner.Read(b) }

func (k *ChunkConn) Write(b []byte) (int, error) {
	if k.slice == nil && len(b) < k.min {
		return k.inner.Write(b)
	}
	total := 0
	for total < len(b) {
		var size int
		var gap time.Duration
		if k.slice != nil {
			size, gap = k.slice.Next(len(b) - total)
		} else {
			span := k.max - k.min
			size = k.min
			if span > 0 && k.rng != nil {
				size = k.min + int(k.rng()*float64(span+1))
			}
			if total > 0 {
				gap = k.gap
			}
		}
		if size > len(b)-total {
			size = len(b) - total
		}
		if size < 1 {
			size = len(b) - total
		}
		if total > 0 && gap > 0 {
			time.Sleep(gap)
		}
		if _, err := k.inner.Write(b[total : total+size]); err != nil {
			return total, err
		}
		total += size
	}
	return total, nil
}

func (k *ChunkConn) Close() error                        { return k.inner.Close() }
func (k *ChunkConn) LocalAddr() net.Addr                 { return k.inner.LocalAddr() }
func (k *ChunkConn) RemoteAddr() net.Addr                { return k.inner.RemoteAddr() }
func (k *ChunkConn) SetDeadline(t time.Time) error       { return k.inner.SetDeadline(t) }
func (k *ChunkConn) SetReadDeadline(t time.Time) error   { return k.inner.SetReadDeadline(t) }
func (k *ChunkConn) SetWriteDeadline(t time.Time) error  { return k.inner.SetWriteDeadline(t) }
