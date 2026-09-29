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

// DefaultGap returns a randomized inter-segment gap within [min, max]
// (uniform draw — the legacy behaviour).
func DefaultGap(rng Rng, min, max time.Duration) time.Duration {
	if rng == nil || max <= min {
		return min
	}
	return min + time.Duration(rng()*float64(max-min))
}

// SkewGap returns a randomized inter-segment gap within [min, max] drawn
// from a quadratic-skewed distribution (u² of a uniform): bounded,
// NONLINEAR, and heavy toward the small end. Real interactive traffic's
// inter-packet gap statistics skew low (bursts of small gaps with the
// occasional longer one); a uniform draw spreads mass evenly and is
// statistically distinguishable. Deterministic for a given (rng) sequence.
func SkewGap(rng Rng, min, max time.Duration) time.Duration {
	if rng == nil || max <= min {
		return min
	}
	u := rng()
	return min + time.Duration(u*u*float64(max-min))
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

// ---- 2.16 — multi-segment ClientHello surgery (fragA/fragB style) ----
//
// The reference sing-box Serverless-v51 tlshello configs split the
// ClientHello into multiple masked segments with specific offset profiles
// (e.g. [6,98,1] / [0,104,1]). AXR generalizes that: the first write is cut
// into 2-4 segments at randomized offsets biased toward the SNI region of
// the record (extensions block: roughly 40-90% of a typical ClientHello),
// separated by randomized 1-8 ms micro-gaps. The kernel emits >=3 TCP
// segments for one logical ClientHello with per-connection offset/timing
// jitter — the "single clean segment carrying SNI" shape gets no match.
//
// Honest boundary (unchanged): TCP-level segmentation of bytes the TLS
// stack already produced. No record padding, no extension rewriting.

const (
	// sniLo/sniHi is the default cut window: where the SNI extension lives
	// in a typical 1.5-2.5 KB ClientHello (after session_id/ciphers,
	// before server_name + ALPN tail).
	sniLo = 0.40
	sniHi = 0.90
	// minSegBytes: the smallest segment worth keeping (a TLS record header
	// plus a few bytes).
	minSegBytes = 8
)

// PlanCuts returns `cuts` strictly increasing cut offsets inside a record of
// length n, each within [n*lo, n*hi], at least minSegBytes apart, or nil
// when infeasible (record too small, window too narrow, or the random draws
// keep colliding). Deterministic for a given (n, cuts, lo, hi, rng)
// sequence.
func PlanCuts(n, cuts int, lo, hi float64, rng Rng) []int {
	if cuts < 1 || rng == nil || n < minSegBytes*(cuts+1) {
		return nil
	}
	if lo < 0.02 {
		lo = 0.02
	}
	if hi > 0.98 {
		hi = 0.98
	}
	if hi <= lo {
		hi = lo + 0.1
	}
	loB := int(float64(n) * lo)
	hiB := int(float64(n) * hi)
	if loB < minSegBytes || hiB > n-minSegBytes {
		return nil
	}
	span := hiB - loB
	if span < minSegBytes*(cuts-1) {
		return nil
	}
	abs := func(a, b int) int {
		if a > b {
			return a - b
		}
		return b - a
	}
	for attempt := 0; attempt < 64; attempt++ {
		pts := make([]int, 0, cuts)
		ok := true
		for i := 0; i < cuts; i++ {
			p := loB + int(rng()*float64(span+1))
			if p < minSegBytes || p > n-minSegBytes {
				ok = false
				break
			}
			for _, q := range pts {
				if abs(p-q) < minSegBytes {
					ok = false
					break
				}
			}
			if !ok {
				break
			}
			pts = append(pts, p)
		}
		if ok {
			// stable ascending order
			for i := 1; i < len(pts); i++ {
				for j := i; j > 0 && pts[j] < pts[j-1]; j-- {
					pts[j], pts[j-1] = pts[j-1], pts[j]
				}
			}
			return pts
		}
	}
	return nil
}

// MultiSplitConn splits the first `left` writes (each at PlanCuts offsets
// in the [lo,hi] window) with SkewGap micro-gaps between segments. The
// first write is the TLS ClientHello; the next one or two writes are the
// rest of the client flight (certificate / key-encipherment / CCS /
// finished) — DPI systems fingerprint the first bytes AFTER the handshake
// too, so the fragmented shape extends past segment one. Writes shorter
// than minRecord, or after the split budget is spent, pass through
// untouched. It implements net.Conn.
type MultiSplitConn struct {
	inner  net.Conn
	left   int // split budget: how many writes may still be split
	cuts   int
	lo     float64
	hi     float64
	gapMin time.Duration
	gapMax time.Duration
	rng    Rng
}

// NewMultiSplitConn wraps c and splits only the FIRST write (the
// ClientHello) — the 2.16 behaviour (split budget = 1). cuts is the number
// of split points (1 => two segments, 2 => three, ...). lo/hi bound the cut
// window as a fraction of the record (use sniLo/sniHi for the SNI region).
// gapMin/gapMax bound the randomized micro-gap between segments (typical:
// 1ms and 8ms).
func NewMultiSplitConn(c net.Conn, cuts int, lo, hi float64, gapMin, gapMax time.Duration, rng Rng) *MultiSplitConn {
	return NewMultiSplitConnV2(c, cuts, 1, lo, hi, gapMin, gapMax, rng)
}

// NewMultiSplitConnV2 wraps c and splits the first `writes` writes (each
// into cuts+1 segments). writes is clamped to [1,5]; a write that is too
// small to split (or whose cuts cannot be planned) does NOT consume budget,
// so the split is still applied to the next eligible write.
func NewMultiSplitConnV2(c net.Conn, cuts, writes int, lo, hi float64, gapMin, gapMax time.Duration, rng Rng) *MultiSplitConn {
	if lo <= 0 {
		lo, hi = sniLo, sniHi
	}
	if gapMin < 0 {
		gapMin = 0
	}
	if gapMax < gapMin {
		gapMax = gapMin
	}
	if cuts < 1 {
		cuts = 1
	}
	if writes < 1 {
		writes = 1
	}
	if writes > 5 {
		writes = 5
	}
	return &MultiSplitConn{inner: c, left: writes, cuts: cuts, lo: lo, hi: hi, gapMin: gapMin, gapMax: gapMax, rng: rng}
}

func (m *MultiSplitConn) Read(b []byte) (int, error) { return m.inner.Read(b) }

// Write splits an eligible write (split budget remaining, record large
// enough) at PlanCuts offsets, honoring one SkewGap micro-gap before each
// subsequent segment. The returned count is the full write length (contract
// of net.Conn); a mid-write error is returned with the bytes already pushed.
func (m *MultiSplitConn) Write(b []byte) (int, error) {
	if m.left > 0 && len(b) >= minRecord {
		if pts := PlanCuts(len(b), m.cuts, m.lo, m.hi, m.rng); pts != nil {
			m.left-- // the budget is consumed only by a write that actually split
			bounds := make([]int, 0, len(pts)+2)
			bounds = append(bounds, 0)
			bounds = append(bounds, pts...)
			bounds = append(bounds, len(b))
			total := 0
			for i := 1; i < len(bounds); i++ {
				if i > 1 {
					if gap := SkewGap(m.rng, m.gapMin, m.gapMax); gap > 0 {
						time.Sleep(gap)
					}
				}
				n, err := m.inner.Write(b[bounds[i-1]:bounds[i]])
				total += n
				if err != nil {
					return total, err
				}
			}
			return total, nil
		}
	}
	return m.inner.Write(b)
}

func (m *MultiSplitConn) Close() error                                   { return m.inner.Close() }
func (m *MultiSplitConn) LocalAddr() net.Addr                            { return m.inner.LocalAddr() }
func (m *MultiSplitConn) RemoteAddr() net.Addr                           { return m.inner.RemoteAddr() }
func (m *MultiSplitConn) SetDeadline(t time.Time) error                  { return m.inner.SetDeadline(t) }
func (m *MultiSplitConn) SetReadDeadline(t time.Time) error              { return m.inner.SetReadDeadline(t) }
func (m *MultiSplitConn) SetWriteDeadline(t time.Time) error             { return m.inner.SetWriteDeadline(t) }
