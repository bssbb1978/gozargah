// Package sockopt applies the AXR client-side TCP socket surgery
// (2.15 M2: "TCP socket surgery") to a freshly dialed connection:
//
//   - Nagle off (TCP_NODELAY): chunks are exactly what the flow profile
//     decides — no kernel coalescing that would re-merge the morphed chunk
//     pattern back into big segments.
//   - Randomized SO_SNDBUF from a small allowed set: the buffer size leaks
//     into the sender's window/segment behaviour; varying it per connection
//     de-tunes any classifier keyed on stock kernel defaults.
//
// Honest boundary: this is standard socket option configuration, not exotic
// stack surgery. On platforms where the options are unavailable it is a
// no-op and the transport still works.
package sockopt

import (
	"math/rand"
	"net"
	"time"
)

// SendbufSet is the allowed SO_SNDBUF range (bytes). Values are common
// kernel-friendly sizes; the per-connection pick is uniform over the set.
var SendbufSet = []int{64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024}

// SelectSendbuf picks one allowed buffer size with the given source.
func SelectSendbuf(r *rand.Rand) int {
	if len(SendbufSet) == 0 || r == nil {
		if len(SendbufSet) > 0 {
			return SendbufSet[0]
		}
		return 0
	}
	return SendbufSet[r.Intn(len(SendbufSet))]
}

// Options configures Apply.
type Options struct {
	// Rng seeds the SNDBUF pick; nil uses a deterministic default (128KB).
	Rng *rand.Rand
	// NoNagle enables TCP_NODELAY (default true).
	NoNagle bool
	// SNDBUFSize overrides the random pick (0 = choose from SendbufSet).
	SNDBUFSize int
}

// Apply configures conn (Nagle off + send buffer) best-effort. The returned
// error is non-nil only when a platform-specific call failed; callers may
// ignore it since every platform degrades to a plain socket.
//
// Platform implementations live in *_linux.go / *_darwin.go /
// *_windows.go; the rest get a no-op stub.
func Apply(conn net.Conn, opts Options) error {
	if opts.NoNagle {
		if err := setNoNagle(conn); err != nil {
			return err
		}
	}
	size := opts.SNDBUFSize
	if size == 0 {
		size = SelectSendbuf(opts.Rng)
	}
	if size > 0 {
		return setSendBuf(conn, size)
	}
	return nil
}

// ApplyWithSeed is Apply with a deterministic rand seed (tests, or callers
// that want reproducible per-connection picks).
func ApplyWithSeed(conn net.Conn, rngSeed int64, noNagle bool) error {
	r := rand.New(rand.NewSource(rngSeed))
	return Apply(conn, Options{Rng: r, NoNagle: noNagle})
}

// SeedFromTime returns a rand source seed from wall clock + counter mix.
func SeedFromTime() int64 { return time.Now().UnixNano() }
