// Package flowprofile shapes the client's post-handshake write pattern to
// match the packet-length and inter-packet-delay statistics of a coarse
// application class (2.15 M2: length-histogram morphing + IPD perturbation).
//
// What it does, honestly:
//   - Each profile is a piecewise length histogram (typical chunk ranges with
//     weights) plus a lognormal inter-packet-delay (IPD) distribution.
//   - The Slicer produced here decides, for every post-handshake write, how
//     many bytes go out per TCP chunk and how long the gap is. Plugged into
//     surgery.ChunkConn, a raw "constant 1400B bursts" signature becomes a
//     length/arrival mixture that approximates the chosen class.
//
// Honest boundary: this morphs the *client's own* write segmentation. It does
// not inspect payloads, does not replay captures of any real user's traffic,
// and is not a guarantee of invisibility — it makes the length/timing
// histogram look like a plausible app class instead of a synthetic relay.
package flowprofile

import (
	"math"
	"time"
)

// Rng is the random source (math/rand.Float64 style).
type Rng func() float64

// ProfileID names a target application class.
type ProfileID string

const (
	ProfileWeb    ProfileID = "web"
	ProfileVideo  ProfileID = "video"
	ProfileChat   ProfileID = "chat"
)

// ForRegime maps the measured network regime to a flow profile:
//
//	stable            -> web     (mixed request/response, the boring baseline)
//	watch             -> chat    (small, bursty, human-paced — hard to flag)
//	suspected_change  -> video   (sustained large flow — mimics bulk transfer)
//	recovering/other  -> web
func ForRegime(regime string) ProfileID {
	switch regime {
	case "watch":
		return ProfileChat
	case "suspected_change":
		return ProfileVideo
	default:
		return ProfileWeb
	}
}

// bin is one length-histogram component: chunks in [lo, hi) bytes with
// relative weight w.
type bin struct {
	lo, hi int
	w      float64
}

// Profile is one target class: a length histogram + lognormal IPD parameters.
type Profile struct {
	ID      ProfileID
	Bins    []bin
	IPDMu   float64 // lognormal mu of the gap (log-seconds)
	IPDSigma float64 // lognormal sigma
	IPDMin  time.Duration
	IPDMax  time.Duration
}

// Profiles returns the built-in class set.
func Profiles() map[ProfileID]Profile {
	return map[ProfileID]Profile{
		// web: mostly small/medium chunks (requests, JSON, HTML fragments),
		// occasional larger; human-ish gaps of tens of ms.
		ProfileWeb: {
			ID: ProfileWeb,
			Bins: []bin{
				{300, 500, 0.34},
				{500, 800, 0.30},
				{800, 1200, 0.22},
				{1200, 1400, 0.14},
			},
			IPDMu: math.Log(30 * time.Millisecond.Seconds()), IPDSigma: 0.9,
			IPDMin: 5 * time.Millisecond, IPDMax: 400 * time.Millisecond,
		},
		// video: dominated by full-size chunks, near-continuous (1..15ms).
		ProfileVideo: {
			ID: ProfileVideo,
			Bins: []bin{
				{500, 900, 0.18},
				{900, 1200, 0.30},
				{1200, 1400, 0.52},
			},
			IPDMu: math.Log(4 * time.Millisecond.Seconds()), IPDSigma: 0.7,
			IPDMin: time.Millisecond, IPDMax: 40 * time.Millisecond,
		},
		// chat: tiny, sparse, bursty with long human thinking pauses.
		ProfileChat: {
			ID: ProfileChat,
			Bins: []bin{
				{100, 250, 0.46},
				{250, 500, 0.34},
				{500, 900, 0.20},
			},
			IPDMu: math.Log(300 * time.Millisecond.Seconds()), IPDSigma: 1.0,
			IPDMin: 15 * time.Millisecond, IPDMax: 2500 * time.Millisecond,
		},
	}
}

// Get returns the named profile, falling back to web for unknown IDs.
func Get(id ProfileID) Profile {
	p := Profiles()
	if v, ok := p[id]; ok {
		return v
	}
	return p[ProfileWeb]
}

// SampleLength draws one chunk length from the profile histogram, clamped to
// [1, remaining]. The clamp keeps the final chunk short without re-rolling,
// which is what a real app also does (write what is left).
func SampleLength(p Profile, rng Rng, remaining int) int {
	if remaining < 1 {
		return 0
	}
	// cumulative weights
	total := 0.0
	for _, b := range p.Bins {
		total += b.w
	}
	if total <= 0 {
		return remaining
	}
	r := rng() * total
	for _, b := range p.Bins {
		r -= b.w
		if r >= 0 {
			continue
		}
		lo := b.lo
		if lo < 1 {
			lo = 1
		}
		hi := b.hi
		if hi > remaining {
			hi = remaining
		}
		if hi < lo {
			return remaining
		}
		return lo + int(rng()*float64(hi-lo+1))
	}
	return remaining
}

// normalDraw returns one standard normal sample via Box-Muller.
func normalDraw(rng Rng) float64 {
	for {
		u1 := rng()
		if u1 < 1e-12 {
			u1 = 1e-12
		}
		u2 := rng()
		z := math.Sqrt(-2 * math.Log(u1)) * math.Cos(2*math.Pi*u2)
		if math.IsNaN(z) || math.IsInf(z, 0) {
			continue
		}
		return z
	}
}

// SampleIPD draws one inter-packet delay from the profile's lognormal,
// clipped to [IPDMin, IPDMax].
func SampleIPD(p Profile, rng Rng) time.Duration {
	g := math.Exp(p.IPDMu + p.IPDSigma*normalDraw(rng)) // seconds
	d := time.Duration(g * float64(time.Second))
	if d < p.IPDMin {
		d = p.IPDMin
	}
	if d > p.IPDMax {
		d = p.IPDMax
	}
	return d
}

// Slicer decides the size and pre-gap of each chunk. surgery.ChunkConn
// consumes it via the surgery.Slicer interface (structural typing). It is
// stateless across calls: the consumer decides whether to honour a gap
// (ChunkConn skips the gap before the first chunk of each Write).
type Slicer struct {
	p   Profile
	rng Rng
}

// NewSlicer builds a slicer for the given regime/ID. rng must be non-nil.
func NewSlicer(id ProfileID, rng Rng) *Slicer {
	if rng == nil {
		rng = func() float64 { return 0.5 }
	}
	return &Slicer{p: Get(id), rng: rng}
}

// ProfileID returns the target class this slicer emulates.
func (s *Slicer) ProfileID() ProfileID { return s.p.ID }

// Next returns the next chunk size (clamped to remaining) and the sampled
// inter-chunk gap.
func (s *Slicer) Next(remaining int) (int, time.Duration) {
	size := SampleLength(s.p, s.rng, remaining)
	if size < 1 {
		size = 1
	}
	return size, SampleIPD(s.p, s.rng)
}
