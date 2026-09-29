// Package bandit is the AXR client-side decision core: a lightweight,
// zero-dependency LinUCB contextual bandit that learns which
// (entry host, transport, TLS fingerprint) arm is currently carrying traffic
// best *under the current network conditions*, and prunes arms that keep
// degrading.
//
// 2.15 upgrade: UCB1 -> LinUCB
//   - UCB1 scores an arm by a single mean reward plus a pull-count bonus.
//     It cannot express "arm A is good on a clean pipe but terrible when RSTs
//     spike". LinUCB scores each arm as a linear function of a context
//     vector (see Context / features), so the same entry can be preferred or
//     avoided as the measured conditions change. That is the whole point for
//     a network whose behaviour is non-stationary.
//
// 2.16 upgrade: 7-dim -> 16-dim context (AXR-v3). The v3 additions and their
// honest data sources (all LOCAL client measurements — nothing else):
//   - f7  throughput level     EWMA of measured tunnel bytes/sec
//   - f8  loss velocity        recent (8-obs) drop rate minus window drop rate
//   - f9  TLS error rate       window fraction failing at the TLS handshake
//   - f10 entry churn          0/1 proxy: the best dial address changed since
//                              the last success (a BGP-flap/anyshift proxy —
//                              the client cannot see routing tables)
//   - f11 flow-profile KL      KL(empirical outflow frame-size histogram ||
//                              target profile) — the core's self-monitoring
//   - f12 time-of-day sin      derived from NowMS
//   - f13 time-of-day cos      derived from NowMS
//   - f14 session longevity    core uptime in hours (24h = max)
//   - f15 regime ordinal       derived from the regime label (a NOVEL regime
//                              widens the confidence interval on purpose:
//                              unexplored conditions deserve exploration)
//
//   - Per arm we keep the ridge-regularised normal-equation state
//         A_a = λI + Σ x xᵀ      (16×16, symmetric positive definite)
//         b_a = Σ r x            (16)
//     with θ_a = A_a⁻¹ b_a, and score an arm at context x by
//         xᵀθ_a + α · √(x A_a⁻¹ x)
//     (exploitation + width of the confidence interval). A is inverted with a
//     partial-pivot Gauss-Jordan in pure Go — no external math dependency.
//
// Honest boundaries (unchanged):
//   - Rewards are shaped into [0,1]; hard failures are represented as reward
//     0 plus a consecutive-failure quarantine, NOT as negative scores. This
//     keeps the contextual-UCB regret intuition valid (it assumes [0,1]).
//   - Deterministic under a fixed seed and a fixed (ctx, call) sequence: the
//     exploration tie-break is the stable arm order, never the wall clock.
//   - No DPI detection here: the inputs are the client's own connection
//     outcomes (ok / rtt / throughput / error class) and the context the
//     measure package derives from exactly those. Nothing else.
package bandit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
)

const (
	// MaxQuarantine is the longest an arm can be excluded after a failure
	// run (backoff: 60s, 2min, 5min, 15min, 15min, ...).
	MaxQuarantineMS = 15 * 60 * 1000
	// PruneKeepAlive is the minimum number of live arms Prune will preserve,
	// so a transient total failure never empties the option set.
	PruneKeepAlive = 2
	// PruneMinPulls / PruneMaxRatio: an arm is prunable only after it has
	// been tried enough and is persistently much worse than its peers.
	PruneMinPulls  = 12
	PruneMaxRatio  = 0.10
	ridge        = 1.0 // λ: ridge regularisation on A (keeps A invertible)
	featureScale = 1.0 // reserved for future per-feature rescaling

	successThroughputTarget = 2.0 * 1000 * 1000 // 2 MB/s saturates the bonus
)

// dim is the context-vector width (2.16): bias, rtt-level, rtt-variance,
// rst-rate, tls-drop, loss-step, http-anomaly, throughput, loss-velocity,
// tls-error-rate, entry-churn, flow-KL, tod-sin, tod-cos, session-age,
// regime-ordinal.
const dim = 16

// Arm is one selectable path: entry host × transport × TLS fingerprint.
type Arm struct {
	Host      string `json:"host"`
	Transport string `json:"transport"` // "ws" | "ws-alt" | "h2" | "h3" | "grpc"
	FP        string `json:"fp"`        // uTLS identity, e.g. "chrome"
}

// ID is the stable key used for persistence and tie-breaks.
func (a Arm) ID() string { return a.Host + "|" + a.Transport + "|" + a.FP }

// Stats is the per-arm learning state that drives quarantine and pruning.
// The LinUCB A/b matrices live separately (see Snapshot.Lin) so this struct
// stays stable across the 2.15 persistence format change.
type Stats struct {
	Pulls              int     `json:"pulls"`
	TotalReward        float64 `json:"total_reward"`
	ConsecFail         int     `json:"consec_fail"`
	ConsecOK           int     `json:"consec_ok"`
	RTTEWMA            float64 `json:"rtt_ewma_ms"`
	QuarantinedUntilMS int64   `json:"quarantined_until_ms"`
	Pruned             bool    `json:"pruned"`
}

// meanReward is the empirical reward mean (the "exploitation" reference).
func (s *Stats) meanReward() float64 {
	if s.Pulls == 0 {
		return 0
	}
	return s.TotalReward / float64(s.Pulls)
}

// Context carries the environment signal the core has from the measure
// package (and optionally the worker manifest regime). The float fields are
// the *raw* measurements; features() normalises them into [0,1].
//
//   - RTTMS:      handshake+first-bytes latency EWMA (ms)
//   - JitterMS:   RTT variance (EWMA of |Δrtt|, ms)
//   - RSTRate:    fraction of the window that failed with a RST
//   - TLSDrop:    fraction that failed at the TLS handshake (drop delta)
//   - LossStep:   CUSUM step-change accumulator (0..~6)
//   - HTTPAnom:   1 if the last observation carried a protocol anomaly, else 0
type Context struct {
	Regime           string  `json:"regime"` // "stable"|"watch"|"suspected_change"|"recovering"
	WeakestTransport string  `json:"weakest_transport"`
	NowMS            int64   `json:"now_ms"`
	RTTMS            float64 `json:"rtt_ms"`
	JitterMS         float64 `json:"jitter_ms"`
	RSTRate          float64 `json:"rst_rate"`
	TLSDrop          float64 `json:"tls_drop"`
	LossStep         float64 `json:"loss_step"`
	HTTPAnom         float64 `json:"http_anom"`
	// 2.16 — AXR-v3 extensions (see the package doc for sources).
	ThroughputBPS float64 `json:"throughput_bps"` // measured tunnel bytes/sec EWMA
	LossVel       float64 `json:"loss_vel"`       // -1..1 (negative = improving)
	TLSErrRate    float64 `json:"tls_err_rate"`   // 0..1 window fraction
	EntryChurn    float64 `json:"entry_churn"`    // 0 or 1: best dial addr changed
	FlowKLDiv     float64 `json:"flow_kl_div"`    // nats, self-monitoring
	SessionAgeH   float64 `json:"session_age_h"`  // core uptime, hours
}

// Outcome is one connection result fed back to the bandit.
type Outcome struct {
	OK         bool
	RTTMS      float64
	Throughput float64 // bytes/sec, best effort, 0 if unknown
	Reason     string  // "ok"|"rst"|"timeout"|"tls_error"|"anomaly"
}

// reward maps an outcome into [0,1]. Successes split into a 0.5 base plus a
// throughput-stability bonus; failures are 0 (quarantine does the exclusion).
func reward(o Outcome) float64 {
	if !o.OK {
		return 0
	}
	r := 0.5
	if o.Throughput > 0 {
		t := o.Throughput / successThroughputTarget
		if t > 1 {
			t = 1
		}
		r += 0.5 * t
	}
	if o.RTTMS > 0 {
		pen := o.RTTMS / 2000.0 * 0.25 // 2000ms -> max 0.25 penalty
		if pen > 0.25 {
			pen = 0.25
		}
		r -= pen
	}
	if r < 0 {
		r = 0
	}
	return r
}

// clamp01 clamps x into [0,1].
func clamp01(x float64) float64 {
	if math.IsNaN(x) || x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// features maps a Context into the normalised dim-dim vector used by LinUCB.
// The first component is a constant bias (intercept) so the model can learn
// a per-arm baseline and the vector is never the zero vector.
func features(ctx Context) vec {
	f := vec{}
	f[0] = 1.0
	f[1] = clamp01(ctx.RTTMS / 2000)   // RTT level (2s = max)
	f[2] = clamp01(ctx.JitterMS / 500) // RTT variance (500ms = max)
	f[3] = clamp01(ctx.RSTRate)        // RST frequency (0..1)
	f[4] = clamp01(ctx.TLSDrop)        // TLS drop rate (0..1)
	f[5] = clamp01(ctx.LossStep / 6)   // loss step (CUSUM cap ~6)
	f[6] = clamp01(ctx.HTTPAnom)       // 0 or 1
	// ---- 2.16 — AXR-v3 extensions ----
	f[7] = clamp01(ctx.ThroughputBPS / 10_000_000) // 10 MB/s = saturated
	f[8] = clamp01((ctx.LossVel + 1) / 2)          // -1..1 -> 0..1
	f[9] = clamp01(ctx.TLSErrRate)                 // 0..1
	f[10] = clamp01(ctx.EntryChurn)                // 0 or 1
	f[11] = clamp01(ctx.FlowKLDiv / 4)             // 4 nats = saturated
	f[12] = (timeOfDaySin(ctx.NowMS) + 1) / 2      // 0..1
	f[13] = (timeOfDayCos(ctx.NowMS) + 1) / 2      // 0..1
	f[14] = clamp01(ctx.SessionAgeH / 24)          // 24h = max
	f[15] = regimeOrdinal(ctx.Regime)
	return f
}

// timeOfDaySin/Cos map the clock time to a smooth periodic pair (24h period)
// so "00:00" and "24:00" are adjacent instead of opposite. Negative or
// non-finite NowMS degrades to the midnight phase (0,1).
func timeOfDayPhase(nowMS int64) float64 {
	hours := float64(nowMS) / 3_600_000
	if math.IsNaN(hours) || math.IsInf(hours, 0) {
		return 0
	}
	phase := math.Mod(hours, 24) / 24 * 2 * math.Pi
	if phase < 0 {
		phase += 2 * math.Pi
	}
	return phase
}

func timeOfDaySin(nowMS int64) float64 { return math.Sin(timeOfDayPhase(nowMS)) }
func timeOfDayCos(nowMS int64) float64 { return math.Cos(timeOfDayPhase(nowMS)) }

// regimeOrdinal ranks regimes for the context vector. A novel/worse regime
// is a different condition, and LinUCB widens its interval there until the
// core accumulates observations under it (deliberate exploration).
func regimeOrdinal(regime string) float64 {
	switch regime {
	case "stable":
		return 0
	case "watch", "recovering":
		return 0.35
	case "suspected_change":
		return 0.7
	default:
		return 0.1
	}
}

// mat / vec are the fixed-width linear-algebra types for the dim×dim state.
type (
	mat [dim][dim]float64
	vec [dim]float64
)

func (m *mat) identityScale(s float64) {
	for i := 0; i < dim; i++ {
		for j := 0; j < dim; j++ {
			if i == j {
				m[i][j] = s
			} else {
				m[i][j] = 0
			}
		}
	}
}

// outer adds x xᵀ to m in place (m += x xᵀ).
func (m *mat) addOuter(x *vec) {
	for i := 0; i < dim; i++ {
		for j := 0; j < dim; j++ {
			m[i][j] += x[i] * x[j]
		}
	}
}

// addScaledVec adds r·x to v in place (v += r x).
func (v *vec) addScaled(x *vec, r float64) {
	for i := 0; i < dim; i++ {
		v[i] += r * x[i]
	}
}

// matVec returns m·v (a fresh vector).
func (m *mat) matVec(v *vec) vec {
	var out vec
	for i := 0; i < dim; i++ {
		s := 0.0
		for j := 0; j < dim; j++ {
			s += m[i][j] * v[j]
		}
		out[i] = s
	}
	return out
}

// dot returns x·y.
func (x *vec) dot(y *vec) float64 {
	s := 0.0
	for i := 0; i < dim; i++ {
		s += x[i] * y[i]
	}
	return s
}

// invert returns the inverse of m via partial-pivot Gauss-Jordan, or
// (zero, false) when m is (numerically) singular. A is always SPD in practice
// (λI + sum of outer products), so this is defensive.
func (m *mat) invert() (mat, bool) {
	aug := make([][]float64, dim)
	for i := 0; i < dim; i++ {
		aug[i] = make([]float64, 2*dim)
		copy(aug[i][:dim], m[i][:])
		aug[i][dim+i] = 1
	}
	for col := 0; col < dim; col++ {
		piv := col
		mx := math.Abs(aug[col][col])
		for r := col + 1; r < dim; r++ {
			if v := math.Abs(aug[r][col]); v > mx {
				mx = v
				piv = r
			}
		}
		if mx < 1e-12 {
			return mat{}, false
		}
		if piv != col {
			aug[col], aug[piv] = aug[piv], aug[col]
		}
		p := aug[col][col]
		for j := 0; j < 2*dim; j++ {
			aug[col][j] /= p
		}
		for r := 0; r < dim; r++ {
			if r == col {
				continue
			}
			f := aug[r][col]
			if f == 0 {
				continue
			}
			for j := 0; j < 2*dim; j++ {
				aug[r][j] -= f * aug[col][j]
			}
		}
	}
	var out mat
	for i := 0; i < dim; i++ {
		copy(out[i][:], aug[i][dim:])
	}
	return out, true
}

// armLin is one arm's LinUCB state.
type armLin struct {
	A mat
	b vec
}

func newArmLin() *armLin {
	l := &armLin{}
	l.A.identityScale(ridge) // λI
	return l
}

// Bandit is the learner. Safe for concurrent use.
type Bandit struct {
	mu     sync.Mutex
	C      float64 // α: exploration scale
	arms   []Arm
	stats  map[string]*Stats
	lin    map[string]*armLin
	seed   uint64
	// lastID is the previously selected arm, used for the diversity bonus
	// during "suspected_change" (encourages rotating away from the status quo).
	lastID string
}

// New creates a bandit over the given arms. c is the exploration constant
// α (1.0 is a good default). seed is retained for seeded tie-breaks; selection
// is already deterministic without it.
func New(c float64, seed uint64, arms []Arm) *Bandit {
	if c <= 0 {
		c = 1.0
	}
	b := &Bandit{C: c, seed: seed, stats: make(map[string]*Stats, len(arms)), lin: make(map[string]*armLin, len(arms))}
	for _, a := range arms {
		b.addArmLocked(a)
	}
	if len(b.arms) == 0 {
		panic("bandit.New: no valid arms")
	}
	return b
}

// addArmLocked registers one arm (caller holds b.mu).
func (b *Bandit) addArmLocked(a Arm) {
	if a.Host == "" || a.Transport == "" {
		return
	}
	if a.FP == "" {
		a.FP = "chrome"
	}
	id := a.ID()
	if _, ok := b.stats[id]; ok {
		return
	}
	b.arms = append(b.arms, a)
	b.stats[id] = &Stats{}
	b.lin[id] = newArmLin()
}

// ErrNoArm is returned when every arm is quarantined/pruned at selection time.
var ErrNoArm = errors.New("bandit: no selectable arm")

// Score is the transparent per-arm decision trace (exported for the local
// decision view and tests).
type Score struct {
	Arm         Arm     `json:"arm"`
	Mean        float64 `json:"mean"`
	Ucb         float64 `json:"ucb"` // LinUCB score (or untried boost)
	Diversity   float64 `json:"diversity"`
	WeakestHit  float64 `json:"weakest_hit"`
	Total       float64 `json:"total"`
	Quarantined bool    `json:"quarantined"`
	Pruned      bool    `json:"pruned"`
}

// linScore computes the LinUCB (mean, exploration) split for arm id at x.
func (b *Bandit) linScore(id string, x *vec) (float64, float64) {
	l := b.lin[id]
	inv, ok := l.A.invert()
	if !ok {
		return 0, 0
	}
	theta := inv.matVec(&l.b)
	mean := x.dot(&theta)
	// xᵀ A¹ x = x · (A⁻¹ x)
	ax := inv.matVec(x)
	v := x.dot(&ax)
	if v < 0 {
		v = 0
	}
	exploration := b.C * math.Sqrt(v)
	return mean, exploration
}

// explorationScale returns α with the regime-driven boost applied.
func (b *Bandit) explorationScale(ctx Context) float64 {
	alpha := b.C
	if ctx.Regime == "suspected_change" {
		alpha *= 1.8 // regime-driven exploration boost
	}
	return alpha
}

// scoresLocked is the core scorer; both Scores and Select use it.
func (b *Bandit) scoresLocked(ctx Context) []Score {
	x := features(ctx)
	xp := x
	alpha := b.explorationScale(ctx)
	out := make([]Score, 0, len(b.arms))
	for _, a := range b.arms {
		id := a.ID()
		s := b.stats[id]
		sc := Score{Arm: a, Quarantined: s.QuarantinedUntilMS > ctx.NowMS, Pruned: s.Pruned}
		sc.Mean = s.meanReward()
		if s.Pulls == 0 {
			// Untried arms get the maximum possible mean so they are explored
			// before any exploitation. This is deliberate: the client must
			// actually *try* every entry at least once or failover can never
			// discover a path that is currently up. It also keeps the first
			// pick deterministic (all equal -> stable ID tie-break).
			sc.Ucb = 1.0 + alpha
		} else {
			mean, exploration := b.linScore(id, &xp)
			sc.Ucb = mean + exploration
		}
		if ctx.WeakestTransport != "" && a.Transport == ctx.WeakestTransport && ctx.Regime != "stable" {
			// A mild nudge OFF the currently weakest transport.
			sc.WeakestHit = -0.05
		}
		if ctx.Regime == "suspected_change" && a.ID() != b.lastID && b.lastID != "" {
			sc.Diversity = 0.05
		}
		sc.Total = sc.Ucb + sc.Diversity + sc.WeakestHit
		out = append(out, sc)
	}
	return out
}

// Scores exposes the full score table for the current context.
func (b *Bandit) Scores(ctx Context) []Score {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.scoresLocked(ctx)
}

// Select returns the best arm for ctx (and the full score table). It never
// selects a pruned arm; a quarantined arm is only selected when no live
// alternative exists (we must keep trying *something*).
func (b *Bandit) Select(ctx Context) (Arm, []Score, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	scores := b.scoresLocked(ctx)
	if len(scores) == 0 {
		return Arm{}, nil, ErrNoArm
	}
	best := -1
	for i, sc := range scores {
		if sc.Pruned || sc.Quarantined {
			continue
		}
		if best < 0 || sc.Total > scores[best].Total || (sc.Total == scores[best].Total && sc.Arm.ID() < scores[best].Arm.ID()) {
			best = i
		}
	}
	if best < 0 {
		// Every live arm is quarantined: still pick the best non-pruned one —
		// the client must keep trying *something* rather than idling.
		for i, sc := range scores {
			if sc.Pruned {
				continue
			}
			if best < 0 || sc.Total > scores[best].Total || (sc.Total == scores[best].Total && sc.Arm.ID() < scores[best].Arm.ID()) {
				best = i
			}
		}
	}
	if best < 0 {
		return Arm{}, scores, ErrNoArm
	}
	b.lastID = scores[best].Arm.ID()
	return scores[best].Arm, scores, nil
}

// Observe feeds one outcome back for arm a, measured under context ctx at time
// now (ms). ctx must be the same context that was current when the arm was
// selected, so the LinUCB update lands on the right feature vector.
func (b *Bandit) Observe(a Arm, o Outcome, ctx Context, now int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := a.ID()
	s, ok := b.stats[id]
	if !ok {
		return
	}
	r := reward(o)
	x := features(ctx)
	if l, ok := b.lin[id]; ok {
		l.A.addOuter(&x)
		l.b.addScaled(&x, r)
	} else {
		l := newArmLin()
		l.A.addOuter(&x)
		l.b.addScaled(&x, r)
		b.lin[id] = l
	}

	s.Pulls++
	s.TotalReward += r
	if o.OK {
		s.ConsecOK++
		s.ConsecFail = 0
		s.QuarantinedUntilMS = 0
		if o.RTTMS > 0 {
			if s.RTTEWMA == 0 {
				s.RTTEWMA = o.RTTMS
			} else {
				s.RTTEWMA = 0.7*s.RTTEWMA + 0.3*o.RTTMS
			}
		}
	} else {
		s.ConsecFail++
		s.ConsecOK = 0
		if s.ConsecFail >= 3 {
			// exponential backoff: 60s, 2min, 5min, 15min (capped)
			step := s.ConsecFail - 3
			if step > 4 {
				step = 4
			}
			backoff := int64(60 * 1000) << step
			if backoff > MaxQuarantineMS {
				backoff = MaxQuarantineMS
			}
			s.QuarantinedUntilMS = now + backoff
		}
	}
}

// Prune permanently disables arms that are persistently terrible, keeping at
// least PruneKeepAlive live arms. Returns the pruned arm IDs.
func (b *Bandit) Prune() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	type candidate struct {
		id  string
		rat float64
	}
	var cands []candidate
	live := 0
	for _, a := range b.arms {
		s := b.stats[a.ID()]
		if !s.Pruned {
			live++
		}
		if s.Pruned || s.Pulls < PruneMinPulls {
			continue
		}
		rat := s.TotalReward / float64(s.Pulls)
		if rat < PruneMaxRatio {
			cands = append(cands, candidate{id: a.ID(), rat: rat})
		}
	}
	// worst ratio first
	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			if cands[j].rat < cands[i].rat {
				cands[i], cands[j] = cands[j], cands[i]
			}
		}
	}
	var pruned []string
	for _, c := range cands {
		if live <= PruneKeepAlive {
			break
		}
		b.stats[c.id].Pruned = true
		live--
		pruned = append(pruned, c.id)
	}
	return pruned
}

// AddArm introduces a new arm at runtime (e.g. a backup entry discovered
// from the worker manifest).
func (b *Bandit) AddArm(a Arm) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addArmLocked(a)
}

// Arms returns a copy of the arm list.
func (b *Bandit) Arms() []Arm {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Arm, len(b.arms))
	copy(out, b.arms)
	return out
}

// LinState is the persistable per-arm LinUCB state. A/B are flexible
// (slice-of-slices) so an OLDER dim's snapshot still UNMARSHALS: Restore
// then validates the shape and rebuilds the ridge prior when the dim has
// changed (2.15 was 7, 2.16 is 16) — the learned arm STATS survive the
// upgrade either way.
type LinState struct {
	A [][]float64 `json:"a"`
	B []float64   `json:"b"`
}

// Snapshot is the JSON-persistable state (arm set + stats + lin + config).
type Snapshot struct {
	C     float64              `json:"c"`
	Seed  uint64               `json:"seed"`
	Arms  []Arm                `json:"arms"`
	Stats map[string]*Stats    `json:"stats"`
	Lin   map[string]*LinState `json:"lin,omitempty"`
	// Dim is the feature width this snapshot's Lin state was learned under
	// (0 in pre-2.16 snapshots).
	Dim int `json:"dim,omitempty"`
}

// Snapshot exports state for persistence.
func (b *Bandit) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	stats := make(map[string]*Stats, len(b.stats))
	for k, v := range b.stats {
		cp := *v
		stats[k] = &cp
	}
	lin := make(map[string]*LinState, len(b.lin))
	for k, v := range b.lin {
		A := make([][]float64, dim)
		for i := 0; i < dim; i++ {
			A[i] = make([]float64, dim)
			copy(A[i], v.A[i][:])
		}
		B := make([]float64, dim)
		copy(B, v.b[:])
		lin[k] = &LinState{A: A, B: B}
	}
	arms := make([]Arm, len(b.arms))
	copy(arms, b.arms)
	return Snapshot{C: b.C, Seed: b.seed, Arms: arms, Stats: stats, Lin: lin, Dim: dim}
}

// validLin reports whether ls is a complete dim×dim Lin state for the
// CURRENT feature width.
func validLin(ls *LinState) bool {
	if ls == nil || ls.A == nil || ls.B == nil {
		return false
	}
	if len(ls.A) != dim || len(ls.B) != dim {
		return false
	}
	for _, row := range ls.A {
		if len(row) != dim {
			return false
		}
	}
	return true
}

// Restore loads persisted state. Unknown arms in old snapshots are ignored;
// missing arms get fresh stats. Arms missing Lin state — or carrying Lin
// state learned under a DIFFERENT feature width (2.15's 7-dim) — get a
// fresh λI so the learner starts from the ridge prior for those arms while
// keeping their accumulated Stats.
func (b *Bandit) Restore(s Snapshot) error {
	if len(s.Arms) == 0 {
		return fmt.Errorf("bandit: empty snapshot")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.C > 0 {
		b.C = s.C
	}
	// A snapshot written under another feature width is structurally
	// incompatible: its Lin matrices are the wrong shape. The per-arm
	// validLin check below would drop them one by one; short-circuit the
	// intent explicitly so the behaviour is documented in one place.
	dimChanged := s.Dim > 0 && s.Dim != dim
	b.arms = nil
	b.stats = make(map[string]*Stats, len(s.Arms))
	b.lin = make(map[string]*armLin, len(s.Arms))
	for _, a := range s.Arms {
		if a.Host == "" || a.Transport == "" {
			continue
		}
		if a.FP == "" {
			a.FP = "chrome"
		}
		id := a.ID()
		if _, ok := b.stats[id]; ok {
			continue
		}
		b.arms = append(b.arms, a)
		if st, ok := s.Stats[id]; ok {
			cp := *st
			b.stats[id] = &cp
		} else {
			b.stats[id] = &Stats{}
		}
		if ls, ok := s.Lin[id]; ok && !dimChanged && validLin(ls) {
			l := &armLin{}
			for i := 0; i < dim; i++ {
				for j := 0; j < dim; j++ {
					l.A[i][j] = ls.A[i][j]
				}
				l.b[i] = ls.B[i]
			}
			b.lin[id] = l
		} else {
			b.lin[id] = newArmLin()
		}
	}
	if len(b.arms) == 0 {
		return fmt.Errorf("bandit: snapshot has no valid arms")
	}
	return nil
}

// Save writes the snapshot atomically (tmp file + rename).
func (b *Bandit) Save(path string) error {
	data, err := json.MarshalIndent(b.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// LoadSnapshot reads a persisted snapshot.
func LoadSnapshot(path string) (Snapshot, error) {
	var s Snapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// writeAtomic writes data to path via a temp file in the same directory.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".axr-bandit-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
