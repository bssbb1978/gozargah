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
// 2.17 upgrade: ensemble (LinUCB + Beta-TS, meta-blended). LinUCB is the
// CONTEXTUAL model (the same entry is good/bad depending on conditions); a
// per-arm Beta-Bernoulli Thompson sampler is the pure BAYESIAN bandit
// (robust when context is thin or misleading). One meta-weight arbitrates:
// after each pull, the realized reward is attributed to whichever member's
// deterministic ranking picked the arm that actually carried, and the
// meta-weight follows the members' realized-reward EMAs (tanh-combined).
// The client thus hedges between "condition-aware" and "outcome-aware"
// learning, and the hedge itself is learned. Zero external dependencies.
//
// Honest boundaries (unchanged):
//   - Rewards are shaped into [0,1]; hard failures are represented as reward
//     0 plus a consecutive-failure quarantine, NOT as negative scores. This
//     keeps the contextual-UCB regret intuition valid (it assumes [0,1]).
//   - Deterministic under a fixed seed and a fixed (ctx, call) sequence: the
//     Thompson draws come from a seeded per-bandit RNG, the tie-breaks are
//     the stable arm order, never the wall clock.
//   - No DPI detection here: the inputs are the client's own connection
//     outcomes (ok / rtt / throughput / error class) and the context the
//     measure package derives from exactly those. Nothing else.
package bandit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
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
	ridge = 1.0 // λ: ridge regularisation on A (keeps A invertible)

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
// 2.17 — the netstate route labels join the scale: "degraded" (international
// entries failing, domestic fronting still live) sits between the measure
// labels; "cut" (nothing carrying) is the widest condition.
func regimeOrdinal(regime string) float64 {
	switch regime {
	case "stable":
		return 0
	case "watch", "recovering":
		return 0.35
	case "degraded":
		return 0.5
	case "suspected_change":
		return 0.7
	case "cut":
		return 1.0
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

// armTS is one arm's Beta-Bernoulli posterior (the Thompson-sampling
// ensemble member, 2.17). alpha/beta start at 1 (uniform prior) and only
// increase, so gamma shapes stay >= 1 (the sampler's easy case).
type armTS struct {
	alpha float64
	beta  float64
}

// posteriorMean is the exploitation reference of the TS member.
func (t *armTS) posteriorMean() float64 {
	return t.alpha / (t.alpha + t.beta)
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
	// ---- 2.17 — ensemble state (LinUCB + Beta-TS, meta-blended) ----
	ts     map[string]*armTS // per-arm Beta posteriors
	tsRng  *rand.Rand        // seeded Thompson-draw RNG (locked by mu)
	metaW  float64           // weight on LinUCB in (0,1); 0.5 = neutral
	emaLin float64           // realized-reward EMA when the LinUCB pick carried
	emaTs  float64           // realized-reward EMA when the TS pick carried
}

// New creates a bandit over the given arms. c is the exploration constant
// α (1.0 is a good default). seed drives the Thompson-draw RNG (selection
// is deterministic for a fixed seed + call sequence).
func New(c float64, seed uint64, arms []Arm) *Bandit {
	if c <= 0 {
		c = 1.0
	}
	b := &Bandit{
		C: c, seed: seed,
		stats: make(map[string]*Stats, len(arms)),
		lin:   make(map[string]*armLin, len(arms)),
		ts:    make(map[string]*armTS, len(arms)),
		metaW: 0.5, emaLin: 0.5, emaTs: 0.5,
	}
	// Mix the seed against a fixed constant so even seed=1 is not the
	// trivially-predictable default RNG stream (XOR in uint64 space, then
	// reinterpret; the bijection keeps determinism).
	b.tsRng = rand.New(rand.NewSource(int64(seed ^ 0x5851F42D4C957F2D)))
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
	b.ts[id] = &armTS{alpha: 1, beta: 1}
}

// gammaSample draws one sample from Gamma(shape, 1) with the
// Marsaglia-Tsang method (shape > 0). For shape < 1 the standard boost
// transformation reduces to the shape+1 case.
func gammaSample(shape float64, rng *rand.Rand) float64 {
	if shape <= 0 || math.IsNaN(shape) || math.IsInf(shape, 0) {
		shape = 1
	}
	if shape < 1 {
		u := rng.Float64()
		for u <= 0 {
			u = rng.Float64()
		}
		return gammaSample(shape+1, rng) * math.Pow(u, 1.0/shape)
	}
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		var x, v float64
		for {
			x = rng.NormFloat64()
			v = 1 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := rng.Float64()
		if u < 1-1.5*x*x*x*x {
			return d * v
		}
		if math.Log(u) < 0.5*x*x + d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

// betaSample draws one sample from Beta(a, b) via the two-gamma ratio.
// Returns the uniform 0.5 for degenerate (non-positive) parameters.
func betaSample(a, b float64, rng *rand.Rand) float64 {
	if a <= 0 || b <= 0 {
		return 0.5
	}
	ga := gammaSample(a, rng)
	gb := gammaSample(b, rng)
	return ga / (ga + gb)
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
	// 2.17 — ensemble audit fields.
	TsScore float64 `json:"ts_score,omitempty"` // TS posterior mean (0..1, draw-free)
	Model   string  `json:"model,omitempty"`    // which member chose this arm ("lin"|"ts")
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
		sc.TsScore = b.tsMean(id) // 2.17 — audit (draw-free, idempotent)
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
//
// 2.17 — ensemble arbitration: both members rank the live candidate set
// (LinUCB by its confidence-bound total; Beta-TS by one posterior draw).
// The meta-weight picks which member's choice carries: w >= 0.5 -> LinUCB,
// else Thompson. The winning member is stamped on the chosen score (audit).
// Draw-free note: Scores() never consumes a draw, so it stays idempotent;
// only Select draws.
func (b *Bandit) Select(ctx Context) (Arm, []Score, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	scores := b.scoresLocked(ctx)
	if len(scores) == 0 {
		return Arm{}, nil, ErrNoArm
	}
	best, ok := b.pickLocked(scores)
	if !ok {
		return Arm{}, scores, ErrNoArm
	}
	b.lastID = scores[best].Arm.ID()
	return scores[best].Arm, scores, nil
}

// liveSetLocked returns the candidate indices: live (non-pruned,
// non-quarantined) arms, or — when every arm is quarantined — the non-pruned
// set (the client must keep trying *something*).
func (b *Bandit) liveSetLocked(scores []Score) []int {
	var live []int
	for i, sc := range scores {
		if !sc.Pruned && !sc.Quarantined {
			live = append(live, i)
		}
	}
	if len(live) == 0 {
		for i, sc := range scores {
			if !sc.Pruned {
				live = append(live, i)
			}
		}
	}
	return live
}

// pickLocked is the ensemble picker (caller holds b.mu).
func (b *Bandit) pickLocked(scores []Score) (int, bool) {
	live := b.liveSetLocked(scores)
	if len(live) == 0 {
		return 0, false
	}
	// LinUCB best (stable ID tie-break).
	linBest := live[0]
	for _, i := range live[1:] {
		if scores[i].Total > scores[linBest].Total ||
			(scores[i].Total == scores[linBest].Total && scores[i].Arm.ID() < scores[linBest].Arm.ID()) {
			linBest = i
		}
	}
	// Thompson best: one posterior draw per candidate (seeded RNG, consumed
	// only here). Stable ID tie-break on equal draws.
	tsBest := live[0]
	bestDraw := math.Inf(-1)
	for _, i := range live {
		d := b.tsDraw(scores[i].Arm.ID())
		if d > bestDraw || (d == bestDraw && scores[i].Arm.ID() < scores[tsBest].Arm.ID()) {
			bestDraw = d
			tsBest = i
		}
	}
	best, model := linBest, "lin"
	if b.metaW < 0.5 {
		best, model = tsBest, "ts"
	}
	scores[best].Model = model
	return best, true
}

// tsDraw draws one posterior sample for the arm (caller holds b.mu).
func (b *Bandit) tsDraw(id string) float64 {
	t := b.ts[id]
	if t == nil {
		return 0.5
	}
	return betaSample(t.alpha, t.beta, b.tsRng)
}

// tsMean returns the arm's TS posterior mean (0..1), 0.5 for unknown arms.
func (b *Bandit) tsMean(id string) float64 {
	t := b.ts[id]
	if t == nil {
		return 0.5
	}
	return t.posteriorMean()
}

// modelArmsLocked returns the (LinUCB-best arm ID, TS-mean-best arm ID) over
// the live candidate set at ctx. Used for meta-credit attribution in
// Observe: each member is credited with the realized reward exactly when
// ITS deterministic ranking would have picked the arm that carried.
func (b *Bandit) modelArmsLocked(ctx Context) (string, string) {
	scores := b.scoresLocked(ctx)
	live := b.liveSetLocked(scores)
	if len(live) == 0 {
		return "", ""
	}
	linBest := live[0]
	for _, i := range live[1:] {
		if scores[i].Total > scores[linBest].Total ||
			(scores[i].Total == scores[linBest].Total && scores[i].Arm.ID() < scores[linBest].Arm.ID()) {
			linBest = i
		}
	}
	linArm := scores[linBest].Arm
	tsBest := live[0]
	tsM := b.tsMean(scores[tsBest].Arm.ID())
	for _, i := range live[1:] {
		m := b.tsMean(scores[i].Arm.ID())
		if m > tsM || (m == tsM && scores[i].Arm.ID() < scores[tsBest].Arm.ID()) {
			tsM = m
			tsBest = i
		}
	}
	return linArm.ID(), scores[tsBest].Arm.ID()
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

	// 2.17 — ensemble update. The TS posterior sees EVERY outcome for this
	// arm (Beta-Bernoulli); the meta-weight re-attributes credit by each
	// member's DETERMINISTIC ranking at ctx (LinUCB total; TS posterior
	// mean) — the sampled draw only decides the final pick, never the
	// credit. A member that keeps being right for the arm that carries
	// earns the arbitration; a member that keeps being wrong yields.
	if t, ok := b.ts[id]; ok {
		t.alpha += r
		t.beta += 1 - r
	}
	linArmID, tsArmID := b.modelArmsLocked(ctx)
	const eta = 0.15
	if linArmID == id {
		b.emaLin += eta * (r - b.emaLin)
	}
	if tsArmID == id {
		b.emaTs += eta * (r - b.emaTs)
	}
	b.metaW = 0.5 + 0.5*math.Tanh(2*(b.emaLin-b.emaTs))
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
	// 2.17 — ensemble state (absent in 2.16 snapshots -> neutral defaults:
	// fresh (1,1) posteriors, meta-weight 0.5).
	Ts     map[string][2]float64 `json:"ts,omitempty"`     // arm -> {alpha, beta}
	MetaW  float64               `json:"meta_w,omitempty"` // weight on LinUCB
	EmaLin float64               `json:"ema_lin,omitempty"`
	EmaTs  float64               `json:"ema_ts,omitempty"`
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
	ts := make(map[string][2]float64, len(b.ts))
	for k, v := range b.ts {
		ts[k] = [2]float64{v.alpha, v.beta}
	}
	arms := make([]Arm, len(b.arms))
	copy(arms, b.arms)
	return Snapshot{
		C: b.C, Seed: b.seed, Arms: arms, Stats: stats, Lin: lin, Dim: dim,
		Ts: ts, MetaW: b.metaW, EmaLin: b.emaLin, EmaTs: b.emaTs,
	}
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
	b.ts = make(map[string]*armTS, len(s.Arms))
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
		// 2.17 — restore the TS posterior if it is well-formed, else fresh
		// (1,1). A 2.16 snapshot has no Ts at all -> every arm starts fresh.
		if pair, ok := s.Ts[id]; ok && pair[0] >= 1 && pair[1] >= 1 &&
			!math.IsNaN(pair[0]) && !math.IsNaN(pair[1]) {
			b.ts[id] = &armTS{alpha: pair[0], beta: pair[1]}
		} else {
			b.ts[id] = &armTS{alpha: 1, beta: 1}
		}
	}
	if len(b.arms) == 0 {
		return fmt.Errorf("bandit: snapshot has no valid arms")
	}
	// 2.17 — ensemble meta state: accept only sane values, else neutral.
	if s.MetaW > 0 && s.MetaW <= 1 {
		b.metaW = s.MetaW
	} else {
		b.metaW = 0.5
	}
	b.emaLin = s.EmaLin
	if b.emaLin < 0 || b.emaLin > 1 {
		b.emaLin = 0.5
	}
	b.emaTs = s.EmaTs
	if b.emaTs < 0 || b.emaTs > 1 {
		b.emaTs = 0.5
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
