// Package measure turns the client's own connection observations into the
// AXR state vector consumed by the bandit:
//
//	RTT (EWMA) · RTT jitter (EWMA of |Δrtt|) · RST rate · TLS-handshake
//	timeout rate · drop-rate step change (lower-branch CUSUM) · last HTTP /
//	protocol anomaly code
//
// and a coarse regime label ("stable"|"watch"|"suspected_change"|"recovering")
// derived deterministically from that vector.
//
// Honest boundary: every input is a local outcome the client itself produced
// (dial/handshake/stream results, latency, error class, response status).
// The package does not inspect payloads and does not "detect DPI" — the
// regime label is a statement about the client's own delivery quality,
// which is all a client can legitimately know.
package measure

import (
	"fmt"
	"math"
	"sync"
)

const (
	windowSize = 40 // sliding observation window
	alphaRTT   = 0.35
	alphaJit   = 0.30
	cusumK     = 0.35 // tolerance in the lower-branch CUSUM
	cusumCap   = 6.0
	cusumAlarm = 2.5

	// Regime thresholds.
	baselineHealthy  = 0.55
	recentBad        = 0.20
	recentGood       = 0.75
	watchDropRate    = 0.25
	hardDropRate     = 0.50
	rstAlarmRate     = 0.25
	timeoutAlarmRate = 0.30
)

// Error classes for non-OK samples. Keep the set small and stable; the
// bandit only cares about OK/!OK, but the class is surfaced in the vector.
const (
	ErrNone    = ""
	ErrRST     = "rst"
	ErrTimeout = "timeout"
	ErrTLS     = "tls_error"
	ErrAnomaly = "anomaly"
)

// Sample is one observation.
type Sample struct {
	OK    bool
	RTTMS float64 // handshake+first-bytes latency, 0 if unknown
	// Throughput is the measured tunnel throughput in bytes/sec (2.16),
	// 0 when unknown (e.g. the stream ended before any traffic).
	Throughput float64
	ErrClass   string // one of the Err* constants when !OK
	Anomaly    int    // last non-2xx/3xx HTTP status or protocol code, 0 = none
	Transport  string // "ws"|"h2"|"h3"|"grpc" (for per-transport weakest)
	UnixMS     int64
}

// Vector is the exported state.
type Vector struct {
	RTTMS            float64 `json:"rtt_ms"`
	JitterMS         float64 `json:"jitter_ms"`
	RSTRate          float64 `json:"rst_rate"`     // fraction of window
	TimeoutRate      float64 `json:"timeout_rate"` // fraction of window
	DropRate         float64 `json:"drop_rate"`    // fraction of window !OK
	StepDelta        float64 `json:"step_delta"`   // CUSUM accumulator (0..cusumCap)
	StepAlarm        bool    `json:"step_alarm"`
	LastAnomaly      int     `json:"last_anomaly"`
	WeakestTransport string  `json:"weakest_transport"`
	Regime           string  `json:"regime"`
	Observations     int     `json:"observations"`
	// 2.16 — AXR-v3 context extensions (all derived from local outcomes):
	ThroughputBPS float64 `json:"throughput_bps"` // EWMA of measured tunnel bytes/sec
	RTTSlopeMS    float64 `json:"rtt_slope_ms"`   // EWMA of signed RTT change per obs
	LossVel       float64 `json:"loss_vel"`       // recent drop rate - window drop rate (-1..1)
	TLSErrRate    float64 `json:"tls_err_rate"`   // fraction of window failing at TLS
}

type obs struct {
	ok   bool
	rst  bool
	tmo  bool
	tls  bool // 2.16: failed at the TLS handshake
	anom int
	tr   string
}

// Tracker is the sliding-window state machine. Safe for concurrent use:
// Feed may run from several tunnel goroutines at once (per-entry trackers
// are shared), and Vector reads the same window — all state lives behind
// the mutex.
type Tracker struct {
	mu sync.Mutex

	win  []obs
	head int
	full bool

	rttEMA   float64
	jitEMA   float64
	rttSlope float64 // 2.16: EWMA of signed RTT delta (ms)
	through  float64 // 2.16: EWMA of measured throughput (bytes/sec)
	prevRTT  float64
	haveRTT  bool

	cusum float64
	// baseline success over the whole window at the moment the CUSUM last
	// reset to 0 (or the start), used for "step change" semantics.
	baseOK int
	baseN  int
}

func NewTracker() *Tracker { return &Tracker{} }

// Feed records one observation.
func (t *Tracker) Feed(s Sample) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.feedLocked(s)
}

// feedLocked records one observation (caller holds t.mu).
func (t *Tracker) feedLocked(s Sample) {
	o := obs{ok: s.OK, tr: s.Transport}
	if !s.OK {
		switch s.ErrClass {
		case ErrRST:
			o.rst = true
		case ErrTimeout:
			o.tmo = true
		case ErrTLS:
			o.tls = true
		}
	}
	// 2.16 — measured tunnel throughput (OK samples only).
	if s.OK && s.Throughput > 0 {
		if t.through == 0 {
			t.through = s.Throughput
		} else {
			t.through = 0.3*s.Throughput + 0.7*t.through
		}
	}
	if s.Anomaly != 0 {
		o.anom = s.Anomaly
	}
	if t.full {
		t.win[t.head] = o
	} else {
		t.win = append(t.win, o)
		if len(t.win) == windowSize {
			t.full = true
		}
	}
	t.head = (t.head + 1) % windowSize

	// --- RTT EWMA + jitter EWMA + signed slope (OK samples with rtt) ---
	if s.OK && s.RTTMS > 0 {
		if !t.haveRTT {
			t.rttEMA = s.RTTMS
			t.prevRTT = s.RTTMS
			t.haveRTT = true
		} else {
			delta := math.Abs(s.RTTMS - t.prevRTT)
			if t.jitEMA == 0 {
				t.jitEMA = delta
			} else {
				t.jitEMA = alphaJit*delta + (1-alphaJit)*t.jitEMA
			}
			// 2.16 — signed slope: positive = RTT climbing (congesting),
			// negative = improving. Capped so one outlier cannot dominate.
			slope := s.RTTMS - t.prevRTT
			if slope > 500 {
				slope = 500
			} else if slope < -500 {
				slope = -500
			}
			t.rttSlope = 0.3*slope + 0.7*t.rttSlope
			t.prevRTT = s.RTTMS
			t.rttEMA = alphaRTT*s.RTTMS + (1-alphaRTT)*t.rttEMA
		}
	}

	// --- lower-branch CUSUM on the OK indicator (alarms on sustained BAD) ---
	// s = max(0, s + (P0 - K) - ok)   with P0 the baseline success prob.
	p0 := t.baseSuccess()
	prev := t.cusum
	t.cusum = math.Max(0, t.cusum+(p0-cusumK)-boolFloat(s.OK))
	if t.cusum > cusumCap {
		t.cusum = cusumCap
	}
	if prev > 0 && t.cusum == 0 {
		// Re-baseline only on the actual recovery crossing, so the baseline
		// remembers the state the CUSUM was alarming from.
		t.baseOK, t.baseN = t.windowOK(), t.windowN()
	}
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Vector computes the current state vector + regime label.
func (t *Tracker) Vector() Vector {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.vectorLocked()
}

// vectorLocked computes the vector under t.mu (Feed cannot interleave).
func (t *Tracker) vectorLocked() Vector {
	n := t.windowN()
	v := Vector{Observations: n}
	if n == 0 {
		v.Regime = "stable"
		return v
	}
	ok := 0
	rst, tmo, tls := 0, 0, 0
	trOK := map[string]int{}
	trN := map[string]int{}
	for i := 0; i < n; i++ {
		idx := (t.head - 1 - i + windowSize*2) % windowSize
		o := t.win[idx]
		if o.ok {
			ok++
		}
		if o.rst {
			rst++
		}
		if o.tmo {
			tmo++
		}
		if o.tls {
			tls++
		}
		if o.tr != "" {
			trN[o.tr]++
			if o.ok {
				trOK[o.tr]++
			}
		}
		if o.anom != 0 && v.LastAnomaly == 0 {
			v.LastAnomaly = o.anom
		}
	}
	v.RTTMS = t.rttEMA
	v.JitterMS = t.jitEMA
	v.RSTRate = float64(rst) / float64(n)
	v.TimeoutRate = float64(tmo) / float64(n)
	v.DropRate = 1 - float64(ok)/float64(n)
	v.StepDelta = t.cusum
	v.StepAlarm = t.cusum >= cusumAlarm
	// 2.16 — v3 context fields.
	v.ThroughputBPS = t.through
	v.RTTSlopeMS = t.rttSlope
	v.TLSErrRate = float64(tls) / float64(n)
	// Loss velocity: how much WORSE (positive) or better (negative) the
	// recent short horizon is than the window baseline.
	recentK := 8
	if recentK > n {
		recentK = n
	}
	recentOK := 0
	for i := 0; i < recentK; i++ {
		if t.win[(t.head-i-1+windowSize*2)%windowSize].ok {
			recentOK++
		}
	}
	v.LossVel = (1 - float64(recentOK)/float64(recentK)) - v.DropRate

	// weakest transport: lowest success ratio among transports with >=3 obs.
	for tr, cnt := range trN {
		ratio := float64(trOK[tr]) / float64(cnt)
		if cnt >= 3 && ratio < 0.75 {
			if v.WeakestTransport == "" || ratio < float64(trOK[v.WeakestTransport])/float64(trN[v.WeakestTransport]) {
				v.WeakestTransport = tr
			}
		}
	}

	v.Regime = t.regime(v)
	return v
}

// regime is the deterministic label logic (mirrors the worker's regime
// semantics: sustained degradation vs a step change vs recovery).
func (t *Tracker) regime(v Vector) string {
	base := t.baseSuccess()
	recent := float64(t.recentOK(10)) / float64(t.recentN(10))
	// Step change: baseline was healthy, recent collapsed (CUSUM confirms or
	// the window-wide drop is already severe).
	if base >= baselineHealthy && recent <= recentBad && (t.cusum >= cusumAlarm || v.DropRate >= hardDropRate) {
		return "suspected_change"
	}
	// Recovery: baseline was unhealthy, recent clearly improved.
	if base < baselineHealthy && recent >= recentGood && v.DropRate < watchDropRate {
		return "recovering"
	}
	if v.DropRate >= watchDropRate || v.RSTRate >= rstAlarmRate || v.TimeoutRate >= timeoutAlarmRate {
		return "watch"
	}
	return "stable"
}

func (t *Tracker) windowN() int {
	if t.full {
		return windowSize
	}
	return len(t.win)
}

func (t *Tracker) windowOK() int {
	c := 0
	for i := 0; i < t.windowN(); i++ {
		if t.win[(t.head-i-1+windowSize*2)%windowSize].ok {
			c++
		}
	}
	return c
}

func (t *Tracker) baseSuccess() float64 {
	if t.baseN == 0 {
		return 1.0 // no history: assume healthy
	}
	return float64(t.baseOK) / float64(t.baseN)
}

func (t *Tracker) recentOK(k int) int {
	c := 0
	for i := 0; i < k && i < t.windowN(); i++ {
		if t.win[(t.head-i-1+windowSize*2)%windowSize].ok {
			c++
		}
	}
	return c
}

func (t *Tracker) recentN(k int) int {
	if t.windowN() < k {
		return t.windowN()
	}
	return k
}

// String is for logs and the local decision view.
func (v Vector) String() string {
	return fmt.Sprintf("rtt=%.0fms jit=%.0fms drop=%.0f%% rst=%.0f%% tmo=%.0f%% tls=%.0f%% vel=%.2f thr=%.0fB/s cusum=%.2f anom=%d regime=%s",
		v.RTTMS, v.JitterMS, v.DropRate*100, v.RSTRate*100, v.TimeoutRate*100, v.TLSErrRate*100,
		v.LossVel, v.ThroughputBPS, v.StepDelta, v.LastAnomaly, v.Regime)
}
