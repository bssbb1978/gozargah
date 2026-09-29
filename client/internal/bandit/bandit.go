// Package bandit is the AXR client-side decision core: a lightweight,
// zero-dependency contextual UCB1 multi-armed bandit that learns which
// (entry host, transport, TLS fingerprint) arm is currently carrying
// traffic best, and prunes arms that keep degrading.
//
// Design notes (honest boundaries):
//   - Rewards are shaped into [0,1]; hard failures are represented as
//     reward 0 plus a consecutive-failure quarantine, NOT as negative UCB
//     values. This keeps the UCB1 regret bound valid (it assumes [0,1]).
//   - Deterministic under a fixed seed and a fixed call sequence: the
//     exploration tie-break is the stable arm order, never the wall clock.
//   - No DPI detection here: the inputs are the client's own connection
//     outcomes (ok / rtt / throughput / error class), nothing more.
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
	PruneMinPulls   = 12
	PruneMaxRatio   = 0.10
	successThroughputTarget = 2.0 * 1000 * 1000 // 2 MB/s saturates the bonus
)

// Arm is one selectable path: entry host × transport × TLS fingerprint.
type Arm struct {
	Host      string `json:"host"`
	Transport string `json:"transport"` // "ws" | "h2" | "h3" | "grpc"
	FP        string `json:"fp"`        // uTLS identity, e.g. "chrome"
}

// ID is the stable key used for persistence and tie-breaks.
func (a Arm) ID() string { return a.Host + "|" + a.Transport + "|" + a.FP }

// Stats is the per-arm learning state.
type Stats struct {
	Pulls              int     `json:"pulls"`
	TotalReward        float64 `json:"total_reward"`
	ConsecFail         int     `json:"consec_fail"`
	ConsecOK           int     `json:"consec_ok"`
	RTTEWMA            float64 `json:"rtt_ewma_ms"`
	QuarantinedUntilMS int64   `json:"quarantined_until_ms"`
	Pruned             bool    `json:"pruned"`
}

// meanReward is the UCB1 "exploitation" term.
func (s *Stats) meanReward() float64 {
	if s.Pulls == 0 {
		return 0
	}
	return s.TotalReward / float64(s.Pulls)
}

// Context carries the environment signal the core has from the measure
// package (and optionally the worker manifest regime).
type Context struct {
	Regime           string `json:"regime"` // "stable"|"watch"|"suspected_change"|"recovering"
	WeakestTransport string `json:"weakest_transport"`
	NowMS            int64  `json:"now_ms"`
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

// Bandit is the learner. Safe for concurrent use.
type Bandit struct {
	mu    sync.Mutex
	C     float64
	arms  []Arm
	stats map[string]*Stats
	seed  uint64
	// lastID is the previously selected arm, used for the diversity bonus
	// during "suspected_change" (encourages rotating away from the status quo).
	lastID string
}

// New creates a bandit over the given arms. c is the exploration constant
// (1.0 is a good default). seed is retained for future seeded randomness;
// selection is already deterministic without it.
func New(c float64, seed uint64, arms []Arm) *Bandit {
	if c <= 0 {
		c = 1.0
	}
	b := &Bandit{C: c, seed: seed, stats: make(map[string]*Stats, len(arms))}
	for _, a := range arms {
		if a.Host == "" || a.Transport == "" {
			continue
		}
		if a.FP == "" {
			a.FP = "chrome"
		}
		if _, ok := b.stats[a.ID()]; ok {
			continue
		}
		b.arms = append(b.arms, a)
		b.stats[a.ID()] = &Stats{}
	}
	if len(b.arms) == 0 {
		panic("bandit.New: no valid arms")
	}
	return b
}

// ErrNoArm is returned when every arm is quarantined/pruned at selection time.
var ErrNoArm = errors.New("bandit: no selectable arm")

// Score is the transparent per-arm decision trace (exported for the local
// decision view and tests).
type Score struct {
	Arm        Arm     `json:"arm"`
	Mean       float64 `json:"mean"`
	Ucb        float64 `json:"ucb"`
	Diversity  float64 `json:"diversity"`
	WeakestHit float64 `json:"weakest_hit"`
	Total      float64 `json:"total"`
	Quarantined bool   `json:"quarantined"`
	Pruned      bool   `json:"pruned"`
}

// Scores exposes the full score table for the current context.
func (b *Bandit) Scores(ctx Context) []Score {
	b.mu.Lock()
	defer b.mu.Unlock()
	total := b.totalPulls()
	exploration := b.C
	if ctx.Regime == "suspected_change" {
		exploration *= 1.8 // regime-driven exploration boost
	}
	out := make([]Score, 0, len(b.arms))
	for _, a := range b.arms {
		s := b.stats[a.ID()]
		sc := Score{Arm: a, Quarantined: s.QuarantinedUntilMS > ctx.NowMS, Pruned: s.Pruned}
		sc.Mean = s.meanReward()
		if s.Pulls > 0 {
			sc.Ucb = sc.Mean + exploration*math.Sqrt(math.Log(float64(total+1))/float64(s.Pulls))
		} else {
			// Untried arms get the max possible mean so they are explored.
			sc.Ucb = 1.0 + exploration
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

func (b *Bandit) scoresLocked(ctx Context) []Score {
	total := b.totalPulls()
	exploration := b.C
	if ctx.Regime == "suspected_change" {
		exploration *= 1.8
	}
	out := make([]Score, 0, len(b.arms))
	for _, a := range b.arms {
		s := b.stats[a.ID()]
		sc := Score{Arm: a, Quarantined: s.QuarantinedUntilMS > ctx.NowMS, Pruned: s.Pruned}
		sc.Mean = s.meanReward()
		if s.Pulls > 0 {
			sc.Ucb = sc.Mean + exploration*math.Sqrt(math.Log(float64(total+1))/float64(s.Pulls))
		} else {
			sc.Ucb = 1.0 + exploration
		}
		if ctx.WeakestTransport != "" && a.Transport == ctx.WeakestTransport && ctx.Regime != "stable" {
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

func (b *Bandit) totalPulls() int {
	total := 0
	for _, s := range b.stats {
		total += s.Pulls
	}
	return total
}

// Observe feeds one outcome back for arm a at time now (ms).
func (b *Bandit) Observe(a Arm, o Outcome, now int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.stats[a.ID()]
	if !ok {
		return
	}
	s.Pulls++
	s.TotalReward += reward(o)
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
	if a.FP == "" {
		a.FP = "chrome"
	}
	if _, ok := b.stats[a.ID()]; ok {
		return
	}
	b.arms = append(b.arms, a)
	b.stats[a.ID()] = &Stats{}
}

// Arms returns a copy of the arm list.
func (b *Bandit) Arms() []Arm {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Arm, len(b.arms))
	copy(out, b.arms)
	return out
}

// Snapshot is the JSON-persistable state (arm set + stats + config).
type Snapshot struct {
	C     float64            `json:"c"`
	Seed  uint64             `json:"seed"`
	Arms  []Arm              `json:"arms"`
	Stats map[string]*Stats  `json:"stats"`
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
	arms := make([]Arm, len(b.arms))
	copy(arms, b.arms)
	return Snapshot{C: b.C, Seed: b.seed, Arms: arms, Stats: stats}
}

// Restore loads persisted state. Unknown arms in old snapshots are ignored;
// missing arms get fresh stats.
func (b *Bandit) Restore(s Snapshot) error {
	if len(s.Arms) == 0 {
		return fmt.Errorf("bandit: empty snapshot")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.C > 0 {
		b.C = s.C
	}
	b.arms = nil
	b.stats = make(map[string]*Stats, len(s.Arms))
	for _, a := range s.Arms {
		if a.Host == "" || a.Transport == "" {
			continue
		}
		if a.FP == "" {
			a.FP = "chrome"
		}
		if _, ok := b.stats[a.ID()]; ok {
			continue
		}
		b.arms = append(b.arms, a)
		if st, ok := s.Stats[a.ID()]; ok {
			cp := *st
			b.stats[a.ID()] = &cp
		} else {
			b.stats[a.ID()] = &Stats{}
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
