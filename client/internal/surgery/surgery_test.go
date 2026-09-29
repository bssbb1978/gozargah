package surgery

import (
	"math/rand"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// recorder collects the write calls the server side sees.
type recorder struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *recorder) start() net.Conn {
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := b.Read(buf)
			if n > 0 {
				r.mu.Lock()
				cp := make([]byte, n)
				copy(cp, buf[:n])
				r.writes = append(r.writes, cp)
				r.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return a
}

func (r *recorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, w := range r.writes {
		n += len(w)
	}
	return n
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

func (r *recorder) sizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, len(r.writes))
	for i, w := range r.writes {
		out[i] = len(w)
	}
	return out
}

// waitUntil polls cond until true or timeout.
func (r *recorder) waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for recorder condition (writes=%d)", r.count())
}

func fakeRng(seed int64) Rng {
	r := rand.New(rand.NewSource(seed))
	return r.Float64
}

func TestPlanHelloSplitBounds(t *testing.T) {
	for seed := int64(1); seed < 20; seed++ {
		off, ok := PlanHelloSplit(512, fakeRng(seed))
		if !ok {
			t.Fatalf("seed %d: expected a split", seed)
		}
		if off < int(float64(512)*splitLo)-2 || off > int(float64(512)*splitHi)+2 {
			t.Fatalf("seed %d: offset %d outside bounds", seed, off)
		}
	}
	if _, ok := PlanHelloSplit(32, fakeRng(1)); ok {
		t.Fatal("tiny record must not be split")
	}
	if _, ok := PlanHelloSplit(512, nil); ok {
		t.Fatal("nil rng must not split")
	}
}

func TestSplitConnSplitsOnlyFirstWrite(t *testing.T) {
	rec := &recorder{}
	inner := rec.start()
	sc := NewSplitConn(inner, 0, 0, fakeRng(42)) // zero gap for speed
	hello := make([]byte, 512)
	for i := range hello {
		hello[i] = byte(i)
	}
	if _, err := sc.Write(hello); err != nil {
		t.Fatal(err)
	}
	// second write must pass through as a single segment
	if _, err := sc.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	inner.Close()
	rec.waitUntil(t, func() bool { return rec.count() == 3 && rec.total() == 518 })
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.writes) != 3 {
		t.Fatalf("expected 3 segments (2 split hello + 1 pass-through), got %d", len(rec.writes))
	}
	full := append(append(append([]byte{}, rec.writes[0]...), rec.writes[1]...), rec.writes[2]...)
	if len(full) != 518 || !reflect.DeepEqual(full[:512], hello) || string(full[512:]) != "second" {
		t.Fatalf("reassembly mismatch: len=%d", len(full))
	}
	if len(rec.writes[0]) == 512 {
		t.Fatal("first write was not actually split")
	}
}

func TestSplitConnReadClose(t *testing.T) {
	a, b := net.Pipe()
	sc := NewSplitConn(a, 0, 0, fakeRng(1))
	go func() {
		b.Write([]byte("ping"))
		time.Sleep(100 * time.Millisecond)
		b.Close()
	}()
	buf := make([]byte, 4)
	n, err := sc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf) != "ping" {
		t.Fatalf("read through wrapper failed: %q", buf)
	}
	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChunkConnFragmentsAndReassembles(t *testing.T) {
	rec := &recorder{}
	inner := rec.start()
	cc := NewChunkConn(inner, 512, 1400, 0, fakeRng(7))
	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := cc.Write(payload); err != nil {
		t.Fatal(err)
	}
	inner.Close()
	rec.waitUntil(t, func() bool { return rec.total() == 10000 })
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.writes) < 8 {
		t.Fatalf("expected many chunks for 10000B with 512-1400B pieces, got %d", len(rec.writes))
	}
	full := make([]byte, 0, 10000)
	for _, w := range rec.writes {
		full = append(full, w...)
	}
	if !reflect.DeepEqual(full, payload) {
		t.Fatalf("chunked reassembly mismatch: %d vs %d bytes", len(full), len(payload))
	}
	for i, w := range rec.writes {
		if i < len(rec.writes)-1 && (len(w) < 512 || len(w) > 1400) {
			t.Fatalf("piece %d out of bounds: %d", i, len(w))
		}
	}
}

func TestChunkConnPassthroughSmallWrites(t *testing.T) {
	rec := &recorder{}
	inner := rec.start()
	cc := NewChunkConn(inner, 512, 1400, 0, fakeRng(7))
	if _, err := cc.Write([]byte("small")); err != nil {
		t.Fatal(err)
	}
	inner.Close()
	rec.waitUntil(t, func() bool { return rec.total() == 5 })
	if rec.count() != 1 {
		t.Fatalf("small write must not be fragmented, got %d pieces", rec.count())
	}
}

func TestDefaultGapBounds(t *testing.T) {
	rng := fakeRng(3)
	for i := 0; i < 50; i++ {
		g := DefaultGap(rng, 20*time.Millisecond, 120*time.Millisecond)
		if g < 20*time.Millisecond || g > 120*time.Millisecond {
			t.Fatalf("gap %v outside [20ms, 120ms]", g)
		}
	}
}

// ---- 2.16 — multi-segment ClientHello surgery ----

func TestPlanCutsBounds(t *testing.T) {
	n := 2000
	rng := fakeRng(7)
	pts := PlanCuts(n, 2, sniLo, sniHi, rng)
	if pts == nil {
		t.Fatal("2 cuts in a 2KB record must be feasible")
	}
	if len(pts) != 2 || pts[0] >= pts[1] {
		t.Fatalf("cuts must be ascending: %v", pts)
	}
	loB, hiB := int(float64(n)*sniLo), int(float64(n)*sniHi)
	for _, p := range pts {
		if p < loB || p > hiB {
			t.Fatalf("cut %d outside [%d, %d]", p, loB, hiB)
		}
		if p < minSegBytes || p > n-minSegBytes {
			t.Fatalf("cut %d leaves a runt segment", p)
		}
	}
	if pts[1]-pts[0] < minSegBytes {
		t.Fatalf("cuts too close: %v", pts)
	}
	// Deterministic for a fixed rng seed.
	pts2 := PlanCuts(n, 2, sniLo, sniHi, fakeRng(7))
	if len(pts2) != len(pts) || pts2[0] != pts[0] || pts2[1] != pts[1] {
		t.Fatalf("PlanCuts must be deterministic: %v vs %v", pts, pts2)
	}
	// Too-small records are infeasible.
	if PlanCuts(20, 2, sniLo, sniHi, fakeRng(1)) != nil {
		t.Fatal("20-byte record cannot carry 2 cuts")
	}
	if PlanCuts(0, 1, 0.5, 0.6, fakeRng(1)) != nil {
		t.Fatal("empty record must be infeasible")
	}
	if PlanCuts(n, 1, 0.5, 0.5, fakeRng(1)) == nil {
		// degenerate window (lo==hi) is widened by one step and feasible
		t.Fatal("degenerate window should self-widen and be feasible")
	}
}

func TestMultiSplitConnSplitsFirstWrite(t *testing.T) {
	rec := &recorder{}
	conn := rec.start()
	defer conn.Close()
	m := NewMultiSplitConn(conn, 2, sniLo, sniHi, 0, 0, fakeRng(3))
	payload := make([]byte, 2200)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	n, err := m.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	rec.waitUntil(t, func() bool { return rec.total() == len(payload) })
	if rec.count() != 3 {
		t.Fatalf("2 cuts must produce 3 segments, got %d (sizes=%v)", rec.count(), rec.sizes())
	}
	// Reassembly must be byte-exact.
	got := make([]byte, 0, len(payload))
	rec.mu.Lock()
	for _, w := range rec.writes {
		got = append(got, w...)
	}
	rec.mu.Unlock()
	if !reflect.DeepEqual(got, payload) {
		t.Fatal("reassembled segments differ from payload")
	}
	// Second write passes through unsplit.
	before := rec.count()
	if _, err := m.Write([]byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	rec.waitUntil(t, func() bool { return rec.count() >= before+1 })
	if rec.count() != before+1 {
		t.Fatalf("second write must not be split: %d", rec.count())
	}
}

func TestMultiSplitConnSmallWritePassthrough(t *testing.T) {
	rec := &recorder{}
	conn := rec.start()
	defer conn.Close()
	m := NewMultiSplitConn(conn, 3, sniLo, sniHi, 0, 0, fakeRng(1))
	// 20 bytes cannot carry 3 cuts+1 segments of >=8 bytes -> passthrough.
	if _, err := m.Write(make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	rec.waitUntil(t, func() bool { return rec.total() == 20 })
	if rec.count() != 1 {
		t.Fatalf("tiny write must stay whole, got %d segments", rec.count())
	}
}

// ---- 2.17 — SkewGap + multi-write surgery (V2) tests ----

// TestSkewGapBounds: bounded to [min,max], and skewed toward the small end
// (mean of u² on [0,1] is 1/3, so the mean gap ≈ min + (max-min)/3).
func TestSkewGapBounds(t *testing.T) {
	min, max := 1*time.Millisecond, 8*time.Millisecond
	rng := func() float64 { return rand.New(rand.NewSource(5)).Float64() }
	// (a fresh source per call is only for bounds; the moment check below
	// uses one continuous stream)
	for i := 0; i < 1000; i++ {
		g := SkewGap(rng, min, max)
		if g < min || g > max {
			t.Fatalf("SkewGap %v outside [%v,%v]", g, min, max)
		}
	}
	src := rand.New(rand.NewSource(5))
	rngC := func() float64 { return src.Float64() }
	const n = 20000
	span := float64(max - min)
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += float64(SkewGap(rngC, min, max) - min)
	}
	meanFrac := (sum / float64(n)) / span
	if mathAbs(meanFrac-1.0/3.0) > 0.05 {
		t.Fatalf("SkewGap mean fraction = %f, want ~1/3 (quadratic skew)", meanFrac)
	}
	// Degenerate bounds collapse to min; nil rng is safe.
	if g := SkewGap(nil, min, max); g != min {
		t.Fatalf("nil rng must return min, got %v", g)
	}
	if g := SkewGap(rngC, max, min); g != min {
		t.Fatalf("max<=min must return min, got %v", g)
	}
}

func mathAbs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// TestMultiSplitV2SplitsFirstNWrites: with split budget 2, the first two
// handshake-sized writes are split, the third passes through whole.
func TestMultiSplitV2SplitsFirstNWrites(t *testing.T) {
	r := &recorder{}
	c := r.start()
	defer c.Close()
	src := rand.New(rand.NewSource(11))
	m := NewMultiSplitConnV2(c, 2, 2, 0.40, 0.90, 0, 0, func() float64 { return src.Float64() })

	w1 := make([]byte, 1500)
	w2 := make([]byte, 1200)
	w3 := make([]byte, 1000)
	for i := range w1 {
		w1[i] = byte(i % 251)
	}
	for i := range w2 {
		w2[i] = byte(i % 199)
	}
	for i := range w3 {
		w3[i] = byte(i % 253)
	}
	if n, err := m.Write(w1); err != nil || n != 1500 {
		t.Fatalf("write1: n=%d err=%v", n, err)
	}
	afterFirst := r.count()
	if afterFirst < 3 {
		t.Fatalf("write1 must split into >=3 segments (2 cuts), got %d writes", afterFirst)
	}
	if n, err := m.Write(w2); err != nil || n != 1200 {
		t.Fatalf("write2: n=%d err=%v", n, err)
	}
	afterSecond := r.count()
	if afterSecond < afterFirst+3 {
		t.Fatalf("write2 must also split (budget 2), got %d new writes", afterSecond-afterFirst)
	}
	if n, err := m.Write(w3); err != nil || n != 1000 {
		t.Fatalf("write3: n=%d err=%v", n, err)
	}
	if r.count() != afterSecond+1 {
		t.Fatalf("write3 must pass through whole (budget spent), got %d new writes", r.count()-afterSecond)
	}
	if got := r.total(); got != 3700 {
		t.Fatalf("total bytes = %d, want 3700", got)
	}
	// Reassemble the third write and check byte integrity.
	ws := r.writes
	if len(ws) == 0 {
		t.Fatal("no writes recorded")
	}
	last := ws[len(ws)-1]
	if len(last) != 1000 {
		t.Fatalf("third write split despite spent budget: %d bytes", len(last))
	}
	for i, b := range last {
		if b != byte(i%253) {
			t.Fatalf("write3 byte %d corrupted: %d != %d", i, b, byte(i%253))
		}
	}
}

// TestMultiSplitV2SmallWriteKeepsBudget: a write too small to split must
// NOT consume budget — the split still lands on the next eligible write.
func TestMultiSplitV2SmallWriteKeepsBudget(t *testing.T) {
	r := &recorder{}
	c := r.start()
	defer c.Close()
	src := rand.New(rand.NewSource(13))
	m := NewMultiSplitConnV2(c, 1, 1, 0.40, 0.90, 0, 0, func() float64 { return src.Float64() })

	small := make([]byte, 50) // < minRecord (96)
	big := make([]byte, 1500)
	for i := range big {
		big[i] = byte(i % 211)
	}
	if n, err := m.Write(small); err != nil || n != 50 {
		t.Fatalf("small write: n=%d err=%v", n, err)
	}
	if r.count() != 1 {
		t.Fatalf("small write must pass through whole, got %d writes", r.count())
	}
	if n, err := m.Write(big); err != nil || n != 1500 {
		t.Fatalf("big write: n=%d err=%v", n, err)
	}
	if r.count() != 2 {
		t.Fatalf("big write must still split (budget kept), got %d total writes", r.count())
	}
}

// TestMultiSplitV1BackwardCompat: the v1 constructor (split budget 1)
// still splits only the first write.
func TestMultiSplitV1BackwardCompat(t *testing.T) {
	r := &recorder{}
	c := r.start()
	defer c.Close()
	src := rand.New(rand.NewSource(17))
	m := NewMultiSplitConn(c, 2, 0.40, 0.90, 0, 0, func() float64 { return src.Float64() })

	w1 := make([]byte, 1500)
	w2 := make([]byte, 1000)
	if n, err := m.Write(w1); err != nil || n != 1500 {
		t.Fatalf("write1: n=%d err=%v", n, err)
	}
	afterFirst := r.count()
	if afterFirst < 3 {
		t.Fatalf("v1 must split the first write into >=3 segments, got %d", afterFirst)
	}
	if n, err := m.Write(w2); err != nil || n != 1000 {
		t.Fatalf("write2: n=%d err=%v", n, err)
	}
	if r.count() != afterFirst+1 {
		t.Fatalf("v1 must NOT split the second write, got %d new writes", r.count()-afterFirst)
	}
}

// TestNewMultiSplitConnV2ClampsWrites: the split budget is clamped to [1,5].
func TestNewMultiSplitConnV2ClampsWrites(t *testing.T) {
	src := rand.New(rand.NewSource(19))
	m := NewMultiSplitConnV2(nil, 1, 0, 0, 0, 0, 0, func() float64 { return src.Float64() })
	if m.left != 1 {
		t.Fatalf("writes=0 must clamp to 1, got %d", m.left)
	}
	m2 := NewMultiSplitConnV2(nil, 1, 99, 0, 0, 0, 0, func() float64 { return src.Float64() })
	if m2.left != 5 {
		t.Fatalf("writes=99 must clamp to 5, got %d", m2.left)
	}
}
