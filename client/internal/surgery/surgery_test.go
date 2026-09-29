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
