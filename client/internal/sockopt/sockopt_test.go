package sockopt

import (
	"math/rand"
	"net"
	"testing"
)

func TestSelectSendbufInSet(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		v := SelectSendbuf(r)
		ok := false
		for _, s := range SendbufSet {
			if v == s {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("sendbuf %d not in allowed set", v)
		}
		seen[v] = true
	}
	// With 200 draws over 4 values, expect several distinct picks.
	if len(seen) < 3 {
		t.Fatalf("expected varied picks, got only %v", seen)
	}
}

func TestSelectSendbufNilRand(t *testing.T) {
	if v := SelectSendbuf(nil); v != SendbufSet[0] {
		t.Fatalf("nil rand must deterministically pick the first size, got %d", v)
	}
}

func TestApplyExplicitSize(t *testing.T) {
	// net.Pipe is not a TCP conn: every platform function must no-op, not error.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := Apply(a, Options{NoNagle: true, SNDBUFSize: 128 * 1024}); err != nil {
		t.Fatalf("Apply on non-TCP conn must no-op, got %v", err)
	}
	if err := ApplyWithSeed(b, 7, true); err != nil {
		t.Fatalf("ApplyWithSeed on non-TCP conn must no-op, got %v", err)
	}
}

func TestApplyOnTCP(t *testing.T) {
	// A real loopback TCP socket: on supported platforms this must succeed;
	// on stub platforms it no-ops (nil error) — both are acceptable.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
		close(done)
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := Apply(c, Options{NoNagle: true, SNDBUFSize: 256 * 1024}); err != nil {
		t.Fatalf("Apply on TCP conn: %v", err)
	}
	<-done
}
