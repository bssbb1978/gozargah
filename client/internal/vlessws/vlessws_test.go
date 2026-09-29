package vlessws

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var testUUID = []byte{
	0x6b, 0x7c, 0x6e, 0x12, 0x50, 0x38, 0x4b, 0x4c,
	0xa1, 0x1b, 0x71, 0x4c, 0x9e, 0x08, 0x9d, 0x6e,
}

func TestBuildVLESSHeaderDomain(t *testing.T) {
	h, err := BuildVLESSHeader(testUUID, "example.com", 8080, false)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 0, 1+16+1+1+2+1+1+len("example.com"))
	want = append(want, 0x00)
	want = append(want, testUUID...)
	want = append(want, 0x00) // optLen
	want = append(want, 0x01) // cmd TCP
	want = append(want, 0x1F, 0x90) // 8080 BE
	want = append(want, 0x02) // atyp domain
	want = append(want, byte(len("example.com")))
	want = append(want, []byte("example.com")...)
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("header mismatch:\n got %x\nwant %x", h, want)
	}
	if len(h) < 24 {
		t.Fatal("header below the 24-byte minimum")
	}
}

func TestBuildVLESSHeaderIPv4(t *testing.T) {
	h, err := BuildVLESSHeader(testUUID, "203.0.113.7", 443, false)
	if err != nil {
		t.Fatal(err)
	}
	if h[21] != 0x01 {
		t.Fatalf("atyp should be 1 for IPv4, got %d", h[21])
	}
	if !bytes.Equal(h[22:26], []byte{203, 0, 113, 7}) {
		t.Fatalf("ipv4 addr mismatch: %x", h[22:26])
	}
}

func TestBuildVLESSHeaderIPv6(t *testing.T) {
	h, err := BuildVLESSHeader(testUUID, "2001:db8::1", 443, false)
	if err != nil {
		t.Fatal(err)
	}
	if h[21] != 0x03 {
		t.Fatalf("atyp should be 3 for IPv6, got %d", h[21])
	}
	if len(h) != 1+16+1+1+2+1+16 {
		t.Fatalf("ipv6 header length = %d", len(h))
	}
}

func TestBuildVLESSHeaderUDP(t *testing.T) {
	h, err := BuildVLESSHeader(testUUID, "example.com", 53, true)
	if err != nil {
		t.Fatal(err)
	}
	if h[18] != 0x02 {
		t.Fatalf("cmd should be 2 for UDP, got %d", h[18])
	}
}

func TestBuildVLESSHeaderRejectsBadUUID(t *testing.T) {
	if _, err := BuildVLESSHeader([]byte("short"), "example.com", 443, false); err == nil {
		t.Fatal("short uuid must be rejected")
	}
}

func TestUUIDFromString(t *testing.T) {
	dashed := "6b7c6e12-5038-4b4c-a11b-714c9e089d6e"
	b, err := UUIDFromString(dashed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b, testUUID) {
		t.Fatalf("uuid mismatch: %x", b)
	}
	plain, err := UUIDFromString("6b7c6e1250384b4ca11b714c9e089d6e")
	if err != nil || !reflect.DeepEqual(plain, testUUID) {
		t.Fatal("plain hex uuid failed")
	}
	if _, err := UUIDFromString("nope"); err == nil {
		t.Fatal("garbage uuid must fail")
	}
}

func TestEarlyDataRoundTrip(t *testing.T) {
	h, _ := BuildVLESSHeader(testUUID, "example.com", 443, false)
	ed, err := EncodeEarlyData(h)
	if err != nil {
		t.Fatal(err)
	}
	// base64url no padding: no '=' and only url-safe chars.
	if bytes.ContainsAny([]byte(ed), "=+/") {
		t.Fatalf("early data not raw-base64url: %s", ed)
	}
	back, err := DecodeEarlyData(ed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, h) {
		t.Fatal("early data round-trip mismatch")
	}
}

func TestEarlyDataLimit(t *testing.T) {
	if _, err := EncodeEarlyData(make([]byte, earlyDataLimit+1)); err == nil {
		t.Fatal("over-limit early data must be rejected")
	}
}

func TestEncodeClientFrameSmall(t *testing.T) {
	payload := []byte("hello")
	mask := [4]byte{0x01, 0x02, 0x03, 0x04}
	frame := EncodeClientFrame(opBinary, payload, mask)
	// header: 0x82 0x85 + 4 mask bytes
	if frame[0] != 0x82 || frame[1] != 0x85 {
		t.Fatalf("frame header = %x %x", frame[0], frame[1])
	}
	if !bytes.Equal(frame[2:6], []byte{1, 2, 3, 4}) {
		t.Fatal("mask key not in place")
	}
	// unmask and verify
	got := make([]byte, len(payload))
	for i, b := range frame[6:] {
		got[i] = b ^ mask[i%4]
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unmasked payload mismatch: %x", got)
	}
}

func TestDecodeServerFrameLengthPaths(t *testing.T) {
	mk := func(n int) []byte { return bytes.Repeat([]byte{0xAB}, n) }

	// 7-bit length
	small := mk(100)
	f := []byte{0x82, 100}
	f = append(f, small...)
	op, payload, n, err := DecodeServerFrame(f)
	if err != nil || op != opBinary || !bytes.Equal(payload, small) || n != len(f) {
		t.Fatalf("small path failed: op=%d n=%d err=%v", op, n, err)
	}

	// 16-bit length
	med := mk(300)
	f = []byte{0x82, 126, 1, 44}
	f = append(f, med...)
	_, payload, n, err = DecodeServerFrame(f)
	if err != nil || !bytes.Equal(payload, med) || n != len(f) {
		t.Fatalf("16-bit path failed: n=%d err=%v", n, err)
	}

	// 64-bit length (use a small payload with the long header form)
	long := mk(50)
	f = []byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 50}
	f = append(f, long...)
	_, payload, n, err = DecodeServerFrame(f)
	if err != nil || !bytes.Equal(payload, long) || n != len(f) {
		t.Fatalf("64-bit path failed: n=%d err=%v", n, err)
	}

	// masked server frame must be rejected
	masked := []byte{0x82, 0x85, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if _, _, _, err = DecodeServerFrame(masked); err == nil {
		t.Fatal("masked server frame must be rejected")
	}

	// short buffer
	if _, _, _, err = DecodeServerFrame([]byte{0x82}); err != io.ErrShortBuffer {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestEncodeDecodeRoundTripLong(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 60000)

	// Client side: encode a masked frame and unmask it to verify.
	mask := MaskKey()
	frame := EncodeClientFrame(opBinary, payload, mask)
	// 60000 < 1<<16 -> 16-bit length header: 2 + 2 + 4 mask = 8 bytes.
	if len(frame) != len(payload)+8 {
		t.Fatalf("frame length = %d, want %d", len(frame), len(payload)+8)
	}
	if frame[1] != 0x80|126 {
		t.Fatalf("16-bit length marker wrong: %x", frame[1])
	}
	if got := int(frame[2])<<8 | int(frame[3]); got != len(payload) {
		t.Fatalf("encoded length = %d", got)
	}
	got := make([]byte, len(payload))
	copy(got, frame[8:])
	for i := range got {
		got[i] ^= mask[i%4]
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("unmasked client frame payload mismatch")
	}

	// Server side: decode an unmasked 16-bit-length frame.
	serverFrame := []byte{0x82, 126, 0xEA, 0x60} // 60000 big-endian
	serverFrame = append(serverFrame, payload...)
	op, dec, n, err := DecodeServerFrame(serverFrame)
	if err != nil || op != opBinary || n != len(serverFrame) {
		t.Fatalf("long decode failed: n=%d err=%v", n, err)
	}
	if !bytes.Equal(dec, payload) {
		t.Fatal("long payload mismatch")
	}
}

func TestExpectedAcceptMatchesRFC(t *testing.T) {
	// RFC 6455 §1.3 example.
	key := []byte("dGhlIHNhbXBsZSBub25jZQ==")
	accept := expectedAccept(key)
	if accept != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept mismatch: %s", accept)
	}
	// And the constant math is right:
	h := sha1.New()
	h.Write(key)
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if base64.StdEncoding.EncodeToString(h.Sum(nil)) != accept {
		t.Fatal("accept derivation mismatch")
	}
}

// ---- 2.18 — WebSocket frame-rhythm fragmentation ----

// decodeClientFrame parses one MASKED client frame (test helper): returns
// opcode, FIN bit, and the unmasked payload.
func decodeClientFrame(f []byte) (opcode byte, fin bool, payload []byte, err error) {
	if len(f) < 2 {
		return 0, false, nil, io.ErrShortBuffer
	}
	opcode = f[0] & 0x0f
	fin = f[0]&0x80 != 0
	if f[1]&0x80 == 0 {
		return 0, false, nil, errors.New("client frame must be masked")
	}
	l := int(f[1] & 0x7f)
	off := 2
	switch l {
	case 126:
		if len(f) < 4 {
			return 0, false, nil, io.ErrShortBuffer
		}
		l = int(binary.BigEndian.Uint16(f[2:4]))
		off = 4
	case 127:
		if len(f) < 10 {
			return 0, false, nil, io.ErrShortBuffer
		}
		l = int(binary.BigEndian.Uint64(f[2:10]))
		off = 10
	}
	if len(f) < off+4+l {
		return 0, false, nil, io.ErrShortBuffer
	}
	mask := [4]byte{f[off], f[off + 1], f[off + 2], f[off + 3]}
	payload = make([]byte, l)
	for i := 0; i < l; i++ {
		payload[i] = f[off+4+i] ^ mask[i%4]
	}
	return opcode, fin, payload, nil
}

func TestEncodeClientFragmentFIN(t *testing.T) {
	mask := [4]byte{9, 8, 7, 6}
	payload := []byte("abc")
	frag := EncodeClientFragment(opBinary, false, payload, mask)
	if frag[0] != 0x02 {
		t.Fatalf("first fragment must carry opcode 2 with FIN clear: %x", frag[0])
	}
	last := EncodeClientFragment(opContinuation, true, payload, mask)
	if last[0] != 0x80 {
		t.Fatalf("final continuation must be 0x80 (FIN+cont): %x", last[0])
	}
	// Unmask both and reassemble.
	var got []byte
	for _, f := range [][]byte{frag, last} {
		_, _, p, err := decodeClientFrame(f)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		got = append(got, p...)
	}
	want := append(append([]byte{}, payload...), payload...)
	if !bytes.Equal(got, want) {
		t.Fatal("unmasked reassembly mismatch")
	}
}

func TestEncodeClientFrameRegression(t *testing.T) {
	// The classic one-shot frame must be byte-identical to FIN=true.
	mask := [4]byte{1, 2, 3, 4}
	p := []byte("hello")
	if !bytes.Equal(EncodeClientFrame(opBinary, p, mask), EncodeClientFragment(opBinary, true, p, mask)) {
		t.Fatal("classic frame layout changed")
	}
}

func TestFragmenterSplitBounds(t *testing.T) {
	src := rand.New(rand.NewSource(11))
	f := NewFragmenter(func() float64 { return src.Float64() })
	// Below the 2*min (512 B) fragmentation floor, a payload stays whole.
	if s := f.Split(300); len(s) != 1 || s[0] != 300 {
		t.Fatalf("300 B must stay whole (below the 2*min floor): %v", s)
	}
	for _, n := range []int{1000, 5000, 10000, 32768, 65536} {
		sizes := f.Split(n)
		if len(sizes) < 2 || len(sizes) > 4 {
			t.Fatalf("n=%d: fragment count %d out of [2,4]: %v", n, len(sizes), sizes)
		}
		sum := 0
		for i, sz := range sizes {
			sum += sz
			if sz < 1 || sz > fragMaxBytes {
				t.Fatalf("n=%d: fragment %d out of [1,%d]: %d", n, i, fragMaxBytes, sz)
			}
			if i < len(sizes)-1 && sz < fragMinBytes {
				t.Fatalf("n=%d: fragment %d below min: %d", n, i, sz)
			}
		}
		if sum != n {
			t.Fatalf("n=%d: sizes sum to %d: %v", n, sum, sizes)
		}
	}
	// Small and empty payloads pass through whole.
	if s := f.Split(100); len(s) != 1 || s[0] != 100 {
		t.Fatalf("small payload must stay whole: %v", s)
	}
	if s := f.Split(0); len(s) != 1 || s[0] != 0 {
		t.Fatalf("empty payload: %v", s)
	}
	// Nil-safety.
	var nf *Fragmenter
	if s := nf.Split(1000); len(s) != 1 || s[0] != 1000 {
		t.Fatalf("nil fragmenter: %v", s)
	}
}

func TestFragmenterDeterministic(t *testing.T) {
	f1 := NewFragmenter(func() float64 { return 0.5 })
	f2 := NewFragmenter(func() float64 { return 0.5 })
	for n := 2000; n <= 4000; n += 512 {
		a, b := f1.Split(n), f2.Split(n)
		if len(a) != len(b) {
			t.Fatalf("n=%d: counts differ: %v vs %v", n, a, b)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("n=%d: size %d differs: %v vs %v", n, i, a, b)
			}
		}
	}
}

// frameRecorder captures each Write on the fake conn (one recorded frame
// per write call — synchronous, like the surgery recorder).
type frameRecorder struct {
	mu     sync.Mutex
	frames [][]byte
}

type frConn struct{ r *frameRecorder }

type frAddr string

func (a frAddr) Network() string { return "pipe" }
func (a frAddr) String() string  { return string(a) }

func (c *frConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *frConn) Write(b []byte) (int, error) {
	c.r.mu.Lock()
	cp := make([]byte, len(b))
	copy(cp, b)
	c.r.frames = append(c.r.frames, cp)
	c.r.mu.Unlock()
	return len(b), nil
}
func (c *frConn) Close() error                   { return nil }
func (c *frConn) LocalAddr() net.Addr            { return frAddr("local") }
func (c *frConn) RemoteAddr() net.Addr           { return frAddr("remote") }
func (c *frConn) SetDeadline(time.Time) error    { return nil }
func (c *frConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *frConn) SetWriteDeadline(time.Time) error { return nil }

func TestFragmenterSendRhythm(t *testing.T) {
	rec := &frameRecorder{}
	src := rand.New(rand.NewSource(23))
	f := NewFragmenter(func() float64 { return src.Float64() })
	c := &Client{conn: &frConn{r: rec}, frag: f}

	payload := make([]byte, 32768)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := c.SendBinary(payload); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	frames := make([][]byte, len(rec.frames))
	copy(frames, rec.frames)
	rec.mu.Unlock()

	if len(frames) < 2 || len(frames) > 4 {
		t.Fatalf("32 KB must fragment into 2-4 frames, got %d", len(frames))
	}
	var got []byte
	for i, f := range frames {
		op, fin, p, err := decodeClientFrame(f)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		var wantOp byte = opBinary
		if i > 0 {
			wantOp = opContinuation
		}
		if op != wantOp {
			t.Fatalf("frame %d: opcode %d, want %d", i, op, wantOp)
		}
		if wantFin := i == len(frames)-1; fin != wantFin {
			t.Fatalf("frame %d: fin=%v, want %v", i, fin, wantFin)
		}
		got = append(got, p...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fragmented reassembly mismatch")
	}
}

func TestFragmenterSmallPassthrough(t *testing.T) {
	rec := &frameRecorder{}
	c := &Client{conn: &frConn{r: rec}, frag: NewFragmenter(func() float64 { return 0.5 })}
	if err := c.SendBinary(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	frames := make([][]byte, len(rec.frames))
	copy(frames, rec.frames)
	rec.mu.Unlock()
	if len(frames) != 1 {
		t.Fatalf("100 B must stay one frame, got %d", len(frames))
	}
	op, fin, p, err := decodeClientFrame(frames[0])
	if err != nil || op != opBinary || !fin || len(p) != 100 {
		t.Fatalf("passthrough frame wrong: op=%d fin=%v n=%d err=%v", op, fin, len(p), err)
	}
}

func TestSendBinaryNoFragmenter(t *testing.T) {
	rec := &frameRecorder{}
	c := &Client{conn: &frConn{r: rec}} // classic behaviour
	p := make([]byte, 20000)
	if err := c.SendBinary(p); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	n := len(rec.frames)
	rec.mu.Unlock()
	if n != 1 {
		t.Fatalf("no fragmenter: exactly one frame expected, got %d", n)
	}
}

// ---- 2.20 — upgrade request shape jitter ----

// parseUpgrade splits the request text into lower-cased header names
// (failing on malformed input, duplicates, or a missing blank-line end).
func parseUpgrade(t *testing.T, req string) map[string]string {
	t.Helper()
	lines := strings.Split(req, "\r\n")
	if len(lines) < 3 || lines[0] != "GET /up HTTP/1.1" {
		t.Fatalf("bad request line: %q", req[:min(40, len(req))])
	}
	if lines[len(lines)-2] != "" {
		t.Fatalf("must end with a blank line: %q", req)
	}
	m := make(map[string]string)
	for _, ln := range lines[1 : len(lines)-2] {
		k, v, ok := strings.Cut(ln, ": ")
		if !ok || k == "" {
			t.Fatalf("bad header line: %q", ln)
		}
		if _, dup := m[strings.ToLower(k)]; dup {
			t.Fatalf("duplicate header %q", k)
		}
		m[strings.ToLower(k)] = v
	}
	return m
}

func TestUpgradeRequestClassicRegression(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	kb := base64.StdEncoding.EncodeToString(key)
	got := buildUpgradeRequest("ex.com", "/up", key, "", nil)
	want := "GET /up HTTP/1.1\r\n" +
		"Host: ex.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + kb + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("classic request changed:\n got %q\nwant %q", got, want)
	}
	// With early data, the protocol header rides in the classic slot.
	got = buildUpgradeRequest("ex.com", "/up", key, "abc", nil)
	want = "GET /up HTTP/1.1\r\n" +
		"Host: ex.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + kb + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: abc\r\n" +
		"\r\n"
	if got != want {
		t.Fatalf("classic request with early data changed:\n got %q\nwant %q", got, want)
	}
}

func TestUpgradeShapeContent(t *testing.T) {
	key := []byte{9, 9, 9, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	kb := base64.StdEncoding.EncodeToString(key)
	locale := "en-GB,en;q=0.9"
	ua := UAPool[0]
	origin := OriginPool[0]

	for seed := int64(1); seed < 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		// Lite
		sh := NewUpgradeShape(rng.Float64, UpgradeLite, locale, "", "")
		m := parseUpgrade(t, buildUpgradeRequest("ex.com", "/up", key, "ed", sh))
		if m["host"] != "ex.com" || m["upgrade"] != "websocket" ||
			m["connection"] != "Upgrade" || m["sec-websocket-key"] != kb ||
			m["sec-websocket-version"] != "13" || m["sec-websocket-protocol"] != "ed" {
			t.Fatalf("lite seed %d: required headers wrong: %v", seed, m)
		}
		if m["accept-encoding"] != "gzip" || m["accept-language"] != locale {
			t.Fatalf("lite seed %d: optional headers missing: %v", seed, m)
		}
		if _, ok := m["user-agent"]; ok {
			t.Fatalf("lite seed %d: must not carry a user agent", seed)
		}
		// Full
		rng = rand.New(rand.NewSource(seed))
		sh = NewUpgradeShape(rng.Float64, UpgradeFull, locale, ua, origin)
		m = parseUpgrade(t, buildUpgradeRequest("ex.com", "/up", key, "", sh))
		if m["sec-fetch-site"] != "cross-site" || m["sec-fetch-mode"] != "websocket" ||
			m["sec-fetch-dest"] != "websocket" || m["origin"] != origin || m["user-agent"] != ua {
			t.Fatalf("full seed %d: browser headers wrong: %v", seed, m)
		}
		if _, ok := m["sec-websocket-protocol"]; ok {
			t.Fatalf("full seed %d: no early data, no protocol header", seed)
		}
	}
}

func TestUpgradeShapeDeterministic(t *testing.T) {
	key := []byte{1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8}
	a := NewUpgradeShape(rand.New(rand.NewSource(77)).Float64, UpgradeFull, LocalePool[2], UAPool[1], OriginPool[2])
	b := NewUpgradeShape(rand.New(rand.NewSource(77)).Float64, UpgradeFull, LocalePool[2], UAPool[1], OriginPool[2])
	ra := buildUpgradeRequest("h.example", "/p?a=1", key, "x", a)
	rb := buildUpgradeRequest("h.example", "/p?a=1", key, "x", b)
	if ra != rb {
		t.Fatalf("same seed must give the same request:\n%q\nvs\n%q", ra, rb)
	}
}

func TestUpgradeShapeOrderInvariants(t *testing.T) {
	key := []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
	for seed := int64(0); seed < 20; seed++ {
		for _, tpl := range []UpgradeTemplate{UpgradeBare, UpgradeLite, UpgradeFull} {
			sh := NewUpgradeShape(rand.New(rand.NewSource(seed)).Float64, tpl, LocalePool[0], UAPool[0], OriginPool[0])
			req := buildUpgradeRequest("ex.com", "/up", key, "ed", sh)
			lines := strings.Split(req, "\r\n")
			if len(lines) < 3 || !strings.HasPrefix(lines[1], "Host: ") {
				t.Fatalf("seed %d tpl %d: first header must be Host: %q", seed, tpl, lines[1])
			}
			pos := func(name string) int {
				for i, ln := range lines[1:] {
					if k, _, ok := strings.Cut(ln, ": "); ok && strings.EqualFold(k, name) {
						return i
					}
				}
				t.Fatalf("seed %d tpl %d: missing %s in:\n%s", seed, tpl, name, req)
				return -1
			}
			pu, pc := pos("Upgrade"), pos("Connection")
			pk, pv, pp := pos("Sec-WebSocket-Key"), pos("Sec-WebSocket-Version"), pos("Sec-WebSocket-Protocol")
			if pu > pc || pc > pk || pk > pv || pv > pp {
				t.Fatalf("seed %d tpl %d: order Upgrade,Connection < Key < Version < Protocol violated: %d %d %d %d %d",
					seed, tpl, pu, pc, pk, pv, pp)
			}
		}
	}
}
