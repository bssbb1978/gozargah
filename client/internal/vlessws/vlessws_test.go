package vlessws

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"reflect"
	"testing"
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
	if got := int(frame[3])<<8 | int(frame[4]); got != len(payload) {
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
	if accept != "s3pPLMIBIZlLFOJHzqTBDOn7nPA=" {
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
