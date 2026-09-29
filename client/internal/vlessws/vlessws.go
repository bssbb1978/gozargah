// Package vlessws implements the AXR VLESS-over-WebSocket client tunnel:
//
//   - the VLESS v1 header, byte-compatible with the gozargah Worker's
//     parser:  [ver:1=0][uuid:16][optLen:1][opt][cmd:1][port:2 BE][atyp:1][addr]
//     with atyp 1=IPv4(4B), 2=domain(len:1+bytes), 3=IPv6(16B); the success
//     response is exactly [ver, 0x00].
//   - 0-RTT early data: the full VLESS header is base64url-encoded (no
//     padding) and carried in Sec-WebSocket-Protocol, which the Worker's
//     acceptWebSocket consumes as up to 2048 decoded bytes prepended to the
//     header buffer — so the client must NOT resend those bytes.
//   - a minimal RFC 6455 client: masked client frames, unmasked server
//     frame parsing, ping→pong, close echo, binary fragmentation.
//
// This is a transport implementation for the AXR core, not a general xray
// replacement: VLESS-WS only, TCP streams (the UDP/0x02 header encoding is
// supported for completeness but the Worker relays WS streams).
package vlessws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// earlyDataLimit mirrors the Worker's 2048-decoded-byte early-data cap.
const earlyDataLimit = 2048

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

const maxFrame = 1 << 20 // 1 MiB guard per (re)assembled message

// errFrameTooLarge is returned when a peer declares a payload length beyond
// maxFrame. The client refuses to allocate for it: RFC 6455 §5.2 allows the
// 64-bit length form up to 2^63-1, which is far more memory than a tunnel
// endpoint should ever be able to make this process reserve.
var errFrameTooLarge = errors.New("ws: frame too large")

// errOrphanContinuation is returned when a message STARTS with a
// continuation opcode. RFC 6455 §5.4 forbids it, and readFrame already
// reassembles legitimately fragmented messages, so delivering such a frame
// as a complete message would silently desynchronise the VLESS stream.
var errOrphanContinuation = errors.New("ws: orphan continuation frame")

// BuildVLESSHeader assembles the VLESS v1 request header for a TCP stream
// (cmd 0x01) or UDP association (cmd 0x02) to host:port.
func BuildVLESSHeader(uuid []byte, host string, port uint16, udp bool) ([]byte, error) {
	if len(uuid) != 16 {
		return nil, errors.New("vless: uuid must be exactly 16 bytes")
	}
	cmd := byte(0x01)
	if udp {
		cmd = 0x02
	}
	var (
		atyp byte
		addr []byte
	)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp, addr = 1, v4
		} else {
			atyp, addr = 3, ip.To16()
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("vless: invalid host")
		}
		atyp = 2
		addr = make([]byte, 1+len(host))
		addr[0] = byte(len(host))
		copy(addr[1:], host)
	}
	buf := make([]byte, 0, 1+16+1+1+2+1+len(addr))
	buf = append(buf, 0x00) // version
	buf = append(buf, uuid...)
	buf = append(buf, 0x00) // option length
	buf = append(buf, cmd)
	buf = append(buf, byte(port>>8), byte(port&0xff))
	buf = append(buf, atyp)
	buf = append(buf, addr...)
	return buf, nil
}

// UUIDFromString parses a 128-bit UUID in dashed or plain hex form into its
// 16 wire bytes.
func UUIDFromString(s string) ([]byte, error) {
	cleaned := strings.NewReplacer("-", "", "{", "", "}", "").Replace(s)
	b, err := hex.DecodeString(cleaned)
	if err != nil || len(b) != 16 {
		return nil, errors.New("vless: invalid uuid " + s)
	}
	return b, nil
}

// EncodeEarlyData base64url-encodes (no padding) a VLESS header for the
// Sec-WebSocket-Protocol early-data slot.
func EncodeEarlyData(header []byte) (string, error) {
	if len(header) > earlyDataLimit {
		return "", fmt.Errorf("vless: early data %d bytes exceeds %d limit", len(header), earlyDataLimit)
	}
	return base64.RawURLEncoding.EncodeToString(header), nil
}

// DecodeEarlyData reverses EncodeEarlyData (Worker-side equivalent, for
// tests and diagnostics).
func DecodeEarlyData(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) > earlyDataLimit {
		return nil, fmt.Errorf("vless: early data exceeds %d bytes", earlyDataLimit)
	}
	return b, nil
}

// MaskKey returns a fresh random RFC 6455 masking key.
func MaskKey() [4]byte {
	var k [4]byte
	_, _ = rand.Read(k[:])
	return k
}

// EncodeClientFragment builds one MASKED client frame with an explicit FIN
// bit: fin=false marks an intermediate fragment of a fragmented message
// (RFC 6455 section 5.4), fin=true the final fragment.
func EncodeClientFragment(opcode byte, fin bool, payload []byte, mask [4]byte) []byte {
	b0 := byte(opcode & 0x0f)
	if fin {
		b0 |= 0x80
	}
	head := []byte{b0}
	n := len(payload)
	switch {
	case n < 126:
		head = append(head, 0x80|byte(n))
	case n < 1<<16:
		head = append(head, 0x80|126, byte(n>>8), byte(n))
	default:
		head = append(head, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(head[len(head)-8:], uint64(n))
	}
	head = append(head, mask[:]...)
	out := make([]byte, 0, len(head)+n)
	out = append(out, head...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	return out
}

// EncodeClientFrame builds a MASKED client frame (FIN set) for one message.
func EncodeClientFrame(opcode byte, payload []byte, mask [4]byte) []byte {
	return EncodeClientFragment(opcode, true, payload, mask)
}

// ---- 2.18 — WebSocket frame-rhythm fragmentation ----
//
// Stock VLESS clients (xray and friends) emit exactly one masked WS frame
// per application write: a fixed, engine-recognizable frame rhythm. AXR
// breaks it at the frame layer: each binary message is emitted as 2-4
// masked continuation frames with per-connection randomized sizes, fresh
// per-frame masking keys, and small SKEWED inter-frame gaps (bursts of
// tiny gaps with the occasional longer one — the u^2 shape that real
// interactive traffic shows). The Worker's WebSocket API reassembles
// continuation frames natively, so the VLESS payload arrives byte-identical.
//
// Honest boundary: this is framing rhythm, not encryption — a passive
// reader still sees a WebSocket carrying VLESS; the fingerprint just no
// longer matches a single-frame-per-write VLESS client. Control frames
// (ping/pong/close) are NEVER fragmented (RFC 6455 section 5.5).

const (
	// fragMinBytes / fragMaxBytes bound the size of every fragment: small
	// enough to read as normal app traffic, large enough (up to ~16 KB)
	// that bulk messages stay fragmentable in 2-4 pieces.
	fragMinBytes = 256
	fragMaxBytes = 16384
	// fragMaxCount caps fragments per message (2..4 keeps the rhythm
	// organic without pathological fragmentation of large writes).
	fragMaxCount = 4
	// fragGapMaxMS bounds the skewed micro-gap between fragments.
	fragGapMaxMS = 3
)

// Rng is the random source used for fragment sizes and gaps
// (math/rand.Float64 style).
type Rng func() float64

// Fragmenter splits one WS binary message into 2..fragMaxCount masked
// continuation frames. Deterministic for a given (payload, rng) sequence.
type Fragmenter struct {
	rng     Rng
	min     int
	max     int
	maxFrag int
	gapMin  time.Duration
	gapMax  time.Duration
}

// NewFragmenter returns a Fragmenter with the default rhythm: fragments in
// [256, 16384] bytes, 2-4 per message, skewed 0..3 ms gaps.
func NewFragmenter(rng Rng) *Fragmenter {
	return NewFragmenterWith(rng, fragMinBytes, fragMaxBytes, fragMaxCount, fragGapMaxMS*time.Millisecond)
}

// NewFragmenterWith returns a Fragmenter with explicit rhythm bounds — the
// 2.19 governor tunes these per stance. Out-of-range values keep the
// corresponding default (min in [64, max/2], max in [min*2, 1 MiB], count
// in [2, 8], gapMax in [0, 50 ms]).
func NewFragmenterWith(rng Rng, minB, maxB, count int, gapMax time.Duration) *Fragmenter {
	f := &Fragmenter{
		rng:     rng,
		min:     fragMinBytes,
		max:     fragMaxBytes,
		maxFrag: fragMaxCount,
		gapMin:  0,
		gapMax:  fragGapMaxMS * time.Millisecond,
	}
	if minB >= 64 && maxB >= 1024 && maxB <= 1<<20 && minB*2 <= maxB {
		f.min, f.max = minB, maxB
	}
	if count >= 2 && count <= 8 {
		f.maxFrag = count
	}
	if gapMax >= 0 && gapMax <= 50*time.Millisecond {
		f.gapMax = gapMax
	}
	return f
}

// Split returns the per-fragment sizes for a payload of length n: [n]
// when fragmentation is infeasible (too small, or too large for
// maxFrag fragments of <= max bytes), otherwise k sizes (kmin <= k <=
// kmax, k >= 2) that sum to n, each in [min, max]. Deterministic for a
// given rng sequence.
func (f *Fragmenter) Split(n int) []int {
	if f == nil || f.rng == nil || n < f.min*2 {
		return []int{n}
	}
	kmin := (n + f.max - 1) / f.max // fragments needed so each fits <= max
	if kmin < 2 {
		kmin = 2
	}
	kmax := f.maxFrag
	if kmax > (n-1)/f.min+1 { // fragments allowed so each can reach min
		kmax = (n-1)/f.min + 1
	}
	if kmin > kmax {
		return []int{n}
	}
	k := kmin + int(f.rng()*float64(kmax-kmin+1))
	sizes := make([]int, k)
	used := 0
	for i := 0; i < k-1; i++ {
		remaining := n - used
		// Later full fragments (>= min) plus a 1-byte tail must still fit.
		reserve := (k-2-i)*f.min + 1
		hi := f.max
		if lim := remaining - reserve; lim < hi {
			hi = lim
		}
		// The tail (last fragment) must stay <= max: draw enough now.
		lo := f.min
		if need := n - (k-1-i)*f.max - used; need > lo {
			lo = need
		}
		if lo > hi { // defensive: infeasible draw window
			lo = hi
		}
		sz := lo
		if hi > lo {
			sz = lo + int(f.rng()*float64(hi-lo+1))
		}
		sizes[i] = sz
		used += sz
	}
	sizes[k-1] = n - used
	return sizes
}

// gap draws the skewed (u^2) inter-fragment gap in [gapMin, gapMax].
func (f *Fragmenter) gap() time.Duration {
	if f.rng == nil || f.gapMax <= f.gapMin {
		return 0
	}
	u := f.rng()
	return f.gapMin + time.Duration(u*u*float64(f.gapMax-f.gapMin))
}

// send emits payload as the planned fragment sequence. The first fragment
// carries the binary opcode with FIN clear; continuations use opcode 0x0;
// only the last sets FIN. Every frame gets a fresh masking key.
func (f *Fragmenter) send(c *Client, payload []byte) error {
	sizes := f.Split(len(payload))
	if len(sizes) == 1 {
		return c.SendControl(opBinary, payload)
	}
	off := 0
	last := len(sizes) - 1
	for i, sz := range sizes {
		op := byte(opBinary)
		if i > 0 {
			op = opContinuation
		}
		frame := EncodeClientFragment(op, i == last, payload[off:off+sz], MaskKey())
		if _, err := c.conn.Write(frame); err != nil {
			return err
		}
		off += sz
		if i < last {
			if gap := f.gap(); gap > 0 {
				time.Sleep(gap)
			}
		}
	}
	return nil
}

// ---- 2.20 — WebSocket upgrade request shape jitter ----
//
// The WS upgrade HTTP request is a visible fingerprint to any MITM and to
// TLS-inspecting DPI around the handshake. Stock VLESS clients send a
// fixed five-header shape in a fixed order. AXR sends bounded
// browser-plausible shapes instead: the required headers keep their
// semantics (header order is HTTP-legal to vary), optional browser
// headers (Accept-Encoding, Accept-Language, Sec-Fetch-*, Origin,
// User-Agent) fill the request out to the shape of a real
// page-initiated WebSocket, and the per-client identity values (locale,
// user agent, page origin) are STABLE within a session — a real browser
// does not change locale per request.
//
// Honest boundary: this is HTTP header shape, not TLS-layer identity
// forgery (the uTLS ClientHello identity remains the source of truth);
// the pools are deliberately small and plausible.

// UpgradeTemplate selects the header-shape family.
type UpgradeTemplate int

const (
	// UpgradeBare is the classic five-header shape (the stock VLESS
	// client look) — kept as a contrast baseline.
	UpgradeBare UpgradeTemplate = iota
	// UpgradeLite adds Accept-Encoding + Accept-Language.
	UpgradeLite
	// UpgradeFull adds the Sec-Fetch-* trio, Origin and User-Agent —
	// the shape a cross-site browser page opening a WebSocket produces.
	UpgradeFull
)

// LocalePool / UAPool / OriginPool are the per-client identity pools. A
// client picks a stable index (UUID-derived) so the shape is consistent
// across connections of the same user.
var (
	LocalePool = []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"en,ar;q=0.9,en-US;q=0.8",
		"ar,en-US;q=0.9,en;q=0.8",
		"fa-IR,fa;q=0.9,en;q=0.8",
	}
	UAPool = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	}
	OriginPool = []string{
		"https://www.google.com",
		"https://www.bing.com",
		"https://web.telegram.org",
		"https://www.whatsapp.com",
		"https://mail.google.com",
	}
)

// UpgradeShape is the per-connection randomizer for the upgrade
// request's header shape.
type UpgradeShape struct {
	template  UpgradeTemplate
	locale    string
	userAgent string
	origin    string
	rng       Rng
}

// NewUpgradeShape builds a shape from stable per-client identity values
// and a per-connection rng. Empty identity values disable the matching
// optional header.
func NewUpgradeShape(rng Rng, template UpgradeTemplate, locale, userAgent, origin string) *UpgradeShape {
	if template < UpgradeBare || template > UpgradeFull {
		template = UpgradeLite
	}
	return &UpgradeShape{template: template, locale: locale, userAgent: userAgent, origin: origin, rng: rng}
}

// buildUpgradeRequest returns the full upgrade request text. shape ==
// nil reproduces the classic fixed five-header request byte-for-byte
// (the pre-2.20 behaviour).
func buildUpgradeRequest(host, path string, key []byte, earlyData string, shape *UpgradeShape) string {
	keyB64 := base64.StdEncoding.EncodeToString(key)
	if shape == nil {
		var b strings.Builder
		b.WriteString("GET " + path + " HTTP/1.1\r\n")
		b.WriteString("Host: " + host + "\r\n")
		b.WriteString("Upgrade: websocket\r\n")
		b.WriteString("Connection: Upgrade\r\n")
		b.WriteString("Sec-WebSocket-Key: " + keyB64 + "\r\n")
		b.WriteString("Sec-WebSocket-Version: 13\r\n")
		if earlyData != "" {
			b.WriteString("Sec-WebSocket-Protocol: " + earlyData + "\r\n")
		}
		b.WriteString("\r\n")
		return b.String()
	}

	// The jittered browser-plausible order:
	//   Host | Upgrade,Connection (rng order) | rotated optional block |
	//   Sec-WebSocket-Key, Sec-WebSocket-Version [, Sec-WebSocket-Protocol]
	// HTTP header names are case-insensitive; a subtle per-connection
	// case flip keeps the shape out of fixed-fingerprint databases.
	var optional [][2]string
	switch shape.template {
	case UpgradeLite:
		optional = append(optional, [2]string{"Accept-Encoding", "gzip"})
		if shape.locale != "" {
			optional = append(optional, [2]string{"Accept-Language", shape.locale})
		}
	case UpgradeFull:
		optional = append(optional, [2]string{"Accept-Encoding", "gzip"})
		if shape.locale != "" {
			optional = append(optional, [2]string{"Accept-Language", shape.locale})
		}
		optional = append(optional,
			[2]string{"Sec-Fetch-Site", "cross-site"},
			[2]string{"Sec-Fetch-Mode", "websocket"},
			[2]string{"Sec-Fetch-Dest", "websocket"})
		if shape.origin != "" {
			optional = append(optional, [2]string{"Origin", shape.origin})
		}
		if shape.userAgent != "" {
			optional = append(optional, [2]string{"User-Agent", shape.userAgent})
		}
	}

	uc := [2]string{"Upgrade", "Connection"}
	if shape.rng != nil && shape.rng() < 0.5 {
		uc = [2]string{"Connection", "Upgrade"}
	}
	if shape.rng != nil && len(optional) > 1 {
		rot := int(shape.rng() * float64(len(optional)))
		optional = append(optional[rot:], optional[:rot]...)
	}
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\n")
	emit := func(name, value string) {
		if shape.rng != nil && shape.rng() < 0.15 {
			name = strings.ToLower(name)
		}
		b.WriteString(name + ": " + value + "\r\n")
	}
	emit("Host", host)
	for _, nm := range uc {
		if nm == "Upgrade" {
			emit("Upgrade", "websocket")
		} else {
			emit("Connection", "Upgrade")
		}
	}
	for _, p := range optional {
		emit(p[0], p[1])
	}
	emit("Sec-WebSocket-Key", keyB64)
	emit("Sec-WebSocket-Version", "13")
	if earlyData != "" {
		emit("Sec-WebSocket-Protocol", earlyData)
	}
	b.WriteString("\r\n")
	return b.String()
}

// DecodeServerFrame parses one COMPLETE UNMASKED server frame from buf.
// It returns the bytes consumed (n) and io.ErrShortBuffer when buf holds
// only a prefix. Server frames must be unmasked (RFC 6455 §5.1).
func DecodeServerFrame(buf []byte) (opcode byte, payload []byte, n int, err error) {
	if len(buf) < 2 {
		return 0, nil, 0, io.ErrShortBuffer
	}
	opcode = buf[0] & 0x0f
	if buf[1]&0x80 != 0 {
		return 0, nil, 0, errors.New("ws: server frame is masked")
	}
	l := int(buf[1] & 0x7f)
	off := 2
	switch l {
	case 126:
		if len(buf) < 4 {
			return 0, nil, 0, io.ErrShortBuffer
		}
		l = int(binary.BigEndian.Uint16(buf[2:4]))
		off = 4
	case 127:
		if len(buf) < 10 {
			return 0, nil, 0, io.ErrShortBuffer
		}
		l = int(binary.BigEndian.Uint64(buf[2:10]))
		off = 10
	}
	if l < 0 || l > maxFrame {
		return 0, nil, 0, errors.New("ws: frame too large")
	}
	total := off + l
	if len(buf) < total {
		return 0, nil, 0, io.ErrShortBuffer
	}
	return opcode, buf[off:total], total, nil
}

// DialOptions configures a VLESS-WS dial.
type DialOptions struct {
	Host      string // entry hostname (SNI + Host header + cert validation)
	DialAddr  string // optional explicit "ip:port" clean-IP override
	Port      int    // entry port used when DialAddr is empty (0 → 443)
	Path      string // websocket path, e.g. "/sub/<base>?ed=2048"
	EarlyData []byte // optional VLESS header for 0-RTT early data
	FP        string // uTLS identity (used only in the axr_utls build)
	SkipCert  bool   // escape hatch; strongly discouraged
	// AfterTLS optionally wraps the post-handshake TLS conn before the
	// WebSocket upgrade (e.g. the surgery package's ChunkConn). The
	// returned conn must remain a valid net.Conn.
	AfterTLS func(net.Conn) net.Conn
	// Fragmenter (2.18) optionally splits each binary message into 2-4
	// masked continuation frames with randomized sizes and skewed
	// micro-gaps. nil keeps the classic one-frame-per-write behaviour.
	Fragmenter *Fragmenter
	// Upgrade (2.20) optionally shapes the WebSocket upgrade request as
	// a browser-plausible header set (order/optional headers/case
	// jitter) instead of the classic fixed five-header look. nil keeps
	// the classic request byte-for-byte.
	Upgrade *UpgradeShape
}

// Client is an open VLESS-WS tunnel.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
	frag *Fragmenter // 2.18 — optional frame-rhythm fragmentation
}

// Dial opens TCP → TLS → WebSocket against the entry and returns the tunnel.
func Dial(ctx context.Context, opts DialOptions) (*Client, error) {
	addr := opts.DialAddr
	if addr == "" {
		if opts.Host == "" {
			return nil, errors.New("vlessws: Host is required")
		}
		port := opts.Port
		if port <= 0 || port > 65535 {
			port = 443
		}
		addr = net.JoinHostPort(opts.Host, strconv.Itoa(port))
	}
	timeout := 8 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	client, err := DialConn(ctx, conn, opts)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

// DialConn performs TLS → WebSocket over an already-established TCP conn
// (e.g. one wrapped by the surgery package's SplitConn). The conn is closed
// on failure; on success ownership passes to the returned Client.
func DialConn(ctx context.Context, conn net.Conn, opts DialOptions) (*Client, error) {
	if opts.Host == "" {
		return nil, errors.New("vlessws: Host is required")
	}
	if opts.Path == "" {
		opts.Path = "/"
	}
	timeout := 8 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	tconn, err := tlsClient(conn, opts.Host, opts.FP, opts.SkipCert)
	if err != nil {
		return nil, err
	}
	if opts.AfterTLS != nil {
		tconn = opts.AfterTLS(tconn)
	}
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = tconn.SetDeadline(time.Time{}) }()

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		tconn.Close()
		return nil, err
	}
	ed := ""
	if len(opts.EarlyData) > 0 {
		v, err := EncodeEarlyData(opts.EarlyData)
		if err != nil {
			tconn.Close()
			return nil, err
		}
		ed = v
	}
	req := buildUpgradeRequest(opts.Host, opts.Path, key, ed, opts.Upgrade)
	if _, err := tconn.Write([]byte(req)); err != nil {
		tconn.Close()
		return nil, err
	}
	br := bufio.NewReader(tconn)
	code, err := readUpgradeStatus(br)
	if err != nil {
		tconn.Close()
		return nil, err
	}
	if code != 101 {
		tconn.Close()
		return nil, fmt.Errorf("vlessws: websocket upgrade rejected (HTTP %d)", code)
	}
	accept := expectedAccept(key)
	if got, err := readUpgradeHeader(br, "Sec-WebSocket-Accept"); err != nil {
		// Absence of the accept header is tolerated for compatibility;
		// presence with a wrong value is not.
		tconn.Close()
		return nil, fmt.Errorf("vlessws: bad Sec-WebSocket-Accept: %w", err)
	} else if got != "" && got != accept {
		tconn.Close()
		return nil, errors.New("vlessws: Sec-WebSocket-Accept mismatch")
	}
	return &Client{conn: tconn, r: br, frag: opts.Fragmenter}, nil
}

// Close closes the tunnel (best-effort WS close frame first).
func (c *Client) Close() error {
	_ = c.SendControl(opClose, []byte{0x03, 0xE8}) // close code 1000, big-endian
	return c.conn.Close()
}

// Conn exposes the underlying net.Conn (for surgery wrappers).
func (c *Client) Conn() net.Conn { return c.conn }

// SendBinary sends one masked binary message. With a Fragmenter
// configured, the message is emitted as 2-4 masked continuation frames
// (randomized sizes, fresh per-frame masking keys, skewed micro-gaps)
// instead of a single frame — the VLESS payload the Worker reassembles is
// byte-identical. Control frames are never fragmented.
func (c *Client) SendBinary(payload []byte) error {
	if f := c.frag; f != nil {
		return f.send(c, payload)
	}
	return c.SendControl(opBinary, payload)
}

// SendControl sends a masked control/message frame.
func (c *Client) SendControl(opcode byte, payload []byte) error {
	frame := EncodeClientFrame(opcode, payload, MaskKey())
	_, err := c.conn.Write(frame)
	return err
}

// RecvBinary returns the next binary message, servicing ping/close control
// frames transparently. Returns io.EOF on a clean close.
func (c *Client) RecvBinary() ([]byte, error) {
	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case opBinary, opText:
			return payload, nil
		case opPing:
			_ = c.SendControl(opPong, payload)
		case opPong:
			// ignore
		case opClose:
			_ = c.SendControl(opClose, payload)
			return nil, io.EOF
		case opContinuation:
			// readFrame reassembles a fragmented message and reports the
			// opcode of its FIRST frame, so a continuation here can only be
			// an orphan (RFC 6455 §5.4). Returning it as a complete message
			// would hand the caller half a VLESS payload.
			return nil, errOrphanContinuation
		default:
			return nil, fmt.Errorf("vlessws: unexpected frame opcode %d", opcode)
		}
	}
}

// WaitVLESSOK reads the 2-byte VLESS response and verifies success.
func (c *Client) WaitVLESSOK() error {
	frame, err := c.RecvBinary()
	if err != nil {
		return err
	}
	if len(frame) != 2 {
		return fmt.Errorf("vlessws: expected 2-byte VLESS response, got %d", len(frame))
	}
	if frame[0] != 0 {
		return fmt.Errorf("vlessws: unsupported VLESS version %d", frame[0])
	}
	if frame[1] != 0 {
		return fmt.Errorf("vlessws: VLESS error code %d", frame[1])
	}
	return nil
}

// readFrame parses one (possibly fragmented) server frame incrementally.
func (c *Client) readFrame() (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.r, hdr); err != nil {
		return 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0f
	if hdr[1]&0x80 != 0 {
		return 0, nil, errors.New("ws: server frame is masked")
	}
	l, err := extLen(c.r, hdr[1]&0x7f)
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, l)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return 0, nil, err
	}
	if !fin {
		for {
			h2 := make([]byte, 2)
			if _, err := io.ReadFull(c.r, h2); err != nil {
				return 0, nil, err
			}
			l2, err := extLen(c.r, h2[1]&0x7f)
			if err != nil {
				return 0, nil, err
			}
			if l2 > maxFrame {
				return 0, nil, errFrameTooLarge
			}
			chunk := make([]byte, l2)
			if _, err := io.ReadFull(c.r, chunk); err != nil {
				return 0, nil, err
			}
			payload = append(payload, chunk...)
			if len(payload) > maxFrame {
				return 0, nil, errors.New("ws: message too large")
			}
			if h2[0]&0x80 != 0 {
				break
			}
		}
	}
	return opcode, payload, nil
}

func readBytes(r io.ByteReader, e []byte) error {
	for i := range e {
		c, err := r.ReadByte()
		if err != nil {
			return err
		}
		e[i] = c
	}
	return nil
}

func extLen(r io.ByteReader, b byte) (int, error) {
	switch b {
	case 126:
		var e [2]byte
		if err := readBytes(r, e[:]); err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint16(e[:])), nil
	case 127:
		var e [8]byte
		if err := readBytes(r, e[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(e[:])
		// Bound BEFORE the int conversion: on 32-bit targets the matrix
		// builds (android/arm64 is 64-bit, but the same code compiles for
		// 386/arm) a 64-bit length can wrap into a small or negative int —
		// and make([]byte, negative) panics. A remote peer must never be
		// able to turn a length field into an allocation or a panic.
		if v > maxFrame {
			return 0, errFrameTooLarge
		}
		return int(v), nil
	default:
		return int(b), nil
	}
}

// readUpgradeStatus parses the HTTP status line, returning the code.
func readUpgradeStatus(r *bufio.Reader) (int, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, errors.New("vlessws: malformed status line")
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, errors.New("vlessws: malformed status code")
	}
	return code, nil
}

// readUpgradeHeader drains the remaining headers and returns the value of
// name ("" if absent).
func readUpgradeHeader(r *bufio.Reader, name string) (string, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if line == "\r\n" || line == "\n" {
			return "", nil
		}
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r\n"), ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v), nil
		}
	}
}

func expectedAccept(key []byte) string {
	h := sha1.New()
	h.Write(key)
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
