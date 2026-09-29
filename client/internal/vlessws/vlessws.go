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

// EncodeClientFrame builds a MASKED client frame (FIN set) for one message.
func EncodeClientFrame(opcode byte, payload []byte, mask [4]byte) []byte {
	head := []byte{0x80 | (opcode & 0x0f), 0x80}
	n := len(payload)
	switch {
	case n < 126:
		head[1] |= byte(n)
	case n < 1<<16:
		head = append(head, 126, byte(n>>8), byte(n))
	default:
		head = append(head, 127, 0, 0, 0, 0, 0, 0, 0, 0)
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
	DialAddr  string // optional explicit "ip:443" clean-IP override
	Path      string // websocket path, e.g. "/sub/<base>?ed=2048"
	EarlyData []byte // optional VLESS header for 0-RTT early data
	FP        string // uTLS identity (used only in the axr_utls build)
	SkipCert  bool   // escape hatch; strongly discouraged
	// AfterTLS optionally wraps the post-handshake TLS conn before the
	// WebSocket upgrade (e.g. the surgery package's ChunkConn). The
	// returned conn must remain a valid net.Conn.
	AfterTLS func(net.Conn) net.Conn
}

// Client is an open VLESS-WS tunnel.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
}

// Dial opens TCP → TLS → WebSocket against the entry and returns the tunnel.
func Dial(ctx context.Context, opts DialOptions) (*Client, error) {
	addr := opts.DialAddr
	if addr == "" {
		if opts.Host == "" {
			return nil, errors.New("vlessws: Host is required")
		}
		addr = opts.Host + ":443"
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
	var b strings.Builder
	b.WriteString("GET " + opts.Path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + opts.Host + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	if len(opts.EarlyData) > 0 {
		ed, err := EncodeEarlyData(opts.EarlyData)
		if err != nil {
			tconn.Close()
			return nil, err
		}
		b.WriteString("Sec-WebSocket-Protocol: " + ed + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := tconn.Write([]byte(b.String())); err != nil {
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
	return &Client{conn: tconn, r: br}, nil
}

// Close closes the tunnel (best-effort WS close frame first).
func (c *Client) Close() error {
	_ = c.SendControl(opClose, []byte{1000, 0})
	return c.conn.Close()
}

// Conn exposes the underlying net.Conn (for surgery wrappers).
func (c *Client) Conn() net.Conn { return c.conn }

// SendBinary sends one masked binary message.
func (c *Client) SendBinary(payload []byte) error {
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
			return payload, nil
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
				return 0, nil, errors.New("ws: fragment too large")
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

func extLen(r io.ByteReader, b byte) (int, error) {
	switch b {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint16(e[:])), nil
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint64(e[:])), nil
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
