// Package eaptls implements the server side of EAP-TLS (RFC 5216 / RFC 9190)
// on top of crypto/tls, independent of any RADIUS transport.
package eaptls

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	CodeRequest  = 1
	CodeResponse = 2
	CodeSuccess  = 3
	CodeFailure  = 4

	TypeIdentity = 1
	TypeNak      = 3
	TypeTLS      = 13

	flagLength = 0x80
	flagMore   = 0x40
	flagStart  = 0x20

	FragmentSize = 1000
)

type State int

const (
	Continue State = iota
	Success
	Failure
)

// Packet is a parsed EAP packet.
type Packet struct {
	Code, ID byte
	Type     byte
	Data     []byte // for TLS: flags + payload
}

func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < 4 {
		return nil, errors.New("short EAP packet")
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l < 4 || l > len(b) {
		return nil, errors.New("bad EAP length")
	}
	p := &Packet{Code: b[0], ID: b[1]}
	if l > 4 {
		p.Type = b[4]
		p.Data = b[5:l]
	}
	return p, nil
}

func Marshal(code, id, typ byte, data []byte) []byte {
	l := 4
	if code == CodeRequest || code == CodeResponse {
		l = 5 + len(data)
	}
	b := make([]byte, l)
	b[0], b[1] = code, id
	binary.BigEndian.PutUint16(b[2:], uint16(l))
	if l > 4 {
		b[4] = typ
		copy(b[5:], data)
	}
	return b
}

// Result is filled when the TLS handshake succeeds.
type Result struct {
	MSK []byte // 64 bytes
}

type event struct {
	needRead bool
	err      error
}

// memConn is an in-memory net.Conn used as the TLS transport.
type memConn struct {
	mu     sync.Mutex
	cond   *sync.Cond
	in     []byte
	out    []byte
	closed bool
	events chan event
}

func newMemConn() *memConn {
	c := &memConn{events: make(chan event, 8)}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *memConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.in) == 0 && !c.closed {
		c.events <- event{needRead: true}
	}
	for len(c.in) == 0 {
		if c.closed {
			return 0, io.EOF
		}
		c.cond.Wait()
	}
	n := copy(p, c.in)
	c.in = c.in[n:]
	return n, nil
}

func (c *memConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	c.out = append(c.out, p...)
	return len(p), nil
}

func (c *memConn) feed(b []byte) {
	c.mu.Lock()
	c.in = append(c.in, b...)
	c.mu.Unlock()
	c.cond.Broadcast()
}

func (c *memConn) take() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.out
	c.out = nil
	return o
}

func (c *memConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}

type dummyAddr struct{}

func (dummyAddr) Network() string                   { return "eap" }
func (dummyAddr) String() string                    { return "eap" }
func (c *memConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

// Session is one EAP-TLS conversation. Not safe for concurrent use.
type Session struct {
	conn    *memConn
	tlsConn *tls.Conn
	started bool

	nextID     byte
	lastReq    []byte // last EAP request sent (for retransmits)
	lastRespID int    // id of the last response processed (-1 none)

	in      []byte // reassembly buffer of client TLS data
	inTotal int
	outBuf  []byte
	outOff  int
	done    bool // handshake finished (final flight queued)
	failed  error
	Res     Result
}

// NewSession creates a session using the supplied TLS config.
func NewSession(cfg *tls.Config) *Session {
	c := newMemConn()
	s := &Session{conn: c, lastRespID: -1}
	s.tlsConn = tls.Server(c, cfg)
	return s
}

func (s *Session) Close() { s.conn.Close() }

func (s *Session) request(data []byte) []byte {
	s.nextID++
	pkt := Marshal(CodeRequest, s.nextID, TypeTLS, data)
	s.lastReq = pkt
	return pkt
}

// Start returns the initial EAP-Request/TLS Start packet.
func (s *Session) Start(id byte) []byte {
	s.nextID = id
	pkt := Marshal(CodeRequest, id, TypeTLS, []byte{flagStart})
	s.lastReq = pkt
	return pkt
}

func (s *Session) nextFragment() []byte {
	remaining := len(s.outBuf) - s.outOff
	n := remaining
	var flags byte
	var hdr []byte
	if s.outOff == 0 && remaining > FragmentSize {
		flags |= flagLength
		hdr = make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, uint32(remaining))
	}
	if n > FragmentSize {
		n = FragmentSize
		flags |= flagMore
	}
	data := append([]byte{flags}, hdr...)
	data = append(data, s.outBuf[s.outOff:s.outOff+n]...)
	s.outOff += n
	return s.request(data)
}

func (s *Session) runHandshake() {
	err := s.tlsConn.Handshake()
	if err == nil {
		cs := s.tlsConn.ConnectionState()
		var msk []byte
		if cs.Version == tls.VersionTLS13 {
			msk, err = cs.ExportKeyingMaterial("EXPORTER_EAP_TLS_Key_Material", []byte{TypeTLS}, 128)
		} else {
			msk, err = cs.ExportKeyingMaterial("client EAP encryption", nil, 128)
			if err != nil {
				err = errors.New("TLS 1.2 peer did not negotiate extended master secret, cannot derive EAP keys (use TLS 1.3 or update the supplicant)")
			}
		}
		if err == nil {
			s.Res.MSK = msk[:64]
			if cs.Version == tls.VersionTLS13 {
				// RFC 9190 section 2.5: protected success indication
				_, err = s.tlsConn.Write([]byte{0x00})
			}
		}
	}
	s.conn.events <- event{err: err}
}

func (s *Session) fail(err error) ([]byte, State, error) {
	s.failed = err
	return Marshal(CodeFailure, s.nextID, 0, nil), Failure, err
}

// Step consumes an EAP-Response and returns the next EAP packet to send.
// A nil packet with Continue means "drop silently".
func (s *Session) Step(resp []byte) ([]byte, State, error) {
	p, err := ParsePacket(resp)
	if err != nil || p.Code != CodeResponse {
		return s.fail(errors.New("malformed EAP response"))
	}
	if p.ID != s.nextID {
		if int(p.ID) == s.lastRespID && s.lastReq != nil {
			return s.lastReq, Continue, nil // retransmit of an answered request
		}
		return nil, Continue, nil
	}
	s.lastRespID = int(p.ID)
	if p.Type == TypeNak {
		return s.fail(errors.New("client NAKed EAP-TLS"))
	}
	if p.Type != TypeTLS || len(p.Data) < 1 {
		return s.fail(fmt.Errorf("unexpected EAP type %d", p.Type))
	}
	flags := p.Data[0]
	payload := p.Data[1:]
	if flags&flagLength != 0 {
		if len(payload) < 4 {
			return s.fail(errors.New("short TLS length field"))
		}
		s.inTotal = int(binary.BigEndian.Uint32(payload))
		payload = payload[4:]
		if s.inTotal > 1<<20 {
			return s.fail(errors.New("TLS message too large"))
		}
	}

	// client ACKing one of our fragments
	if len(payload) == 0 && flags&flagMore == 0 {
		if s.outOff < len(s.outBuf) {
			return s.nextFragment(), Continue, nil
		}
		if s.done {
			return Marshal(CodeSuccess, s.nextID, 0, nil), Success, nil
		}
		return s.fail(errors.New("unexpected empty EAP-TLS response"))
	}

	s.in = append(s.in, payload...)
	if len(s.in) > 1<<20 {
		return s.fail(errors.New("TLS message too large"))
	}
	if flags&flagMore != 0 {
		return s.request([]byte{0}), Continue, nil // ACK, ask for more
	}

	// complete client message
	msg := s.in
	s.in = nil
	s.conn.feed(msg)
	if !s.started {
		s.started = true
		go s.runHandshake()
	}
	select {
	case ev := <-s.conn.events:
		out := s.conn.take()
		if ev.err != nil {
			s.failed = ev.err
			return s.failWithErr(ev.err)
		}
		if !ev.needRead {
			s.done = true
		}
		s.outBuf, s.outOff = out, 0
	case <-time.After(15 * time.Second):
		return s.fail(errors.New("TLS handshake timeout"))
	}
	if len(s.outBuf) == 0 {
		if s.done {
			return Marshal(CodeSuccess, s.nextID, 0, nil), Success, nil
		}
		return s.request([]byte{0}), Continue, nil
	}
	return s.nextFragment(), Continue, nil
}

func (s *Session) failWithErr(err error) ([]byte, State, error) {
	return Marshal(CodeFailure, s.nextID, 0, nil), Failure, err
}
