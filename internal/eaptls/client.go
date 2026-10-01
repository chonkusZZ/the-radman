package eaptls

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"time"
)

// Client is an EAP-TLS peer (supplicant). It is used by tests and by the
// node's built-in "eaptest" diagnostic command.
type Client struct {
	conn    *memConn
	tc      *tls.Conn
	started bool
	in      []byte
	outBuf  []byte
	outOff  int
	done    bool
	MSK     []byte
	Version uint16
}

func NewClient(cfg *tls.Config) *Client {
	c := newMemConn()
	return &Client{conn: c, tc: tls.Client(c, cfg)}
}

func (c *Client) Close() { c.conn.Close() }

func (c *Client) run() {
	err := c.tc.Handshake()
	if err == nil {
		cs := c.tc.ConnectionState()
		c.Version = cs.Version
		if cs.Version == tls.VersionTLS13 {
			c.MSK, err = cs.ExportKeyingMaterial("EXPORTER_EAP_TLS_Key_Material", []byte{TypeTLS}, 128)
		} else {
			c.MSK, err = cs.ExportKeyingMaterial("client EAP encryption", nil, 128)
		}
		if len(c.MSK) >= 64 {
			c.MSK = c.MSK[:64]
		}
	}
	c.conn.events <- event{err: err}
}

func (c *Client) next(id byte) []byte {
	remaining := len(c.outBuf) - c.outOff
	n := remaining
	var flags byte
	var hdr []byte
	if c.outOff == 0 && remaining > FragmentSize {
		flags |= flagLength
		hdr = make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, uint32(remaining))
	}
	if n > FragmentSize {
		n = FragmentSize
		flags |= flagMore
	}
	data := append([]byte{flags}, hdr...)
	data = append(data, c.outBuf[c.outOff:c.outOff+n]...)
	c.outOff += n
	return Marshal(CodeResponse, id, TypeTLS, data)
}

// Step takes a server EAP packet and returns the EAP response to send.
func (c *Client) Step(req []byte) ([]byte, State, error) {
	p, err := ParsePacket(req)
	if err != nil {
		return nil, Failure, err
	}
	switch p.Code {
	case CodeSuccess:
		return nil, Success, nil
	case CodeFailure:
		return nil, Failure, errors.New("EAP-Failure")
	}
	if p.Type != TypeTLS || len(p.Data) < 1 {
		return nil, Failure, errors.New("unexpected EAP request")
	}
	flags := p.Data[0]
	payload := p.Data[1:]
	if flags&flagLength != 0 && len(payload) >= 4 {
		payload = payload[4:]
	}
	ack := Marshal(CodeResponse, p.ID, TypeTLS, []byte{0})

	if flags&flagStart == 0 && len(payload) == 0 && flags&flagMore == 0 {
		if c.outOff < len(c.outBuf) {
			return c.next(p.ID), Continue, nil
		}
		return ack, Continue, nil
	}
	c.in = append(c.in, payload...)
	if flags&flagMore != 0 {
		return ack, Continue, nil
	}
	if c.done {
		c.in = nil
		return ack, Continue, nil
	}
	msg := c.in
	c.in = nil
	if flags&flagStart != 0 {
		c.started = true
		go c.run()
	} else {
		c.conn.feed(msg)
	}
	select {
	case ev := <-c.conn.events:
		c.outBuf, c.outOff = c.conn.take(), 0
		if ev.err != nil {
			if len(c.outBuf) > 0 {
				return c.next(p.ID), Continue, nil // send our alert, then the server fails us
			}
			return nil, Failure, ev.err
		}
		if !ev.needRead {
			c.done = true
		}
	case <-time.After(15 * time.Second):
		return nil, Failure, errors.New("client handshake timeout")
	}
	if len(c.outBuf) == 0 {
		return ack, Continue, nil
	}
	return c.next(p.ID), Continue, nil
}
