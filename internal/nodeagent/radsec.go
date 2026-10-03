package nodeagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"layeh.com/radius"

	"radman/internal/pki"
)

// RadSecSecret is the fixed shared secret mandated by RFC 6614 for RADIUS over TLS.
const RadSecSecret = "radsec"

type ctxKey int

const apNameKey ctxKey = 1

// streamWriter serialises responses on a RadSec connection.
type streamWriter struct {
	mu sync.Mutex
	c  net.Conn
}

func (w *streamWriter) Write(p *radius.Packet) error {
	b, err := p.Encode()
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err = w.c.Write(b)
	return err
}

// radsecTLS builds the per-connection TLS config from the current runtime, so certificate,
// CA and AP-certificate changes apply to new connections without restarting the listener.
func (s *Server) radsecTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			rt := s.rt.Load()
			if rt == nil || rt.radsecPool == nil {
				return nil, errors.New("RadSec is not configured")
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{rt.Cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    rt.radsecPool,
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					c, err := x509.ParseCertificate(raw[0])
					if err != nil {
						return err
					}
					if _, ok := rt.radsecSerials[pki.SerialHex(c)]; !ok {
						return errors.New("access point certificate is revoked or not registered")
					}
					return nil
				},
			}, nil
		},
	}
}

func (s *Server) listenRadSec(addr string) error {
	l, err := tls.Listen("tcp", addr, s.radsecTLS())
	if err != nil {
		return err
	}
	s.radsecLn = l
	s.log.Infof("RadSec (RADIUS/TLS) listening on %s", addr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serveRadSec(c.(*tls.Conn))
		}
	}()
	return nil
}

func (s *Server) serveRadSec(c *tls.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := c.Handshake(); err != nil {
		s.log.Warnf("RadSec handshake from %s failed: %v", c.RemoteAddr(), err)
		return
	}
	rt := s.rt.Load()
	cs := c.ConnectionState()
	apName := ""
	if rt != nil && len(cs.PeerCertificates) > 0 {
		serial := pki.SerialHex(cs.PeerCertificates[0])
		apName = rt.radsecSerials[serial]
		s.radsecConns.Store(c, serial)
		defer s.radsecConns.Delete(c)
	}
	s.log.Infof("RadSec connection from %s (%s)", c.RemoteAddr(), apName)
	w := &streamWriter{c: c}
	ctx := context.WithValue(context.Background(), apNameKey, apName)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[2:4]))
		if n < 20 || n > radius.MaxPacketLength {
			return
		}
		buf := make([]byte, n)
		copy(buf, hdr[:])
		if _, err := io.ReadFull(c, buf[4:]); err != nil {
			return
		}
		p, err := radius.Parse(buf, []byte(RadSecSecret))
		if err != nil {
			s.log.Warnf("RadSec: bad packet from %s: %v", c.RemoteAddr(), err)
			return
		}
		req := (&radius.Request{LocalAddr: c.LocalAddr(), RemoteAddr: c.RemoteAddr(), Packet: p}).WithContext(ctx)
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch p.Code {
			case radius.CodeAccessRequest:
				s.handleAuth(w, req)
			case radius.CodeAccountingRequest:
				s.handleAcct(w, req)
			case radius.CodeStatusServer: // RFC 5997 keepalive
				w.Write(p.Response(radius.CodeAccessAccept))
			}
		}()
	}
}

func ipOf(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	}
	h, _, _ := net.SplitHostPort(a.String())
	return net.ParseIP(strings.Trim(h, "[]"))
}
